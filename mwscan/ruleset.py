import os
import re
import json
import logging
import hashlib
import requests
import yara
import time
from requests.exceptions import RequestException
from mwscan import settings

# For very old installs, eg CentOS: https://github.com/magesec/magesec/issues/60
try:
    requests.packages.urllib3.disable_warnings()
except AttributeError:
    # Ubuntu 12.04
    pass


def strip_last_url_path(url):
    parent, _, _ = url.rpartition('/')
    return parent


def last_url_path(url):
    return url.rpartition('/')[2]


class RulesProvider:
    rules_url = None
    whitelist_url = None

    def __init__(self, **kwargs):
        logging.info("Using {0} rules.".format(self.__class__.__name__))
        self._args = kwargs.get('args')

    def find_whitelist_in_rawrules(self, rawrules):
        # Find whitelist hashes from comments, because yara whitelist
        # hashing is too slow. See https://github.com/VirusTotal/yara/issues/592

        m = re.search(
            '/\*[^*]*WHITELIST = (\{.*?\})\s*\*/', rawrules, flags=re.DOTALL)
        return set(json.loads(m.group(1)) if m else [])

    def get_rules(self):
        return self._recursive_fetch(self.rules_url)

    def get_whitelist(self):
        if not self.whitelist_url:
            return set()

        data = self._httpget(self.whitelist_url)
        hashes = re.findall('[a-f0-9]{40}', data)  # assume sha1 hex hash
        return set(hashes)

    def transform_rules(self, rawrules):
        """For specific rules providers, to mangle into mwscan compatible form"""
        whitelist = set()
        return rawrules, whitelist

    def _get_cache_filename(self, url):
        hash = hashlib.sha1(url.encode()).hexdigest()
        cachefile = self.__class__.__name__.lower() + '.cache_' + hash
        cachefile = os.path.join(settings.CACHEDIR, cachefile)
        return cachefile

    def _get_cache_timestamp_content(self, cachefile):

        cachedcontent = None
        mtime = None

        if os.path.exists(cachefile):

            mtime = os.path.getmtime(cachefile)
            mtime = time.gmtime(mtime)
            mtime = time.strftime('%a, %d %b %Y %H:%M:%S GMT', mtime)

            with open(cachefile) as fh:
                cachedcontent = fh.read()

        return mtime, cachedcontent

    def _httpget(self, url):
        """ Fetch URL and use if-modified-since header, store in cache, 
        fail if upstream fails """

        filename = last_url_path(url)
        cachefile = self._get_cache_filename(url)
        mtime, cachedcontent = self._get_cache_timestamp_content(cachefile)
        headers = dict()
        # requests 0.8.2 doesn't like None header values
        if mtime:
            headers['if-modified-since'] = mtime

        logging.debug("Fetching {0}".format(filename))

        try:
            resp = requests.get(url, headers=headers)
        except RequestException as e:
            if cachedcontent is not None:
                return cachedcontent
            raise RuntimeError(
                "No cache and invalid response for {0}: {1}".format(url, e))

        if resp.status_code == 200:
            with open(cachefile, 'wb') as fh:
                fh.write(resp.content)

            return resp.content.decode()

        if resp.status_code == 304:
            logging.debug('Upstream {0} is the same as our cache (HTTP 304)'.format(url))

        # Upstream hasn't changed (304) or has err'd
        if cachedcontent is not None:
            return cachedcontent

        raise RuntimeError("No cache @ {0} and invalid response for {1}: {2}".format(
            cachefile, url, resp.status_code))

    def get(self):
        """Returns rules, whitelist"""

        rawrules = self.get_rules()

        # provider specific transformation, if necessary
        rawrules, whitelist = self.transform_rules(rawrules)

        # if alternative whitelist method is required
        whitelist.update(self.get_whitelist())
        whitelist.update(self.find_whitelist_in_rawrules(rawrules))

        rules = yara.compile(source=rawrules)

        return rules, whitelist

    def _recursive_fetch(self, url):

        def include(match):
            relpath = match.group(1)
            # return match.group(1)
            newurl = strip_last_url_path(url) + '/' + relpath
            return "/* included from {0} */\n".format(newurl) + self._recursive_fetch(newurl)

        data = self._httpget(url)
        data = re.sub(r'include "([^"]+?)"\s+', include, data)
        # data = re.sub('import "hash"\s*', '', data)
        return data


class Files(RulesProvider):

    # initialize with Files(args)
    def get_rules(self):
        path = self._args.rules
        logging.info("Loading {0}".format(self._args.rules))
        with open(path) as fh:
            return fh.read()


class NBS(RulesProvider):

    rules_url = 'https://raw.githubusercontent.com/nbs-system/php-malware-finder/master/php-malware-finder/php.yar'

    def transform_rules(self, rawrules):
        whitelist = set()
        rules = list()

        tokens = re.findall(
            '\n(?:global )?(?:private )?rule .+?\n\{\n.+?\n\}', rawrules, flags=re.DOTALL)

        for token in tokens:
            hashes = re.findall('== "([a-f0-9]{40})"', token)

            if 'rule IsWhitelisted' in token:
                continue

            if hashes or 'hash.sha1' in token:
                whitelist.update(hashes)
            else:
                token = token.strip()
                token = re.sub(' and not IsWhitelisted', '', token)

                rules.append(token.strip())

        return '\n'.join(rules), whitelist


class Magemojo(RulesProvider):
    rules_url = 'https://raw.githubusercontent.com/magesec/magesecurityscanner/master/yararules.yar'
    whitelist_url = 'https://raw.githubusercontent.com/magesec/magesecurityscanner/master/magesecurityscan/sha1whitelist.json'


class Magesec(RulesProvider):
    rules_url = 'https://magesec.org/download/yara-standard.yar'
    whitelist_url = 'https://magesec.org/download/whitelist.json'


class Mwscan(RulesProvider):
    rules_url = 'https://mwscan.s3.amazonaws.com/mwscan.yar'


class MageHost(RulesProvider):
    rules_url = 'https://raw.githubusercontent.com/magehost/magento-malware-scanner/master/rules/magehost.yar'
    whitelist_url = 'https://raw.githubusercontent.com/magehost/magento-malware-scanner/master/rules/magehost_whitelist.json'


providers = {
    'nbs': NBS,
    'byte': Mwscan,  # backwards compatible
    'mwscan': Mwscan,
    'magehost': MageHost,
    'magemojo': Magemojo,
    'magesec': Magesec,
    'file': Files,
}
