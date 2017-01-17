import requests
import re
import json
import logging
import yara


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

        m = re.search('/\*[^*]*WHITELIST = (\{.*?\})\s*\*/', rawrules, flags=re.DOTALL)
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


    def _httpget(self, url):

        filename = last_url_path(url)
        logging.debug("Fetching {0}".format(filename))

        return requests.get(url).text


    def get(self):
        """Returns rules, whitelist"""

        rawrules = self.get_rules()

        # provider specific transformation
        rawrules, whitelist = self.transform_rules(rawrules)

        # if alternative whitelist method is required
        whitelist.update(self.get_whitelist())
        whitelist.update(self.find_whitelist_in_rawrules(rawrules))

        rules = yara.compile(source=rawrules)

        logging.debug("Loaded {0} yara rules and {1} whitelist entries".format(
            len(list(iter(rules))),
            len(whitelist),
        ))

        return rules, whitelist

    def _recursive_fetch(self, url):

        def include(match):
            relpath = match.group(1)
            # return match.group(1)
            newurl = strip_last_url_path(url) + '/' + relpath
            return "/* included from {0} */\n".format(newurl) + self._recursive_fetch(newurl)

        data = self._httpget(url)
        data = re.sub('include "([^"]+?)"\s+', include, data)
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

        tokens = re.findall('\n(?:global )?(?:private )?rule .+?\n\{\n.+?\n\}', rawrules, flags=re.DOTALL)

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


class Byte(RulesProvider):
    rules_url = 'https://raw.githubusercontent.com/gwillem/magento-malware-scanner/master/build/all-confirmed.yar'


providers = {
    'nbs': NBS,
    'byte': Byte,
    'magemojo': Magemojo,
    'magesec': Magesec,
    'file': Files,
}
