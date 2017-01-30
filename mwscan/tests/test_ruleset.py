import os
import sys
import mwscan.ruleset
from mwscan.ruleset import providers, RulesProvider
from mwscan import settings
from unittest import TestCase

try:
    from unittest import mock
except ImportError:
    import mock

# speed up repeated tests, depends on py2/3 pickle version
try:
    import requests_cache
    requests_cache.install_cache('rulesets-{0}'.format(sys.version_info[0]), expire_after=3600 * 24)
except ImportError:
    pass


settings.CACHEDIR = '/cachedir'
openmock = mwscan.ruleset.open = mock.mock_open()

class TestRuleset():

    """
        Checks rule providers:
         - Minimum number of parsed rules / whitelists
         - Do rules compile with our Yara?

        DRY: uses test generators (doesn't work with unittest.TestCase)

    """

    def _check_provider(self, provider, expected_numrules, expected_numwhitelist):

        provobj = providers[provider]()
        rules, whitelist = provobj.get()

        # cannot iterate two times over yara.Rules object,
        # no other way to count unfortunately
        got_numrules = len(list(iter(rules)))
        got_numwhitelist = len(whitelist)

        assert type(rules).__name__ == 'Rules', \
            'wrong type: %s' % type(rules).__name__

        assert got_numrules >= expected_numrules, \
          'wrong num rules: %s' % got_numrules

        assert got_numwhitelist >= expected_numwhitelist, \
            'wrong num whitelists %s' % got_numwhitelist

    def test_providers(self):

        tests = (
            # provider, min rules, min whitelisted
            ('nbs', 15, 1279),
            ('byte', 60, 20),
            ('magesec', 150, 100000),
            # ('magemojo', 150, 65000),
        )

        for provider, numrules, numwhitelists in tests:
            yield self._check_provider, provider, numrules, numwhitelists


class TestHttpGet(TestCase):

    def setUp(self):
        self.rp = RulesProvider()

    def test_get_cachefile(self):

        url = 'http://bla'

        cachefile = self.rp._get_cache_filename(url)
        self.assertEqual(cachefile, '/cachedir/rulesprovider.cache_3f3f5be699e1117a2e7db8f7b1394581bd3aa1bd')

    @mock.patch('mwscan.ruleset.requests.get')
    def test_httpget_returns_cached_result(self, getmock):

        dummycontent = 'cachedcontent'
        dummyts = 1485427826

        # getmock = mwscan.ruleset.requests.get = mock.MagicMock()
        getmock.status_code = 304

        cachecontentmock = self.rp._get_cache_timestamp_content = mock.MagicMock()
        cachecontentmock.return_value = dummyts, dummycontent

        url = 'bla'
        content = self.rp._httpget(url)

        self.assertEqual(content, dummycontent)
        getmock.assert_called_with(url, headers={'if-modified-since': dummyts})
        openmock.assert_not_called()

    def test_httpget_raises_with_unreachable_url(self):
        url = 'http://localhost:99999'
        with self.assertRaises(RuntimeError):
            self.rp._httpget(url)

    def test_httpget_raises_with_invalid_url(self):
        url = 'noschemahere'
        with self.assertRaises(RuntimeError):
            self.rp._httpget(url)
