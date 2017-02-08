import os
import logging

CACHEDIR = os.path.expanduser('~/.cache/mwscan')
LAST_RUN_FILE = os.path.join(CACHEDIR, 'last_run')
DEFAULT_EXCLUDEFILE = os.path.expanduser('~/.config/mwscan/excludes')
DEFAULT_RULES_FILE = os.path.join(os.path.dirname(__file__), 'data', 'all-confirmed.yar')
CODE_EXT = ('php', 'phtml', 'js', 'jsx', 'html', 'php3', 'php4', 'php5', 'php7', 'sh')

logging.basicConfig(format='[*] %(message)s', level=logging.DEBUG)
logging.getLogger('requests').setLevel(logging.WARNING)
