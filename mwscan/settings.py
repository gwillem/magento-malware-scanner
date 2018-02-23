import os
import logging

CACHEDIR = os.path.expanduser('~/.cache/mwscan')
LAST_RUN_FILE = os.path.join(CACHEDIR, 'last_run')
DEFAULT_EXCLUDEFILE = os.path.expanduser('~/.config/mwscan/excludes')
CODE_EXT = ('php', 'phtml', 'js', 'jsx', 'html', 'php3', 'php4', 'php5', 'php7', 'sh', 'ini')

logging.basicConfig(format='[*] %(message)s', level=logging.DEBUG)
logging.getLogger('requests').setLevel(logging.WARNING)
