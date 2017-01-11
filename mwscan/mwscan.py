#!/usr/bin/env python

"""

   web-malware-scanner.py,

        A Yara wrapper to efficiently detect malware code in
        web files. Supports incremental mode, whitelisting and
        extension filtering.

        See `mwscan.py --help` for usage.

   Copyright (C) 2017 Willem de Groot <gwillem@gmail.com>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA

"""

import os
import re
import sys
import argparse
import logging
import hashlib
import json
import time
from os import path

try:
    import yara
except ImportError:
    yara = None

try:
    import psutil
except ImportError:
    psutil = None


DEFAULT_RULES_FILE = path.join(path.dirname(__file__), 'data', 'all-confirmed.yar')
LAST_RUN_FILE = path.expanduser('~/.mwscan_last_run')
CODE_EXT = ('php', 'phtml', 'js', 'jsx', 'html', 'php3', 'php4', 'php5', 'php7', 'sh')

logging.basicConfig(format='%(asctime)s %(message)s', datefmt='%c', level=logging.DEBUG)


def parse_args():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description="Scan webfolders for hidden malware.",
    )
    parser.add_argument('path', help='File or dir to scan.')
    parser.add_argument('-r', '--rules', help='Yara rules file.', default=DEFAULT_RULES_FILE)
    parser.add_argument('-n', '--newonly', help='Only consider files that were modified/created since last succesful run.'.format(LAST_RUN_FILE), action='store_true')
    parser.add_argument('-d', '--deep', action='store_true', help='Scan all files, not just code.')
    parser.add_argument('-q', '--quiet', action='store_true', help='Supress output except for matches.')

    args = parser.parse_args()

    if args.quiet:
        logging.root.setLevel(logging.WARNING)

    if args.newonly and not os.path.isdir(args.path):
        logging.error('I can only use --newonly on a directory!')
        sys.exit(1)

    if not os.path.exists(args.path):
        logging.error('{0} does not exist!'.format(args.path))
        sys.exit(1)

    if args.deep:
        args.req_ext = []
    else:
        args.req_ext = CODE_EXT

    if not os.path.isfile(args.rules):
        logging.error("Rules file {0} does not exist. Use --rules <path>".format(args.rules))
        sys.exit(1)

    if args.newonly:
        args.newer_than = find_last_run_timestamp(args.path)
    else:
        args.newer_than = None

    return args


def path_to_timestamp_file(path):

    id = str(os.geteuid()) + '\0' + path
    hash = hashlib.md5(id.encode()).hexdigest()
    return LAST_RUN_FILE + '.' + hash


def find_last_run_timestamp(path):
    tsfile = path_to_timestamp_file(path)

    if os.path.isdir(path) and os.path.isfile(tsfile):
        ts = os.path.getmtime(tsfile)
        logging.debug("Not scanning files older than {0} (from {1})".format(time.ctime(ts), tsfile))
    else:
        ts = None
        logging.debug("No timestamp reference file found for {0}, I will scan everything.".format(path))

    return ts


def write_last_run_timestamp(path):

    tsfile = path_to_timestamp_file(path)
    logging.debug("Storing last run timestamp for {0} in {1}".format(path, tsfile))

    if os.path.exists(tsfile):
        os.unlink(tsfile)

    return open(tsfile, 'a').close()


def find_targets(root_path, newer_than=None, req_ext=None):
    """
     Produce an iterator for all the relevant files recursively found under root_path.
     If root_path is a file, return an iterator with just that.
     Param ignore_older_than is an epoch timestamp from os.path.getmtime()
    """

    if os.path.isfile(root_path):
        yield root_path

    if not os.path.isdir(root_path):
        raise RuntimeError("%s is not a file or directory" % root_path)

    for root, dirs, files in os.walk(root_path):
        for myfile in files:
            path = os.path.join(root, myfile)

            if req_ext and myfile.split('.')[-1] not in req_ext:
                    continue

            if newer_than:
                # if mtime OR ctime is newer, do scan
                if os.path.getmtime(path) < newer_than and os.path.getctime(path) < newer_than:
                    continue

            yield path


def load_rules(path):

    with open(path) as fh:
        rawrules = fh.read()

    # Find whitelist hashes from comments, because yara whitelist
    # hashing is too slow. See https://github.com/VirusTotal/yara/issues/592
    m = re.search('/\*[^*]*WHITELIST = (\{.*?\})\s*\*/', rawrules, flags=re.DOTALL)
    whitelist = set(json.loads(m.group(1)) if m else [])
    rules = yara.compile(source=rawrules)

    logging.debug("Loaded {0}: {1} yara rules and {2} whitelist entries".format(
        path,
        len(list(iter(rules))),
        len(whitelist),
    ))

    return rules, whitelist


def scan_files(files, rules, whitelist):
    num_files = 0
    num_malware = 0
    num_whitelisted = 0

    for path in files:
        num_files += 1

        with open(path, 'rb') as fh:
            data = fh.read()

        sha1sum = hashlib.sha1(data).hexdigest()
        if sha1sum in whitelist:
            num_whitelisted += 1
            logging.debug("Whitelisted: {0}".format(path))
            continue

        matches = rules.match(data=data)
        if matches:
            num_malware += 1

        for m in matches:
            print("{0!s} {1}".format(m, path))

    return num_files, num_malware, num_whitelisted


def main():

    if not yara:
        logging.warning("You need to install python(3)-yara. Try one of these\n\n"
                        "\tsudo apt-get install python-yara\n"
                        "\tsudo pip install yara")
        return 1

    args = parse_args()

    # don't swamp the machine
    if psutil:
        mylife = psutil.Process()
        mylife.ionice(psutil.IOPRIO_CLASS_IDLE)
    else:
        logging.warning("Missing psutil, not adjusting IO priority.")

    rules, whitelist = load_rules(args.rules)

    try:
        files = find_targets(args.path,
                             newer_than=args.newer_than,
                             req_ext=args.req_ext)

        total, malware, whitelisted = scan_files(files, rules, whitelist)

        if args.newonly:
            write_last_run_timestamp(args.path)

        logging.info("Finished scanning {0} files: {1} malware and {2} whitelisted.".format(total, malware, whitelisted))

    except KeyboardInterrupt:
        return 1



if __name__ == '__main__':
    sys.exit(main())
