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
import time
from mwscan import settings
from mwscan.ruleset import providers

try:
    import psutil
except ImportError:
    psutil = None


def parse_args():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description="Scan webfolders for hidden malware.",
    )
    parser.add_argument('path', help='File or dir to scan.')
    parser.add_argument('-n', '--newonly', help='Only show newly found infections since last run.', action='store_true')
    parser.add_argument('-d', '--deep', action='store_true', help='Scan all files, not just code.')
    parser.add_argument('-q', '--quiet', action='store_true', help='Supress output except for matches.')
    parser.add_argument('-r', '--rules', help='Yara rules file.', default=settings.DEFAULT_RULES_FILE)
    parser.add_argument('-s', '--ruleset', choices=sorted(providers.keys()), help='Download and use from upstream')
    parser.add_argument('-w', '--whitelist', help='Use extra SHA1 whitelist file.')

    args = parser.parse_args()

    if args.quiet:
        logging.root.setLevel(logging.WARNING)

    if (args.ruleset and args.ruleset != 'file'):
        args.rules = None

    if args.rules:
        args.ruleset = 'file'

    if args.newonly and not os.path.isdir(args.path):
        parser.error('I can only use --newonly on a directory!')

    if not os.path.exists(args.path):
        parser.error('{0} does not exist!'.format(args.path))

    if args.deep:
        args.req_ext = []
    else:
        args.req_ext = settings.CODE_EXT

    if args.rules and not os.path.isfile(args.rules):
        parser.error("Rules file {0} does not exist. Use --rules <path>".format(args.rules))

    return args


def scanpath_to_runfile(path):
    abspath = os.path.abspath(path)
    return settings.LAST_RUN_FILE + '.' + re.sub('[^\w\d]', '_', abspath.strip('/'))


def load_last_run_results(scanpath):
    resultfile = scanpath_to_runfile(scanpath)

    if not os.path.isfile(resultfile):
        return set()

    with open(resultfile) as fh:
        return set([x.strip() for x in fh])


def write_last_run_results(scanpath, malware):
    resultfile = scanpath_to_runfile(scanpath)
    logging.debug("Saving results to {0}".format(resultfile))

    with open(resultfile, 'w') as fh:
        for x in sorted(malware):
            fh.write("{0}\n".format(x))


def find_targets(root_path, newer_than=None, req_ext=None):
    """
     Produce an iterator for all the relevant files recursively found under root_path.
     If root_path is a file, return an iterator with just that.
     Param ignore_older_than is an epoch timestamp from os.path.getmtime()
    """

    if os.path.isfile(root_path):
        yield root_path
    elif not os.path.isdir(root_path):
        raise RuntimeError("%s is not a file or directory" % root_path)

    for root, dirs, files in os.walk(root_path):
        for myfile in files:
            path = os.path.join(root, myfile)

            if req_ext and myfile.split('.')[-1] not in req_ext:
                continue

            if os.path.islink(path):
                continue

            if newer_than:
                # if mtime OR ctime is newer, do scan
                if os.path.getmtime(path) < newer_than and os.path.getctime(path) < newer_than:
                    continue

            yield path


def scan_files(files, rules, whitelist):
    num_files = 0
    num_malware = 0
    num_whitelisted = 0

    malware = set()
    whitelisted = set()

    for path in files:
        num_files += 1

        try:
            with open(path, 'rb') as fh:
                data = fh.read()
        except IOError:
            logging.warning("IO error on {0}: skipping.".format(path))
            continue

        sha1sum = hashlib.sha1(data).hexdigest()
        if sha1sum in whitelist:
            num_whitelisted += 1
            whitelisted.add(path)
            continue

        matches = rules.match(data=data)
        if matches:
            malware.add(path)
            num_malware += 1

        for m in matches:
            logging.info("Malware: {0} ({1!s})".format(path, m))

    logging.info("Finished scanning {0} files: {1} malware and {2} whitelisted.".format(num_files, num_malware, num_whitelisted))

    return malware, whitelisted


def filter_new_infections(path, infected):
    prev_infected = load_last_run_results(path)
    new_infected = infected - prev_infected
    write_last_run_results(path, infected)
    return new_infected


def main():

    args = parse_args()

    # don't swamp the machine
    if psutil and sys.platform != "darwin":
        mylife = psutil.Process()
        mylife.ionice(psutil.IOPRIO_CLASS_IDLE)

    # ensure cache dir
    if not os.path.exists(settings.CACHEDIR):
        os.makedirs(settings.CACHEDIR, 0o700)

    provider = providers[args.ruleset]
    rules, whitelist = provider(args=args).get()

    if args.whitelist:
        with open(args.whitelist) as fh:
            whitelist.update(re.findall('[a-z0-9]{40}', fh.read()))

    logging.debug("Loaded {0} yara rules and {1} whitelist entries".format(
        len(list(iter(rules))),
        len(whitelist),
    ))

    try:
        files = find_targets(args.path, req_ext=args.req_ext)

        infected, whitelisted = scan_files(files, rules, whitelist)

        if args.newonly:
            for path in filter_new_infections(args.path, infected):
                cmtime = max(os.path.getmtime(path), os.path.getctime(path))
                cmtime = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(cmtime))
                print("{0} {1}".format(cmtime, path))


    except KeyboardInterrupt:
        return 1


if __name__ == '__main__':
    sys.exit(main())
