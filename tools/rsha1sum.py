#!/usr/bin/env python

"""

Recursively sha1sum a dir (to generate whitelists)

Usage: rsha1sum <dir> > whitelist.txt

"""

import hashlib
import os
import sys

path = sys.argv[1]

allhashes = set()

for root, dirs, files in os.walk(path):
    for filename in files:
        fullpath = os.path.join(root, filename)
        try:
            with open(fullpath) as fh:
                hash = hashlib.sha1(fh.read()).hexdigest()
        except (OSError, IOError):
            continue
        # sys.stderr.write("{} {}\n".format(hash, fullpath))
        allhashes.add(hash)

for h in allhashes:
    print(h)


