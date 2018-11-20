#!/usr/bin/env python3

# find files under path within day

import argparse
import os
from datetime import datetime, timedelta


def sec2date(epoch):
    return datetime.fromtimestamp(epoch).strftime('%Y-%m-%d %T')

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('path', help="Path", type=str)
    parser.add_argument('--days', type=int, default=1, help='Days around date')
    parser.add_argument('--date', '-d', type=str, required=True, help='Date (yyyy-mm-dd)')
    args = parser.parse_args()


    date = datetime.strptime(args.date, '%Y-%m-%d')
    start = (date - timedelta(days=args.days)).timestamp()
    end = (date + timedelta(days=args.days + 1)).timestamp()  # so that we consider the full target day

    c = 0

    for root, dirs, files in os.walk(args.path):
        for name in (dirs + files):
            c += 1
            if c % 1000 == 0:
                print('\r{} files....'.format(c), end='')
            fname = os.path.join(root, name)
            ctime = os.lstat(fname).st_ctime
            if ctime < start or ctime > end:
                continue
            print('\r{} {}'.format(sec2date(ctime), fname))
