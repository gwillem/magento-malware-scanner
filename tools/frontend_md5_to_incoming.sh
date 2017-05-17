#!/bin/bash

set -e
set -x

cd "$(dirname "$0")"

for i in $(find ../corpus/incoming/frontend/ -type f ! -size 0); do
    new="$(md5sum $i | cut -d' ' -f1)"
    echo "$i -> $new"
    mv $i ../corpus/frontend/$new
done
