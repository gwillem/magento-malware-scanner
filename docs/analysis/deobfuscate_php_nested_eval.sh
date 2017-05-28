#!/bin/bash
#
# Copyright (C) 2017 MageHost - Jeroen Vermeulen <jeroen@magehost.pro>
#
if [ -z $1 ]; then
    echo
    echo "USAGE:  $0  path/to/License.php"
    echo
    exit 99
fi
# Try 'gsed' first to make it work on macOS
SED=$( which gsed || which sed )
echo
echo "WARNING: This script will execute code from '$1' as user 'nobody'."
read -p "Press enter to continue: " x
DEST="$1.dec.php"
cp "$1" "$DEST"
STEP=0
while egrep -q 'eval\(("\\x65\\x76\\x61\\x6C\\x28|\w+\()' "$DEST" ||
      ( egrep -q 'eval\(' "$DEST" && egrep -q '\\x\w\w\\x\w\w\\x\w\w\\x\w\w\\x\w\w' "$DEST" ); do
    ((STEP++))
    if [ $STEP -gt 1000 ]; then
        echo Stopping after trying 1000 steps.
        exit 10
    fi
    # Vladimir Popov's trick
    $SED -i "s/eval(base64_decode('JF9WPWd6aW5mbGF0ZShiYXNlNjRfZGVjb2RlKCRfVikpOyRfVj1zdHJ0cigkX1YsJzEyMzQ1NnZsYWRpJywndmxhZGkxMjM0NTYnKTtldmFsKCRfVik7'));/\$_V=gzinflate(base64_decode(\$_V));\$_V=strtr(\$_V,'123456vladi','vladi123456');eval(\$_V);/" "$DEST"
    #
    echo "<?php $( cat "$DEST" | sed 's/eval(/echo(/g' | sudo -u nobody php )" > "$DEST"
    echo -n "."
    # Enable to keep steps for debugging
    # cp "$DEST" "$DEST.dec-$STEP.php"
done
echo
echo "Result is written to '$DEST'."
echo