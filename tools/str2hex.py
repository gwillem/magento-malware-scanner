#!/usr/bin/env python3
 
import sys

out = ''
chars = ' '.join(sys.argv[1:])

if not chars:
    print("No arg to convert!")
    sys.exit(1)

for c in chars:
    out += hex(ord(c))

print("{} = \"{}\"".format(chars, out.upper().replace('0X', '\\x')))
