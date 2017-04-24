#!/usr/bin/env python3

import re
import time

SECTIONS = ('backend', 'frontend')

YARA_RULE = '(rule (\S+) \{.+?\n\})'
NEEDLE = '\$ = (.+)\n'

for section in SECTIONS:
	print("Parsing {}".format(section))

	with open('rules/{}.yar'.format(section)) as fh:
		content = fh.read()

	customfh = open('rules/{}-custom.yar'.format(section), 'w')

	standardfh = open('rules/{}.txt'.format(section), 'w')
	standardfh.write('''
# This file contains the {} malware signatures in two forms:
#   - String literals (without backslash escaping)
#   - Regexes (enclosed in / / characters)
# 
# NB: Regex is slower! So literals are preferred.\n\n\n'''.lstrip().format(section.upper()))


	# print("got content with length {}".format(len(content)))

	for block, rulename in re.findall(YARA_RULE, content, flags=re.DOTALL):
		# print("{} {}".format(rulename, block))

		if 'condition: any of them' not in block:
			customfh.write(block.strip()+'\n')
			continue



		standardfh.write('# {}\n'.format(rulename))
		for needle in re.findall(NEEDLE, block):
			# print("found needle in rulename", rulename, needle) 

			if needle.startswith('"'):  # otherwise, regex
				needle = needle[1:-1].decode('string_escape')

			standardfh.write('{}\n'.format(needle))

		standardfh.write('\n')


	customfh.close()
