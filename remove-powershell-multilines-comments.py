#!/usr/bin/env python3

import sys

comment = False
for line in sys.stdin.readlines():
	if line.strip() == '<#':
		comment = True
	if not comment:
		print(line.strip())
	if line.strip() == '#>':
		comment = False