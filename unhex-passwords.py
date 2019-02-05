#!/usr/bin/env python3

import re
import sys


def main():
    regex = re.compile('\$HEX\[([a-fA-F0-9]*)\]')
    for line in sys.stdin:
        while re.search(regex, line):
            decoded = bytes.fromhex(re.search(regex, line).group(1)).decode('utf-8')
            line = regex.sub(decoded, line.strip())
        print(line.strip())


if __name__ == '__main__':
    main()

