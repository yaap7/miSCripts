#!/usr/bin/env python3

import re
import sys


def unhex_line(line):
    regex = re.compile('\$HEX\[([a-fA-F0-9]*)\]')
    while re.search(regex, line):
        try:
            decoded = bytes.fromhex(re.search(regex, line).group(1)).decode('iso-8859-1')
            # patch to avoid issue with '\9' in decoded
            decoded = decoded.replace('\\', '\\\\')
            line = regex.sub(decoded, line.strip())
        except Exception as e:
            sys.stderr.write('Error with line = {}'.format(line))
            sys.stderr.write('decoded = {}'.format(decoded))
            raise e
    return(line.strip())


def main():
    for line in sys.stdin:
        print(unhex_line(line))

if __name__ == '__main__':
    main()
