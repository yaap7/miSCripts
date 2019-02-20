#!/usr/bin/env python3

import re
import sys


def main():
    regex = re.compile('\$HEX\[([a-fA-F0-9]*)\]')
    for line in sys.stdin:
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
        print(line.strip())


if __name__ == '__main__':
    main()
