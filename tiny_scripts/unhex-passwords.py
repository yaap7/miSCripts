#!/usr/bin/env python3

import re
import sys


def unhex_line(line):
    regex = re.compile(r'\$HEX\[([a-fA-F0-9]*)\]')
    while re.search(regex, line):
        try:
            decoded = bytes.fromhex(regex.search(line).group(1)).decode('iso-8859-1')
            # patch to avoid issue with '\9' in decoded
            decoded = decoded.replace('\\', '\\\\')
            line = regex.sub(decoded, line.strip())
        except ValueError:
            # The value inside HEX brackets is not hex only
            # so we assume it is an error and
            # we simply remove it to avoid decode errors
            line = regex.sub('', line)
        except Exception as e:
            sys.stderr.write('Error with line = {}\n'.format(line))
            sys.stderr.write('decoded = {}\n'.format(decoded))
            raise e
    return(line.strip())


def main():
    for line in sys.stdin:
        print(unhex_line(line))

if __name__ == '__main__':
    main()
