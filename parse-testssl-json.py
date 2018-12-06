#!/usr/bin/env python3

import argparse
import json
import logging
import re
import sys


def main():
    # Argument definition
    argParser = argparse.ArgumentParser(description='Extract the list of ciphers from a testssl.sh json file.')
    argParser.add_argument('-d', '--debug', help='Turn on debug mode', action='store_true')
    argParser.add_argument('testssl', help='testssl.sh json file to be parsed', nargs='+')
    args = argParser.parse_args()

    rootLog = logging.getLogger()
    ch = logging.StreamHandler(sys.stdout)
    logging.getLogger().setLevel(logging.WARNING)
    ch.setLevel(logging.INFO)
    if args.debug:
        ch.setLevel(logging.DEBUG)
    logging.getLogger().setLevel(logging.DEBUG)
    ch.setFormatter(logging.Formatter('%(message)s'))
    rootLog.addHandler(ch)

    for testssl in args.testssl:
        logging.debug('Parsing file {}.'.format(testssl))
        with open(testssl, 'r') as f:
            results = json.load(f)
            for item in results:
                if re.match('^cipher_x', item['id']):
                    logging.info(item['finding'])


if __name__ == '__main__':
    main()
