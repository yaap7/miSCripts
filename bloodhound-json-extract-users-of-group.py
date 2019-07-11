#!/usr/bin/env python3

import argparse
import json
import logging
import re
import sys


def main():
    # Parse arguments
    argParser = argparse.ArgumentParser(description='Extract list of members of groups from a Bloodhound JSON file.')
    argParser.add_argument('-f', '--file', required=True, dest='json_file', help='JSON file to read.')
    argParser.add_argument('-s', '--separator', default=',', help='Define the main field separator (Default: ",")')
    argParser.add_argument('group_names', default=['ADMINISTRATORS', 'ADMINISTRATEURS'], nargs='*', help='Group name to look for.')
    argParser.add_argument('-v', '--verbose', dest='verbosity', help='Turn on debug mode.', action='store_true')
    args = argParser.parse_args()

    # Configure logging to stdout
    logger = logging.getLogger()
    handler = logging.StreamHandler(sys.stdout)
    if args.verbosity:
        logger.setLevel(logging.DEBUG)
        formatter = logging.Formatter(fmt='%(asctime)-19s %(levelname)-8s %(message)s', datefmt='%Y-%m-%d_%H:%M:%S')
    else:
        logger.setLevel(logging.INFO)
        formatter = logging.Formatter(fmt='%(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    # define separators
    sep = args.separator

    # read input file
    with open(args.json_file, 'r') as f:
        b = json.loads(f.read())
    
    logging.debug('Looking for groups: {}'.format(args.group_names))
    logging.info('group_name{}member_type{}member_name'.format(sep, sep))
    for group in b['groups']:
        if group['Name'].split('@')[0] in args.group_names:
            logging.debug('Group found: {}'.format(group['Name']))
            for member in group['Members']:
                logging.info('{}{}{}{}{}'.format(group['Name'], sep, member['MemberType'], sep, member['MemberName']))


if __name__ == '__main__':
    main()
