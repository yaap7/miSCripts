#!/usr/bin/env python3

import argparse
import sys
import censys.ipv4
from os.path import dirname, join


def main():
    # Check args
    argParser = argparse.ArgumentParser(description='Port scan using censys database')
    argParser.add_argument('filter', nargs='+', help='Censys filter to search for. Can be a list of IPs.')
    argParser.add_argument('-c', '--csv', dest='csv', help='Turn on CSV output', action='store_true')
    args = argParser.parse_args()
    # Retrieve Censys API key
    api_id, api_secret = open(join(dirname(sys.argv[0]),'censys_api_key.txt'), 'r').readline().split(':')
    c = censys.ipv4.CensysIPv4(api_id=api_id, api_secret=api_secret)
    # search
    query = ' '.join(args.filter)
    fields = ['ip', 'protocols']
    for result in c.search(query=query, fields=fields):
        if args.csv:
            print('IP,Port')
        else:
            print('Result for {}'.format(result['ip']))
        for port in result['protocols']:
            if args.csv:
                print('{},{}'.format(result['ip'], port))
            else:
                print('+ Open port: {}'.format(port))


if __name__ == '__main__':
    main()
