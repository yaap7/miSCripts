#!/usr/bin/env python3

import argparse
import json
import logging
import requests
import sys
from os.path import dirname, join


def query_ipvoid(api_key, ip):
    url = 'https://endpoint.apivoid.com/iprep/v1/pay-as-you-go/?key={}&ip={}'.format(api_key, ip)
    response = requests.get(url)
    if not (200 <= response.status_code < 300):
        logging.error('Error: status_code = {} for ip = {}'.format(response.status_code, ip))
        logging.error('Reponse text = {}'.format(response.text))
        return False
    return response.text


def parse_output(output, ip):
    o = json.loads(output)
    if 'success' in o and o['success']:
        # normally parse the result
        print('{} has a detection rate of {}'.format(ip, o['data']['report']['blacklists']['detection_rate']))
        engines = o['data']['report']['blacklists']['engines']
        for engine in engines.values():
            if engine['detected']:
                print('* {} is detected in engine {}'.format(ip, engine['engine']))
    else:
        if 'error' in o:
            logging.error('Error: {} returns an error = {}'.format(ip, o['error']))
        else:
            logging.error('Error: {} returns an unknown error.'.format(ip))


def main(args):
    # Retrieve APIvoid API key
    api_key = open(join(dirname(sys.argv[0]),'apivoid_api_key.txt'), 'r').readline().strip()
    print('api_key = {}'.format(api_key))
    # query
    for ip in args.ips:
        result = query_ipvoid(api_key, ip)
        print('result = {}'.format(result))
        if result:
            if args.prefix:
                with open('{}{}.log'.format(args.prefix, ip), 'w') as f:
                    json.dump(json.loads(result), f, indent=2, sort_keys=True)
            parse_output(result, ip)


if __name__ == '__main__':
    # Check args
    argParser = argparse.ArgumentParser(description='Query ipvoid.com to get reputation of IP.')
    argParser.add_argument('ips', nargs='+', help='IPs to search for.')
    argParser.add_argument('-o', '--output', dest='prefix', default='', help='Enable output in a file per IP. Prefix can be specified')
    args = argParser.parse_args()
    # logging configuration
    logging.basicConfig(format='%(asctime)-15s %(message)s', level=logging.INFO, datefmt='%Y-%m-%d_%H:%M:%S')
    logging.Formatter
    main(args)
