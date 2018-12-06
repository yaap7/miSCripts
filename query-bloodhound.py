#!/usr/bin/env python3

import argparse
import base64
import json
import logging
import requests


def print_list(l, t=0):
    for i in l:
        if isinstance(i, str):
            print(' '*t + '  - {}'.format(i))
        elif isinstance(i, int):
            print(' '*t + '  - {}'.format(i))
        elif isinstance(i, dict):
            print(' '*t + '  - {')
            print_dict(i, t+4)
            print(' '*(t+4) + '}')
        elif isinstance(i, list):
            print(' '*t + '  - [')
            print_list(i, t+4)
            print(' '*(t+4) + ']')
        else:
            print('####### ERROR, type {} not supported yet.'.format(type(i)))


def print_dict(d, t=0):
    for k in d:
        if isinstance(d[k], str):
            print(' '*t + '  - {} = {}'.format(k, d[k]))
        elif isinstance(d[k], int):
            print(' '*t + '  - {} = {}'.format(k, d[k]))
        elif isinstance(d[k], dict):
            print(' '*t + '  - {} = {{'.format(k))
            print_dict(d[k], t+4)
            print(' '*(t+4) + '}')
        elif isinstance(d[k], list):
            print(' '*t + '  - {} = ['.format(k))
            print_list(d[k], t+4)
            print(' '*(t+4) + ']')
        else:
            print('####### ERROR, type {} not supported yet.'.format(type(d[k])))


def find_computer_pwn3d_from_user(user, args):
    if '@' not in user:
        user = user + '@' + args.domain
    statement = 'MATCH (u:User), (c:Computer) WHERE u.name="{}" WITH u, c MATCH p = (u)-[r*1..]->(c) return DISTINCT c'.format(user.upper())
    authB64 = base64.b64encode('{}:{}'.format(args.user, args.password).encode('utf-8'))
    headers = { "Accept": "application/json; charset=UTF-8",
                    "Content-Type": "application/json",
                    "Authorization": authB64}
    data = {"statements": [{'statement': statement}]}
    url = 'http://{}/db/data/transaction/commit'.format(args.host)
    r = requests.post(url=url,headers=headers,json=data)
    j = json.loads(r.text)
    result = []
    for row in j['results'][0]['data']:
        result.append(row['row'][0]['name'])
    return result


def main():
    # Argument definition
    argParser = argparse.ArgumentParser(description='Perform queries on a neo4j database pre-filled with BloodHound results.')
    argParser.add_argument('-d', '--debug', help='Turn on debug mode', action='store_true')
    argParser.add_argument('-D', '--domain', help='Define the domain (FQDN required)', default='')
    argParser.add_argument('-H', '--host', help='Define the host to connect to (default: localhost:7474)', default='localhost:7474')
    argParser.add_argument('-u', '--user', help='Define the user (default: neo4j)', default='neo4j')
    argParser.add_argument('-p', '--password', help='Define the password (default: neo4j)', default='neo4j')
    argParser.add_argument('users', help='Users own3d to be abused', nargs='*')
    args = argParser.parse_args()

    # enable debug is requested
    logLevel = logging.INFO
    if args.debug:
        logLevel = logging.DEBUG
    logging.basicConfig(level=logLevel, format='%(message)s')
    logging.debug('Debug enabled.')

    logging.debug('Host = {}'.format(args.host))
    logging.debug('Users = {}'.format(args.users))
    for user in args.users:
        for computer in find_computer_pwn3d_from_user(user, args):
            print(computer)


if __name__ == '__main__':
    main()
