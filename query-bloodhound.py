#!/usr/bin/env python3

import argparse
import base64
import json
import logging
import requests
import sys


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
    logging.debug('statement = {}'.format(statement))
    authB64 = base64.b64encode('{}:{}'.format(args.user, args.password).encode('utf-8'))
    headers = { "Accept": "application/json; charset=UTF-8",
                    "Content-Type": "application/json",
                    "Authorization": authB64}
    data = {"statements": [{'statement': statement}]}
    url = 'http://{}/db/data/transaction/commit'.format(args.host)
    r = requests.post(url=url,headers=headers,json=data)
    j = json.loads(r.text)
    if 'errors' in j and len(j['errors']) > 0:
        return j['errors']
    result = []
    for row in j['results'][0]['data']:
        result.append(row['row'][0]['name'])
    return result


def list_domain_admins(args):
    statement = 'MATCH (u:User), (g:Group) WHERE g.name = "DOMAIN ADMINS@{}" WITH u, g MATCH (g)<-[r:MemberOf*1..]-(u) RETURN DISTINCT u'.format(args.domain.upper())
    logging.debug('statement = {}'.format(statement))
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
    argParser.add_argument('-v', '--verbose', dest='verbosity', help='Turn on debug mode', action='store_true')
    argParser.add_argument('-d', '--domain', help='Define the domain (FQDN required)', required=True)
    argParser.add_argument('-H', '--host', help='Define the host to connect to (default: localhost:7474)', default='localhost:7474')
    argParser.add_argument('-u', '--user', help='Define the user (default: neo4j)', default='neo4j')
    argParser.add_argument('-p', '--password', help='Define the password (default: neo4j)', default='neo4j')
    argParser.add_argument('-t', '--type', help='Define the request type (default: show-domain-admins). Can be "show-domain-admins" or "users"', default='show-domain-admins', required=True)
    argParser.add_argument('users', help='Users own3d to be abused', nargs='*')
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


    logging.debug('Host = {}'.format(args.host))
    logging.debug('Users = {}'.format(args.users))
    
    if args.type == 'show-domain-admins':
        for admin in list_domain_admins(args):
            logging.info(admin)
    elif args.type == 'users':
        for user in args.users:
            for computer in find_computer_pwn3d_from_user(user, args):
                logging.info(computer)
    else:
        argParser.error('-t argument is invalid.')


if __name__ == '__main__':
    main()
