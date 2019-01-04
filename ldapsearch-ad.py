#!/usr/bin/env python3

import argparse
import ldap3
import logging
import sys


def list_uac_flags(uac):
    ''' Return a list of property flags as described at:
    https://support.microsoft.com/en-gb/help/305144/how-to-use-the-useraccountcontrol-flags-to-manipulate-user-account-pro '''
    flags = []
    if uac & 0x1 > 0:
        flags.append('SCRIPT')
    if uac & 0x2 > 0:
        flags.append('ACCOUNTDISABLE')
    if uac & 0x8 > 0:
        flags.append('HOMEDIR_REQUIRED')
    if uac & 0x10 > 0:
        flags.append('LOCKOUT')
    if uac & 0x20 > 0:
        flags.append('PASSWD_NOTREQD')
    if uac & 0x40 > 0:
        flags.append('PASSWD_CANT_CHANGE')
    if uac & 0x80 > 0:
        flags.append('ENCRYPTED_TEXT_PWD_ALLOWED')
    if uac & 0x100 > 0:
        flags.append('TEMP_DUPLICATE_ACCOUNT')
    if uac & 0x200 > 0:
        flags.append('NORMAL_ACCOUNT')
    if uac & 0x800 > 0:
        flags.append('INTERDOMAIN_TRUST_ACCOUNT')
    if uac & 0x1000 > 0:
        flags.append('WORKSTATION_TRUST_ACCOUNT')
    if uac & 0x2000 > 0:
        flags.append('SERVER_TRUST_ACCOUNT')
    if uac & 0x10000 > 0:
        flags.append('DONT_EXPIRE_PASSWORD')
    if uac & 0x20000 > 0:
        flags.append('MNS_LOGON_ACCOUNT')
    if uac & 0x40000 > 0:
        flags.append('SMARTCARD_REQUIRED')
    if uac & 0x80000 > 0:
        flags.append('TRUSTED_FOR_DELEGATION')
    if uac & 0x100000 > 0:
        flags.append('NOT_DELEGATED')
    if uac & 0x200000 > 0:
        flags.append('USE_DES_KEY_ONLY')
    if uac & 0x400000 > 0:
        flags.append('DONT_REQ_PREAUTH')
    if uac & 0x800000 > 0:
        flags.append('PASSWORD_EXPIRED')
    if uac & 0x1000000 > 0:
        flags.append('TRUSTED_TO_AUTH_FOR_DELEGATION')
    if uac & 0x04000000 > 0:
        flags.append('PARTIAL_SECRETS_ACCOUNT')
    return flags


def get_server_info(args):
    logging.info('Getting info from LDAP server {}'.format(args.ldap_server))
    server = ldap3.Server(args.ldap_server, get_info='ALL')
    conn = ldap3.Connection(server, auto_bind=True)
    logging.info('get_info=ALL:\n{}'.format(str(server.info)))
    if args.output_file:
        with open(args.output_file, 'a') as f:
            f.write('{}\n'.format(server.info.to_json()))


def get_whoami(args):
    logging.info('Executing whoami on LDAP server {}'.format(args.ldap_server))
    server = ldap3.Server(args.ldap_server)
    domain_username = '{}\\{}'.format(args.domain, args.username)
    logging.debug('Using NTLM authentication with username = {}'.format(domain_username))
    with ldap3.Connection(server, user=domain_username, password=args.password, authentication='NTLM', auto_bind=True) as conn:
        whoami = conn.extend.standard.who_am_i()
    logging.info('You are: "{}"'.format(whoami))
    if args.output_file:
        with open(args.output_file, 'a') as f:
            f.write('You are: {}\n'.format(whoami))


def get_search(args):
    logging.info('Searching on LDAP server {}'.format(args.ldap_server))
    server = ldap3.Server(args.ldap_server, get_info='ALL')
    domain_username = '{}\\{}'.format(args.domain, args.username)
    logging.debug('Using NTLM authentication with username = {}'.format(domain_username))
    try:
        with ldap3.Connection(server, user=domain_username, password=args.password, authentication='NTLM', auto_bind=True) as conn:
            base_dn = server.info.other.get('defaultNamingContext')[0]
            logging.debug('Found base DN = {}'.format(base_dn))
            logging.debug('Search filter = {}'.format(args.search_filter))
            logging.debug('Looking for attributes = {}'.format(args.search_attributes))
            conn.search(base_dn, args.search_filter, attributes=args.search_attributes, size_limit=args.size_limit)
            entries = conn.entries
        if args.output_file:
            f = open(args.output_file, 'a')
        if not entries:
            logging.info('No result found.')
        for entry in entries:
            logging.info('Entry = \n{}'.format(entry))
            if args.output_file:
                f.write('{}\n'.format(entry.entry_to_json()))
        if args.output_file:
            f.close
    except ldap3.core.exceptions.LDAPBindError as e:
        logging.error('{}'.format(e))
    except ldap3.core.exceptions.LDAPInvalidFilterError as e:
        logging.error('{} (perhaps missing parenthesis?)'.format(e))


def main():
    # Parse arguments
    argParser = argparse.ArgumentParser(description="Active Directory LDAP Enumerator")
    argParser.add_argument('-l', '--server', required=True, dest='ldap_server', help='IP address of the LDAP server.')
    argParser.add_argument('-t', '--type', required=True, dest='request_type', help='Request type: info, whoami, search, TODO')
    argParser.add_argument('-d', '--domain', dest='domain', help='Authentication account\'s FQDN. Example: "contoso.local".')
    argParser.add_argument('-u', '--username', dest='username', help='Authentication account\'s username.')
    argParser.add_argument('-p', '--password', dest='password', help='Authentication account\'s password.')
    argParser.add_argument('-s', '--search-filter', dest='search_filter', help='Search filter (use LDAP format).')
    argParser.add_argument('search_attributes', default='*', nargs='*', help='LDAP attributes to look for.')
    argParser.add_argument('-z', '--size_limit', dest='size_limit', default=10, help='Size limit (default is server\'s limit).')
    argParser.add_argument('-o', '--output', dest='output_file', help='Write results in specified file too.')
    argParser.add_argument('-v', '--verbose', dest='verbosity', help='Turn on debug mode', action='store_true')
    args = argParser.parse_args()

    # Set mandatory arguments for each request_type
    mandatory_arguments = {}
    mandatory_arguments['info'] = []
    mandatory_arguments['whoami'] = ['domain', 'username', 'password']
    mandatory_arguments['search'] = ['domain', 'username', 'password', 'search_filter']
    if args.request_type not in mandatory_arguments.keys():
        argParser.error('request type must be one of: {}.'.format(', '.join(mandatory_arguments.keys())))
    for mandatory_argument in mandatory_arguments[args.request_type]:
        if vars(args)[mandatory_argument] is None:
            argParser.error('{} argument is mandatory with request type = {}'.format(mandatory_argument, args.request_type))

    # Configure logging
    logLevel = logging.INFO
    if args.verbosity:
        logLevel = logging.DEBUG
    logging.basicConfig(level=logLevel, format='%(asctime)-19s %(levelname)-8s %(message)s', datefmt='%Y-%m-%d_%H:%M:%S')


    if args.request_type == 'info':
        get_server_info(args)
    elif args.request_type == 'whoami':
        get_whoami(args)
    elif args.request_type == 'search':
        get_search(args)
    else:
        logging.error('Error: no request type supplied. (Please use "-t")')


if __name__ == '__main__':
    main()

