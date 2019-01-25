#!/usr/bin/env python3

import argparse
import ldap3
import logging
import re
import sys


def c_cyan(message):
    return '\x1b[0;36;40m{}\x1b[0m'.format(message)


def c_green(message):
    return '\x1b[0;32;40m{}\x1b[0m'.format(message)


def c_orange(message):
    return '\x1b[0;33;40m{}\x1b[0m'.format(message)


def c_purple(message):
    return '\x1b[0;35;40m{}\x1b[0m'.format(message)


def c_red(message):
    return '\x1b[0;31;40m{}\x1b[0m'.format(message)

    
def c_white_on_red(message):
    return '\x1b[1;37;41m{}\x1b[0m'.format(message)



def list_functionality_level(num):
    ''' Return the functionality level as described at:
    https://msdn.microsoft.com/en-us/library/cc223274.aspx
    Note: it is the same for forest, domain, and domain controller. '''
    n = int(num)
    func_levels = [
        c_white_on_red('Windows 2000'),
        c_white_on_red('Windows 2003 with mixed domains'),
        c_white_on_red('Windows 2003'),
        c_red('Windows 2008'),
        c_red('Windows 2008 R2'),
        c_orange('Windows 2012'),
        c_orange('Windows 2012 R2'),
        c_green('Windows 2016')
        ]
    if 0 <= n < len(func_levels):
        return func_levels[n]
    else:
        return 'Not known, update this script. (value = {})'.format(num)


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


def list_uac_colored_flags(uac):
    ''' Return a list of property flags as described at:
    https://support.microsoft.com/en-gb/help/305144/how-to-use-the-useraccountcontrol-flags-to-manipulate-user-account-pro '''
    flags = []
    if uac & 0x1 > 0:
        flags.append('SCRIPT')
    if uac & 0x2 > 0:
        flags.append(c_cyan('ACCOUNTDISABLE'))
    if uac & 0x8 > 0:
        flags.append('HOMEDIR_REQUIRED')
    if uac & 0x10 > 0:
        flags.append(c_cyan('LOCKOUT'))
    if uac & 0x20 > 0:
        flags.append(c_red('PASSWD_NOTREQD'))
    if uac & 0x40 > 0:
        flags.append(c_orange('PASSWD_CANT_CHANGE'))
    if uac & 0x80 > 0:
        flags.append(c_red('ENCRYPTED_TEXT_PWD_ALLOWED'))
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
        flags.append(c_red('DONT_EXPIRE_PASSWORD'))
    if uac & 0x20000 > 0:
        flags.append('MNS_LOGON_ACCOUNT')
    if uac & 0x40000 > 0:
        flags.append('SMARTCARD_REQUIRED')
    if uac & 0x80000 > 0:
        flags.append('TRUSTED_FOR_DELEGATION')
    if uac & 0x100000 > 0:
        flags.append('NOT_DELEGATED')
    if uac & 0x200000 > 0:
        flags.append(c_red('USE_DES_KEY_ONLY'))
    if uac & 0x400000 > 0:
        flags.append('DONT_REQ_PREAUTH')
    if uac & 0x800000 > 0:
        flags.append(c_cyan('PASSWORD_EXPIRED'))
    if uac & 0x1000000 > 0:
        flags.append(c_orange('TRUSTED_TO_AUTH_FOR_DELEGATION'))
    if uac & 0x04000000 > 0:
        flags.append('PARTIAL_SECRETS_ACCOUNT')
    return ', '.join(flags)


def list_samaccounttype(sat):
    ''' Return the SAM-Account-Type as described at:
    https://docs.microsoft.com/en-us/windows/desktop/adschema/a-samaccounttype '''
    if sat == 0x0:
        return 'SAM_DOMAIN_OBJECT'
    elif sat == 0x10000000:
        return 'SAM_GROUP_OBJECT'
    elif sat == 0x10000001:
        return 'SAM_NON_SECURITY_GROUP_OBJECT'
    elif sat == 0x20000000:
        return 'SAM_ALIAS_OBJECT'
    elif sat == 0x20000001:
        return 'SAM_NON_SECURITY_ALIAS_OBJECT'
    elif sat == 0x30000000:
        return 'SAM_USER_OBJECT'
    elif sat == 0x30000000:
        return 'SAM_NORMAL_USER_ACCOUNT'
    elif sat == 0x30000001:
        return 'SAM_MACHINE_ACCOUNT'
    elif sat == 0x30000002:
        return 'SAM_TRUST_ACCOUNT'
    elif sat == 0x40000000:
        return 'SAM_APP_BASIC_GROUP'
    elif sat == 0x40000001:
        return 'SAM_APP_QUERY_GROUP'
    elif sat == 0x7fffffff:
        return 'SAM_ACCOUNT_TYPE_MAX'
    else:
        return 'Error: unknown value'



def list_trustType(trustType):
    '''Return the trust type as defined here: https://msdn.microsoft.com/en-us/library/cc223771.aspx'''
    if trustType == 1:
        return 'The trusted domain is a Windows domain not running Active Directory.'
    elif trustType == 2:
        return 'The trusted domain is a Windows domain running Active Directory.'
    elif trustType == 3:
        return 'The trusted domain is running a non-Windows, RFC4120-compliant Kerberos distribution.'
    elif trustType == 4:
        return 'Historical reference; this value is not used in Windows.'
    else:
        return 'Error: unknown value.'


def list_trustDirection(trustDirection):
    '''Return the trust direction as defined here: https://msdn.microsoft.com/en-us/library/cc223768.aspx'''
    if trustDirection == 0:
        return 'Disabled'
    elif trustDirection == 1:
        return 'Outbound'
    elif trustDirection == 2:
        return 'Inbound'
    elif trustDirection == 3:
        return 'Bidirectional'
    else:
        return 'Error: unknown value.'


def list_trustAttributes(ta):
    '''Return the trust attribute flags as defined here: https://msdn.microsoft.com/en-us/library/cc223779.aspx'''
    flags = []
    if ta & 0x1 > 0:
        flags.append('TRUST_ATTRIBUTE_NON_TRANSITIVE')
    if ta & 0x2 > 0:
        flags.append('TRUST_ATTRIBUTE_UPLEVEL_ONLY')
    if ta & 0x4 > 0:
        flags.append('TRUST_ATTRIBUTE_QUARANTINED_DOMAIN')
    if ta & 0x8 > 0:
        flags.append('TRUST_ATTRIBUTE_FOREST_TRANSITIVE')
    if ta & 0x10 > 0:
        flags.append('TRUST_ATTRIBUTE_CROSS_ORGANIZATION')
    if ta & 0x20 > 0:
        flags.append('TRUST_ATTRIBUTE_WITHIN_FOREST')
    if ta & 0x40 > 0:
        flags.append('TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL')
    if ta & 0x80 > 0:
        flags.append('TRUST_ATTRIBUTE_USES_RC4_ENCRYPTION')
    if ta & 0x200 > 0:
        flags.append('TRUST_ATTRIBUTE_CROSS_ORGANIZATION_NO_TGT_DELEGATION')
    if ta & 0x400 > 0:
        flags.append('TRUST_ATTRIBUTE_PIM_TRUST')
    return flags


def get_server_info(args):
    logging.info('Getting info from LDAP server {}'.format(args.ldap_server))
    server = ldap3.Server(args.ldap_server, get_info='ALL')
    conn = ldap3.Connection(server, auto_bind=True)
    # logging.info('get_info=ALL:\n{}'.format(str(server.info)))
    logging.info('Forest functionality level = {}'.format(list_functionality_level(server.info.other['forestFunctionality'][0])))
    logging.info('Domain functionality level = {}'.format(list_functionality_level(server.info.other['domainFunctionality'][0])))
    logging.info('Domain controller functionality level = {}'.format(list_functionality_level(server.info.other['domainControllerFunctionality'][0])))
    logging.info('rootDomainNamingContext = {}'.format(server.info.other['rootDomainNamingContext'][0]))
    logging.info('defaultNamingContext = {}'.format(server.info.other['defaultNamingContext'][0]))
    logging.info('ldapServiceName = {}'.format(server.info.other['ldapServiceName'][0]))
    logging.info('naming_contexts = {}'.format(server.info.naming_contexts))
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



def return_trust_infos(trust):
    r = '{} ({})\n'.format(trust.name.value, trust.flatName.value)
    r += '    trustAttributes = {}\n'.format(list_trustAttributes(trust.trustAttributes.value))
    r += '    trustDirection = {}\n'.format(list_trustDirection(trust.trustDirection.value))
    r += '    trustType = {}\n'.format(list_trustType(trust.trustType.value))
    r += '    trustPartner = {}\n'.format(trust.trustPartner.value)
    r += '    securityIdentifier = {}\n'.format(ldap3.protocol.formatters.formatters.format_sid(trust.securityIdentifier.value))
    r += '    whenCreated = {}\n'.format(trust.whenCreated.value)
    r += '    whenChanged = {}\n'.format(trust.whenChanged.value)
    return r


def get_trusts(args):
    logging.info('Looking for trusts on LDAP server {}'.format(args.ldap_server))
    server = ldap3.Server(args.ldap_server, get_info='ALL')
    domain_username = '{}\\{}'.format(args.domain, args.username)
    logging.debug('Using NTLM authentication with username = {}'.format(domain_username))
    try:
        with ldap3.Connection(server, user=domain_username, password=args.password, authentication='NTLM', auto_bind=True) as conn:
            search_filter = '(objectClass=trustedDomain)'
            search_attributes = '*'
            size_limit = 50
            base_dn = server.info.other.get('defaultNamingContext')[0]
            logging.debug('Found base DN = {}'.format(base_dn))
            logging.debug('Search filter = {}'.format(search_filter))
            logging.debug('Looking for attributes = {}'.format(search_attributes))
            conn.search(base_dn, search_filter, attributes=search_attributes, size_limit=size_limit)
            entries = conn.entries
        if args.output_file:
            f = open(args.output_file, 'a')
        if not entries:
            logging.info('No trusts found.')
        for entry in entries:
            logging.info('Trust = {}'.format(return_trust_infos(entry)))
            if args.output_file:
                f.write('{}\n'.format(entry.entry_to_json()))
        if args.output_file:
            f.close
    except ldap3.core.exceptions.LDAPBindError as e:
        logging.error('{}'.format(e))
    # except Exception as e:
    #     logging.error('{}'.format(e))


def return_show_user(user):
    r = '{}\n'.format(user.samAccountName.value)
    if 'adminCount' in user.entry_attributes_as_dict.keys():
        if user.admincount.value == 1:
            r += '{}\n'.format(c_red('The adminCount is set to 1!'))
        elif user.admincount.value == 0:
            pass
        else:
            r += c_purple('Unknown value for adminCount: {}\n'.format(user.admincount.value))
    r += 'userAccountControl = {}\n'.format(list_uac_colored_flags(user.userAccountControl.value))
    r += 'sAMAccountType = {}\n'.format(list_samaccounttype(user.samaccounttype.value))
    groups = []
    for group in user.memberOf.value:
        group_cn = re.search('CN=([^,]*),', group).group(1)
        if re.search('domain admins', group_cn, re.IGNORECASE):
            groups.append(c_red(group_cn))
        elif re.search('admin', group_cn, re.IGNORECASE):
            groups.append(c_orange(group_cn))
        else:
            groups.append(group_cn)
    r += 'memberOf = {}\n'.format(', '.join(groups))
    return r



def get_show(args):
    logging.info('Searching on LDAP server {}'.format(args.ldap_server))
    server = ldap3.Server(args.ldap_server, get_info='ALL')
    domain_username = '{}\\{}'.format(args.domain, args.username)
    logging.debug('Using NTLM authentication with username = {}'.format(domain_username))
    try:
        with ldap3.Connection(server, user=domain_username, password=args.password, authentication='NTLM', auto_bind=True) as conn:
            # search_filter = "(&(objectClass=user)(!(objectClass=computer)))"
            # search_attributes = ['cn', 'servicePrincipalName', 'samaccountname', 'userAccountControl']
            # size_limit = 10
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
            logging.info('Show User = {}'.format(return_show_user(entry)))
            if args.output_file:
                f.write('{}\n'.format(entry.entry_to_json()))
        if args.output_file:
            f.close
    except ldap3.core.exceptions.LDAPBindError as e:
        logging.error('{}'.format(e))
    except ldap3.core.exceptions.LDAPInvalidFilterError as e:
        logging.error('{} (perhaps missing parenthesis?)'.format(e))
    # except Exception as e:
    #     logging.error('{}'.format(e))


def main():
    # Parse arguments
    argParser = argparse.ArgumentParser(description="Active Directory LDAP Enumerator")
    argParser.add_argument('-l', '--server', required=True, dest='ldap_server', help='IP address of the LDAP server.')
    argParser.add_argument('-t', '--type', required=True, dest='request_type', help='Request type: info, whoami, search, trusts, TODO')
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
    mandatory_arguments['trusts'] = ['domain', 'username', 'password']
    mandatory_arguments['show'] = ['domain', 'username', 'password', 'search_filter']
    if args.request_type not in mandatory_arguments.keys():
        argParser.error('request type must be one of: {}.'.format(', '.join(mandatory_arguments.keys())))
    for mandatory_argument in mandatory_arguments[args.request_type]:
        if vars(args)[mandatory_argument] is None:
            argParser.error('{} argument is mandatory with request type = {}'.format(mandatory_argument, args.request_type))

    # Configure logging to stdout
    logger = logging.getLogger()
    handler = logging.StreamHandler(sys.stdout)
    if args.verbosity:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)
    formatter = logging.Formatter(fmt='%(asctime)-19s %(levelname)-8s %(message)s', datefmt='%Y-%m-%d_%H:%M:%S')
    handler.setFormatter(formatter)
    logger.addHandler(handler)


    if args.request_type == 'info':
        get_server_info(args)
    elif args.request_type == 'whoami':
        get_whoami(args)
    elif args.request_type == 'search':
        get_search(args)
    elif args.request_type == 'trusts':
        get_trusts(args)
    elif args.request_type == 'show':
        get_show(args)
    else:
        logging.error('Error: no request type supplied. (Please use "-t")')


if __name__ == '__main__':
    main()

