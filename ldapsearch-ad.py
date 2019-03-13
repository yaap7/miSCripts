#!/usr/bin/env python3

import argparse
import ldap3
import logging
import re
import sys


def c_cyan(message):
    """Mostly for general usefull information."""
    return '\x1b[0;36;40m{}\x1b[0m'.format(message)


def c_green(message):
    """Color text for good configuration."""
    return '\x1b[0;32;40m{}\x1b[0m'.format(message)


def c_orange(message):
    """Color text for weak configuration."""
    return '\x1b[0;33;40m{}\x1b[0m'.format(message)


def c_purple(message):
    """Color text for abnormal behavior of the tool itself."""
    return '\x1b[0;35;40m{}\x1b[0m'.format(message)


def c_red(message):
    """Color text for bad configuration."""
    return '\x1b[0;31;40m{}\x1b[0m'.format(message)

    
def c_white_on_red(message):
    """Color text for very bad configuration."""
    return '\x1b[1;37;41m{}\x1b[0m'.format(message)


def str_title(title):
    return '\x1b[1;37;40m###  {}  ###\x1b[0m'.format(title)


def str_human_date(date):
    nb_sec = int((- date ) / 10000000)
    if nb_sec > 60 :
        nb_min = int(nb_sec / 60)
        nb_sec = nb_sec % 60
        if nb_min > 60:
            nb_hour = int(nb_min / 60)
            nb_min = nb_min % 60
            if nb_hour > 24:
                nb_day = int(nb_hour / 24)
                nb_hour = nb_hour % 24
                return '{} days, {} hours, {} minutes, {} secondes'.format(nb_day, nb_hour, nb_min, nb_sec)
            return '{} hours, {} minutes, {} secondes'.format(nb_hour, nb_min, nb_sec)
        return '{} minutes, {} secondes'.format(nb_min, nb_sec)
    return '{} secondes'.format(nb_sec)


def str_functionality_level(num):
    """Return the functionality level as described at:
    https://msdn.microsoft.com/en-us/library/cc223274.aspx
    Note: it is the same for forest, domain, and domain controller."""
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
    """Return a list of property flags as described at:
    https://support.microsoft.com/en-gb/help/305144/how-to-use-the-useraccountcontrol-flags-to-manipulate-user-account-pro"""
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
    """Return a list of property flags as described at:
    https://support.microsoft.com/en-gb/help/305144/how-to-use-the-useraccountcontrol-flags-to-manipulate-user-account-pro"""
    flags = []
    if uac & 0x1 > 0:
        flags.append('SCRIPT')
    if uac & 0x2 > 0:
        flags.append(c_cyan('ACCOUNTDISABLE'))
    if uac & 0x8 > 0:
        flags.append('HOMEDIR_REQUIRED')
    if uac & 0x10 > 0:
        flags.append(c_orange('LOCKOUT'))
    if uac & 0x20 > 0:
        flags.append(c_white_on_red('PASSWD_NOTREQD'))
    if uac & 0x40 > 0:
        flags.append(c_red('PASSWD_CANT_CHANGE'))
    if uac & 0x80 > 0:
        flags.append(c_white_on_red('ENCRYPTED_TEXT_PWD_ALLOWED'))
    if uac & 0x100 > 0:
        flags.append('TEMP_DUPLICATE_ACCOUNT')
    if uac & 0x200 > 0:
        flags.append('NORMAL_ACCOUNT')
    if uac & 0x800 > 0:
        flags.append(c_cyan('INTERDOMAIN_TRUST_ACCOUNT'))
    if uac & 0x1000 > 0:
        flags.append(c_cyan('WORKSTATION_TRUST_ACCOUNT'))
    if uac & 0x2000 > 0:
        flags.append(c_cyan('SERVER_TRUST_ACCOUNT'))
    if uac & 0x10000 > 0:
        flags.append(c_red('DONT_EXPIRE_PASSWORD'))
    if uac & 0x20000 > 0:
        flags.append('MNS_LOGON_ACCOUNT')
    if uac & 0x40000 > 0:
        flags.append('SMARTCARD_REQUIRED')
    if uac & 0x80000 > 0:
        flags.append(c_orange('TRUSTED_FOR_DELEGATION'))
    if uac & 0x100000 > 0:
        flags.append('NOT_DELEGATED')
    if uac & 0x200000 > 0:
        flags.append(c_red('USE_DES_KEY_ONLY'))
    if uac & 0x400000 > 0:
        flags.append(c_cyan('DONT_REQ_PREAUTH'))
    if uac & 0x800000 > 0:
        flags.append(c_cyan('PASSWORD_EXPIRED'))
    if uac & 0x1000000 > 0:
        flags.append(c_orange('TRUSTED_TO_AUTH_FOR_DELEGATION'))
    if uac & 0x04000000 > 0:
        flags.append('PARTIAL_SECRETS_ACCOUNT')
    return flags


def str_samaccounttype(sat):
    """Return the SAM-Account-Type as described at:
    https://docs.microsoft.com/en-us/windows/desktop/adschema/a-samaccounttype"""
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


def str_object_type(entry):
    if 'sAMAccountType' in entry.entry_attributes_as_dict.keys():
        sat = entry.sAMAccountType.value
        if sat == 0x0:
            return 'domain'
        elif sat == 0x10000000:
            return 'group'
        elif sat == 0x30000000:
            return 'user'
        elif sat == 0x30000001:
            return 'computer'
        else:
            return 'sAMAccountType = {}. Please complete this script.'.format(sat)
    else:
        return 'Unable to find correct type (sAMAccountType not present).'


def list_trustType(trustType):
    """Return the trust type as defined here: https://msdn.microsoft.com/en-us/library/cc223771.aspx"""
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
    """Return the trust direction as defined here: https://msdn.microsoft.com/en-us/library/cc223768.aspx"""
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
    """Return the trust attribute flags as defined here: https://msdn.microsoft.com/en-us/library/cc223779.aspx"""
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
    logging.debug('Getting info from LDAP server {}'.format(args.ldap_server))
    server = ldap3.Server(args.ldap_server, get_info='ALL')
    ldap3.Connection(server, auto_bind=True)
    # logging.info('get_info=ALL:\n{}'.format(str(server.info)))
    logging.info('Forest functionality level = {}'.format(str_functionality_level(server.info.other['forestFunctionality'][0])))
    logging.info('Domain functionality level = {}'.format(str_functionality_level(server.info.other['domainFunctionality'][0])))
    logging.info('Domain controller functionality level = {}'.format(str_functionality_level(server.info.other['domainControllerFunctionality'][0])))
    logging.info('rootDomainNamingContext = {}'.format(server.info.other['rootDomainNamingContext'][0]))
    logging.info('defaultNamingContext = {}'.format(server.info.other['defaultNamingContext'][0]))
    logging.info('ldapServiceName = {}'.format(server.info.other['ldapServiceName'][0]))
    logging.info('naming_contexts = {}'.format(server.info.naming_contexts))
    if args.output_file:
        with open(args.output_file, 'a') as f:
            f.write('{}\n'.format(server.info.to_json()))


def get_whoami(args):
    logging.debug('Executing whoami on LDAP server {}'.format(args.ldap_server))
    server = ldap3.Server(args.ldap_server)
    domain_username = '{}\\{}'.format(args.domain, args.username)
    logging.debug('Using NTLM authentication with username = {}'.format(domain_username))
    with ldap3.Connection(server, user=domain_username, password=args.password, authentication='NTLM', auto_bind=True) as conn:
        whoami = conn.extend.standard.who_am_i()
    logging.info('You are: "{}"'.format(whoami))
    if args.output_file:
        with open(args.output_file, 'a') as f:
            f.write('You are: {}\n'.format(whoami))


def search(args):
    logging.debug('Searching on LDAP server {}'.format(args.ldap_server))
    server = ldap3.Server(args.ldap_server, get_info='ALL')
    domain_username = '{}\\{}'.format(args.domain, args.username)
    logging.debug('Using NTLM authentication with username = {}'.format(domain_username))
    try:
        with ldap3.Connection(server, user=domain_username, password=args.password, authentication='NTLM', auto_bind=True) as conn:
            base_dn = server.info.other.get('defaultNamingContext')[0]
            search_filter = '({})'.format(args.search_filter)
            search_attributes = args.search_attributes
            size_limit = args.size_limit
            logging.debug('Found base DN = {}'.format(base_dn))
            logging.debug('Search filter = {}'.format(search_filter))
            logging.debug('Looking for attributes = {}'.format(search_attributes))
            conn.search(base_dn, search_filter, attributes=search_attributes, size_limit=size_limit)
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


def search_large(args):
    "Search for a pattern at large and print only dn with matching attributes"
    logging.debug('Searching on LDAP server {}'.format(args.ldap_server))
    server = ldap3.Server(args.ldap_server, get_info='ALL')
    domain_username = '{}\\{}'.format(args.domain, args.username)
    logging.debug('Using NTLM authentication with username = {}'.format(domain_username))
    try:
        with ldap3.Connection(server, user=domain_username, password=args.password, authentication='NTLM', auto_bind=True) as conn:
            base_dn = server.info.other.get('defaultNamingContext')[0]
            search_filter = '(|(cn=*SEARCH_FILTER*)(company=*SEARCH_FILTER*)(department=*SEARCH_FILTER*)(description=*SEARCH_FILTER*)(displayname=*SEARCH_FILTER*)(distinguishedName=*SEARCH_FILTER*)(givenname=*SEARCH_FILTER*)(l=*SEARCH_FILTER*)(mail=*SEARCH_FILTER*)(mailnickname=*SEARCH_FILTER*)(mobile=*SEARCH_FILTER*)(msExchArchiveName=*SEARCH_FILTER*)(name=*SEARCH_FILTER*)(samaccountname=*SEARCH_FILTER*)(sn=*SEARCH_FILTER*)(title=*SEARCH_FILTER*)(userprincipalname=*SEARCH_FILTER*)(wwwhomepage=*SEARCH_FILTER*))'.replace('SEARCH_FILTER', args.search_filter)
            search_attributes = ['distinguishedName']
            size_limit = args.size_limit
            logging.debug('Found base DN = {}'.format(base_dn))
            logging.debug('Search filter = {}'.format(search_filter))
            logging.debug('Looking for attributes = {}'.format(search_attributes))
            conn.search(base_dn, search_filter, attributes=search_attributes, size_limit=size_limit)
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


def list_trust_info(trust):
    """Return the most usefull information about trusts."""
    r = []
    r.append('+ {} ({})'.format(trust.name.value, trust.flatName.value))
    r.append('|___trustAttributes = {}'.format(list_trustAttributes(trust.trustAttributes.value)))
    r.append('|___trustDirection = {}'.format(list_trustDirection(trust.trustDirection.value)))
    r.append('|___trustType = {}'.format(list_trustType(trust.trustType.value)))
    r.append('|___trustPartner = {}'.format(trust.trustPartner.value))
    if 'securityIdentifier' in trust:
        r.append('|___securityIdentifier = {}'.format(ldap3.protocol.formatters.formatters.format_sid(trust.securityIdentifier.value)))
    r.append('|___whenCreated = {}'.format(trust.whenCreated.value))
    r.append('|___whenChanged = {}'.format(trust.whenChanged.value))
    return r


def get_trusts(args):
    """Main function to get info about trusts."""
    logging.debug('Looking for trusts on LDAP server {}'.format(args.ldap_server))
    server = ldap3.Server(args.ldap_server, get_info='ALL')
    domain_username = '{}\\{}'.format(args.domain, args.username)
    logging.debug('Using NTLM authentication with username = {}'.format(domain_username))
    try:
        with ldap3.Connection(server, user=domain_username, password=args.password, authentication='NTLM', auto_bind=True) as conn:
            search_filter = '(objectClass=trustedDomain)'
            size_limit = 50
            base_dn = server.info.other.get('defaultNamingContext')[0]
            logging.debug('Found base DN = {}'.format(base_dn))
            logging.debug('Search filter = {}'.format(search_filter))
            logging.debug('Looking for attributes = {}'.format(args.search_attributes))
            conn.search(base_dn, search_filter, attributes=args.search_attributes, size_limit=size_limit)
            entries = conn.entries
        if args.output_file:
            f = open(args.output_file, 'a')
        if not entries:
            logging.info('No trusts found.')
        for entry in entries:
            logging.info('Trust =')
            for out_line in list_trust_info(entry):
                logging.info('{}'.format(out_line))
            if args.output_file:
                f.write('{}\n'.format(entry.entry_to_json()))
        if args.output_file:
            f.close
    except ldap3.core.exceptions.LDAPBindError as e:
        logging.error('{}'.format(e))


def list_default_pass_pol(pass_pol):
    """Return a list of strings containing info about the default password policy."""
    r = ['+ Default password policy:']
    attributes = pass_pol.entry_attributes_as_dict
    pass_len = attributes['minPwdLength'][0]
    # Password length
    if pass_len < 8:
        r.append('|___Minimum password length = {}'.format(c_red(pass_len)))
    elif pass_len < 12:
        r.append('|___Minimum password length = {}'.format(c_orange(pass_len)))
    else:
        r.append('|___Minimum password length = {}'.format(c_green(pass_len)))
    # Password properties as described here: https://ldapwiki.com/wiki/PwdProperties
    pass_properties = attributes['pwdProperties'][0]
    if pass_properties & 1 > 0:
        r.append('|___Password complexity = {}'.format(c_green('Enabled')))
    # Lockout settings
    if attributes['lockoutThreshold'][0] == 0:
        r.append('|___Lockout threshold = {}'.format(c_white_on_red('Disabled')))
    else:
        r.append('|___Lockout threshold = {}'.format(attributes['lockoutThreshold'][0]))
        r.append('|___  Lockout duration = {}'.format(str_human_date(attributes['lockoutDuration'][0])))
        r.append('|___  Lockout observation window = {}'.format(str_human_date(attributes['lockOutObservationWindow'][0])))
    return r


def list_pass_pol(pass_pol):
    """Return a list of strings containing info about a Fine-Grained Password Policy."""
    r = ['+ Fined grained password policy found: {}'.format(c_cyan(pass_pol.cn.value))]
    attributes = pass_pol.entry_attributes_as_dict
    r.append('|____Password settings precedence = {}'.format(attributes['msDS-PasswordSettingsPrecedence'][0]))
    pass_len = attributes['msDS-MinimumPasswordLength'][0]
    # Password length
    if pass_len < 8:
        r.append('|___Minimum password length = {}'.format(c_red(pass_len)))
    elif pass_len < 12:
        r.append('|___Minimum password length = {}'.format(c_orange(pass_len)))
    else:
        r.append('|___Minimum password length = {}'.format(c_green(pass_len)))
    # Password complexity
    if attributes['msDS-PasswordComplexityEnabled'][0]:
        r.append('|___Password complexity enabled = {}'.format(c_green(attributes['msDS-PasswordComplexityEnabled'][0])))
    else:
        r.append('|___Password complexity enabled = {}'.format(c_red(attributes['msDS-PasswordComplexityEnabled'][0])))
    # Password reversible encryption?
    if attributes['msDS-PasswordReversibleEncryptionEnabled'][0]:
        r.append('|___Password reversible encryption enabled = {}'.format(c_white_on_red(attributes['msDS-PasswordReversibleEncryptionEnabled'][0])))
    else:
        r.append('|___Password reversible encryption enabled = {}'.format(attributes['msDS-PasswordReversibleEncryptionEnabled'][0]))
    # Lockout settings
    if attributes['msDS-LockoutThreshold'][0] == 0:
        r.append('|___Lockout threshold = {}'.format(c_white_on_red('Disabled')))
    else:
        r.append('|___Lockout threshold = {}'.format(attributes['msDS-LockoutThreshold'][0]))
        r.append('|___  Lockout duration = {}'.format(str_human_date(attributes['msDS-LockoutDuration'][0])))
        r.append('|___  Lockout observation window = {}'.format(str_human_date(attributes['msDS-LockoutObservationWindow'][0])))
    return r


def get_pass_pols(args):
    """Main function to get info about password policies."""
    logging.debug('Looking for all password policies on LDAP server {}'.format(args.ldap_server))
    server = ldap3.Server(args.ldap_server, get_info='ALL')
    domain_username = '{}\\{}'.format(args.domain, args.username)
    logging.debug('Using NTLM authentication with username = {}'.format(domain_username))
    try:
        with ldap3.Connection(server, user=domain_username, password=args.password, authentication='NTLM', auto_bind=True) as conn:
            base_dn = server.info.other.get('defaultNamingContext')[0]
            search_filter = '(objectClass=domainDNS)'
            search_attributes = args.search_attributes
            size_limit = args.size_limit
            logging.debug('Found base DN = {}'.format(base_dn))
            logging.debug('Search filter = {}'.format(search_filter))
            logging.debug('Looking for attributes = {}'.format(search_attributes))
            conn.search(base_dn, search_filter, attributes=search_attributes, size_limit=size_limit)
            entries = conn.entries
            if not entries:
                logging.info('No default password policy found, maybe an error in the script (try to change the hardcoded filter).')
            else:
                if args.output_file:
                    f = open(args.output_file, 'a')
                for entry in entries:
                    for out_line in list_default_pass_pol(entry):
                        logging.info(out_line)
                    if args.output_file:
                        f.write('{}\n'.format(entry.entry_to_json()))
                if args.output_file:
                    f.close
            base_dn = server.info.other.get('defaultNamingContext')[0]
            search_filter = '(objectClass=MsDS-PasswordSettings)'
            search_attributes = args.search_attributes
            size_limit = args.size_limit
            logging.debug('Found base DN = {}'.format(base_dn))
            logging.debug('Search filter = {}'.format(search_filter))
            logging.debug('Looking for attributes = {}'.format(search_attributes))
            conn.search(base_dn, search_filter, attributes=search_attributes, size_limit=size_limit)
            entries = conn.entries
            if not entries:
                logging.info('No fine grained password policy found (high privileges are required).')
            else:
                if args.output_file:
                    f = open(args.output_file, 'a')
                for entry in entries:
                    for out_line in list_pass_pol(entry):
                        logging.info(out_line)
                    if args.output_file:
                        f.write('{}\n'.format(entry.entry_to_json()))
                if args.output_file:
                    f.close
    except ldap3.core.exceptions.LDAPBindError as e:
        logging.error('{}'.format(e))


def list_groups(entry):
    """Return a list containing the CN of each group the parameter is member of."""
    if 'memberOf' not in entry.entry_attributes_as_dict.keys():
        return ['memberOf attribute not found']
    groups = []
    # dirty patch because "memberOf.value" return a string if there is only one group
    # and a list a string if there is more than one group
    logging.debug('type of memberOf = {}'.format(type(entry.memberOf.value)))
    if isinstance(entry.memberOf.value, str):
        groups_raw = [entry.memberOf.value]
    else:
        groups_raw = entry.memberOf.value
    for group in groups_raw:
        group_cn = re.search('CN=([^,]*),', group).group(1)
        if re.search('(domain admins|admins du domaine)', group_cn, re.IGNORECASE):
            groups.append(c_red(group_cn))
        if re.search('(administrators|administrateurs)', group_cn, re.IGNORECASE):
            groups.append(c_red(group_cn))
        elif re.search('admin', group_cn, re.IGNORECASE):
            groups.append(c_orange(group_cn))
        else:
            groups.append(group_cn)
    return groups


def list_user_details(user):
    r = ['+ {}'.format(user.samAccountName.value)]
    r.append('|___type: {}'.format(str_object_type(user)))
    if 'displayName' in user.entry_attributes_as_dict.keys():
        r.append('|___displayName = {}'.format(user.displayName.value))
    if 'adminCount' in user.entry_attributes_as_dict.keys():
        if user.admincount.value == 1:
            r.append('|___{}'.format(c_red('The adminCount is set to 1')))
        elif user.admincount.value == 0:
            pass
        else:
            r.append('|___{}'.format(c_purple('Unknown value for adminCount: {}'.format(user.admincount.value))))
    if 'userAccountControl' in user.entry_attributes_as_dict.keys():
        r.append('|___userAccountControl = {}'.format(', '.join(list_uac_colored_flags(user.userAccountControl.value))))
    r.append('|___sAMAccountType = {}'.format(str_samaccounttype(user.samaccounttype.value)))
    if 'memberOf' in user.entry_attributes_as_dict.keys():
        r.append('|___memberOf = {}'.format(', '.join(list_groups(user))))
    return r


def show_user(args):
    logging.debug('Looking for users on LDAP server {}'.format(args.ldap_server))
    server = ldap3.Server(args.ldap_server, get_info='ALL')
    domain_username = '{}\\{}'.format(args.domain, args.username)
    logging.debug('Using NTLM authentication with username = {}'.format(domain_username))
    try:
        with ldap3.Connection(server, user=domain_username, password=args.password, authentication='NTLM', auto_bind=True) as conn:
            base_dn = server.info.other.get('defaultNamingContext')[0]
            search_filter = '(&(objectClass=user)({}))'.format(args.search_filter)
            search_attributes = args.search_attributes
            size_limit = args.size_limit
            logging.debug('Found base DN = {}'.format(base_dn))
            logging.debug('Search filter = {}'.format(search_filter))
            logging.debug('Looking for attributes = {}'.format(search_attributes))
            conn.search(base_dn, search_filter, attributes=search_attributes, size_limit=size_limit)
            entries = conn.entries
        if args.output_file:
            f = open(args.output_file, 'a')
        if not entries:
            logging.info('No result found.')
        for entry in entries:
            for out_line in list_user_details(entry):
                logging.info(out_line)
            if args.output_file:
                f.write('{}\n'.format(entry.entry_to_json()))
        if args.output_file:
            f.close
    except ldap3.core.exceptions.LDAPBindError as e:
        logging.error('{}'.format(e))
    except ldap3.core.exceptions.LDAPInvalidFilterError as e:
        logging.error('{} (perhaps missing parenthesis?)'.format(e))


def list_user_brief(user):
    """Return a list of brief info of a single user."""
    if str_object_type(user) != 'user':
        return ['Invalid type for "{}", not a user?'.format(user.sAMAccountName.value)]
    uac_flags = list_uac_colored_flags(user.userAccountControl.value)
    uac_flags.remove('NORMAL_ACCOUNT')
    if uac_flags:
        r = ['+ {} ({})'.format(user.sAMAccountName.value, ', '.join(uac_flags))]
    else:
        r = ['+ {}'.format(user.sAMAccountName.value)]
    return r


def show_group_members(args):
    logging.debug('Looking for group members on LDAP server {}'.format(args.ldap_server))
    server = ldap3.Server(args.ldap_server, get_info='ALL')
    domain_username = '{}\\{}'.format(args.domain, args.username)
    logging.debug('Using NTLM authentication with username = {}'.format(domain_username))
    with ldap3.Connection(server, user=domain_username, password=args.password, authentication='NTLM', auto_bind=True) as conn:
        # first of all, we need to extract the exact dn to be able to search for nested groups
        search_filter = '({})'.format(args.search_filter)
        search_attributes = 'distinguishedName'
        size_limit = 2
        base_dn = server.info.other.get('defaultNamingContext')[0]
        logging.debug('Found base DN = {}'.format(base_dn))
        logging.debug('Search filter = {}'.format(search_filter))
        logging.debug('Looking for attributes = {}'.format(search_attributes))
        conn.search(base_dn, search_filter, attributes=search_attributes, size_limit=size_limit)
        groups = conn.entries
        logging.debug('Number of dn found = {}'.format(len(groups)))
        for group in groups:
            da_dn = group.distinguishedName.value
            logging.info('group\'s distinguishedName = {} '.format(c_cyan(da_dn)))
            # search for nested groups
            search_filter = '(&(memberOf:1.2.840.113556.1.4.1941:={})(!(objectClass=group))(!(objectClass=computer)))'.format(da_dn)
            search_attributes = args.search_attributes
            size_limit = args.size_limit
            logging.debug('Found base DN = {}'.format(base_dn))
            logging.debug('Search filter = {}'.format(search_filter))
            logging.debug('Looking for attributes = {}'.format(search_attributes))
            conn.search(base_dn, search_filter, attributes=search_attributes, size_limit=size_limit)
            members = conn.entries
            logging.info('{} members found:'.format(len(members)))
            for member in members:
                for out_line in list_user_brief(member):
                    logging.info(out_line)
        if args.output_file and groups is not None:
            with open(args.output_file, 'a') as f:
                for group in groups:
                    f.write('{}\n'.format(group.entry_to_json()))


def show_user_list(args):
    logging.debug('Looking for user list on LDAP server {}'.format(args.ldap_server))
    server = ldap3.Server(args.ldap_server, get_info='ALL')
    domain_username = '{}\\{}'.format(args.domain, args.username)
    logging.debug('Using NTLM authentication with username = {}'.format(domain_username))
    with ldap3.Connection(server, user=domain_username, password=args.password, authentication='NTLM', auto_bind=True) as conn:
        # first of all, we need to extract the exact dn to be able to search for nested groups
        search_filter = '(&(objectClass=user)({}))'.format(args.search_filter)
        search_attributes = args.search_attributes
        size_limit = args.size_limit
        base_dn = server.info.other.get('defaultNamingContext')[0]
        logging.debug('Found base DN = {}'.format(base_dn))
        logging.debug('Search filter = {}'.format(search_filter))
        logging.debug('Looking for attributes = {}'.format(search_attributes))
        conn.search(base_dn, search_filter, attributes=search_attributes, size_limit=size_limit)
        users = conn.entries
        logging.debug('Number of users found = {}'.format(len(users)))
        for user in users:
            for out_line in list_user_brief(user):
                logging.info(out_line)
    if args.output_file and users is not None:
        with open(args.output_file, 'a') as f:
            for user in users:
                f.write('{}\n'.format(user.entry_to_json()))


def show_administrators(args):
    args.search_filter = '|(CN=Administrators)(CN=Administrateurs)'
    show_group_members(args)


def show_kerberoast(args):
    logging.info('Looking for kerberoastable users on LDAP server {}'.format(args.ldap_server))
    server = ldap3.Server(args.ldap_server, get_info='ALL')
    domain_username = '{}\\{}'.format(args.domain, args.username)
    logging.debug('Using NTLM authentication with username = {}'.format(domain_username))
    try:
        with ldap3.Connection(server, user=domain_username, password=args.password, authentication='NTLM', auto_bind=True) as conn:
            base_dn = server.info.other.get('defaultNamingContext')[0]
            search_filter = '(&(objectClass=user)(servicePrincipalName=*)(!(objectClass=computer))(!(cn=krbtgt))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'
            search_attributes = ['cn', 'samaccountname', 'serviceprincipalname']
            size_limit = 50
            logging.debug('Found base DN = {}'.format(base_dn))
            logging.debug('Search filter = {}'.format(search_filter))
            logging.debug('Looking for attributes = {}'.format(search_attributes))
            conn.search(base_dn, search_filter, attributes=search_attributes, size_limit=size_limit)
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
    argParser.add_argument('-t', '--type', required=True, dest='request_type', help='Request type: info, whoami, search, search-large, trusts, pass-pols, show-admins, show-user, show-user-list, kerberoast, all')
    argParser.add_argument('-d', '--domain', dest='domain', help='Authentication account\'s FQDN. Example: "contoso.local".')
    argParser.add_argument('-u', '--username', dest='username', help='Authentication account\'s username.')
    argParser.add_argument('-p', '--password', dest='password', help='Authentication account\'s password.')
    argParser.add_argument('-s', '--search-filter', dest='search_filter', help='Search filter (use LDAP format).')
    argParser.add_argument('search_attributes', default='*', nargs='*', help='LDAP attributes to look for.')
    argParser.add_argument('-z', '--size_limit', dest='size_limit', default=100, help='Size limit (default is server\'s limit).')
    argParser.add_argument('-o', '--output', dest='output_file', help='Write results in specified file too.')
    argParser.add_argument('-v', '--verbose', dest='verbosity', help='Turn on debug mode', action='store_true')
    args = argParser.parse_args()

    # Set mandatory arguments for each request_type
    mandatory_arguments = {}
    mandatory_arguments['info'] = []
    mandatory_arguments['whoami'] = ['domain', 'username', 'password']
    mandatory_arguments['search'] = ['domain', 'username', 'password', 'search_filter']
    mandatory_arguments['search-large'] = ['domain', 'username', 'password', 'search_filter']
    mandatory_arguments['trusts'] = ['domain', 'username', 'password']
    mandatory_arguments['pass-pols'] = ['domain', 'username', 'password']
    mandatory_arguments['show-admins'] = ['domain', 'username', 'password']
    mandatory_arguments['show-user'] = ['domain', 'username', 'password', 'search_filter']
    mandatory_arguments['show-user-list'] = ['domain', 'username', 'password', 'search_filter']
    mandatory_arguments['kerberoast'] = ['domain', 'username', 'password']
    mandatory_arguments['all'] = ['domain', 'username', 'password']
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
        formatter = logging.Formatter(fmt='%(asctime)-19s %(levelname)-8s %(message)s', datefmt='%Y-%m-%d_%H:%M:%S')
    else:
        logger.setLevel(logging.INFO)
        formatter = logging.Formatter(fmt='%(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)


    if args.request_type == 'info':
        get_server_info(args)
    elif args.request_type == 'whoami':
        get_whoami(args)
    elif args.request_type == 'search':
        search(args)
    elif args.request_type == 'search-large':
        search_large(args)
    elif args.request_type == 'trusts':
        get_trusts(args)
    elif args.request_type == 'pass-pols':
        get_pass_pols(args)
    elif args.request_type == 'show-admins':
        show_administrators(args)
    elif args.request_type == 'show-user':
        show_user(args)
    elif args.request_type == 'show-user-list':
        show_user_list(args)
    elif args.request_type == 'kerberoast':
        show_kerberoast(args)
    elif args.request_type == 'all':
        logging.info(str_title('Server Info'))
        get_server_info(args)
        logging.info(str_title('List of Administrators'))
        show_administrators(args)
        logging.info(str_title('List of Trusts'))
        get_trusts(args)
        logging.info(str_title('Details of Password Policies'))
        get_pass_pols(args)
        logging.info(str_title('Possible Kerberoast Clients'))
        show_kerberoast(args)

    else:
        logging.error('Error: no request type supplied. (Please use "-t")')


if __name__ == '__main__':
    main()

