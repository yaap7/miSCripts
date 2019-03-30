# Misc Scripts


## clean-cme

Remove colors and null-byte in a [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) output.

### Usage

`crackmapexec smb 192.168.0.0/24 | tee discover_192.168.0.0-24.cme`
`crakcmapexec smb … … --lsa | tee …_lsa.cme`

Then:

`clean-cme`

It will find every file with extension `.cme`, and create a clean copy in `.txt` format.




## clean-conf

Remove comments and empty lines.

### Usage

`cat /etc/apache2/apache2.conf | clean-conf`





## colorize

Simple way to quickly identify text of interest while keeping the rest of the content.
Like `grep --color` but also keep the text that does not match.

### Usage

`curl -I https://github.com/ 2>/dev/null | colorize GitHub`


See also: [uncolorize](#uncolorize)




## convert-cme-discover-to-csv.sh

As the name suggests, it converts the output of a simple discovery scan from [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) to a CSV file.


### Usage

`crackmapexec smb 192.168.0.0/24 | tee discover_192.168.0.0-24.cme`

`cat discover_192.168.0.0-24.cme | convert-cme-discover-to-csv.sh`

```
ip,domain,hostname,signing,smbv1,os
192.168.0.10,CONTOSO,SRV-DC1,True,True,Windows Server 2012 R2 Datacenter 9600 x64
192.168.0.13,CONTOSO,SRV-DNS,True,True,Windows Server 2016 Standard 14393 x64
192.168.0.11,CONTOSO,SRV-DC2,True,True,Windows Server 2012 R2 Datacenter 9600 x64
192.168.0.16,CONTOSO,SRV-WEB01,True,True,Windows Server 2012 R2 Datacenter 9600 x64
192.168.0.14,CONTOSO,SRV-SQL02,True,True,Windows Server 2012 R2 Datacenter 9600 x64
192.168.0.12,CONTOSO,SRV-EXCH1,True,True,Windows Server 2012 R2 Datacenter 9600 x64
192.168.0.17,CONTOSO,SRV-PRINT1,True,True,Windows Server 2012 R2 Datacenter 9600 x64
[...snip...]
```

Could be easily pretty-printed using csvlook (from [csvkit](https://csvkit.readthedocs.io/en/latest/)):

`cat discover_192.168.0.0-24.cme | convert-cme-discover-to-csv.sh | csvlook`

```
| ip           | domain  | hostname   | signing | smbv1 | os                                         |
| ------------ | ------- | ---------- | ------- | ----- | ------------------------------------------ |
| 192.168.0.10 | CONTOSO | SRV-DC1    |    True |  True | Windows Server 2012 R2 Datacenter 9600 x64 |
| 192.168.0.13 | CONTOSO | SRV-DNS    |    True |  True | Windows Server 2016 Standard 14393 x64     |
| 192.168.0.11 | CONTOSO | SRV-DC2    |    True |  True | Windows Server 2012 R2 Datacenter 9600 x64 |
| 192.168.0.16 | CONTOSO | SRV-WEB01  |    True |  True | Windows Server 2012 R2 Datacenter 9600 x64 |
| 192.168.0.14 | CONTOSO | SRV-SQL02  |    True |  True | Windows Server 2012 R2 Datacenter 9600 x64 |
| 192.168.0.12 | CONTOSO | SRV-EXCH1  |    True |  True | Windows Server 2012 R2 Datacenter 9600 x64 |
| 192.168.0.17 | CONTOSO | SRV-PRINT1 |    True |  True | Windows Server 2012 R2 Datacenter 9600 x64 |
[...snip...]
```



## enum-web-users.py

Python3 script to quickly create a POC of user enumeration through a web application.


## extract-data-from-pcap.py

Python3 script to extract all data in TCP segment of an entire pcap.
No filter implemented for the moment (please filter with tshark or wireshark).


## extract-infos-from-pcap.py

Python3 script to all juicy information from a pcap file. Used for passive network recon.

TODO:

* use `argparse` for a nice usage message;
* retrieve the `originating vlan` in STP;
* retrive all information from LLDP trames.


## extract-ports-from-nessus.py

Python3 script to retrieve a list of IP addresses which listened on a specific port from a nessus (broken XML) file.




## grep-ip

Print IP patterns from stdin.

### Usage

`cat scan_tcp.gnmap | grep '445/open/tcp' | grep-ip > cibles_port_445.txt`






## ldapsearch-ad.py

Python3 script to get various information from a domain controller through his LDAP service.

### Usage

Help:

```
$ ./ldapsearch-ad.py -h
usage: ldapsearch-ad.py [-h] -l LDAP_SERVER -t REQUEST_TYPE [-d DOMAIN]
                        [-u USERNAME] [-p PASSWORD] [-s SEARCH_FILTER]
                        [-z SIZE_LIMIT] [-o OUTPUT_FILE] [-v]
                        [search_attributes [search_attributes ...]]

Active Directory LDAP Enumerator

positional arguments:
  search_attributes     LDAP attributes to look for.

optional arguments:
  -h, --help            show this help message and exit
  -l LDAP_SERVER, --server LDAP_SERVER
                        IP address of the LDAP server.
  -t REQUEST_TYPE, --type REQUEST_TYPE
                        Request type: info, whoami, search, trusts, pass-pols,
                        show-domain-admins, show-user, auto
  -d DOMAIN, --domain DOMAIN
                        Authentication account's FQDN. Example:
                        "contoso.local".
  -u USERNAME, --username USERNAME
                        Authentication account's username.
  -p PASSWORD, --password PASSWORD
                        Authentication account's password.
  -s SEARCH_FILTER, --search-filter SEARCH_FILTER
                        Search filter (use LDAP format).
  -z SIZE_LIMIT, --size_limit SIZE_LIMIT
                        Size limit (default is server's limit).
  -o OUTPUT_FILE, --output OUTPUT_FILE
                        Write results in specified file too.
  -v, --verbose         Turn on debug mode
```


Retrieve server **information** without credentials using `-t info`:

```
$ ./ldapsearch-ad.py -l 192.168.56.20 -t info
Getting info from LDAP server 192.168.56.20
Forest functionality level = Windows 2012 R2
Domain functionality level = Windows 2012 R2
Domain controller functionality level = Windows 2012 R2
rootDomainNamingContext = DC=evilcorp,DC=lab2
defaultNamingContext = DC=evilcorp,DC=lab2
ldapServiceName = evilcorp.lab2:mtldc1$@EVILCORP.LAB2
naming_contexts = ['DC=evilcorp,DC=lab2', 'CN=Configuration,DC=evilcorp,DC=lab2', 'CN=Schema,CN=Configuration,DC=evilcorp,DC=lab2', 'DC=DomainDnsZones,DC=evilcorp,DC=lab2', 'DC=ForestDnsZones,DC=evilcorp,DC=lab2']
```

Check authentication using `-t whoami`:

```
$ ./ldapsearch-ad.py -l 192.168.56.20 -d evilcorp -u bbilly -p 'P@$$w0rd' -t whoami
Executing whoami on LDAP server 192.168.56.20
You are: "u:EVILCORP\bbilly"
```

List **trusts** attributes using `-t trusts` (user account needed):

```
$ ./ldapsearch-ad.py -l 192.168.56.20 -d evilcorp -u jjohnny -p 'P@$$word' -t trusts
Looking for trusts on LDAP server 192.168.56.20
Trust =
+ fra.evilcorp.lab2 (FRA)
|___trustAttributes = ['TRUST_ATTRIBUTE_WITHIN_FOREST']
|___trustDirection = Bidirectional
|___trustType = The trusted domain is a Windows domain running Active Directory.
|___trustPartner = fra.evilcorp.lab2
|___securityIdentifier = S-1-5-21-2894840767-735700-3593130334
|___whenCreated = 2019-03-09 04:57:15+00:00
|___whenChanged = 2019-03-09 04:57:15+00:00
```

List **password policies** using `-t pass-pols` (user account needed for default password policy / admin account needed for fine grained password policies):

```
$ ./ldapsearch-ad.py -l 192.168.56.20 -d evilcorp -u jjohnny -p 'P@$$word' -t pass-pols
Looking for all password policies on LDAP server 192.168.56.20
+ Default password policy:
|___Minimum password length = 7
|___Password complexity = Enabled
|___Lockout threshold = Disabled
No fine grained password policy found (high privileges are often required).
```

Show the **domain admins** and their most interesting flags using `-t show-domain-admins` (user account needed):

```
$ ./ldapsearch-ad.py -l 192.168.56.20 -d evilcorp -u jjohnny -p 'P@$$word' -t show-domain-admins
Looking for domain admins on LDAP server 192.168.56.20
Domain admin group's distinguishedName = CN=Domain Admins,CN=Users,DC=evilcorp,DC=lab2 
3 domain admins found:
+ Administrator
+ bbilly (ENCRYPTED_TEXT_PWD_ALLOWED)
+ dhcp_service
```

Show the most interesting attributes of a user using `-t show-user` (user account needed):

```
$ ./ldapsearch-ad.py -l 192.168.56.20 -d evilcorp -u jjohnny -p 'P@$$word' -t show-user -s '(samaccountname=bbilly)'
Looking for users on LDAP server 192.168.56.20
+ bbilly
|___type: user
|___The adminCount is set to 1
|___userAccountControl = ENCRYPTED_TEXT_PWD_ALLOWED, NORMAL_ACCOUNT
|___sAMAccountType = SAM_USER_OBJECT
|___memberOf = Bad admins
```

or even computers or groups. Everything depend of the search parameter `-s`.

```
$ ./ldapsearch-ad.py -l 192.168.56.20 -d evilcorp -u jjohnny -p 'P@$$word' -t show-user -s '(samaccountname=mtldc1$)'
Looking for users on LDAP server 192.168.56.20
+ MTLDC1$
|___type: computer
|___userAccountControl = SERVER_TRUST_ACCOUNT, TRUSTED_FOR_DELEGATION
|___sAMAccountType = SAM_MACHINE_ACCOUNT

$ ./ldapsearch-ad.py -l 192.168.56.20 -d evilcorp -u jjohnny -p 'P@$$word' -t show-user -s '(cn=bad admins)'
Looking for users on LDAP server 192.168.56.20
+ bad_admins
|___type: group
|___displayName = Bad Admins
|___The adminCount is set to 1
|___sAMAccountType = SAM_GROUP_OBJECT
|___memberOf = Domain Admins
```

Retrieve all interesting information with a simple user account using `-t auto`:

```
$ ./ldapsearch-ad.py -l 192.168.56.20 -d evilcorp -u jjohnny -p 'P@$$word' -t auto
###  Server Info  ###
Getting info from LDAP server 192.168.56.20
Forest functionality level = Windows 2012 R2
Domain functionality level = Windows 2012 R2
Domain controller functionality level = Windows 2012 R2
rootDomainNamingContext = DC=evilcorp,DC=lab2
defaultNamingContext = DC=evilcorp,DC=lab2
ldapServiceName = evilcorp.lab2:mtldc1$@EVILCORP.LAB2
naming_contexts = ['DC=evilcorp,DC=lab2', 'CN=Configuration,DC=evilcorp,DC=lab2', 'CN=Schema,CN=Configuration,DC=evilcorp,DC=lab2', 'DC=DomainDnsZones,DC=evilcorp,DC=lab2', 'DC=ForestDnsZones,DC=evilcorp,DC=lab2']
###  List of Domain Admins  ###
Looking for domain admins on LDAP server 192.168.56.20
Domain admin group's distinguishedName = CN=Domain Admins,CN=Users,DC=evilcorp,DC=lab2 
3 domain admins found:
+ Administrator
+ bbilly (ENCRYPTED_TEXT_PWD_ALLOWED)
+ dhcp_service
###  List of Trusts  ###
Looking for trusts on LDAP server 192.168.56.20
Trust =
+ fra.evilcorp.lab2 (FRA)
|___trustAttributes = ['TRUST_ATTRIBUTE_WITHIN_FOREST']
|___trustDirection = Bidirectional
|___trustType = The trusted domain is a Windows domain running Active Directory.
|___trustPartner = fra.evilcorp.lab2
|___securityIdentifier = S-1-5-21-2894840767-735700-3593130334
|___whenCreated = 2019-03-09 04:57:15+00:00
|___whenChanged = 2019-03-09 04:57:15+00:00
###  Details of Password Policies  ###
Looking for all password policies on LDAP server 192.168.56.20
+ Default password policy:
|___Minimum password length = 7
|___Password complexity = Enabled
|___Lockout threshold = Disabled
No fine grained password policy found (high privileges are often required).
```


### Advanced usage using search

Search for any information using the powerfull ldap filter syntax with `-t search`:

```
$ ./ldapsearch-ad.py -l 192.168.56.20 -d evilcorp -u jjohnny -p 'P@$$word' -t search -s '(&(objectClass=user)(servicePrincipalName=*))' cn serviceprincipalname
Searching on LDAP server 192.168.56.20
Entry = 
DN: CN=MTLDC1,OU=Domain Controllers,DC=evilcorp,DC=lab2 - STATUS: Read - READ TIME: 2019-03-09T19:40:12.086215
    cn: MTLDC1
    servicePrincipalName: Dfsr-12F9A27C-BF97-4787-9364-D31B6C55EB04/MTLDC1.evilcorp.lab2
                          ldap/MTLDC1.evilcorp.lab2/ForestDnsZones.evilcorp.lab2
                          ldap/MTLDC1.evilcorp.lab2/DomainDnsZones.evilcorp.lab2
                          DNS/MTLDC1.evilcorp.lab2
                          GC/MTLDC1.evilcorp.lab2/evilcorp.lab2
[…]
```


### TODO

* give usefull `search` examples ;
* add pretty output for other functions (get-user, get-spn, etc) while keeping a json output ;
* continuously improve this documentation

for v2:

* change the core architecture to create an object and do not open multiple connection for `-t all`

### Credits

Thanks to [Bengui](https://youtu.be/xKG9v0UfuH0?t=228) for the username convention.


## lyncsmash_gg.py

Quick adaptation of the [lyncsmash](https://github.com/nyxgeek/lyncsmash) original tool. To be removed.




## nat-vm

Simple script to add the correct `iptables` rules to NAT a VM in `host-only adapter` mode (used with [VirtualBox](https://www.virtualbox.org/)).

### Usage

`nat-vm -h`

```
Basic usage: /home/gg/bin/nat-vm -i <iface> <vm_ip>
Example: /home/gg/bin/nat-vm -i eth0 192.168.56.10
default interface: eth0
```

`nat-vm 192.168.56.10`
or
`nat-vm -i wlan0 192.168.56.10`






## ntlmssp-decode.py

Quick python2 script to decode the NTLM SSP authentication because I was not happy with the existing tools.
Have to be manually edited to change the challenge to decode.


## ntlmsum

Show the NTLM hash of each line (from a file, or inline).

### Usages

```
$ ./ntlmsum 'P@$$w0rd'
f56a8399599f1be040128b1dd9623c29
```
```
$ cat pass.txt | ./ntlmsum 
f56a8399599f1be040128b1dd9623c29
```
```
$ ./ntlmsum 'P@$$w0rd' 'Ub3r_$3cRe7'
f56a8399599f1be040128b1dd9623c29
733aac45c620a5c11c9e03a40262fc7c
```
```
$ cat multipass.txt | ./ntlmsum
f56a8399599f1be040128b1dd9623c29
733aac45c620a5c11c9e03a40262fc7c
```


## parse-o365-log.py

Python3 script to parse Office365 logs.
Work only on a specific test, so should be greatly enhanced for other test-cases.


## parse-testssl-json.py

Python3 script to parse the json output of [testssl.sh](https://testssl.sh/).
To be continued on next web application pentest.


## query-bloodhound.py

Python3 script to query a neo4j database pre-filled with BloodHound results.
For the moment, just return the list of computer where a specific user have administrative rights.

To be continued.


## remove-powershell-multilines-comments.py

Python3 script to remove all comments of a powershell script.

Functionality to be added: split very huge base64 chunks in part of about 450 bytes to allow copy paste in a powershell terminal (do you have a better method? real question).


## search-censys.py

Search for open ports for a specific IP on Censys (need an API key).

**usage**: `./search-censys.py ip:192.30.253.112`
```
Result for 192.30.253.112
+ Open port: 443/https
+ Open port: 22/ssh
+ Open port: 80/http
```

or CSV output with `-c`: `./search-censys.py -c ip:192.30.253.112 ip:192.30.253.113`
```
192.30.253.113,443/https
192.30.253.113,22/ssh
192.30.253.113,80/http
192.30.253.112,443/https
192.30.253.112,22/ssh
192.30.253.112,80/http
```


## search-nessus-445.py

To be merged with `extract-ports-from-nessus.py`.


## split-lines.sh

Same as the original `split` but split on "new line" (simple wrapper around `head` and `tail`).

**usage**: `split-lines big_file.txt 100`
    will create chunks of 100 lines in big_file.txt-00, big_file.txt-01, etc.




## uncolorize

Remove any control sequence usually used to color text in terminals.

See also: [colorize](#colorize)




## unhex-passwords.py

Used for parsing the output of hashcat: replace every occurence of `$HEX[...]` by the decoded hex string between brackets.

**usage**: `cat hashcat-output.txt | ./unhex-passwords.py | tee hashcat-output-clean.txt`
