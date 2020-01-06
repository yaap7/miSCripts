# Misc Scripts

## clean-cme

Remove colors and null-byte in a [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) output.

### clean-cme usage

`crackmapexec smb 192.168.0.0/24 | tee discover_192.168.0.0-24.cme`

`crakcmapexec smb … … --lsa | tee …_lsa.cme`

Then:

`clean-cme`

It will find every file with extension `.cme`, and create a clean copy in `.txt` format.

## clean-conf

Remove comments and empty lines.

### clean-conf usage

`cat /etc/apache2/apache2.conf | clean-conf`

## colorize

Simple way to quickly identify text of interest while keeping the rest of the content.
Like `grep --color` but also keep the text that does not match.

### colorize usage

`curl -I https://github.com/ 2>/dev/null | colorize GitHub`

See also: [uncolorize](#uncolorize)

## convert-cme-discover-to-csv.sh

As the name suggests, it converts the output of a simple discovery scan from [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) to a CSV file.

### convert-cme-discover-to-csv.sh usage

`crackmapexec smb 192.168.0.0/24 | tee discover_192.168.0.0-24.cme`

`cat discover_192.168.0.0-24.cme | convert-cme-discover-to-csv.sh`

``` csv
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

Could be easily pretty-printed using `csvlook` (from [csvkit](https://csvkit.readthedocs.io/en/latest/)):

`cat discover_192.168.0.0-24.cme | convert-cme-discover-to-csv.sh | csvlook`

``` text
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

## grep-ip

Print IP patterns from stdin.

### grep-ip usage

`cat scan_tcp.gnmap | grep '445/open/tcp' | grep-ip > cibles_port_445.txt`

## grep-hash-ntlm

Grep for NTLM hash strings.

**Warning**: MD5 and LM hashes have the same format, so they will also be grepped.

### grep-hash-ntlm usage

``` bash
cat big_unsorted_logs.txt | grep-hash-ntlm
```

## hashcat-print-stats.sh

Print percentage of cracked passwords for each files.

See file format below.

## hashcat-show-all.sh

Run `hashcat` with `--show` and the correct options on multiple `*.hash` files.

Files format:

`[users_]filename<_hash_type>.<hash|show>`

Examples:

* `users_ntds_ntlm_1000.hash`
* `all_lm_3000.show`

The `hash_type` is usefull to set the correct `-m` argument.

The files starting by `users` indicate a file containing usernames, so the `--username` argument is needed.

## ldapsearch-ad.py

Python3 script to quickly get various information from a domain controller through his LDAP service.

Moved here: [https://github.com/yaap7/ldapsearch-ad](https://github.com/yaap7/ldapsearch-ad)

## lyncsmash_gg.py

Quick adaptation of the [lyncsmash](https://github.com/nyxgeek/lyncsmash) original tool. To be removed.

## nat-vm

Simple script to add the correct `iptables` rules to NAT a VM in `host-only adapter` mode (used with [VirtualBox](https://www.virtualbox.org/)).

### nat-vm usage

`nat-vm -h`

``` text
Basic usage: ./nat-vm [-i <iface>] [-d] <vm_ip>
Example: ./nat-vm -i eth0 192.168.56.10
default interface: eth0
-d = remove configuration
```

`nat-vm 192.168.56.10`
or
`nat-vm -i wlan0 192.168.56.10`

It is now possible to remove the configuration by adding a `-d` to the command line.

## nessus-syn-scan-to-csv.py

Python3 script to retrieve an IP/port/protocol from a nessus (broken XML) file.

`nessus-syn-scan-to-csv.py 192.168.0.1.nessus 192.168.0.2.nessus`

``` csv
ip,port,protocol
192.168.0.1,80,tcp
192.168.0.1,443,tcp
192.168.0.2,443,tcp
```

## ntlmssp-decode.py

Quick python2 script to decode the NTLM SSP authentication because I was not happy with the existing tools.
Have to be manually edited to change the challenge to decode.

## ntlmsum

Show the NTLM hash of each line (from a file, or inline).

### ntlmsum usage

``` text
$ ./ntlmsum 'P@$$w0rd'
f56a8399599f1be040128b1dd9623c29
```

``` text
$ cat pass.txt | ./ntlmsum
f56a8399599f1be040128b1dd9623c29
```

``` text
$ ./ntlmsum 'P@$$w0rd' 'Ub3r_$3cRe7'
f56a8399599f1be040128b1dd9623c29
733aac45c620a5c11c9e03a40262fc7c
```

``` text
$ cat multipass.txt | ./ntlmsum
f56a8399599f1be040128b1dd9623c29
733aac45c620a5c11c9e03a40262fc7c
```

## parse-o365-log.py

Python3 script to parse Office365 logs.
Work only on a specific test, so should be greatly enhanced for other test-cases.

## parse-secretsdump.sh

Shell script to parse the output of [secretsdump.py](https://github.com/yaap7/wiKB/blob/master/tools/impacket.md#secretsdumppy) to print statistics and hashcat-ready files.

It supports:

* user/computer accounts
* history hashes
* lm/ntlm
* user status (enabled/disabled)

### parse-secretsdump.sh usage

* Print statistics

`parse-secretsdump.sh -s secretsdump_ntds_full_dc1.contoso.intra.txt | csvlook`

``` text
| Metric                                                            | Number |
| ----------------------------------------------------------------- | ------ |
| Number of total hashes                                            |    320 |
| Number of computer accounts                                       |     79 |
| Number of user accounts                                           |    219 |
| Number of user accounts enabled                                   |    699 |
| Number of user accounts disabled                                  |    520 |
| Number of user accounts with unknown status                       |      0 |
| Number of user accounts with non-empty LM hash                    |    860 |
| Number of user accounts with non-empty NTLM hash                  |    217 |
| Number of user accounts with empty NTLM hash                      |      2 |
| Number of distinct non-empty LM user hashes (including history)   |    856 |
| Number of distinct non-empty NTLM user hashes (including history) |    181 |
```

* extract hashes

`parse-secretsdump.sh -e -o hashcat_ntds secretsdump_ntds_full_dc1.contoso.intra.txt`

`ls -1 hashcat_ntds`

``` text
all_lm_3000.hash
all_ntlm_1000.hash
ntds_base_file.txt
users_enabled_ntlm_1000.hash
users_lm_3000.hash
users_ntlm_1000.hash
```

## parse-testssl-json.py

Python3 script to parse the json output of [testssl.sh](https://testssl.sh/).

WIP: To be continued on next web application pentest.

## parse-weleakinfo.py

Parse the content of a web page from [WeLeakInfo](https://weleakinfo.com/) and output data in CSV format to be used with [CSVKit](https://csvkit.readthedocs.io/en/latest/).

### parse-weleakinfo.py usage

1. Save the plain HTML to a file.

2. Print the type of information found in the page (multiple files could be used at the same time)

    `parse-weleakinfo.py -s search_raw_webpage.html`

    ``` text
    * Username
    * Email
    * First Name
    * Address
    * Password
    * Registered IP Address
    * Date of Birth
    * First Last
    * Phone
    * …
    ```

3. Output only specific columns

`parse-weleakinfo.py -c Username,Email,Password search_raw_webpage.html`

The output could then be filtered, queried, and shown using CSVKit.

Example to show lines containing a non-empty password:

`parse-weleakinfo.py -c Username,Email,Password search_raw_webpage.html | csvgrep -c Password -r '.' | csvlook`

## query-bloodhound.py

Python3 script to query a neo4j database pre-filled with BloodHound results.
For the moment, just return the list of computer where a specific user have administrative rights.

To be continued.

## recon-ip

Get as much information as possible about an IP address.

``` bash
recon-ip 54.90.107.240 1.1.1.1
```

Could use `curl` or `wget`, `shodan`, `censys`, and `greynoise` for the moment.

Install optionnal requirements: `pip install shodan censys greynoise`

## remove-powershell-multilines-comments.py

Python3 script to remove all comments of a powershell script.

Functionality to be added: split very huge base64 chunks in part of about 450 bytes to allow copy paste in a powershell terminal (do you have a better method? real question).

## search-censys.py

Search for open ports for a specific IP on Censys (need an API key).

**usage**: `./search-censys.py ip:192.30.253.112`

``` text
Result for 192.30.253.112
+ Open port: 443/https
+ Open port: 22/ssh
+ Open port: 80/http
```

or CSV output with `-c`: `./search-censys.py -c ip:192.30.253.112 ip:192.30.253.113`

``` text
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
