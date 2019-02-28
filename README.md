# Misc Scripts

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


## ldapsearch-ad.py

Python3 script to get various information from a domain controller through his LDAP service.

TODO:

* better explain the usage here.
* add pretty output for other functions (get-user, get-spn, etc) while keeping a json output.


## lyncsmash_gg.py

Quick adaptation of the [lyncsmash](https://github.com/nyxgeek/lyncsmash) original tool. To be removed.


## ntlmssp-decode.py

Quick python2 script to decode the NTLM SSP authentication because I was not happy with the existing tools.
Have to be manually edited to change the challenge to decode.


## ntlmsum

Show the NTLM hash of each line (from a file, or inline).

**usages**:

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


## unhex-passwords.py

Used for parsing the output of hashcat: replace every occurence of `$HEX[...]` by the decoded hex string between brackets.

**usage**: `cat hashcat-output.txt | ./unhex-passwords.py | tee hashcat-output-clean.txt`
