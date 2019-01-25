# Misc Scripts

## enum-web-users.py

Python3 script to quickly create a POC of user enumeration through a web application.


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


## search-nessus-445.py

To be merged with `extract-ports-from-nessus.py`.


## split-lines.sh

Same as the original `split` but split on "new line" (simple wrapper around `head` and `tail`).

**usage**: `split-lines big_file.txt 100`
    will create chunks of 100 lines in big_file.txt-00, big_file.txt-01, etc.
