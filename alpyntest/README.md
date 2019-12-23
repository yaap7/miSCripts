# alpyntest

A small docker image to embed python3 pentest tools used to Active Directory enumeration or exploitation.

## Installed Tools

* [x] [python3](https://pkgs.alpinelinux.org/package/edge/main/x86/python3) with pip
* [x] [csvkit](https://csvkit.readthedocs.io/)
* [x] [git](https://pkgs.alpinelinux.org/package/edge/main/x86/git)
* [x] [ldapsearch-ad](https://github.com/yaap7/ldapsearch-ad)
* [x] [impacket](https://github.com/SecureAuthCorp/impacket)
* [x] [pypykatz](https://github.com/skelsec/pypykatz)
* [x] [lsassy](https://github.com/Hackndo/lsassy)
* [x] [ntlmrecon](https://github.com/sachinkamath/ntlmrecon)
* [x] [Enum4LinuxPy](https://github.com/0v3rride/Enum4LinuxPy)
* [x] [BloodHound.py](https://github.com/fox-it/BloodHound.py)
* [x] [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) (@mpgn version)
* [x] [various scripts](https://github.com/yaap7/miSCripts/tree/master/tiny_scripts)

## Build Image

`cd` to this directory and launch `docker build`:

``` bash
docker build -t alpyntest --build-arg USER_ID=$(id -u) --build-arg GROUP_ID=$(id -g) .
```

## Create Container from Image

Use the bash alias from [bash_alias](bash_alias) or customize this base command:

``` bash
docker run -it --rm -v $PWD:/data alpyntest /bin/sh -l
```

## TODO

* [x] integrate CrackMapExec once a valid python3 version is available (see [byt3bl33d3r/CrackMapExec#323](https://github.com/byt3bl33d3r/CrackMapExec/pull/323))
* [x] integrate lsassy module to CrackMapExec
* [ ] debug lsassy (SMB error?)
* [ ] debug CME - lsassy module
* [ ] debug CME - mimikatz module
* [ ] try all options of CrackMapExec to debug all the failing options
* [x] add a [Python-based BloodHound Ingestor](https://github.com/fox-it/BloodHound.py)
* [ ] debug `bloodhound-python`. it requires a real situation with a working DNS environment
* [ ] debug Enum4LinuxPy (`ERROR: net is not in your path.`) I installed `samba-client` since it requires `nmblookup` but it is not enough…
* [x] a [first script](discover-ip.sh) to use all tools before having a first valid account (so mostly systems enumeration)
* [ ] a second script to use all tools once we get a valid user account (Active Directory enumeration)
* [ ] a third script to dump the domain and parse the results once we get a valid admin account
