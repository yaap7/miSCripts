# alpyntest

A small docker image to embed python3 pentest tools used to Active Directory enumeration or exploitation.

## Installed Tools

* [x] [python3](https://pkgs.alpinelinux.org/package/edge/main/x86/python3) with pip
* [x] [csvkit](https://pkgs.alpinelinux.org/package/edge/main/x86/python3)
* [x] [git](https://pkgs.alpinelinux.org/package/edge/main/x86/git)
* [x] [ldapsearch-ad](https://github.com/yaap7/ldapsearch-ad)
* [x] [impacket](https://github.com/SecureAuthCorp/impacket)
* [x] [pypykatz](https://github.com/skelsec/pypykatz)
* [x] [lsassy](https://github.com/Hackndo/lsassy)
* [x] [ntlmrecon](https://github.com/sachinkamath/ntlmrecon)
* [x] [Enum4LinuxPy](https://github.com/0v3rride/Enum4LinuxPy)
* [ ] [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec)
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

* [ ] add a [Python-based BloodHound Ingestor](https://github.com/fox-it/BloodHound.py)
* [ ] integrate CrackMapExec once a valid python3 version is available (see [byt3bl33d3r/CrackMapExec#323](https://github.com/byt3bl33d3r/CrackMapExec/pull/323))
* [x] a [first script](discover-ip.sh) to use all tools before having a first valid account (so mostly systems enumeration)
* [ ] a second script to use all tools once we get a valid user account (Active Directory enumeration)
* [ ] a third script to dump the domain and parse the results once we get a valid admin account
