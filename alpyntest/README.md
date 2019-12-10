# alpyntest

A small docker image to embed python3 pentest tools used to Active Directory enumeration or exploitation.

## Installed Tools

* [x] [ldapsearch-ad](https://github.com/yaap7/ldapsearch-ad)
* [x] [impacket](https://github.com/SecureAuthCorp/impacket)
* [x] [pypykatz](https://github.com/skelsec/pypykatz)
* [x] [lsassy](https://github.com/Hackndo/lsassy)
* [ ] [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec)

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

