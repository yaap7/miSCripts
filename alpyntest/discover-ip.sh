#!/bin/sh

if [ "$#" -ne 1 ] ; then
  echo "Usage: $0 192.168.42.1" >&2
  exit 1
fi

if [ "x$(echo $1 | grep-ip.py)" != "x$1" ] ; then
  echo 'invalid IP' >&2
  exit 2
fi

echo "Discovering $1"
# crackmapexec smb "$1"
ldapsearch-ad.py -t info -l "$1"
ntlmrecon --outfile "/tmp/ntlmrecon_$1.csv" --input "$1"
csvlook "/tmp/ntlmrecon_$1.csv"
