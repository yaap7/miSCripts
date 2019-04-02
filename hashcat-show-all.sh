#!/bin/bash

find . -name '*.hash' | while read i ; do
    num="$(echo "$i" | grep -o '_[0-9]*.hash' | grep -o '[0-9]*')"
    ishow="${i%.*}.show"
    if basename "$i" | grep -q "^user" ; then
        user='--username'
    else
        user=''
    fi
    $(echo "hashcat -m $num $user --show $i") > "$ishow"
done
