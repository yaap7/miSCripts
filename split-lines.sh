#!/bin/bash

# usage: split-lines big_file.txt 100
# will create chunks of 100 lines in big_file.txt-00, big_file.txt-01, etc.

total="$(cat "$1" | wc -l)"

i=1
j=0
while [[ "$i" -lt "$total" ]] ; do 
    cat $1 | tail -n +"$i" | head -n "$2" > "${1}-$(printf "%02d" $j)"
    i=$(($i + $2))
    j=$(($j + 1))
done

