#!/bin/bash

find . -name '*.hash' | while read fil ; do
    fil_show="${fil%.*}.show"
    if [[ -f "$fil_show" ]] ; then
        echo "($(($(wc -l "$fil_show"| grep -o "^[0-9]*")*100/$(wc -l "$fil" | grep -o "^[0-9]*"))) %) $fil"
    else
        echo "( 0 %) $fil"
    fi
done
