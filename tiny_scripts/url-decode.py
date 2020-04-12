#!/usr/bin/env python3

from urllib.parse import unquote
import sys


def url_decode(s):
    return unquote(s)


def main():
    if len(sys.argv) > 1:
        for arg in sys.argv:
            print(url_decode(arg))
    else:
        for line in sys.stdin.readlines():
            print(url_decode(line))


if __name__ == "__main__":
    main()
