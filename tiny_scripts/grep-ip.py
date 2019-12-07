#!/usr/bin/env python3

import argparse
import ipaddress
import re
import sys


def main(args):
  re_ip = re.compile(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')

  for line in sys.stdin:
    for match in re_ip.finditer(line):
      try:
        ip = ipaddress.ip_address(match.group(0))
        if args.is_global:
          if ip.is_global:
            print(ip)
        elif args.is_private:
          if ip.is_private:
            print(ip)
        else:
          print(ip)
      except ValueError:
        continue
      

if __name__ == "__main__":
  # arguments parsing
  argParser = argparse.ArgumentParser(description='Grep only valid IP addresses from stdin.')
  argGroup = argParser.add_mutually_exclusive_group()
  argGroup.add_argument('-g', '--global', dest='is_global', help='Return global IP addresses only', action='store_true')
  argGroup.add_argument('-p', '--private', dest='is_private', help='Return private IP addresses only', action='store_true')
  args = argParser.parse_args()
  main(args)