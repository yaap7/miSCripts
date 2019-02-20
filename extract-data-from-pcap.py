#!/usr/bin/env python3

import argparse
import sys

from scapy.all import TCP
from scapy.all import rdpcap


def main():
    argParser = argparse.ArgumentParser(description="Extract all data in TCP segments from a pcap file.")
    argParser.add_argument('-i', '--input', dest='pcap_file', help='The pcap file to extract data from.')
    argParser.add_argument('-v', '--verbose', dest='verbosity', help='Turn on debug mode', action='store_true')
    args = argParser.parse_args()
    pkts = rdpcap(args.pcap_file)
    for pkt in pkts:
        if TCP in pkt:
            try:
                sys.stdout.write(bytes(pkt[TCP].payload).decode('utf-8'))
            except:
                pass


if __name__ == '__main__':
    main()
