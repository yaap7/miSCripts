#!/usr/bin/env python3

import argparse
import logging
import re
import sys
import xml.etree.ElementTree as ET


def main():
    # Argument definition
    argParser = argparse.ArgumentParser(description='Extract list of open ports from a Nessus file.')
    argParser.add_argument('-d', '--debug', help='Turn on debug mode', action='store_true')
    argParser.add_argument('-s', '--separator', help='Define the main field separator (Default: ":")')
    argParser.add_argument('-p', '--port-separator', help='Define the ports separator (Default: ",")')
    argParser.add_argument('nessus', help='Nessus file to be parsed', nargs='+')
    args = argParser.parse_args()

    # enable debug is requested
    logLevel = logging.INFO
    if args.debug:
        logLevel = logging.DEBUG
    logging.basicConfig(level=logLevel, format='%(message)s')
    logging.debug('Debug enabled.')

    # define separators
    sep = ':'
    if args.separator:
        sep = args.separator[0]
    sepPorts = ','
    if args.port_separator:
        sepPorts = args.port_separator[0]

    # parse Nessus file
    for nessus in args.nessus:
        tree = ET.parse(nessus)
        root = tree.getroot()
        isReportHost = False
        for reportHost in root.iterfind('.//ReportHost'):
            isReportHost = True
            ip = reportHost.attrib['name']
            logging.debug('IP found: {}'.format(ip))
            ports = []
            logging.debug('ReportHost found: {}.'.format(ip))
            isReportScan = False
            for synScan in reportHost.iterfind('ReportItem[@pluginName="Nessus TCP scanner"]'):
                isReportScan = True
                proto = synScan.attrib['protocol']
                if proto != 'tcp':
                    logging.error('Error: TCP scan return a non TCP result')
                    sys.exit(1)
                ports.append(synScan.attrib['port'])

            if isReportScan:
                logging.info('{}{}{}'.format(ip, sep, sepPorts.join(ports)))
            else:
                logging.debug('No TCP scan found for {}.'.format(ip))
        if not isReportHost:
            logging.warning('No host found.')


if __name__ == '__main__':
    main()
