#!/usr/bin/env python3

import argparse
import logging
import re
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
            ip = reportHost.find('./HostProperties/tag[@name="host-ip"]').text
            ports = []
            logging.debug('ReportHost found: {}.'.format(ip))
            isReportScan = False
            for synScan in reportHost.iterfind('ReportItem[@pluginName="Nessus SYN scanner"]'):
                isReportScan = True
                pluginOutput = synScan.find('plugin_output').text
                logging.debug('Plugin output = {}.'.format(pluginOutput))
                match = re.search('Port (\d+/..p) was found to be open', pluginOutput)
                if match is not None:
                    port = match.group(1)
                    ports.append(port)
                else:
                    logging.warning('Error: Incorrect plugin output for ReportHost={}.'.format(ip))

            if isReportScan:
                logging.info('{}{}{}'.format(ip, sep, sepPorts.join(ports)))
            else:
                logging.debug('No SYN scan found for {}.'.format(ip))
        if not isReportHost:
            logging.warning('No host found.')


if __name__ == '__main__':
    main()
