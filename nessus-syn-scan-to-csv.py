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
    argParser.add_argument('-s', '--separator', default=',', help='Define the main field separator (Default: ",")')
    argParser.add_argument('nessus', help='Nessus file to be parsed', nargs='+')
    args = argParser.parse_args()

    # enable debug is requested
    logger = logging.getLogger()
    handler = logging.StreamHandler(sys.stdout)
    if args.debug:
        logger.setLevel(logging.DEBUG)
        formatter = logging.Formatter(fmt='%(asctime)-19s %(levelname)-8s %(message)s', datefmt='%Y-%m-%d_%H:%M:%S')
    else:
        logger.setLevel(logging.INFO)
        formatter = logging.Formatter(fmt='%(message)s', datefmt='%Y-%m-%d_%H:%M:%S')
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    # define separators
    sep = args.separator

    # parse Nessus file
    logging.info('ip{}port{}protocol'.format(sep, sep))
    for nessus in args.nessus:
        tree = ET.parse(nessus)
        root = tree.getroot()
        isReportHost = False
        for reportHost in root.iterfind('.//ReportHost'):
            isReportHost = True
            ip = reportHost.find('./HostProperties/tag[@name="host-ip"]').text
            logging.debug('ReportHost found: {}.'.format(ip))
            for synScan in reportHost.iterfind('ReportItem[@pluginName="Nessus SYN scanner"]'):
                pluginOutput = synScan.find('plugin_output').text
                logging.debug('Plugin output = {}.'.format(pluginOutput))
                match = re.search('Port (\d+/..p) was found to be open', pluginOutput)
                if match is not None:
                    service = match.group(1).split('/')
                    port = service[0]
                    proto = service[1]
                    logging.info('{}{}{}{}{}'.format(ip, sep, port, sep, proto))
                else:
                    logging.warning('Error: Incorrect plugin output for ReportHost={}.'.format(ip))
            else:
                logging.debug('No SYN scan found for {}.'.format(ip))
        if not isReportHost:
            logging.warning('No host found.')


if __name__ == '__main__':
    main()
