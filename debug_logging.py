#!/usr/bin/env python3

import argparse
import logging
import sys


def main():
    # Parse arguments
    argParser = argparse.ArgumentParser(description="Logging module debugger")
    argParser.add_argument('-v', '--verbose', dest='verbosity', help='Turn on debug mode', action='store_true')
    args = argParser.parse_args()

    # Configure logging
    # logLevel = logging.INFO
    # if args.verbosity:
    #     logLevel = logging.DEBUG
    # logging.basicConfig(level=logLevel, format='%(asctime)-19s %(levelname)-8s %(message)s', datefmt='%Y-%m-%d_%H:%M:%S')


    logger = logging.getLogger()
    handler = logging.StreamHandler(sys.stdout)
    if args.verbosity:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)
    formatter = logging.Formatter(fmt='%(asctime)-19s %(levelname)-8s %(message)s', datefmt='%Y-%m-%d_%H:%M:%S')
    handler.setFormatter(formatter)
    logger.addHandler(handler)


    logger.debug('debug 1')
    logger.info('info 1')
    logger.warning('warning 1')
    logger.error('error 1')
    logger.critical('critical 1')





if __name__ == '__main__':
    main()

