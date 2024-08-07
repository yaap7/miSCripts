#!/usr/bin/env python3

import argparse
import logging
import sys


def main(args):
    # start of program
    logging.info("hello world!")


if __name__ == "__main__":
    # arguments parsing
    argParser = argparse.ArgumentParser(description="Default description to replace.")
    argParser.add_argument("files", nargs="+", help="Input files to parse.")
    argParser.add_argument(
        "-c", "--csv", dest="csv", help="Turn on CSV output", action="store_true"
    )
    argParser.add_argument(
        "-v", "--verbose", dest="debug", help="Turn on debugging", action="store_true"
    )
    args = argParser.parse_args()
    # logging configuration
    logger = logging.getLogger()
    handler = logging.StreamHandler(sys.stdout)
    if args.debug:
        logger.setLevel(logging.DEBUG)
        formatter = logging.Formatter(
            fmt="%(asctime)-19s %(levelname)-8s %(message)s",
            datefmt="%Y-%m-%d_%H:%M:%S",
        )
    else:
        logger.setLevel(logging.INFO)
        formatter = logging.Formatter(fmt="%(message)s", datefmt="%Y-%m-%d_%H:%M:%S")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    main(args)
