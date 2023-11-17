#!/usr/bin/env python3

from base64 import b64decode
from re import search
from argparse import ArgumentParser


def gen_candidates(b64: str) -> list:
    mod = len(b64) % 4
    if mod == 0:
        return [
            f"{b64}",
            f"{b64[1:]}=",
            f"{b64[2:]}==",
        ]
    elif mod == 1:
        return [
            f"{b64[0:-1]}",
            f"{b64[1:]}==",
            f"{b64[2:]}=",
        ]
    elif mod == 2:
        return [
            f"{b64}==",
            f"{b64[2:]}",
            f"{b64[3:]}=",
        ]
    elif mod == 3:
        return [
            f"{b64}=",
            f"{b64[1:]}==",
            f"{b64[3:]}",
        ]
    return ["internal error"]


def is_contain_text(garbage: bytes) -> bool:
    return search(b"[a-zA-Z0-9-]{4,}", garbage)


def bf_base64(encoded_str: str):
    text_found = False
    for candidate in gen_candidates(encoded_str):
        decoded = b64decode(candidate)
        # debug
        # print(f"{candidate} -> {decoded}")
        if is_contain_text(decoded):
            text_found = True
            print(f"text found in {candidate} -> {decoded}")
    if not text_found:
        print(f"Nothing found in {encoded_str}")


def main():
    argParser = ArgumentParser(
        description="Try different variations (kind of dump brute force) on inputs to try to recover texts from base64 inputs."
    )
    argParser.add_argument(
        "-c",
        "--color",
        dest="colors",
        action="store_true",
        help='Define the main field separator (Default: ",")',
    )
    argParser.add_argument("b64", help="Base64 encoded texts", nargs="+")
    args = argParser.parse_args()

    if args.colors:
        print("--color: To be implemented.")
    for b64 in args.b64:
        bf_base64(b64)


if __name__ == "__main__":
    main()
