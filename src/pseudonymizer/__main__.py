"""Command-line interface for pseudonymizing lines from stdin."""

from __future__ import annotations

import argparse
import os
import re
import sys

from pseudonymizer import PseudoError, Pseudonymizer

_DOMAIN_RE = re.compile(r"^[a-z0-9_]{1,32}$")


def main(argv: list[str] | None = None) -> int:
    """Run the CLI; return 0 on success, 1 for invalid values, 2 for usage/missing key."""
    parser = argparse.ArgumentParser(
        prog="pseudonymizer", description="Pseudonymize UTF-8 lines from stdin."
    )
    parser.add_argument(
        "--key-env", required=True, help="environment variable holding the key as hex"
    )
    parser.add_argument("--key-id", required=True, help="key id for the supplied key")
    parser.add_argument("--domain", required=True, help="domain for pseudonymization")

    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code) if isinstance(exc.code, int) else 2

    env_name = args.key_env
    key_hex = os.environ.get(env_name)
    if key_hex is None:
        print("missing key", file=sys.stderr)
        return 2
    try:
        key_bytes = bytes.fromhex(key_hex)
    except ValueError:
        print("invalid key", file=sys.stderr)
        return 2

    try:
        pseudonymizer = Pseudonymizer({args.key_id: key_bytes}, active_key_id=args.key_id)
    except PseudoError as exc:
        print(exc, file=sys.stderr)
        return 2

    if not _DOMAIN_RE.fullmatch(args.domain):
        print("invalid domain", file=sys.stderr)
        return 2

    for raw_line in sys.stdin:
        value = raw_line.rstrip("\r\n")
        if not value:
            continue
        try:
            token = pseudonymizer.pseudonymize(value, domain=args.domain)
        except PseudoError as exc:
            print(exc, file=sys.stderr)
            return 1
        print(token)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
