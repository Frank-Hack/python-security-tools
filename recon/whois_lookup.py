#!/usr/bin/env python3
"""
whois_lookup.py
---------------
Simple WHOIS lookup tool.

Educational / authorized use only.
"""

from __future__ import annotations

import argparse
import whois


def lookup(domain: str) -> None:
    try:
        data = whois.whois(domain)
    except Exception as e:
        print(f"[!] WHOIS lookup failed: {e}")
        return

    if not data:
        print("[!] No WHOIS data returned.")
        return

    print(f"[+] WHOIS information for: {domain}\n")

    fields = [
        "domain_name",
        "registrar",
        "creation_date",
        "expiration_date",
        "name_servers",
        "emails",
        "country",
    ]

    for field in fields:
        value = getattr(data, field, None)
        if value:
            print(f"{field}: {value}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="WHOIS lookup helper (authorized/educational use)."
    )
    parser.add_argument(
        "-d", "--domain",
        required=True,
        help="Target domain (e.g., example.com)"
    )

    args = parser.parse_args()
    lookup(args.domain)


if __name__ == "__main__":
    main()
