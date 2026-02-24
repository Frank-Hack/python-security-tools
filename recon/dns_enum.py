#!/usr/bin/env python3
"""
dns_enum.py
-----------
Simple DNS enumeration tool.

Educational / authorized use only.
"""

from __future__ import annotations

import argparse
import dns.resolver
from typing import Iterable


DEFAULT_RECORDS = ["A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT"]


def resolve_dns_records(domain: str, record_types: Iterable[str]) -> None:
    resolver = dns.resolver.Resolver()

    print(f"[+] Enumerating DNS records for: {domain}\n")

    for record_type in record_types:
        try:
            answers = resolver.resolve(domain, record_type)
        except dns.resolver.NoAnswer:
            print(f"[-] No {record_type} record found.")
            continue
        except dns.resolver.NXDOMAIN:
            print("[!] Domain does not exist.")
            return
        except dns.resolver.Timeout:
            print("[!] DNS query timed out.")
            return
        except Exception as e:
            print(f"[!] Error resolving {record_type}: {e}")
            continue

        print(f"[+] {record_type} records:")
        for data in answers:
            print(f"    {data}")
        print()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="DNS enumeration helper (authorized/educational use)."
    )
    parser.add_argument(
        "-d", "--domain",
        required=True,
        help="Target domain (e.g., example.com)"
    )
    parser.add_argument(
        "-r", "--records",
        nargs="*",
        default=DEFAULT_RECORDS,
        help="DNS record types to query (default: common set)"
    )

    args = parser.parse_args()

    resolve_dns_records(args.domain, args.records)


if __name__ == "__main__":
    main()
