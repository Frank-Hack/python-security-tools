#!/usr/bin/env python3
import os
import argparse
from dotenv import load_dotenv
import shodan

from recon.shodan_client import ShodanSearch


DEFAULT_UA_NOTE = "Uses SHODAN_API_KEY from environment or .env (local only)."


def mask_key(k: str) -> str:
    if not k:
        return ""
    k = k.strip()
    if len(k) <= 6:
        return "***"
    return f"{k[:3]}***{k[-3:]}"


def print_match(i: int, match: dict) -> None:
    ip = match.get("ip_str", "N/A")
    hostnames = match.get("hostnames") or []
    org = match.get("org", "N/A")
    port = match.get("port", "N/A")
    product = match.get("product", "N/A")
    transport = match.get("transport", "N/A")

    loc = match.get("location") or {}
    country = loc.get("country_name", "N/A")
    city = loc.get("city", "N/A")

    print(f"\nResult {i}")
    print(f"IP: {ip}")
    print(f"Port: {port}/{transport}")
    print(f"Org: {org}")
    print(f"Product: {product}")
    print(f"Hostnames: {', '.join(hostnames) if hostnames else 'N/A'}")
    print(f"Location: {city}, {country}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Shodan OSINT search helper (authorized/educational use)."
    )
    parser.add_argument("-q", "--query", required=True, help="Shodan query (e.g., http.title:dvwa)")
    parser.add_argument("-p", "--page", type=int, default=1, help="Results page (default: 1)")
    parser.add_argument("-n", "--limit", type=int, default=10, help="Max results to display (default: 10)")
    parser.add_argument("--no-env", action="store_true", help="Do not load .env (only OS env vars)")
    args = parser.parse_args()

    if not args.no_env:
        load_dotenv()  # loads local .env if present

    api_key = os.getenv("SHODAN_API_KEY")
    if not api_key:
        print("[!] Missing SHODAN_API_KEY in environment.")
        print("    Tip: create a local .env with SHODAN_API_KEY=... (do NOT commit it).")
        return 2

    try:
        client = ShodanSearch(api_key)
        results = client.search(args.query, page=args.page)
    except ValueError as e:
        print(f"[!] Input error: {e}")
        return 2
    except shodan.APIError as e:
        print(f"[!] Shodan API error: {e}")
        print(f"    (Using key: {mask_key(api_key)})")
        return 3
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
        return 4

    matches = results.get("matches") or []
    total = results.get("total", 0)

    print(f"[+] Query: {args.query}")
    print(f"[+] Total results: {total}")
    print(f"[+] Showing up to {min(args.limit, len(matches))} matches from page {args.page}")

    if not matches:
        print("[!] No matches returned.")
        return 0

    for i, m in enumerate(matches[: args.limit], start=1):
        print_match(i, m)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
