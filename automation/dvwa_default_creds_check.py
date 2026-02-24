#!/usr/bin/env python3
"""
dvwa_default_creds_check.py
---------------------------
Checks whether a DVWA instance accepts default credentials (admin/password).

Educational / authorized use only.
Use ONLY on systems you own or have explicit permission to test.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass

import requests
from requests.exceptions import RequestException


@dataclass
class Target:
    host: str
    port: int = 80
    https: bool = False
    timeout: int = 15


def build_url(t: Target) -> str:
    scheme = "https" if t.https else "http"
    return f"{scheme}://{t.host}:{t.port}/login.php"


def fetch_csrf_token(session: requests.Session, url: str, timeout: int) -> str | None:
    """
    Fetch DVWA login page and extract user_token (CSRF token).
    """
    try:
        r = session.get(url, verify=False, timeout=timeout)
        r.raise_for_status()
    except RequestException as exc:
        print(f"[!] Error fetching login page: {exc}")
        return None

    m = re.search(r"user_token'\s+value='([0-9a-f]+)'", r.text, re.IGNORECASE)
    if not m:
        print("[!] CSRF token not found. Is this DVWA login page?")
        return None
    return m.group(1)


def check_default_creds(t: Target) -> bool:
    """
    Returns True if DVWA accepts default creds (admin/password), otherwise False.
    """
    url = build_url(t)
    sess = requests.Session()

    token = fetch_csrf_token(sess, url, t.timeout)
    if not token:
        return False

    payload = {
        "username": "admin",
        "password": "password",
        "user_token": token,
        "Login": "Login",
    }

    try:
        r = sess.post(
            url,
            data=payload,
            allow_redirects=False,
            verify=False,
            timeout=t.timeout,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
    except RequestException as exc:
        print(f"[!] Error posting login form: {exc}")
        return False

    # DVWA typically redirects to index.php on success
    location = r.headers.get("Location", "")
    if r.status_code in (301, 302) and "index.php" in location:
        return True

    return False


def main() -> int:
    parser = argparse.ArgumentParser(
        description="DVWA default credentials checker (admin/password) - authorized use only."
    )
    parser.add_argument("--host", required=True, help="Target host/IP (e.g., 127.0.0.1)")
    parser.add_argument("--port", type=int, default=80, help="Target port (default: 80)")
    parser.add_argument("--https", action="store_true", help="Use HTTPS")
    parser.add_argument("--timeout", type=int, default=15, help="Timeout seconds (default: 15)")
    args = parser.parse_args()

    # Silence urllib3 warning when verify=False (common in labs/self-signed)
    requests.packages.urllib3.disable_warnings()  # type: ignore

    target = Target(host=args.host, port=args.port, https=args.https, timeout=args.timeout)

    ok = check_default_creds(target)
    if ok:
        print("[+] DVWA accepts DEFAULT credentials: admin/password")
        return 0
    else:
        print("[-] Default credentials not accepted (or target not reachable).")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
