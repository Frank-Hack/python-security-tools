#!/usr/bin/env python3
"""
cve_lookup.py
-------------
Vulnerability intelligence helper using NVD (NIST) CVE API v2.0.

Features:
- Search CVEs by keyword (service / product / term)
- Filter by CVSS minimum score
- Limit results
- Output as table / JSON / CSV
- Sort by CVSS (desc by default)

Educational / defensive use.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import requests
from rich.console import Console
from rich.table import Table


NVD_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"


@dataclass
class CVEItem:
    cve_id: str
    description: str
    cvss: Optional[float]
    severity: str
    url: str


def _pick_description(descriptions: List[Dict[str, Any]], lang_preference: str) -> str:
    if not descriptions:
        return "No disponible"
    # Try preferred language
    for d in descriptions:
        if d.get("lang") == lang_preference and d.get("value"):
            return d["value"].strip()
    # Fallback to English
    for d in descriptions:
        if d.get("lang") == "en" and d.get("value"):
            return d["value"].strip()
    # Any
    for d in descriptions:
        if d.get("value"):
            return d["value"].strip()
    return "No disponible"


def _extract_cvss(metrics: Dict[str, Any]) -> Tuple[Optional[float], str]:
    """
    Extract CVSS baseScore and severity from NVD metrics.
    Prioritize CVSS v3.1, then v3.0, then v2.0.
    """
    if not metrics:
        return None, "N/A"

    # v3.1
    v31 = metrics.get("cvssMetricV31")
    if isinstance(v31, list) and v31:
        data = v31[0].get("cvssData", {}) or {}
        score = data.get("baseScore")
        sev = data.get("baseSeverity", "N/A")
        return (float(score) if score is not None else None), str(sev)

    # v3.0
    v30 = metrics.get("cvssMetricV30")
    if isinstance(v30, list) and v30:
        data = v30[0].get("cvssData", {}) or {}
        score = data.get("baseScore")
        sev = data.get("baseSeverity", "N/A")
        return (float(score) if score is not None else None), str(sev)

    # v2.0
    v2 = metrics.get("cvssMetricV2")
    if isinstance(v2, list) and v2:
        data = v2[0].get("cvssData", {}) or {}
        score = data.get("baseScore")
        # v2 doesn't always provide severity; approximate buckets
        sev = "N/A"
        if score is not None:
            s = float(score)
            if s >= 9.0:
                sev = "CRITICAL"
            elif s >= 7.0:
                sev = "HIGH"
            elif s >= 4.0:
                sev = "MEDIUM"
            else:
                sev = "LOW"
        return (float(score) if score is not None else None), sev

    return None, "N/A"


def nvd_request(params: Dict[str, Any], timeout: int = 20, retries: int = 3, backoff: float = 2.0) -> Dict[str, Any]:
    """
    Calls NVD API with basic retry/backoff for rate limiting or transient errors.
    """
    headers = {
        "User-Agent": "python-security-tools (cve_lookup) - educational",
        "Accept": "application/json",
    }

    last_exc: Optional[Exception] = None
    for attempt in range(1, retries + 1):
        try:
            r = requests.get(NVD_ENDPOINT, params=params, headers=headers, timeout=timeout)
            # NVD can rate-limit; 429 indicates slow down
            if r.status_code == 429:
                sleep_s = backoff * attempt
                time.sleep(sleep_s)
                continue
            r.raise_for_status()
            return r.json()
        except Exception as exc:
            last_exc = exc
            time.sleep(backoff * attempt)

    raise RuntimeError(f"Failed to fetch NVD data after {retries} retries: {last_exc}")


def search_cves(keyword: str, limit: int, lang: str, min_cvss: Optional[float], sort_desc: bool) -> List[CVEItem]:
    # NVD uses pagination; we keep it simple but reliable.
    results: List[CVEItem] = []
    start_index = 0
    page_size = min(2000, max(1, limit))  # NVD allows up to 2000 per request

    while len(results) < limit:
        params = {
            "keywordSearch": keyword,
            "startIndex": start_index,
            "resultsPerPage": page_size,
        }
        data = nvd_request(params=params)

        vulns = data.get("vulnerabilities") or []
        if not vulns:
            break

        for v in vulns:
            cve = (v.get("cve") or {})
            cve_id = cve.get("id", "N/A")
            desc = _pick_description(cve.get("descriptions") or [], lang_preference=lang)
            metrics = cve.get("metrics") or {}
            score, sev = _extract_cvss(metrics)

            if min_cvss is not None:
                if score is None or score < min_cvss:
                    continue

            results.append(
                CVEItem(
                    cve_id=cve_id,
                    description=desc,
                    cvss=score,
                    severity=sev,
                    url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                )
            )
            if len(results) >= limit:
                break

        # next page
        start_index += len(vulns)

        total = data.get("totalResults")
        if isinstance(total, int) and start_index >= total:
            break

    # sort
    def key_fn(x: CVEItem) -> float:
        return x.cvss if x.cvss is not None else -1.0

    results.sort(key=key_fn, reverse=sort_desc)
    return results[:limit]


def print_table(items: List[CVEItem]) -> None:
    console = Console()
    table = Table(title="CVE Results (NVD)")
    table.add_column("CVE", style="cyan", no_wrap=True)
    table.add_column("CVSS", style="green", no_wrap=True)
    table.add_column("Severity", style="magenta", no_wrap=True)
    table.add_column("Description", overflow="fold")
    table.add_column("URL", style="blue", overflow="fold")

    for it in items:
        cvss_str = f"{it.cvss:.1f}" if it.cvss is not None else "N/A"
        table.add_row(it.cve_id, cvss_str, it.severity, it.description, it.url)

    console.print(table)


def export_csv(items: List[CVEItem], path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["cve_id", "cvss", "severity", "description", "url"])
        for it in items:
            w.writerow([it.cve_id, it.cvss if it.cvss is not None else "", it.severity, it.description, it.url])


def export_json(items: List[CVEItem], path: str) -> None:
    payload = [
        {
            "cve_id": it.cve_id,
            "cvss": it.cvss,
            "severity": it.severity,
            "description": it.description,
            "url": it.url,
        }
        for it in items
    ]
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)


def main() -> int:
    p = argparse.ArgumentParser(description="CVE lookup tool (NVD API) - vulnerability intelligence.")
    p.add_argument("-k", "--keyword", required=True, help="Keyword/service/product to search (e.g., apache, openssl, wordpress)")
    p.add_argument("-n", "--limit", type=int, default=20, help="Max CVEs to return (default: 20)")
    p.add_argument("--min-cvss", type=float, default=None, help="Filter: only CVEs with CVSS >= value")
    p.add_argument("--lang", default="es", choices=["es", "en"], help="Preferred description language (default: es)")
    p.add_argument("--asc", action="store_true", help="Sort by CVSS ascending (default: descending)")
    p.add_argument("--json-out", default=None, help="Export results to JSON file")
    p.add_argument("--csv-out", default=None, help="Export results to CSV file")

    args = p.parse_args()
    if args.limit < 1:
        print("[!] limit must be >= 1")
        return 2

    try:
        items = search_cves(
            keyword=args.keyword,
            limit=args.limit,
            lang=args.lang,
            min_cvss=args.min_cvss,
            sort_desc=(not args.asc),
        )
    except Exception as e:
        print(f"[!] Error: {e}")
        return 3

    if not items:
        print("[!] No CVEs found.")
        return 0

    print_table(items)

    if args.json_out:
        export_json(items, args.json_out)
        print(f"[+] JSON exported to: {args.json_out}")

    if args.csv_out:
        export_csv(items, args.csv_out)
        print(f"[+] CSV exported to: {args.csv_out}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
