#!/usr/bin/env python3
"""
Geographic analysis of Cowrie attacker source IPs.

Maps unique source IP addresses from Cowrie logs to country-level
attribution using the ipinfo.io API. Requires an API token for
production use (free tier available).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any

# Reuse log reader from sibling module when run as part of the package
try:
    from parse_logs import read_cowrie_logs
except ImportError:
    read_cowrie_logs = None  # type: ignore[misc, assignment]


IPINFO_API_URL = "https://ipinfo.io/{ip}/json"
DEFAULT_RATE_LIMIT_SECONDS = 0.5  # Respect free-tier rate limits


def extract_unique_ips(log_path: Path) -> set[str]:
    """
    Collect unique attacker source IPs from Cowrie events.

    Args:
        log_path: Path to Cowrie JSON log file.

    Returns:
        Set of unique IP address strings.
    """
    if read_cowrie_logs is None:
        raise RuntimeError("parse_logs module required; run from analysis/ directory")

    ips: set[str] = set()
    for event in read_cowrie_logs(log_path):
        ip = event.get("src_ip") or event.get("peerIP")
        if ip:
            ips.add(str(ip))
    return ips


def lookup_ip(ip: str, token: str | None = None) -> dict[str, Any]:
    """
    Query ipinfo.io for geolocation metadata.

    Args:
        ip: IPv4 or IPv6 address string.
        token: Optional ipinfo.io API token (or set IPINFO_TOKEN env var).

    Returns:
        Parsed JSON response from ipinfo.io.
    """
    import requests
    url = IPINFO_API_URL.format(ip=ip)
    params = {"token": token} if token else {}
    try:
        response = requests.get(
            url,
            params=params,
            timeout=10,
            headers={"Accept": "application/json", "User-Agent": "honeypot-soc-lab/1.0"},
        )
        return response.json()
    except Exception as exc:
        return {"error": str(exc)}


def map_ips_to_countries(
    ips: set[str],
    token: str | None = None,
    rate_limit: float = DEFAULT_RATE_LIMIT_SECONDS,
) -> dict[str, dict[str, Any]]:
    """
    Resolve each IP to ipinfo.io metadata.

    Args:
        ips: Set of IP addresses to look up.
        token: ipinfo.io API token.
        rate_limit: Seconds to sleep between requests.

    Returns:
        Dictionary mapping IP → ipinfo response (includes ``country``,
        ``region``, ``city``, ``org``, etc.).
    """
    results: dict[str, dict[str, Any]] = {}
    for ip in sorted(ips):
        try:
            results[ip] = lookup_ip(ip, token=token)
        except urllib.error.HTTPError as exc:
            print(f"Warning: lookup failed for {ip}: {exc}", file=sys.stderr)
            results[ip] = {"error": str(exc)}
        time.sleep(rate_limit)
    return results


def count_by_country(ip_data: dict[str, dict[str, Any]]) -> Counter[str]:
    """
    Aggregate IP lookups by country code.

    Args:
        ip_data: Output from :func:`map_ips_to_countries`.

    Returns:
        Counter of country codes (or ``UNKNOWN`` when unavailable).
    """
    countries: Counter[str] = Counter()
    for ip, data in ip_data.items():
        country = data.get("country") or data.get("country_code") or "UNKNOWN"
        countries[country] += 1
    return countries


def print_geo_report(country_counts: Counter[str], total_ips: int) -> None:
    """
    Print country distribution to stdout.

    Args:
        country_counts: Counter from :func:`count_by_country`.
        total_ips: Total unique IPs analyzed.
    """
    print("=" * 60)
    print("Geographic Analysis — honeypot-soc-lab")
    print("=" * 60)
    print(f"Unique IPs analyzed: {total_ips}\n")
    print(f"{'Country':<12} {'IPs':>8} {'%':>8}")
    print("-" * 30)
    for country, count in country_counts.most_common():
        pct = (count / total_ips * 100) if total_ips else 0
        print(f"{country:<12} {count:>8} {pct:>7.1f}%")
    print("=" * 60)


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Map Cowrie attacker IPs to countries via ipinfo.io.",
    )
    parser.add_argument(
        "--input",
        "-i",
        type=Path,
        required=True,
        help="Path to cowrie.json",
    )
    parser.add_argument(
        "--token",
        default=os.environ.get("IPINFO_TOKEN"),
        help="ipinfo.io API token (default: IPINFO_TOKEN env var)",
    )
    parser.add_argument(
        "--rate-limit",
        type=float,
        default=DEFAULT_RATE_LIMIT_SECONDS,
        help="Seconds between API requests",
    )
    return parser.parse_args()


def main() -> int:
    """
    Entry point: extract IPs, geolocate, print country report.

    Returns:
        Exit code (0 on success).
    """
    args = parse_args()
    try:
        ips = extract_unique_ips(args.input)
    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    if not ips:
        print("No source IPs found in log file.", file=sys.stderr)
        return 0

    if not args.token:
        print(
            "Warning: no IPINFO_TOKEN set; ipinfo.io may rate-limit anonymous requests.",
            file=sys.stderr,
        )

    ip_data = map_ips_to_countries(ips, token=args.token, rate_limit=args.rate_limit)
    country_counts = count_by_country(ip_data)
    print_geo_report(country_counts, total_ips=len(ips))
    return 0


if __name__ == "__main__":
    sys.exit(main())
