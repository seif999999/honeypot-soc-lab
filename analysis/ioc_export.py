#!/usr/bin/env python3
"""
IOC export pipeline for Cowrie SSH honeypot logs.

Extracts attacker IPs, malicious download URLs, and file hashes from
Cowrie command fields, enriches the top 100 IPs via AbuseIPDB, and writes
two CSV files suitable for threat intelligence sharing or SIEM ingestion.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterator

import httpx

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_LOG_PATH = (
    Path(__file__).resolve().parent.parent
    / "honeypot"
    / "sample-logs"
    / "all-cowrie-logs.json"
)
OUTPUT_IPS_CSV = Path(__file__).resolve().parent.parent / "docs" / "ioc-ips.csv"
OUTPUT_URLS_CSV = Path(__file__).resolve().parent.parent / "docs" / "ioc-urls.csv"

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
TOP_IP_ENRICHMENT_LIMIT = 100
API_DELAY_SECONDS = 0.5
MALICIOUS_SCORE_THRESHOLD = 50

# wget/curl download targets
URL_PATTERN = re.compile(r"https?://[^\s\"'<>|;&]+", re.IGNORECASE)
WGET_CURL_PATTERN = re.compile(r"\b(wget|curl)\b", re.IGNORECASE)

# MD5 (32), SHA-1 (40), SHA-256 (64) hex digests in command strings
HASH_PATTERN = re.compile(
    r"\b([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b",
)

IP_CSV_COLUMNS = [
    "ip",
    "event_count",
    "country",
    "isp",
    "abuseipdb_score",
    "total_reports",
    "is_malicious",
]
URL_CSV_COLUMNS = ["url", "times_seen", "associated_ips"]


def resolve_log_path(path: Path) -> Path:
    """
    Resolve a Cowrie log path that may be a file or a wrapper directory.

    Args:
        path: User-supplied path to the log file or containing directory.

    Returns:
        Resolved path to the actual newline-delimited JSON log file.

    Raises:
        FileNotFoundError: If no readable log file can be located.
    """
    if path.is_file():
        return path
    if path.is_dir():
        nested = path / path.name
        if nested.is_file():
            return nested
        json_files = sorted(path.glob("*.json"))
        if len(json_files) == 1:
            return json_files[0]
    raise FileNotFoundError(f"Log file not found: {path}")


def iter_cowrie_events(log_path: Path) -> Iterator[dict[str, Any]]:
    """
    Yield parsed Cowrie events from a newline-delimited JSON log file.

    Malformed lines are skipped silently.

    Args:
        log_path: Path to the Cowrie JSON log file.

    Yields:
        Parsed event dictionaries.
    """
    with log_path.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def get_command_text(event: dict[str, Any]) -> str:
    """
    Extract shell command text from a Cowrie event.

    Args:
        event: Parsed Cowrie event dictionary.

    Returns:
        Command string, or empty string if not a command event.
    """
    if event.get("eventid") != "cowrie.command.input":
        return ""
    return str(event.get("input") or event.get("message") or "")


def extract_urls_from_command(command: str) -> list[str]:
    """
    Extract HTTP(S) URLs from wget/curl command strings.

    Args:
        command: Shell command text.

    Returns:
        List of URL strings found in the command.
    """
    if not WGET_CURL_PATTERN.search(command):
        return []
    return URL_PATTERN.findall(command)


def extract_hashes_from_command(command: str) -> list[str]:
    """
    Extract MD5, SHA-1, or SHA-256 hex digests from a command string.

    Args:
        command: Shell command text.

    Returns:
        List of hash strings (lowercase-normalized).
    """
    return [match.lower() for match in HASH_PATTERN.findall(command)]


def extract_iocs(
    log_path: Path,
) -> tuple[Counter[str], dict[str, int], dict[str, set[str]], set[str]]:
    """
    Stream the log file and collect IP, URL, and hash indicators.

    Args:
        log_path: Path to the Cowrie JSON log file.

    Returns:
        Tuple of:
            - ``ip_event_counts``: events per attacker IP
            - ``url_stats``: URL → occurrence count
            - ``url_ips``: URL → set of associated source IPs
            - ``file_hashes``: unique MD5/SHA digests found in command fields
    """
    ip_event_counts: Counter[str] = Counter()
    url_stats: Counter[str] = Counter()
    url_ips: dict[str, set[str]] = defaultdict(set)
    file_hashes: set[str] = set()

    for event in iter_cowrie_events(log_path):
        ip = str(event.get("src_ip") or "")
        if ip:
            ip_event_counts[ip] += 1

        command = get_command_text(event)
        if not command:
            continue

        for url in extract_urls_from_command(command):
            url_stats[url] += 1
            if ip:
                url_ips[url].add(ip)

        for digest in extract_hashes_from_command(command):
            file_hashes.add(digest)

    return ip_event_counts, dict(url_stats), dict(url_ips), file_hashes


def lookup_abuseipdb(
    client: httpx.Client,
    ip: str,
    api_key: str,
) -> dict[str, str]:
    """
    Query AbuseIPDB for reputation data on a single IP address.

    API failures are handled gracefully; missing fields are filled with ``N/A``.

    Args:
        client: Shared httpx client.
        ip: IPv4 or IPv6 address string.
        api_key: AbuseIPDB API key.

    Returns:
        Dictionary with ``country``, ``isp``, ``abuseipdb_score``, and
        ``total_reports`` keys.
    """
    na_result = {
        "country": "N/A",
        "isp": "N/A",
        "abuseipdb_score": "N/A",
        "total_reports": "N/A",
    }

    if not api_key:
        return na_result

    try:
        response = client.get(
            ABUSEIPDB_URL,
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=10.0,
        )
        response.raise_for_status()
        data = response.json().get("data", {})
        return {
            "country": str(data.get("countryCode") or "N/A"),
            "isp": str(data.get("isp") or "N/A"),
            "abuseipdb_score": str(data.get("abuseConfidenceScore", "N/A")),
            "total_reports": str(data.get("totalReports", "N/A")),
        }
    except (httpx.HTTPError, json.JSONDecodeError, KeyError):
        return na_result


def enrich_top_ips(
    top_ips: list[str],
    api_key: str,
) -> dict[str, dict[str, str]]:
    """
    Enrich the top-N IPs with AbuseIPDB reputation metadata.

    Args:
        top_ips: IP addresses to enrich, in priority order.
        api_key: AbuseIPDB API key.

    Returns:
        Mapping of IP → enrichment field dictionary.
    """
    enrichment: dict[str, dict[str, str]] = {}

    with httpx.Client() as client:
        for idx, ip in enumerate(top_ips, start=1):
            enrichment[ip] = lookup_abuseipdb(client, ip, api_key)
            if idx % 25 == 0:
                print(f"Enriched {idx}/{len(top_ips)} IPs via AbuseIPDB...")
            time.sleep(API_DELAY_SECONDS)

    return enrichment


def is_malicious(score_str: str) -> bool:
    """
    Determine whether an AbuseIPDB score qualifies as malicious.

    Args:
        score_str: Score string from AbuseIPDB (or ``N/A``).

    Returns:
        ``True`` if score is >= ``MALICIOUS_SCORE_THRESHOLD``, else ``False``.
    """
    try:
        return int(score_str) >= MALICIOUS_SCORE_THRESHOLD
    except (ValueError, TypeError):
        return False


def build_ip_rows(
    ip_event_counts: Counter[str],
    enrichment: dict[str, dict[str, str]],
) -> list[dict[str, str | bool]]:
    """
    Build CSV row dictionaries for all unique attacker IPs.

    Top-N IPs receive AbuseIPDB enrichment; all others get ``N/A`` fields.

    Args:
        ip_event_counts: Events per attacker IP.
        enrichment: AbuseIPDB data for enriched IPs.

    Returns:
        List of row dictionaries sorted by event count descending.
    """
    na_fields = {
        "country": "N/A",
        "isp": "N/A",
        "abuseipdb_score": "N/A",
        "total_reports": "N/A",
    }

    rows: list[dict[str, str | bool]] = []
    for ip, count in ip_event_counts.most_common():
        meta = enrichment.get(ip, na_fields)
        score = str(meta["abuseipdb_score"])
        rows.append(
            {
                "ip": ip,
                "event_count": str(count),
                "country": str(meta["country"]),
                "isp": str(meta["isp"]),
                "abuseipdb_score": score,
                "total_reports": str(meta["total_reports"]),
                "is_malicious": is_malicious(score),
            }
        )
    return rows


def build_url_rows(
    url_stats: dict[str, int],
    url_ips: dict[str, set[str]],
) -> list[dict[str, str]]:
    """
    Build CSV row dictionaries for all extracted malicious URLs.

    Args:
        url_stats: URL → occurrence count mapping.
        url_ips: URL → associated source IP set mapping.

    Returns:
        List of row dictionaries sorted by ``times_seen`` descending.
    """
    rows: list[dict[str, str]] = []
    for url, count in sorted(url_stats.items(), key=lambda item: item[1], reverse=True):
        ips = sorted(url_ips.get(url, set()))
        rows.append(
            {
                "url": url,
                "times_seen": str(count),
                "associated_ips": ";".join(ips),
            }
        )
    return rows


def write_csv(
    rows: list[dict[str, Any]],
    output_path: Path,
    fieldnames: list[str],
) -> None:
    """
    Write rows to a CSV file with the given column schema.

    Args:
        rows: Row dictionaries to write.
        output_path: Destination CSV path.
        fieldnames: Ordered list of column names.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Export Cowrie honeypot IOCs to CSV with AbuseIPDB enrichment.",
    )
    parser.add_argument(
        "--input",
        "-i",
        type=Path,
        default=DEFAULT_LOG_PATH,
        help="Path to Cowrie JSON log file (default: sample logs)",
    )
    parser.add_argument(
        "--key",
        "-k",
        type=str,
        default="",
        help="AbuseIPDB API key for enriching top 100 IPs",
    )
    return parser.parse_args()


def main() -> int:
    """
    Entry point: extract IOCs, enrich top IPs, and write CSV exports.

    Returns:
        Exit code ``0`` on success, ``1`` on error.
    """
    args = parse_args()

    try:
        log_path = resolve_log_path(args.input)
    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    api_key = args.key.strip()
    if not api_key:
        print(
            "Warning: no AbuseIPDB API key provided (--key). "
            "Enrichment fields will be set to N/A.",
            file=sys.stderr,
        )

    try:
        print(f"Reading log file: {log_path}")
        ip_event_counts, url_stats, url_ips, file_hashes = extract_iocs(log_path)

        top_ips = [ip for ip, _ in ip_event_counts.most_common(TOP_IP_ENRICHMENT_LIMIT)]
        print(f"Enriching top {len(top_ips)} IPs via AbuseIPDB...")
        enrichment = enrich_top_ips(top_ips, api_key)

        ip_rows = build_ip_rows(ip_event_counts, enrichment)
        url_rows = build_url_rows(url_stats, url_ips)

        write_csv(ip_rows, OUTPUT_IPS_CSV, IP_CSV_COLUMNS)
        write_csv(url_rows, OUTPUT_URLS_CSV, URL_CSV_COLUMNS)

        malicious_count = sum(1 for row in ip_rows if row["is_malicious"])

        print(f"\nIP export saved  : {OUTPUT_IPS_CSV} ({len(ip_rows):,} rows)")
        print(f"URL export saved : {OUTPUT_URLS_CSV} ({len(url_rows):,} rows)")
        print(f"\n--- IOC Export Summary ---")
        print(f"Total IPs exported      : {len(ip_rows):,}")
        print(f"Flagged malicious (>={MALICIOUS_SCORE_THRESHOLD}): {malicious_count:,}")
        print(f"Unique URLs found       : {len(url_rows):,}")
        print(f"Unique file hashes      : {len(file_hashes):,}")
        return 0

    except OSError as exc:
        print(f"Error reading log file: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"Unexpected error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
