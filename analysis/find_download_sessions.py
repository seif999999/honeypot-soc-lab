#!/usr/bin/env python3
"""
Recent malware download session analysis for Cowrie honeypot logs.

Extracts ``cowrie.session.file_download`` events and displays the most
recent download attempts with timestamp, source IP, and target URL.
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    from parse_logs import read_cowrie_logs
except ImportError:
    read_cowrie_logs = None  # type: ignore[misc, assignment]


FILE_DOWNLOAD_EVENT = "cowrie.session.file_download"
RECENT_LIMIT = 20


@dataclass
class DownloadRecord:
    """A single file download event from Cowrie logs."""

    timestamp: str
    src_ip: str
    url: str


def extract_download_records(log_path: Path) -> list[DownloadRecord]:
    """
    Collect file download events from Cowrie logs.

    Args:
        log_path: Path to the Cowrie JSON log file.

    Returns:
        List of download records in log file order.

    Raises:
        RuntimeError: If ``parse_logs`` is not importable.
        FileNotFoundError: If ``log_path`` does not exist.
    """
    if read_cowrie_logs is None:
        raise RuntimeError("parse_logs module required; run from analysis/ directory")

    records: list[DownloadRecord] = []

    for event in read_cowrie_logs(log_path):
        if event.get("eventid") != FILE_DOWNLOAD_EVENT:
            continue

        url = _get_url(event)
        if not url:
            continue

        records.append(
            DownloadRecord(
                timestamp=str(event.get("timestamp") or "unknown"),
                src_ip=str(event.get("src_ip") or "unknown"),
                url=url,
            )
        )

    return records


def _get_url(event: dict[str, Any]) -> str | None:
    """
    Extract a download URL from a file download event.

    Args:
        event: Parsed Cowrie event dictionary.

    Returns:
        URL string, or ``None`` if not present.
    """
    url = event.get("url")
    if url is not None and str(url).strip():
        return str(url).strip()
    return None


def print_recent_downloads(records: list[DownloadRecord], limit: int = RECENT_LIMIT) -> None:
    """
    Print the most recent download attempts.

    Args:
        records: All download records extracted from the log.
        limit: Maximum number of recent entries to display.
    """
    recent = sorted(records, key=lambda r: r.timestamp, reverse=True)[:limit]

    print("=" * 80)
    print("Recent Download Sessions — honeypot-soc-lab")
    print("=" * 80)
    print(f"Total download attempts with URL : {len(records):,}")
    print(f"Showing most recent              : {min(limit, len(recent))}")

    print(f"\n{'Timestamp':<28} {'Source IP':<18} {'URL'}")
    print("-" * 80)

    if recent:
        for record in recent:
            url_display = record.url if len(record.url) <= 40 else record.url[:37] + "..."
            print(f"{record.timestamp:<28} {record.src_ip:<18} {url_display}")
    else:
        print("(none)")

    print("=" * 80)


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Show recent malware download attempts from Cowrie logs.",
    )
    parser.add_argument(
        "--input",
        "-i",
        type=Path,
        required=True,
        help="Path to Cowrie JSON log file",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=RECENT_LIMIT,
        help=f"Number of recent downloads to show (default: {RECENT_LIMIT})",
    )
    return parser.parse_args()


def main() -> int:
    """
    Entry point: extract download records and print recent attempts.

    Returns:
        Exit code ``0`` on success, ``1`` on error.
    """
    args = parse_args()

    try:
        records = extract_download_records(args.input)
        print_recent_downloads(records, limit=args.limit)
        return 0
    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"Error reading log file: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
