#!/usr/bin/env python3
"""
Malware download URL analysis for Cowrie honeypot logs.

Extracts unique download URLs from ``cowrie.session.file_download`` events
and reports total download attempts versus distinct URL count.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

try:
    from parse_logs import read_cowrie_logs
except ImportError:
    read_cowrie_logs = None  # type: ignore[misc, assignment]


FILE_DOWNLOAD_EVENT = "cowrie.session.file_download"


def extract_download_urls(log_path: Path) -> tuple[list[str], set[str]]:
    """
    Collect download URLs from Cowrie file download events.

    Args:
        log_path: Path to the Cowrie JSON log file.

    Returns:
        Tuple of ``(all_urls, unique_urls)`` where ``all_urls`` contains
        one entry per download attempt with a URL field.

    Raises:
        RuntimeError: If ``parse_logs`` is not importable.
        FileNotFoundError: If ``log_path`` does not exist.
    """
    if read_cowrie_logs is None:
        raise RuntimeError("parse_logs module required; run from analysis/ directory")

    all_urls: list[str] = []
    unique_urls: set[str] = set()

    for event in read_cowrie_logs(log_path):
        if event.get("eventid") != FILE_DOWNLOAD_EVENT:
            continue

        url = _get_url(event)
        if url:
            all_urls.append(url)
            unique_urls.add(url)

    return all_urls, unique_urls


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


def print_download_report(all_urls: list[str], unique_urls: set[str]) -> None:
    """
    Print download statistics and alphabetically sorted unique URLs.

    Args:
        all_urls: All URL values from download events (with duplicates).
        unique_urls: Set of distinct URL strings.
    """
    print("=" * 60)
    print("Download URL Analysis — honeypot-soc-lab")
    print("=" * 60)
    print(f"Total download attempts : {len(all_urls):,}")
    print(f"Unique URLs found       : {len(unique_urls):,}")

    print("\nUnique URLs (alphabetical):")
    print("-" * 60)
    if unique_urls:
        for url in sorted(unique_urls):
            print(url)
    else:
        print("(none)")
    print("=" * 60)


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="List unique malware download URLs from Cowrie logs.",
    )
    parser.add_argument(
        "--input",
        "-i",
        type=Path,
        required=True,
        help="Path to Cowrie JSON log file",
    )
    return parser.parse_args()


def main() -> int:
    """
    Entry point: extract download URLs and print report.

    Returns:
        Exit code ``0`` on success, ``1`` on error.
    """
    args = parse_args()

    try:
        all_urls, unique_urls = extract_download_urls(args.input)
        print_download_report(all_urls, unique_urls)
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
