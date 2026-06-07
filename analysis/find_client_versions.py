#!/usr/bin/env python3
"""
SSH client version analysis for Cowrie honeypot logs.

Extracts remote SSH client version strings from ``cowrie.client.version``
events and reports the most frequently observed client fingerprints.
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path
from typing import Any

try:
    from parse_logs import read_cowrie_logs
except ImportError:
    read_cowrie_logs = None  # type: ignore[misc, assignment]


CLIENT_VERSION_EVENT = "cowrie.client.version"
TOP_N = 20


def extract_client_versions(log_path: Path) -> Counter[str]:
    """
    Count SSH client version strings from Cowrie log events.

    Args:
        log_path: Path to the Cowrie JSON log file.

    Returns:
        Counter mapping version strings to occurrence counts.

    Raises:
        RuntimeError: If ``parse_logs`` is not importable.
        FileNotFoundError: If ``log_path`` does not exist.
    """
    if read_cowrie_logs is None:
        raise RuntimeError("parse_logs module required; run from analysis/ directory")

    version_counts: Counter[str] = Counter()

    for event in read_cowrie_logs(log_path):
        if event.get("eventid") != CLIENT_VERSION_EVENT:
            continue

        version = _get_version(event)
        if version:
            version_counts[version] += 1

    return version_counts


def _get_version(event: dict[str, Any]) -> str | None:
    """
    Extract the SSH client version string from an event.

    Args:
        event: Parsed Cowrie event dictionary.

    Returns:
        Version string, or ``None`` if not present.
    """
    version = event.get("version")
    if version is not None and str(version).strip():
        return str(version).strip()
    return None


def print_version_report(version_counts: Counter[str], top_n: int = TOP_N) -> None:
    """
    Print the top-N most common SSH client versions as a formatted table.

    Args:
        version_counts: Version string occurrence counter.
        top_n: Number of top entries to display.
    """
    total_events = sum(version_counts.values())
    unique_versions = len(version_counts)

    print("=" * 70)
    print("SSH Client Version Analysis — honeypot-soc-lab")
    print("=" * 70)
    print(f"Total version events  : {total_events:,}")
    print(f"Unique client versions: {unique_versions:,}")

    print(f"\nTop {top_n} SSH Client Versions:")
    print(f"{'Rank':<6} {'Count':>10}  {'Version':<50}")
    print("-" * 70)

    for rank, (version, count) in enumerate(version_counts.most_common(top_n), start=1):
        display = version if len(version) <= 50 else version[:47] + "..."
        print(f"{rank:<6} {count:>10,}  {display}")

    if not version_counts:
        print("(none)")

    print("=" * 70)


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Report top SSH client versions from Cowrie logs.",
    )
    parser.add_argument(
        "--input",
        "-i",
        type=Path,
        required=True,
        help="Path to Cowrie JSON log file",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=TOP_N,
        help=f"Number of top versions to show (default: {TOP_N})",
    )
    return parser.parse_args()


def main() -> int:
    """
    Entry point: extract client versions and print report.

    Returns:
        Exit code ``0`` on success, ``1`` on error.
    """
    args = parse_args()

    try:
        version_counts = extract_client_versions(args.input)
        print_version_report(version_counts, top_n=args.top)
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
