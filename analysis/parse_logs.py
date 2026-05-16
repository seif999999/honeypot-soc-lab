#!/usr/bin/env python3
"""
Cowrie JSON log parser for honeypot-soc-lab.

Reads newline-delimited JSON logs produced by the Cowrie honeypot,
extracts structured events, and prints a high-level summary suitable
for SOC triage and threat reporting.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterator


def read_cowrie_logs(log_path: Path) -> Iterator[dict[str, Any]]:
    """
    Yield parsed JSON objects from a Cowrie log file.

    Cowrie writes one JSON object per line to ``cowrie.json``. Malformed
    lines are skipped with a warning on stderr.

    Args:
        log_path: Path to the Cowrie JSON log file.

    Yields:
        Parsed event dictionaries.

    Raises:
        FileNotFoundError: If ``log_path`` does not exist.
    """
    if not log_path.is_file():
        raise FileNotFoundError(f"Log file not found: {log_path}")

    with log_path.open(encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as exc:
                print(
                    f"Warning: skipping invalid JSON at line {line_no}: {exc}",
                    file=sys.stderr,
                )


def extract_events(events: Iterator[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Materialize events into a list for repeated analysis passes.

    For very large logs, consider streaming-only workflows instead of
    calling this function.

    Args:
        events: Iterator of Cowrie event dictionaries.

    Returns:
        List of all events.
    """
    return list(events)


def summarize_events(events: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Build aggregate statistics from Cowrie events.

    Args:
        events: List of parsed Cowrie event dictionaries.

    Returns:
        Summary dictionary with counts by event type, unique IPs, and
        time range (if timestamps are present).
    """
    event_ids: Counter[str] = Counter()
    source_ips: set[str] = set()
    timestamps: list[str] = []

    for event in events:
        event_id = event.get("eventid", "unknown")
        event_ids[event_id] += 1

        src_ip = event.get("src_ip") or event.get("peerIP")
        if src_ip:
            source_ips.add(str(src_ip))

        ts = event.get("timestamp")
        if ts:
            timestamps.append(str(ts))

    summary: dict[str, Any] = {
        "total_events": len(events),
        "unique_source_ips": len(source_ips),
        "events_by_type": dict(event_ids.most_common()),
        "top_event_types": event_ids.most_common(10),
    }

    if timestamps:
        summary["first_seen"] = min(timestamps)
        summary["last_seen"] = max(timestamps)

    return summary


def print_summary(summary: dict[str, Any]) -> None:
    """
    Print a human-readable summary to stdout.

    Args:
        summary: Output from :func:`summarize_events`.
    """
    print("=" * 60)
    print("Cowrie Log Summary — honeypot-soc-lab")
    print("=" * 60)
    print(f"Total events:        {summary['total_events']}")
    print(f"Unique source IPs:   {summary['unique_source_ips']}")

    if "first_seen" in summary:
        print(f"First seen:          {summary['first_seen']}")
        print(f"Last seen:           {summary['last_seen']}")

    print("\nEvents by type:")
    for event_id, count in summary.get("top_event_types", []):
        print(f"  {event_id:<40} {count:>8}")
    print("=" * 60)


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Parse Cowrie JSON logs and print a summary.",
    )
    parser.add_argument(
        "--input",
        "-i",
        type=Path,
        required=True,
        help="Path to cowrie.json (or exported log file)",
    )
    return parser.parse_args()


def main() -> int:
    """
    Entry point: read logs, summarize, and print results.

    Returns:
        Exit code (0 on success, non-zero on error).
    """
    args = parse_args()
    try:
        events = extract_events(read_cowrie_logs(args.input))
        summary = summarize_events(events)
        print_summary(summary)
    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
