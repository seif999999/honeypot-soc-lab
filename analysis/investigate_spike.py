#!/usr/bin/env python3
"""
Hourly spike investigation for Cowrie SSH honeypot logs.

Groups all events by UTC hour, identifies the busiest periods in the
collection window, and drills into the peak hour with event-type and
source-IP breakdowns to support root-cause analysis.
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from parse_logs import read_cowrie_logs
except ImportError:
    read_cowrie_logs = None  # type: ignore[misc, assignment]


TOP_HOURS = 10
TOP_IPS = 20


def parse_timestamp(raw: str) -> datetime | None:
    """
    Parse a Cowrie ISO-8601 timestamp into a timezone-aware datetime.

    Args:
        raw: Timestamp string (e.g. ``2026-05-26T00:00:33.948979Z``).

    Returns:
        UTC ``datetime`` object, or ``None`` if parsing fails.
    """
    if not raw:
        return None
    normalized = raw.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(normalized).astimezone(timezone.utc)
    except ValueError:
        return None


def truncate_to_hour(ts: datetime) -> datetime:
    """Truncate a datetime to the start of its UTC hour."""
    return ts.replace(minute=0, second=0, microsecond=0)


def aggregate_by_hour(
    log_path: Path,
) -> tuple[
    Counter[datetime],
    dict[datetime, Counter[str]],
    dict[datetime, Counter[str]],
]:
    """
    Group Cowrie events by UTC hour with event-type and IP sub-counts.

    Args:
        log_path: Path to the Cowrie JSON log file.

    Returns:
        Tuple of ``(hourly_totals, hourly_event_types, hourly_ips)``.

    Raises:
        RuntimeError: If ``parse_logs`` is not importable.
        FileNotFoundError: If ``log_path`` does not exist.
    """
    if read_cowrie_logs is None:
        raise RuntimeError("parse_logs module required; run from analysis/ directory")

    hourly_totals: Counter[datetime] = Counter()
    hourly_event_types: dict[datetime, Counter[str]] = defaultdict(Counter)
    hourly_ips: dict[datetime, Counter[str]] = defaultdict(Counter)

    for event in read_cowrie_logs(log_path):
        ts = parse_timestamp(str(event.get("timestamp") or ""))
        if ts is None:
            continue

        hour_key = truncate_to_hour(ts)
        hourly_totals[hour_key] += 1

        event_type = str(event.get("eventid") or "unknown")
        hourly_event_types[hour_key][event_type] += 1

        src_ip = event.get("src_ip")
        if src_ip:
            hourly_ips[hour_key][str(src_ip)] += 1

    return hourly_totals, dict(hourly_event_types), dict(hourly_ips)


def format_hour(hour: datetime) -> str:
    """Format an hour bucket for display."""
    return hour.strftime("%Y-%m-%d %H:00 UTC")


def print_spike_report(
    hourly_totals: Counter[datetime],
    hourly_event_types: dict[datetime, Counter[str]],
    hourly_ips: dict[datetime, Counter[str]],
    top_hours: int = TOP_HOURS,
    top_ips: int = TOP_IPS,
) -> None:
    """
    Print top busiest hours and a detailed breakdown of the peak hour.

    Args:
        hourly_totals: Total events per UTC hour.
        hourly_event_types: Event-type counts per UTC hour.
        hourly_ips: Source-IP counts per UTC hour.
        top_hours: Number of busiest hours to list.
        top_ips: Number of top source IPs to show for the peak hour.
    """
    if not hourly_totals:
        print("No events with valid timestamps found.", file=sys.stderr)
        return

    total_events = sum(hourly_totals.values())
    collection_hours = len(hourly_totals)
    busiest = hourly_totals.most_common(1)[0]
    peak_hour, peak_count = busiest

    print("=" * 70)
    print("Hourly Spike Investigation — honeypot-soc-lab")
    print("=" * 70)
    print(f"Total events parsed     : {total_events:,}")
    print(f"Hours with activity     : {collection_hours:,}")
    print(f"Peak hour               : {format_hour(peak_hour)} ({peak_count:,} events)")

    print(f"\nTop {top_hours} Busiest Hours:")
    print(f"{'Rank':<6} {'Hour (UTC)':<24} {'Events':>10} {'% of Total':>12}")
    print("-" * 70)

    for rank, (hour, count) in enumerate(hourly_totals.most_common(top_hours), start=1):
        pct = (count / total_events * 100) if total_events else 0.0
        print(f"{rank:<6} {format_hour(hour):<24} {count:>10,} {pct:>11.1f}%")

    event_types = hourly_event_types.get(peak_hour, Counter())
    ip_counts = hourly_ips.get(peak_hour, Counter())

    print(f"\nPeak Hour Breakdown — {format_hour(peak_hour)}")
    print("-" * 70)
    print(f"Total events in hour  : {peak_count:,}")
    print(f"Unique event types    : {len(event_types):,}")
    print(f"Unique source IPs     : {len(ip_counts):,}")

    print("\nEvent Types:")
    print(f"{'Event ID':<40} {'Count':>10} {'% of Hour':>12}")
    print("-" * 70)
    for event_type, count in event_types.most_common():
        pct = (count / peak_count * 100) if peak_count else 0.0
        display = event_type if len(event_type) <= 40 else event_type[:37] + "..."
        print(f"{display:<40} {count:>10,} {pct:>11.1f}%")

    print(f"\nTop {top_ips} Source IPs:")
    print(f"{'Rank':<6} {'Source IP':<18} {'Events':>10} {'% of Hour':>12}")
    print("-" * 70)
    if ip_counts:
        for rank, (ip, count) in enumerate(ip_counts.most_common(top_ips), start=1):
            pct = (count / peak_count * 100) if peak_count else 0.0
            print(f"{rank:<6} {ip:<18} {count:>10,} {pct:>11.1f}%")
    else:
        print("(none)")

    print("=" * 70)


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Investigate hourly attack spikes in Cowrie honeypot logs.",
    )
    parser.add_argument(
        "--input",
        "-i",
        type=Path,
        required=True,
        help="Path to Cowrie JSON log file",
    )
    parser.add_argument(
        "--top-hours",
        type=int,
        default=TOP_HOURS,
        help=f"Number of busiest hours to list (default: {TOP_HOURS})",
    )
    parser.add_argument(
        "--top-ips",
        type=int,
        default=TOP_IPS,
        help=f"Number of top IPs to show for peak hour (default: {TOP_IPS})",
    )
    return parser.parse_args()


def main() -> int:
    """
    Entry point: aggregate events by hour and print spike investigation report.

    Returns:
        Exit code ``0`` on success, ``1`` on error.
    """
    args = parse_args()

    try:
        hourly_totals, hourly_event_types, hourly_ips = aggregate_by_hour(args.input)
        print_spike_report(
            hourly_totals,
            hourly_event_types,
            hourly_ips,
            top_hours=args.top_hours,
            top_ips=args.top_ips,
        )
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
