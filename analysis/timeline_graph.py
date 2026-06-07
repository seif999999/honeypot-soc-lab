#!/usr/bin/env python3
"""
Attack volume timeline charts for Cowrie SSH honeypot logs.

Streams newline-delimited Cowrie JSON logs, buckets events by calendar day
and by hour-of-day (UTC), and produces publication-quality bar charts for
SOC reporting and portfolio documentation.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

import matplotlib.dates as mdates
import matplotlib.pyplot as plt

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_LOG_PATH = (
    Path(__file__).resolve().parent.parent
    / "honeypot"
    / "sample-logs"
    / "all-cowrie-logs.json"
)
OUTPUT_DAILY = (
    Path(__file__).resolve().parent.parent / "docs" / "attack-timeline-daily.png"
)
OUTPUT_HOURLY = (
    Path(__file__).resolve().parent.parent / "docs" / "attack-timeline-hourly.png"
)

DAILY_BAR_COLOR = "#1a3a5c"
HOURLY_BAR_COLOR = "#8b0000"
AVERAGE_LINE_COLOR = "red"
GRID_COLOR = "#cccccc"
GRID_ALPHA = 0.3
FIGURE_DPI = 300


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


def collect_timestamps(log_path: Path) -> list[datetime]:
    """
    Extract valid UTC timestamps from every event in the log file.

    Args:
        log_path: Path to the Cowrie JSON log file.

    Returns:
        List of parsed UTC datetime objects.
    """
    timestamps: list[datetime] = []
    for event in iter_cowrie_events(log_path):
        ts = parse_timestamp(str(event.get("timestamp") or ""))
        if ts is not None:
            timestamps.append(ts)
    return timestamps


def bucket_by_day(timestamps: list[datetime]) -> Counter[datetime]:
    """
    Count events per calendar day (UTC midnight boundary).

    Args:
        timestamps: List of event timestamps.

    Returns:
        Counter keyed by date at midnight UTC.
    """
    daily: Counter[datetime] = Counter()
    for ts in timestamps:
        day_key = ts.replace(hour=0, minute=0, second=0, microsecond=0)
        daily[day_key] += 1
    return daily


def bucket_by_hour_of_day(timestamps: list[datetime]) -> Counter[int]:
    """
    Count events per hour-of-day (0–23 UTC), aggregated across all days.

    Args:
        timestamps: List of event timestamps.

    Returns:
        Counter keyed by hour integer (0–23).
    """
    hourly: Counter[int] = Counter()
    for ts in timestamps:
        hourly[ts.hour] += 1
    return hourly


def plot_daily_chart(daily_counts: Counter[datetime], output_path: Path) -> None:
    """
    Render a daily attack volume bar chart with an average reference line.

    Args:
        daily_counts: Event counts keyed by calendar day.
        output_path: Destination PNG path.
    """
    sorted_days = sorted(daily_counts.keys())
    values = [daily_counts[day] for day in sorted_days]
    daily_average = 44729

    fig, ax = plt.subplots(figsize=(14, 6))
    ax.bar(sorted_days, values, color=DAILY_BAR_COLOR, width=0.8, edgecolor="none")

    ax.axhline(
        y=daily_average,
        color=AVERAGE_LINE_COLOR,
        linestyle="--",
        linewidth=1.5,
        label=f"Daily average ({daily_average:,.0f})",
    )

    ax.set_title("SSH Honeypot — Daily Attack Volume (May 2026)", fontsize=14, fontweight="bold")
    ax.set_xlabel("Date")
    ax.set_ylabel("Attack Events")
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%Y-%m-%d"))
    ax.grid(axis="y", color=GRID_COLOR, alpha=GRID_ALPHA)
    ax.legend(loc="upper right")

    plt.setp(ax.get_xticklabels(), rotation=45, ha="right")
    fig.tight_layout()

    output_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output_path, dpi=FIGURE_DPI)
    plt.close(fig)


def plot_hourly_chart(hourly_counts: Counter[int], output_path: Path) -> None:
    """
    Render a bar chart of total attack events by hour-of-day (UTC).

    Args:
        hourly_counts: Event counts keyed by hour (0–23).
        output_path: Destination PNG path.
    """
    hours = list(range(24))
    values = [hourly_counts.get(h, 0) for h in hours]

    fig, ax = plt.subplots(figsize=(14, 6))
    ax.bar(hours, values, color=HOURLY_BAR_COLOR, width=0.8, edgecolor="none")

    ax.set_title(
        "SSH Honeypot — Attack Volume by Hour of Day (UTC)",
        fontsize=14,
        fontweight="bold",
    )
    ax.set_xlabel("Hour (UTC)")
    ax.set_ylabel("Total Attack Events")
    ax.set_xticks(hours)
    ax.set_xticklabels([f"{h:02d}" for h in hours])

    fig.tight_layout()

    output_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output_path, dpi=FIGURE_DPI)
    plt.close(fig)


def print_summary(
    daily_counts: Counter[datetime],
    hourly_counts: Counter[int],
    total_events: int,
) -> None:
    """
    Print a text summary of attack volume statistics.

    Args:
        daily_counts: Event counts keyed by calendar day.
        hourly_counts: Event counts keyed by hour-of-day (0–23).
        total_events: Total number of parsed events.
    """
    num_days = len(daily_counts)
    avg_per_day = total_events / num_days if num_days else 0.0

    peak_day, peak_day_count = daily_counts.most_common(1)[0] if daily_counts else (None, 0)
    peak_hour, peak_hour_count = hourly_counts.most_common(1)[0] if hourly_counts else (0, 0)
    quietest_hour, quietest_hour_count = (
        hourly_counts.most_common()[-1] if hourly_counts else (0, 0)
    )

    print("\n--- Attack Volume Summary ---")
    print(f"Total events parsed : {total_events:,}")
    print(f"Collection days     : {num_days}")
    print(f"Average per day     : {avg_per_day:,.1f}")
    if peak_day:
        print(f"Peak day            : {peak_day.strftime('%Y-%m-%d')} ({peak_day_count:,} events)")
    print(f"Peak hour (UTC)     : {peak_hour:02d}:00 ({peak_hour_count:,} events)")
    print(f"Quietest hour (UTC) : {quietest_hour:02d}:00 ({quietest_hour_count:,} events)")


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Generate daily and hourly attack volume charts from Cowrie logs.",
    )
    parser.add_argument(
        "--input",
        "-i",
        type=Path,
        default=DEFAULT_LOG_PATH,
        help="Path to Cowrie JSON log file (default: sample logs)",
    )
    return parser.parse_args()


def main() -> int:
    """
    Entry point: parse timestamps, generate charts, and print summary.

    Returns:
        Exit code ``0`` on success, ``1`` on error.
    """
    args = parse_args()

    try:
        log_path = resolve_log_path(args.input)
    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    try:
        print(f"Reading log file: {log_path}")
        timestamps = collect_timestamps(log_path)

        if not timestamps:
            print("Error: no valid timestamps found in log file.", file=sys.stderr)
            return 1

        daily_counts = bucket_by_day(timestamps)
        hourly_counts = bucket_by_hour_of_day(timestamps)

        plot_daily_chart(daily_counts, OUTPUT_DAILY)
        print(f"Daily chart saved to: {OUTPUT_DAILY}")

        plot_hourly_chart(hourly_counts, OUTPUT_HOURLY)
        print(f"Hourly chart saved to: {OUTPUT_HOURLY}")

        print_summary(daily_counts, hourly_counts, len(timestamps))
        return 0

    except OSError as exc:
        print(f"Error reading log file: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"Unexpected error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
