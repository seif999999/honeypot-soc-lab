#!/usr/bin/env python3
"""
Post-login command analysis for Cowrie honeypot logs.

Extracts shell commands entered by attackers after successful (or
simulated) login and reports command frequency for TTP identification.
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

try:
    from parse_logs import read_cowrie_logs
except ImportError:
    read_cowrie_logs = None  # type: ignore[misc, assignment]


COMMAND_EVENT_ID = "cowrie.command.input"


def extract_commands(log_path: Path) -> tuple[list[str], dict[str, list[str]]]:
    """
    Extract all commands and optional per-session groupings.

    Args:
        log_path: Path to Cowrie JSON log file.

    Returns:
        Tuple of (flat command list, session_id → commands mapping).
    """
    if read_cowrie_logs is None:
        raise RuntimeError("parse_logs module required; run from analysis/ directory")

    commands: list[str] = []
    by_session: dict[str, list[str]] = defaultdict(list)

    for event in read_cowrie_logs(log_path):
        if event.get("eventid") != COMMAND_EVENT_ID:
            continue

        cmd = _get_command_text(event)
        if not cmd:
            continue

        commands.append(cmd)
        session_id = str(event.get("session") or event.get("session_id") or "unknown")
        by_session[session_id].append(cmd)

    return commands, dict(by_session)


def _get_command_text(event: dict[str, Any]) -> str | None:
    """
    Normalize command text from a Cowrie command event.

    Cowrie may store the command in ``input`` or ``message`` depending on
    version and configuration.

    Args:
        event: Cowrie event dictionary.

    Returns:
        Stripped command string or None.
    """
    for key in ("input", "command", "message"):
        value = event.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    return None


def normalize_command(cmd: str) -> str:
    """
    Light normalization for frequency counting.

    Collapses internal whitespace and lowercases for grouping; original
    commands are preserved in session exports.

    Args:
        cmd: Raw command string.

    Returns:
        Normalized command for counting.
    """
    return " ".join(cmd.split()).lower()


def count_commands(commands: list[str], normalize: bool = True) -> Counter[str]:
    """
    Count command frequency.

    Args:
        commands: List of command strings.
        normalize: If True, apply :func:`normalize_command` before counting.

    Returns:
        Counter of commands.
    """
    counter: Counter[str] = Counter()
    for cmd in commands:
        key = normalize_command(cmd) if normalize else cmd
        counter[key] += 1
    return counter


def print_command_report(
    command_counts: Counter[str],
    total_commands: int,
    session_count: int,
    top: int = 25,
) -> None:
    """
    Print command frequency table.

    Args:
        command_counts: Output from :func:`count_commands`.
        total_commands: Total command events.
        session_count: Number of sessions with at least one command.
        top: Number of top commands to display.
    """
    print("=" * 60)
    print("Command Analysis — honeypot-soc-lab")
    print("=" * 60)
    print(f"Total commands:       {total_commands}")
    print(f"Unique commands:      {len(command_counts)}")
    print(f"Sessions w/ commands: {session_count}")

    print(f"\nTop {top} Commands:")
    print(f"{'Command':<50} {'Count':>8}")
    print("-" * 60)
    for cmd, count in command_counts.most_common(top):
        display = cmd if len(cmd) <= 48 else cmd[:45] + "..."
        print(f"{display:<50} {count:>8}")
    print("=" * 60)


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Track and count attacker commands from Cowrie logs.",
    )
    parser.add_argument(
        "--input",
        "-i",
        type=Path,
        required=True,
        help="Path to cowrie.json",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=25,
        help="Number of top commands to show (default: 25)",
    )
    parser.add_argument(
        "--no-normalize",
        action="store_true",
        help="Disable command normalization before counting",
    )
    return parser.parse_args()


def main() -> int:
    """
    Entry point: extract commands and print frequency report.

    Returns:
        Exit code (0 on success).
    """
    args = parse_args()
    try:
        commands, by_session = extract_commands(args.input)
    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    command_counts = count_commands(commands, normalize=not args.no_normalize)
    print_command_report(
        command_counts,
        total_commands=len(commands),
        session_count=len(by_session),
        top=args.top,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
