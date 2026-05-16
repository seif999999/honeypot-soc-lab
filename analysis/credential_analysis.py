#!/usr/bin/env python3
"""
Credential stuffing analysis for Cowrie honeypot logs.

Extracts username and password fields from login-related events and
reports the most frequently attempted credentials for threat reporting.
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


# Cowrie event IDs associated with authentication attempts
LOGIN_EVENT_IDS = frozenset({
    "cowrie.login.failed",
    "cowrie.login.success",
})


def extract_credentials(log_path: Path) -> tuple[list[str], list[str], Counter[tuple[str, str]]]:
    """
    Extract usernames, passwords, and pairs from login events.

    Args:
        log_path: Path to Cowrie JSON log file.

    Returns:
        Tuple of (usernames list, passwords list, (username, password) pair counter).
        Lists contain one entry per attempt for frequency analysis.
    """
    if read_cowrie_logs is None:
        raise RuntimeError("parse_logs module required; run from analysis/ directory")

    usernames: list[str] = []
    passwords: list[str] = []
    pairs: Counter[tuple[str, str]] = Counter()

    for event in read_cowrie_logs(log_path):
        if event.get("eventid") not in LOGIN_EVENT_IDS:
            continue

        username = _normalize_field(event, "username", "account")
        password = _normalize_field(event, "password")

        if username:
            usernames.append(username)
        if password:
            passwords.append(password)
        if username and password:
            pairs[(username, password)] += 1

    return usernames, passwords, pairs


def _normalize_field(event: dict[str, Any], *keys: str) -> str | None:
    """
    Return the first non-empty string value for given keys in an event.

    Args:
        event: Cowrie event dictionary.
        *keys: Field names to check in order.

    Returns:
        Stripped string value or None.
    """
    for key in keys:
        value = event.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    return None


def top_n(counter: Counter[str], n: int = 10) -> list[tuple[str, int]]:
    """
    Return the top *n* items from a counter.

    Args:
        counter: String counter (e.g., usernames or passwords).
        n: Number of results.

    Returns:
        List of (value, count) tuples.
    """
    return counter.most_common(n)


def print_credential_report(
    usernames: list[str],
    passwords: list[str],
    pairs: Counter[tuple[str, str]],
    top: int = 15,
) -> None:
    """
    Print top usernames, passwords, and credential pairs.

    Args:
        usernames: All username attempts.
        passwords: All password attempts.
        pairs: (username, password) pair counter.
        top: Number of top entries to display per section.
    """
    username_counts = Counter(usernames)
    password_counts = Counter(passwords)

    print("=" * 60)
    print("Credential Analysis — honeypot-soc-lab")
    print("=" * 60)
    print(f"Total login attempts: {len(usernames)}")
    print(f"Unique usernames:     {len(username_counts)}")
    print(f"Unique passwords:     {len(password_counts)}")
    print(f"Unique pairs:         {len(pairs)}")

    print(f"\nTop {top} Usernames:")
    print(f"{'Username':<30} {'Count':>8}")
    print("-" * 40)
    for user, count in top_n(username_counts, top):
        print(f"{user:<30} {count:>8}")

    print(f"\nTop {top} Passwords:")
    print(f"{'Password':<30} {'Count':>8}")
    print("-" * 40)
    for pwd, count in top_n(password_counts, top):
        # Redact in shared logs if needed; full value shown for lab analysis
        display = pwd if len(pwd) <= 40 else pwd[:37] + "..."
        print(f"{display:<30} {count:>8}")

    print(f"\nTop {top} Username / Password Pairs:")
    print(f"{'Username':<20} {'Password':<20} {'Count':>8}")
    print("-" * 50)
    for (user, pwd), count in pairs.most_common(top):
        pwd_display = pwd if len(pwd) <= 18 else pwd[:15] + "..."
        print(f"{user:<20} {pwd_display:<20} {count:>8}")
    print("=" * 60)


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Analyze top usernames and passwords from Cowrie logs.",
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
        default=15,
        help="Number of top entries to show (default: 15)",
    )
    return parser.parse_args()


def main() -> int:
    """
    Entry point: extract credentials and print frequency report.

    Returns:
        Exit code (0 on success).
    """
    args = parse_args()
    try:
        usernames, passwords, pairs = extract_credentials(args.input)
    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print_credential_report(usernames, passwords, pairs, top=args.top)
    return 0


if __name__ == "__main__":
    sys.exit(main())
