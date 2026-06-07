#!/usr/bin/env python3
"""
Credential intelligence analysis for Cowrie honeypot logs.

Compares attacker passwords extracted from login events against the
RockYou breach wordlist to measure how many attempts rely on known
leaked credentials versus custom or targeted passwords.
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


LOGIN_EVENT_IDS = frozenset({
    "cowrie.login.failed",
    "cowrie.login.success",
})

TOP_N = 20


def extract_password_counts(log_path: Path) -> Counter[str]:
    """
    Extract password attempt frequencies from Cowrie login events.

    Scans ``cowrie.login.failed`` and ``cowrie.login.success`` events for
    the ``password`` field and counts each distinct value by total attempts.

    Args:
        log_path: Path to the Cowrie JSON log file.

    Returns:
        Counter mapping password strings to attempt counts.

    Raises:
        RuntimeError: If ``parse_logs`` is not importable.
        FileNotFoundError: If ``log_path`` does not exist.
    """
    if read_cowrie_logs is None:
        raise RuntimeError("parse_logs module required; run from analysis/ directory")

    password_counts: Counter[str] = Counter()

    for event in read_cowrie_logs(log_path):
        if event.get("eventid") not in LOGIN_EVENT_IDS:
            continue

        password = _normalize_field(event, "password")
        if password:
            password_counts[password] += 1

    return password_counts


def _normalize_field(event: dict[str, Any], *keys: str) -> str | None:
    """
    Return the first non-empty string value for given keys in an event.

    Args:
        event: Cowrie event dictionary.
        *keys: Field names to check in order.

    Returns:
        Stripped string value or ``None``.
    """
    for key in keys:
        value = event.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    return None


def load_rockyou_wordlist(wordlist_path: Path) -> set[str]:
    """
    Load the RockYou wordlist into a set for fast membership lookups.

    Encoding errors are ignored so corrupted bytes in the wordlist file
    do not halt processing.

    Args:
        wordlist_path: Path to the RockYou plaintext wordlist file.

    Returns:
        Set of password strings from the wordlist.

    Raises:
        FileNotFoundError: If ``wordlist_path`` does not exist.
    """
    if not wordlist_path.is_file():
        raise FileNotFoundError(f"Wordlist not found: {wordlist_path}")

    words: set[str] = set()
    with wordlist_path.open(encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            word = line.rstrip("\n\r")
            if word:
                words.add(word)

    return words


def classify_passwords(
    password_counts: Counter[str],
    rockyou: set[str],
) -> tuple[set[str], set[str], int, int]:
    """
    Split unique log passwords into RockYou matches and non-matches.

    Args:
        password_counts: Password attempt counter from honeypot logs.
        rockyou: Loaded RockYou wordlist set.

    Returns:
        Tuple of ``(in_rockyou, not_in_rockyou, attempts_in_rockyou,
        attempts_not_in_rockyou)`` where the first two items are sets of
        unique password strings and the latter two are total attempt counts.
    """
    in_rockyou: set[str] = set()
    not_in_rockyou: set[str] = set()
    attempts_in = 0
    attempts_not_in = 0

    for password, count in password_counts.items():
        if password in rockyou:
            in_rockyou.add(password)
            attempts_in += count
        else:
            not_in_rockyou.add(password)
            attempts_not_in += count

    return in_rockyou, not_in_rockyou, attempts_in, attempts_not_in


def _display_password(password: str, max_len: int = 40) -> str:
    """Truncate long passwords for readable terminal output."""
    if len(password) <= max_len:
        return password
    return password[: max_len - 3] + "..."


def print_intelligence_report(
    password_counts: Counter[str],
    rockyou: set[str],
    wordlist_size: int,
    top_n: int = TOP_N,
) -> None:
    """
    Print RockYou comparison statistics and ranked password lists.

    Args:
        password_counts: Password attempt counter from honeypot logs.
        rockyou: Loaded RockYou wordlist set.
        wordlist_size: Number of entries loaded from the wordlist file.
        top_n: Number of top passwords to show in each ranked section.
    """
    unique_total = len(password_counts)
    total_attempts = sum(password_counts.values())

    in_rockyou, not_in_rockyou, attempts_in, attempts_not_in = classify_passwords(
        password_counts, rockyou
    )

    matched_unique = len(in_rockyou)
    unmatched_unique = len(not_in_rockyou)
    match_pct = (matched_unique / unique_total * 100) if unique_total else 0.0
    custom_pct = (unmatched_unique / unique_total * 100) if unique_total else 0.0

    attempts_in_pct = (attempts_in / total_attempts * 100) if total_attempts else 0.0
    attempts_custom_pct = (attempts_not_in / total_attempts * 100) if total_attempts else 0.0

    in_rockyou_ranked = [
        (pwd, password_counts[pwd])
        for pwd in in_rockyou
    ]
    in_rockyou_ranked.sort(key=lambda item: item[1], reverse=True)

    not_in_rockyou_ranked = [
        (pwd, password_counts[pwd])
        for pwd in not_in_rockyou
    ]
    not_in_rockyou_ranked.sort(key=lambda item: item[1], reverse=True)

    print("=" * 60)
    print("Credential Intelligence — honeypot-soc-lab")
    print("=" * 60)
    print(f"RockYou wordlist entries loaded : {wordlist_size:,}")
    print(f"Total login password attempts   : {total_attempts:,}")
    print(f"Unique passwords in logs        : {unique_total:,}")
    print()
    print("--- RockYou Match Summary ---")
    print(f"Passwords found in RockYou      : {matched_unique:,}")
    print(f"Passwords NOT in RockYou        : {unmatched_unique:,}")
    print(f"Unique password match rate      : {match_pct:.1f}%")
    print()
    print(f"Attempts using RockYou passwords: {attempts_in:,} ({attempts_in_pct:.1f}%)")
    print(f"Attempts using other passwords  : {attempts_not_in:,} ({attempts_custom_pct:.1f}%)")

    print(f"\nTop {top_n} Passwords IN RockYou (breach-list / dictionary):")
    print(f"{'Password':<30} {'Attempts':>10}")
    print("-" * 42)
    for pwd, count in in_rockyou_ranked[:top_n]:
        print(f"{_display_password(pwd):<30} {count:>10,}")
    if not in_rockyou_ranked:
        print("(none)")

    print(f"\nTop {top_n} Passwords NOT in RockYou (custom / targeted):")
    print(f"{'Password':<30} {'Attempts':>10}")
    print("-" * 42)
    for pwd, count in not_in_rockyou_ranked[:top_n]:
        print(f"{_display_password(pwd):<30} {count:>10,}")
    if not in_rockyou_ranked:
        print("(none)")

    print("\n--- Classification Summary ---")
    print(f"Common dictionary (RockYou)     : {match_pct:.1f}% of unique passwords")
    print(f"Custom / targeted (not RockYou) : {custom_pct:.1f}% of unique passwords")
    print()
    print(f"By attempt volume:")
    print(f"  Dictionary (RockYou)          : {attempts_in_pct:.1f}% of all attempts")
    print(f"  Custom / targeted               : {attempts_custom_pct:.1f}% of all attempts")
    print("=" * 60)


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description=(
            "Compare Cowrie honeypot passwords against the RockYou wordlist "
            "to assess breach-list reuse."
        ),
    )
    parser.add_argument(
        "--input",
        "-i",
        type=Path,
        required=True,
        help="Path to Cowrie JSON log file",
    )
    parser.add_argument(
        "--wordlist",
        "-w",
        type=Path,
        required=True,
        help="Path to RockYou wordlist file",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=TOP_N,
        help=f"Number of top passwords to show per section (default: {TOP_N})",
    )
    return parser.parse_args()


def main() -> int:
    """
    Entry point: extract passwords, compare against RockYou, print report.

    Returns:
        Exit code ``0`` on success, ``1`` on error.
    """
    args = parse_args()

    try:
        print(f"Loading RockYou wordlist: {args.wordlist}")
        rockyou = load_rockyou_wordlist(args.wordlist)
        print(f"Loaded {len(rockyou):,} unique entries.\n")

        print(f"Reading log file: {args.input}")
        password_counts = extract_password_counts(args.input)

        if not password_counts:
            print("No passwords found in login events.", file=sys.stderr)
            return 0

        print_intelligence_report(
            password_counts,
            rockyou,
            wordlist_size=len(rockyou),
            top_n=args.top,
        )
        return 0

    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"Error reading file: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
