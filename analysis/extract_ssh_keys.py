#!/usr/bin/env python3
"""
SSH public key extraction for Cowrie honeypot logs.

Scans ``cowrie.command.input`` events that reference ``authorized_keys``
and extracts attacker-injected SSH public keys along with source attribution.
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    from parse_logs import read_cowrie_logs
except ImportError:
    read_cowrie_logs = None  # type: ignore[misc, assignment]


COMMAND_INPUT_EVENT = "cowrie.command.input"

# Match OpenSSH authorized_keys public key lines (rsa, ed25519, ecdsa, dss)
SSH_PUBLIC_KEY_PATTERN = re.compile(
    r"(ssh-(?:rsa|ed25519|dss|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521)"
    r"\s+[A-Za-z0-9+/=]+"
    r"(?:\s+[^\s\"\\'<>|;&]+)?)",
)


@dataclass
class KeyRecord:
    """A single SSH key injection observed in a Cowrie command event."""

    public_key: str
    src_ip: str
    timestamp: str
    session_id: str


def extract_ssh_key_records(log_path: Path) -> list[KeyRecord]:
    """
    Extract SSH public keys from authorized_keys injection commands.

    Args:
        log_path: Path to the Cowrie JSON log file.

    Returns:
        List of key records, one per key found in each matching command.

    Raises:
        RuntimeError: If ``parse_logs`` is not importable.
        FileNotFoundError: If ``log_path`` does not exist.
    """
    if read_cowrie_logs is None:
        raise RuntimeError("parse_logs module required; run from analysis/ directory")

    records: list[KeyRecord] = []

    for event in read_cowrie_logs(log_path):
        if event.get("eventid") != COMMAND_INPUT_EVENT:
            continue

        command = str(event.get("input") or event.get("message") or "")
        if "authorized_keys" not in command:
            continue

        keys = extract_keys_from_command(command)
        if not keys:
            continue

        src_ip = str(event.get("src_ip") or "unknown")
        timestamp = str(event.get("timestamp") or "unknown")
        session_id = str(event.get("session") or "unknown")

        for public_key in keys:
            records.append(
                KeyRecord(
                    public_key=public_key,
                    src_ip=src_ip,
                    timestamp=timestamp,
                    session_id=session_id,
                )
            )

    return records


def extract_keys_from_command(command: str) -> list[str]:
    """
    Parse SSH public key strings from a shell command.

    Args:
        command: Raw command text from a Cowrie event.

    Returns:
        List of unique public key strings found in the command.
    """
    matches = SSH_PUBLIC_KEY_PATTERN.findall(command)
    # Preserve order while deduplicating within a single command
    seen: set[str] = set()
    keys: list[str] = []
    for key in matches:
        normalized = key.strip()
        if normalized and normalized not in seen:
            seen.add(normalized)
            keys.append(normalized)
    return keys


def aggregate_keys(records: list[KeyRecord]) -> tuple[
    Counter[str],
    dict[str, set[str]],
    dict[str, list[KeyRecord]],
]:
    """
    Aggregate key records by public key string.

    Args:
        records: All extracted key records.

    Returns:
        Tuple of ``(frequency_counter, ips_by_key, records_by_key)``.
    """
    frequency: Counter[str] = Counter()
    ips_by_key: dict[str, set[str]] = defaultdict(set)
    records_by_key: dict[str, list[KeyRecord]] = defaultdict(list)

    for record in records:
        frequency[record.public_key] += 1
        ips_by_key[record.public_key].add(record.src_ip)
        records_by_key[record.public_key].append(record)

    return frequency, dict(ips_by_key), dict(records_by_key)


def _truncate_key(public_key: str, max_len: int = 72) -> str:
    """Truncate a long public key for compact table display."""
    if len(public_key) <= max_len:
        return public_key
    return public_key[: max_len - 3] + "..."


def print_key_report(
    records: list[KeyRecord],
    frequency: Counter[str],
    ips_by_key: dict[str, set[str]],
) -> None:
    """
    Print unique SSH public keys with frequency and associated source IPs.

    Args:
        records: All extracted key records.
        frequency: Occurrence count per public key.
        ips_by_key: Source IPs associated with each public key.
    """
    unique_keys = len(frequency)
    total_injections = len(records)
    unique_ips = {record.src_ip for record in records}

    print("=" * 80)
    print("SSH Public Key Extraction — honeypot-soc-lab")
    print("=" * 80)
    print(f"Total key injection attempts : {total_injections:,}")
    print(f"Unique SSH public keys found   : {unique_keys:,}")
    print(f"Unique source IPs              : {len(unique_ips):,}")

    print("\nUnique SSH Public Keys (by frequency):")
    print("-" * 80)

    if not frequency:
        print("(none)")
        print("=" * 80)
        return

    for rank, (public_key, count) in enumerate(frequency.most_common(), start=1):
        ips = sorted(ips_by_key.get(public_key, set()))
        ip_list = ", ".join(ips) if ips else "unknown"

        print(f"\n[{rank}] Frequency: {count:,}")
        print(f"    Key: {_truncate_key(public_key, max_len=76)}")
        if len(public_key) > 76:
            print(f"         (full) {public_key}")
        print(f"    Associated IPs ({len(ips)}): {ip_list}")

    print("=" * 80)


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Extract SSH public keys injected via authorized_keys commands.",
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
    Entry point: extract SSH keys and print report.

    Returns:
        Exit code ``0`` on success, ``1`` on error.
    """
    args = parse_args()

    try:
        records = extract_ssh_key_records(args.input)
        frequency, ips_by_key, _ = aggregate_keys(records)
        print_key_report(records, frequency, ips_by_key)
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
