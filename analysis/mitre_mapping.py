#!/usr/bin/env python3
"""
MITRE ATT&CK mapping for Cowrie honeypot events.

Maps Cowrie ``eventid`` values to MITRE ATT&CK technique IDs and names
to support threat reports and detection engineering for honeypot-soc-lab.
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path
from typing import NamedTuple

try:
    from parse_logs import read_cowrie_logs
except ImportError:
    read_cowrie_logs = None  # type: ignore[misc, assignment]


class AttackTechnique(NamedTuple):
    """MITRE ATT&CK technique reference."""

    technique_id: str
    technique_name: str
    tactic: str


# Cowrie eventid → MITRE ATT&CK mapping
# Extend as new event types are observed in your environment.
COWRIE_TO_MITRE: dict[str, AttackTechnique] = {
    "cowrie.session.connect": AttackTechnique(
        "T1595.001",
        "Scanning IP Blocks",
        "Reconnaissance",
    ),
    "cowrie.login.failed": AttackTechnique(
        "T1110",
        "Brute Force",
        "Credential Access",
    ),
    "cowrie.login.success": AttackTechnique(
        "T1110.001",
        "Brute Force: Password Guessing",
        "Credential Access",
    ),
    "cowrie.command.input": AttackTechnique(
        "T1059",
        "Command and Scripting Interpreter",
        "Execution",
    ),
    "cowrie.command.failed": AttackTechnique(
        "T1059",
        "Command and Scripting Interpreter",
        "Execution",
    ),
    "cowrie.session.file_download": AttackTechnique(
        "T1105",
        "Ingress Tool Transfer",
        "Command and Control",
    ),
    "cowrie.session.file_upload": AttackTechnique(
        "T1105",
        "Ingress Tool Transfer",
        "Command and Control",
    ),
    "cowrie.client.version": AttackTechnique(
        "T1071",
        "Application Layer Protocol",
        "Command and Control",
    ),
    "cowrie.client.fingerprint": AttackTechnique(
        "T1592",
        "Gather Victim Host Information",
        "Reconnaissance",
    ),
    "cowrie.direct-tcprequest": AttackTechnique(
        "T1571",
        "Non-Standard Port",
        "Command and Control",
    ),
    "cowrie.session.closed": AttackTechnique(
        "T1078",
        "Valid Accounts",
        "Defense Evasion",
    ),
}

DEFAULT_TECHNIQUE = AttackTechnique(
    "T1190",
    "Exploit Public-Facing Application",
    "Initial Access",
)


def map_event_to_technique(event_id: str) -> AttackTechnique:
    """
    Return the MITRE ATT&CK technique for a Cowrie event ID.

    Args:
        event_id: Cowrie ``eventid`` string (e.g., ``cowrie.login.failed``).

    Returns:
        :class:`AttackTechnique` for known events, or ``DEFAULT_TECHNIQUE``.
    """
    return COWRIE_TO_MITRE.get(event_id, DEFAULT_TECHNIQUE)


def analyze_log_mitre(log_path: Path) -> Counter[str]:
    """
    Count events per MITRE technique ID across a log file.

    Args:
        log_path: Path to Cowrie JSON log file.

    Returns:
        Counter keyed by technique ID (e.g., ``T1110``).
    """
    if read_cowrie_logs is None:
        raise RuntimeError("parse_logs module required; run from analysis/ directory")

    technique_counts: Counter[str] = Counter()
    for event in read_cowrie_logs(log_path):
        event_id = event.get("eventid", "unknown")
        technique = map_event_to_technique(event_id)
        technique_counts[technique.technique_id] += 1
    return technique_counts


def build_technique_details() -> dict[str, AttackTechnique]:
    """
    Build a deduplicated map of technique ID → technique metadata.

    Returns:
        Dictionary of unique techniques from :data:`COWRIE_TO_MITRE`.
    """
    details: dict[str, AttackTechnique] = {}
    for technique in COWRIE_TO_MITRE.values():
        details[technique.technique_id] = technique
    details[DEFAULT_TECHNIQUE.technique_id] = DEFAULT_TECHNIQUE
    return details


def print_mitre_report(
    technique_counts: Counter[str],
    technique_details: dict[str, AttackTechnique],
) -> None:
    """
    Print MITRE ATT&CK mapping summary.

    Args:
        technique_counts: Counts from :func:`analyze_log_mitre`.
        technique_details: Metadata lookup by technique ID.
    """
    total = sum(technique_counts.values())
    print("=" * 70)
    print("MITRE ATT&CK Mapping — honeypot-soc-lab")
    print("=" * 70)
    print(f"Total mapped events: {total}\n")
    print(f"{'ID':<12} {'Tactic':<22} {'Technique':<30} {'Count':>8}")
    print("-" * 70)

    for tech_id, count in technique_counts.most_common():
        tech = technique_details.get(tech_id)
        if tech:
            print(
                f"{tech.technique_id:<12} {tech.tactic:<22} "
                f"{tech.technique_name:<30} {count:>8}"
            )
        else:
            print(f"{tech_id:<12} {'Unknown':<22} {'Unknown':<30} {count:>8}")

    print("\nCowrie eventid → MITRE reference mapping:")
    print("-" * 70)
    for event_id, tech in sorted(COWRIE_TO_MITRE.items()):
        print(f"  {event_id:<35} → {tech.technique_id} {tech.technique_name}")
    print("=" * 70)


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Map Cowrie events to MITRE ATT&CK techniques.",
    )
    parser.add_argument(
        "--input",
        "-i",
        type=Path,
        help="Path to cowrie.json (omit to print static mapping only)",
    )
    parser.add_argument(
        "--list-mapping",
        action="store_true",
        help="Print eventid → MITRE mapping table and exit",
    )
    return parser.parse_args()


def main() -> int:
    """
    Entry point: analyze log or list static mapping.

    Returns:
        Exit code (0 on success).
    """
    args = parse_args()
    technique_details = build_technique_details()

    if args.list_mapping or args.input is None:
        print_mitre_report(Counter(), technique_details)
        if args.input is None and not args.list_mapping:
            print("\nTip: pass --input cowrie.json to analyze a log file.", file=sys.stderr)
        return 0

    try:
        technique_counts = analyze_log_mitre(args.input)
    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print_mitre_report(technique_counts, technique_details)
    return 0


if __name__ == "__main__":
    sys.exit(main())
