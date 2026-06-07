#!/usr/bin/env python3
"""
Interactive world map of Cowrie SSH honeypot attacker source IPs.

Streams newline-delimited Cowrie JSON logs, geolocates the top 500 attacker
IPs via the ipinfo.io free API, and renders them on a dark Folium basemap
with circle markers sized by event volume.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any, Iterator

import folium
import httpx

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_LOG_PATH = (
    Path(__file__).resolve().parent.parent
    / "honeypot"
    / "sample-logs"
    / "all-cowrie-logs.json"
)
OUTPUT_MAP = Path(__file__).resolve().parent.parent / "docs" / "attacker-map.html"

IPINFO_URL = "https://ipinfo.io/{ip}/json"
TOP_IP_LIMIT = 500
API_DELAY_SECONDS = 0.1
PROGRESS_INTERVAL = 50

MIN_RADIUS = 3
MAX_RADIUS = 20
MARKER_COLOR = "#ff4444"
MARKER_OPACITY = 0.7


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

    Malformed lines are skipped silently so large exports can be processed
    without halting on occasional corruption.

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


def count_events_by_ip(log_path: Path) -> Counter[str]:
    """
    Count honeypot events per unique attacker source IP.

    Args:
        log_path: Path to the Cowrie JSON log file.

    Returns:
        Counter mapping ``src_ip`` values to event counts.
    """
    ip_counts: Counter[str] = Counter()
    for event in iter_cowrie_events(log_path):
        ip = event.get("src_ip")
        if ip:
            ip_counts[str(ip)] += 1
    return ip_counts


def lookup_ip_geo(client: httpx.Client, ip: str) -> dict[str, Any] | None:
    """
    Query ipinfo.io for geolocation metadata (no API key required).

    API failures are handled silently; callers receive ``None`` on error.

    Args:
        client: Shared httpx client for connection reuse.
        ip: IPv4 or IPv6 address string.

    Returns:
        Parsed JSON response, or ``None`` if the lookup failed.
    """
    url = IPINFO_URL.format(ip=ip)
    try:
        response = client.get(
            url,
            headers={"Accept": "application/json", "User-Agent": "honeypot-soc-lab/1.0"},
            timeout=10.0,
        )
        response.raise_for_status()
        return response.json()
    except (httpx.HTTPError, json.JSONDecodeError):
        return None


def parse_loc(loc: str) -> tuple[float, float] | None:
    """
    Parse ipinfo.io ``loc`` field (``"latitude,longitude"``) into floats.

    Args:
        loc: Location string from ipinfo.io response.

    Returns:
        ``(latitude, longitude)`` tuple, or ``None`` if parsing fails.
    """
    try:
        lat_str, lon_str = loc.split(",", maxsplit=1)
        return float(lat_str), float(lon_str)
    except (ValueError, AttributeError):
        return None


def scale_radius(count: int, min_count: int, max_count: int) -> float:
    """
    Map an event count to a circle radius between MIN_RADIUS and MAX_RADIUS.

    Args:
        count: Event count for this IP.
        min_count: Minimum count among plotted IPs.
        max_count: Maximum count among plotted IPs.

    Returns:
        Scaled circle radius in pixels.
    """
    if max_count <= min_count:
        return float(MAX_RADIUS)
    ratio = (count - min_count) / (max_count - min_count)
    return MIN_RADIUS + ratio * (MAX_RADIUS - MIN_RADIUS)


def add_title_overlay(attack_map: folium.Map) -> None:
    """Add a fixed title banner in the top-right corner of the map."""
    title_html = """
    <div style="
        position: fixed;
        top: 12px;
        right: 12px;
        z-index: 9999;
        background-color: rgba(0, 0, 0, 0.75);
        padding: 10px 16px;
        border-radius: 6px;
        font-family: Arial, sans-serif;
        font-size: 15px;
        font-weight: bold;
        color: #ffffff;
        box-shadow: 0 2px 6px rgba(0,0,0,0.4);
    ">
        SSH Honeypot — Global Attacker Origins
    </div>
    """
    attack_map.get_root().html.add_child(folium.Element(title_html))


def add_size_legend(
    attack_map: folium.Map,
    min_count: int,
    mid_count: int,
    max_count: int,
) -> None:
    """
    Add a fixed legend explaining how circle size maps to event volume.

    Args:
        attack_map: Folium map instance.
        min_count: Lowest event count among plotted markers.
        mid_count: Median-ish reference count for the legend.
        max_count: Highest event count among plotted markers.
    """
    legend_html = f"""
    <div style="
        position: fixed;
        bottom: 30px;
        left: 12px;
        z-index: 9999;
        background-color: rgba(0, 0, 0, 0.75);
        padding: 12px 16px;
        border-radius: 6px;
        font-family: Arial, sans-serif;
        font-size: 12px;
        color: #ffffff;
        box-shadow: 0 2px 6px rgba(0,0,0,0.4);
        line-height: 1.8;
    ">
        <b>Circle Size = Event Count</b><br>
        <span style="display:inline-block;width:12px;height:12px;
              background:{MARKER_COLOR};opacity:{MARKER_OPACITY};
              border-radius:50%;margin-right:6px;vertical-align:middle;"></span>
        Low (~{min_count:,})<br>
        <span style="display:inline-block;width:18px;height:18px;
              background:{MARKER_COLOR};opacity:{MARKER_OPACITY};
              border-radius:50%;margin-right:6px;vertical-align:middle;"></span>
        Medium (~{mid_count:,})<br>
        <span style="display:inline-block;width:24px;height:24px;
              background:{MARKER_COLOR};opacity:{MARKER_OPACITY};
              border-radius:50%;margin-right:6px;vertical-align:middle;"></span>
        High (~{max_count:,})
    </div>
    """
    attack_map.get_root().html.add_child(folium.Element(legend_html))


def build_map(
    ip_data: list[tuple[str, int, str, float, float]],
    output_path: Path,
) -> None:
    """
    Render an interactive Folium map with proportional red circle markers.

    Args:
        ip_data: List of ``(ip, event_count, country, lat, lon)`` tuples.
        output_path: Destination path for the HTML map file.
    """
    attack_map = folium.Map(
        location=[20, 0],
        zoom_start=2,
        tiles="CartoDB dark_matter",
        attr="© OpenStreetMap contributors © CARTO",
    )

    add_title_overlay(attack_map)

    if ip_data:
        counts = [count for _, count, _, _, _ in ip_data]
        min_count = min(counts)
        max_count = max(counts)
        mid_count = sorted(counts)[len(counts) // 2]
        add_size_legend(attack_map, min_count, mid_count, max_count)

        for ip, count, country, lat, lon in ip_data:
            radius = scale_radius(count, min_count, max_count)
            popup_html = (
                f"<b>IP:</b> {ip}<br>"
                f"<b>Country:</b> {country}<br>"
                f"<b>Event Count:</b> {count:,}"
            )
            folium.CircleMarker(
                location=[lat, lon],
                radius=radius,
                color=MARKER_COLOR,
                fill=True,
                fill_color=MARKER_COLOR,
                fill_opacity=MARKER_OPACITY,
                popup=folium.Popup(popup_html, max_width=280),
                tooltip=f"{ip} — {count:,} events",
            ).add_to(attack_map)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    attack_map.save(str(output_path))


def geolocate_top_ips(
    ip_counts: Counter[str],
    limit: int = TOP_IP_LIMIT,
) -> tuple[list[tuple[str, int, str, float, float]], int]:
    """
    Geolocate the top-N IPs by event count via ipinfo.io.

    Args:
        ip_counts: Counter of IP addresses to event counts.
        limit: Maximum number of IPs to look up.

    Returns:
        Tuple of ``(mapped_ip_data, skipped_count)`` where ``mapped_ip_data``
        contains successfully geolocated entries and ``skipped_count`` is the
        number of lookups that could not be plotted.
    """
    top_ips = ip_counts.most_common(limit)
    results: list[tuple[str, int, str, float, float]] = []
    skipped = 0

    with httpx.Client() as client:
        for idx, (ip, count) in enumerate(top_ips, start=1):
            geo = lookup_ip_geo(client, ip)
            if geo and geo.get("loc"):
                coords = parse_loc(str(geo["loc"]))
                if coords:
                    lat, lon = coords
                    country = str(geo.get("country") or "Unknown")
                    results.append((ip, count, country, lat, lon))
                else:
                    skipped += 1
            else:
                skipped += 1

            if idx % PROGRESS_INTERVAL == 0:
                print(f"Processed {idx}/{len(top_ips)} IPs...")

            time.sleep(API_DELAY_SECONDS)

    return results, skipped


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Generate an interactive attacker geolocation map from Cowrie logs.",
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
    Entry point: parse logs, geolocate top IPs, and save the Folium map.

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
        ip_counts = count_events_by_ip(log_path)
        unique_ips = len(ip_counts)
        total_events = sum(ip_counts.values())
        print(f"Found {unique_ips:,} unique IPs across {total_events:,} events.")

        print(f"Geolocating top {TOP_IP_LIMIT} IPs via ipinfo.io...")
        ip_data, skipped = geolocate_top_ips(ip_counts, limit=TOP_IP_LIMIT)

        build_map(ip_data, OUTPUT_MAP)

        print(f"\nMap saved to: {OUTPUT_MAP}")
        print(f"Summary: {len(ip_data):,} IPs mapped, {skipped:,} skipped (geo lookup failed)")
        return 0

    except OSError as exc:
        print(f"Error reading log file: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"Unexpected error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
