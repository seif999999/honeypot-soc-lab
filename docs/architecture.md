# Architecture — honeypot-soc-lab

This document describes the end-to-end telemetry pipeline from internet attackers through honeypot capture, secure log forwarding, SIEM ingestion, and analyst-facing outputs.

---

## High-Level Data Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           INTERNET (Untrusted)                              │
│   Scanners · Botnets · Credential Stuffing · Manual Attackers               │
└───────────────────────────────────┬─────────────────────────────────────────┘
                                    │ SSH (22) / Telnet (23)
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  ORACLE CLOUD VPS — Ubuntu 22.04 LTS                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  Cowrie Honeypot                                                     │   │
│  │  • Emulates SSH/Telnet shell (medium/high interaction proxy modes)   │   │
│  │  • Logs: cowrie.json (session, login, command, file download, etc.)│   │
│  │  • Output: /home/cowrie/cowrie/var/log/cowrie/                     │   │
│  └───────────────────────────────┬─────────────────────────────────────┘   │
│                                      │                                         │
│  ┌───────────────────────────────────▼─────────────────────────────────────┐   │
│  │  Filebeat                                                                │   │
│  │  • Tails cowrie.json                                                     │   │
│  │  • Adds host metadata, timestamps                                        │   │
│  │  • Ships to Wazuh agent listener OR manager syslog/API endpoint          │   │
│  └───────────────────────────────┬─────────────────────────────────────┘   │
└───────────────────────────────────┼─────────────────────────────────────────┘
                                    │
                    ┌───────────────▼───────────────┐
                    │  Tailscale Mesh VPN         │
                    │  • WireGuard-based tunnel   │
                    │  • No public SIEM exposure  │
                    │  • VPS ↔ Analyst workstation│
                    └───────────────┬───────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  LOCAL MACHINE — Wazuh SIEM Stack                                           │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────────────┐  │
│  │ Wazuh Manager│→ │ Wazuh Indexer│→ │ Wazuh Dashboard (OpenSearch)     │  │
│  │ Rules · Decoders│  │ Storage      │  │ Visualizations · Alerts · Hunt   │  │
│  └──────────────┘  └──────────────┘  └──────────────────────────────────┘  │
│                                                                              │
│  Custom decoders/rules: siem/rules/                                          │
└───────────────────────────────────┬─────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  ANALYSIS LAYER (Python)                                                     │
│  parse_logs · geo_analysis · credential_analysis · command_tracker ·        │
│  mitre_mapping → Threat Report (docs/threat-report-template.md)             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Component Details

### 1. Attackers → Cowrie Honeypot

| Attribute | Detail |
|-----------|--------|
| **Location** | Oracle Cloud Infrastructure (OCI) Always Free ARM/AMD VPS |
| **OS** | Ubuntu 22.04 LTS, hardened baseline (UFW, fail2ban optional, non-root deploy user) |
| **Service** | Cowrie — Python-based medium-interaction honeypot |
| **Exposed ports** | TCP 22 (SSH redirect to Cowrie), optionally 23 (Telnet) |
| **Log format** | Newline-delimited JSON (`cowrie.json`) per event |
| **Event types** | `cowrie.session.connect`, `cowrie.login.failed`, `cowrie.login.success`, `cowrie.command.input`, `cowrie.session.file_download`, etc. |

Cowrie does not provide a real shell to attackers; it records intent (credentials, commands, downloads) for research and detection engineering.

### 2. Cowrie → Filebeat

Filebeat runs on the VPS as a lightweight shipper:

- **Input:** `log` or `filestream` input pointed at `cowrie.json`
- **Parsing:** JSON decoding enabled; optional `add_fields` for `data_source: cowrie`
- **Output:** Wazuh agent (recommended) or direct syslog/TCP to manager on the Tailscale IP of the local host
- **Reliability:** Registry-based offset tracking; survives restarts without duplicate flood (at-least-once semantics)

### 3. Filebeat → Tailscale Tunnel

| Why Tailscale | Benefit |
|---------------|---------|
| No inbound ports on home network | Manager not exposed to the internet |
| Encrypted overlay (WireGuard) | Logs transit privately |
| Stable private IPs | Filebeat output target is `100.x.x.x` (Tailscale CGNAT range) |
| ACLs (optional) | Restrict which nodes can reach Wazuh ports (1514, 1515, 55000) |

Both the Oracle VPS and the local Wazuh host join the same Tailscale tailnet. Filebeat (or Wazuh agent) connects to the manager using the workstation's Tailscale address.

### 4. Tailscale → Wazuh SIEM (Local)

The local stack typically includes:

| Component | Function |
|-----------|----------|
| **Wazuh Manager** | Receives agent/Filebeat events, runs decoders and rules, generates alerts |
| **Wazuh Indexer** | Stores alerts and archives (OpenSearch-compatible) |
| **Wazuh Dashboard** | Kibana-like UI for search, dashboards, and MITRE-aligned views |

**Ingestion path:**

1. Events arrive at manager (agent protocol or syslog)
2. Decoders extract JSON fields from Cowrie (`src_ip`, `username`, `password`, `input`, `eventid`)
3. Rules in `siem/rules/` fire on brute force, successful login, suspicious commands
4. Alerts indexed and visible in Dashboard within seconds to minutes

### 5. SIEM → Dashboards and Alerts

| Output | Description |
|--------|-------------|
| **Real-time alerts** | Email/Slack/webhook (optional) on high-severity rules |
| **Dashboards** | Session timeline, top source IPs, credential heatmaps, command word clouds |
| **Hunting** | Wazuh Dashboard Discover / WQL queries on `agent.labels` and Cowrie fields |
| **Retention** | Index lifecycle per local disk policy (e.g., 30–90 days) |

### 6. Analysis Pipeline

Offline Python scripts in `analysis/` consume exported or raw `cowrie.json` for:

- Session and event summaries (`parse_logs.py`)
- Country-level attribution (`geo_analysis.py`)
- Credential stuffing patterns (`credential_analysis.py`)
- Post-exploitation command TTPs (`command_tracker.py`)
- MITRE ATT&CK technique mapping (`mitre_mapping.py`)

Results feed the formal [threat-report-template.md](threat-report-template.md).

---

## Security Considerations

- **Isolation:** Honeypot VPS should have no lateral access to production networks; dedicated cloud account/VLAN recommended.
- **Tailscale ACLs:** Limit source → destination ports; deny unexpected peers.
- **Secrets:** API keys (e.g., ipinfo.io) via environment variables, never committed.
- **Legal:** Log only attack traffic against the decoy; document purpose for cloud provider abuse contacts.

---

## Network Ports Reference

| Port | Service | Exposure |
|------|---------|----------|
| 22 | Cowrie (via iptables redirect) | Public (internet) |
| 1514 | Wazuh agent connection | Tailscale only |
| 1515 | Wazuh agent enrollment | Tailscale only |
| 443 | Wazuh Dashboard | Localhost or Tailscale |
| 55000 | Wazuh API | Localhost or Tailscale |

---

## Future Enhancements

- [ ] Integrate MISP or OpenCTI for IOC sharing
- [ ] Add Suricata IDS on VPS for pre-Cowrie network context
- [ ] Automate weekly threat reports via CI
- [ ] Ship logs to cold storage (S3-compatible) for long-term research
