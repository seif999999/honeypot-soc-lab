# honeypot-soc-lab

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat&logo=python&logoColor=white)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat&logo=docker&logoColor=white)](https://www.docker.com/)
[![Ubuntu](https://img.shields.io/badge/Ubuntu-22.04%20LTS-E95420?style=flat&logo=ubuntu&logoColor=white)](https://ubuntu.com/)

A hands-on Security Operations Center (SOC) lab that deploys a **Cowrie SSH honeypot** on Oracle Cloud, forwards telemetry through **Filebeat** over a **Tailscale** tunnel, and ingests events into a local **Wazuh SIEM** for detection, alerting, and threat intelligence analysis.

---

## Project Overview

This repository documents an end-to-end honeypot-to-SIEM pipeline designed for security research and SOC training. Attackers interact with a realistic SSH/Telnet decoy (Cowrie); every session, credential attempt, and command is logged as structured JSON. Logs are shipped securely to a Wazuh manager running on a local workstation, where custom rules, dashboards, and Python analysis scripts support incident triage and threat reporting.

**Goals:**

- Capture real-world attacker behavior against an internet-exposed honeypot
- Centralize and correlate events in a production-grade open-source SIEM
- Profile attackers (geography, credentials, commands, MITRE ATT&CK techniques)
- Produce repeatable, professional threat intelligence reports

---

## Architecture

```
Internet Attackers
       │
       ▼
┌──────────────────────┐
│  Cowrie Honeypot     │  Oracle Cloud VPS (Ubuntu)
│  SSH / Telnet        │
└──────────┬───────────┘
           │ JSON logs
           ▼
┌──────────────────────┐
│  Filebeat            │  Log shipper on VPS
└──────────┬───────────┘
           │ Tailscale encrypted tunnel
           ▼
┌──────────────────────┐
│  Wazuh SIEM          │  Local machine (Manager + Indexer + Dashboard)
│  Rules · Alerts      │
└──────────┬───────────┘
           │
           ▼
   Dashboards · Alerts · Python Analysis
```

See [docs/architecture.md](docs/architecture.md) for the full pipeline description.

---

## Technologies Used

| Layer | Technology | Role |
|-------|------------|------|
| Honeypot | [Cowrie](https://github.com/cowrie/cowrie) | SSH/Telnet honeypot, JSON logging |
| Cloud | Oracle Cloud (Always Free VPS) | Internet-facing deployment |
| Log shipping | [Filebeat](https://www.elastic.co/beats/filebeat) | Forward Cowrie logs to Wazuh |
| Networking | [Tailscale](https://tailscale.com/) | Encrypted VPS ↔ local tunnel |
| SIEM | [Wazuh](https://wazuh.com/) | Ingestion, rules, alerts, dashboards |
| Analysis | Python 3.10+ | Log parsing, geo, credentials, MITRE mapping |
| Containerization | Docker (optional) | Local Wazuh stack deployment |

---

## Repository Structure

```
honeypot-soc-lab/
├── README.md
├── docs/
│   ├── architecture.md
│   ├── runbook.md
│   └── threat-report-template.md
├── honeypot/
│   ├── setup.md
│   └── sample-logs/
├── siem/
│   ├── setup.md
│   └── rules/
└── analysis/
    ├── parse_logs.py
    ├── geo_analysis.py
    ├── credential_analysis.py
    ├── command_tracker.py
    └── mitre_mapping.py
```

---

## Key Findings

> _Placeholder — populate after running the lab and completing analysis._

| Metric | Value |
|--------|-------|
| Total sessions observed | _TBD_ |
| Unique source IPs | _TBD_ |
| Top attacking country | _TBD_ |
| Most common username | _TBD_ |
| Most common password | _TBD_ |
| Distinct commands executed | _TBD_ |

---

## Dashboard Screenshots

> _Placeholder — add screenshots from Wazuh Dashboard once the pipeline is live._

| Dashboard | Description |
|-----------|-------------|
| `honeypot-overview.png` | Session volume and source IP map |
| `honeypot-credentials.png` | Top usernames/passwords attempted |
| `honeypot-commands.png` | Post-login command frequency |

---

## Threat Report

Completed threat intelligence reports should follow the template in [docs/threat-report-template.md](docs/threat-report-template.md).

**Latest report:** _Link to published report (e.g., `docs/reports/YYYY-MM-threat-report.md`)_

---

## Quick Start

1. Deploy Cowrie on Oracle Cloud — see [honeypot/setup.md](honeypot/setup.md)
2. Configure Wazuh locally — see [siem/setup.md](siem/setup.md)
3. Connect Filebeat over Tailscale — see [docs/runbook.md](docs/runbook.md)
4. Run analysis scripts in `analysis/`

---

## License

This project is provided for educational and research purposes. Use responsibly and only on infrastructure you own or have explicit permission to test.

---

## Disclaimer

Deploying internet-facing honeypots carries legal and operational responsibilities. Ensure compliance with your jurisdiction, cloud provider terms of service, and organizational policies before deployment.
