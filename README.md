# 🛡️ Honeypot + SOC Lab

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat&logo=python&logoColor=white)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat&logo=docker&logoColor=white)](https://www.docker.com/)
[![Ubuntu](https://img.shields.io/badge/Ubuntu-22.04%20LTS-E95420?style=flat&logo=ubuntu&logoColor=white)](https://ubuntu.com/)
[![Wazuh](https://img.shields.io/badge/Wazuh-4.9.0-blue?style=flat)](https://wazuh.com/)
[![Oracle Cloud](https://img.shields.io/badge/Oracle%20Cloud-Always%20Free-red?style=flat)](https://www.oracle.com/cloud/free/)
[![License](https://img.shields.io/badge/License-Educational-green?style=flat)]()

An end-to-end threat detection pipeline built for real-world security research. A Cowrie SSH honeypot deployed on Oracle Cloud captures live attacker activity, ships logs via Filebeat through an encrypted Tailscale tunnel to a self-hosted Wazuh SIEM, and produces professional threat intelligence reports backed by real attack data.

---

## 🏗️ Architecture

![Architecture Diagram](docs/architecture.png)

```
Internet Attackers
       │  SSH Port 22
       ▼
┌─────────────────────────┐
│   Cowrie SSH Honeypot   │  Oracle Cloud VPS — Frankfurt, Germany
│   158.180.54.157        │  Ubuntu 22.04 LTS
└───────────┬─────────────┘
            │ JSON logs → Filebeat
            │ Tailscale tunnel (100.73.203.110 → 100.104.212.88)
            ▼
┌─────────────────────────┐
│   Wazuh SIEM            │  Local Workstation — Windows 11
│   Manager + Indexer     │  Docker Compose
│   + Dashboard           │
└───────────┬─────────────┘
            │
            ▼
  Real-time Alerts · Dashboards · Threat Intelligence Report
```

---

## 📋 Project Overview

This project simulates a real Security Operations Center pipeline using entirely free, open-source tools. The honeypot is exposed to the public internet and receives real attack traffic within minutes of deployment. All attacker activity — login attempts, credentials used, commands executed, and files downloaded — is captured in structured JSON and analyzed through a combination of a production-grade SIEM and custom Python scripts.

**What this demonstrates:**
- Cloud infrastructure deployment and hardening
- Honeypot design and operational security
- Log ingestion and pipeline engineering
- SIEM detection rule development mapped to MITRE ATT&CK
- Threat intelligence analysis and professional reporting

---

## 🛠️ Technologies

| Layer | Technology | Purpose |
|---|---|---|
| Honeypot | Cowrie | SSH/Telnet honeypot, structured JSON logging |
| Cloud | Oracle Cloud Always Free | Internet-facing VPS deployment |
| Log Shipping | Filebeat | Forward Cowrie JSON logs to Wazuh |
| Networking | Tailscale | Encrypted private tunnel between VPS and SIEM |
| SIEM | Wazuh 4.9.0 | Log ingestion, detection rules, alerting, dashboards |
| Analysis | Python 3.10+ | Log parsing, geo-IP mapping, credential analysis, MITRE mapping |
| Containerization | Docker Compose | Local Wazuh stack deployment |

---

## 📁 Repository Structure

```
honeypot-soc-lab/
├── README.md
├── docs/
│   ├── architecture.md          ← Full pipeline documentation
│   ├── architecture.png         ← Architecture diagram
│   ├── runbook.md               ← Operational runbook
│   ├── threat-report-template.md
│   └── threat-report.pdf        ← Final threat intelligence report (added May 28)
├── honeypot/
│   ├── setup.md                 ← Complete Cowrie setup guide
│   └── sample-logs/             ← Anonymized real attack logs
├── siem/
│   ├── setup.md                 ← Complete Wazuh setup guide
│   └── rules/                   ← Custom Wazuh detection rules
└── analysis/
    ├── parse_logs.py
    ├── geo_analysis.py
    ├── credential_analysis.py
    ├── command_tracker.py
    └── mitre_mapping.py
```

---

## 📊 Key Findings

> Results from 14-day honeypot deployment — May 14 to May 28, 2026.
> Full analysis in [docs/threat-report.pdf](docs/threat-report.pdf)

| Metric | Value |
|---|---|
| Total events captured | TBD |
| Unique attacking IPs | TBD |
| Countries of origin | TBD |
| Most common username | TBD |
| Most common password | TBD |
| Post-login sessions recorded | TBD |
| Malware download attempts | TBD |
| MITRE ATT&CK techniques observed | TBD |

---

## 📸 Dashboard Screenshots

> To be added after pipeline activation on May 28, 2026.

---

## 🚀 Reproducing This Project

**1. Deploy the honeypot**
Follow [honeypot/setup.md](honeypot/setup.md) — complete step-by-step guide for Oracle Cloud + Cowrie.

**2. Deploy the SIEM**
Follow [siem/setup.md](siem/setup.md) — Wazuh via Docker on Windows.

**3. Connect the pipeline**
Follow [docs/runbook.md](docs/runbook.md) — Tailscale + Filebeat setup and activation.

**4. Run analysis**
```bash
cd analysis
python parse_logs.py --input ../honeypot/sample-logs/cowrie.json
python geo_analysis.py --input ../honeypot/sample-logs/cowrie.json
python credential_analysis.py --input ../honeypot/sample-logs/cowrie.json
python command_tracker.py --input ../honeypot/sample-logs/cowrie.json
python mitre_mapping.py --input ../honeypot/sample-logs/cowrie.json
```

---

## 📄 Threat Intelligence Report

The full threat intelligence report is available at [docs/threat-report.pdf](docs/threat-report.pdf).

Report sections:
1. Executive Summary
2. Methodology
3. Attack Overview
4. Attacker Profiling
5. Credential Analysis
6. Command Analysis
7. MITRE ATT&CK Mapping
8. Indicators of Compromise
9. Recommendations
10. Conclusion

---

## ✍️ Author

**Seif Allah Nazmy**
3rd Year Computer Science Student — Cybersecurity Track
German International University, Cairo

[![LinkedIn](https://img.shields.io/badge/LinkedIn-seif--allah--nazmy-blue?style=flat&logo=linkedin)](https://www.linkedin.com/in/seif-allah-nazmy-a80a75241)
[![GitHub](https://img.shields.io/badge/GitHub-seif999999-black?style=flat&logo=github)](https://github.com/seif999999)

---

## ⚠️ Disclaimer

This project is for educational and research purposes only. The honeypot is deployed on infrastructure owned and controlled by the author. All data collected is used solely for threat intelligence research. Ensure compliance with your jurisdiction and cloud provider terms of service before replicating this setup.
