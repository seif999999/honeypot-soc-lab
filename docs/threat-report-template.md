# Threat Intelligence Report
## SSH Honeypot Analysis — Frankfurt Deployment

| | |
|---|---|
| **Author** | Seif Allah Nazmy |
| **Date** | May 28, 2026 |
| **Version** | 1.0 |
| **Classification** | Public |

---

## 1. Executive Summary

Over a 14-day period from May 14 to May 28, 2026, an SSH honeypot was deployed on a public cloud server in Frankfurt, Germany to attract and analyze real-world cyberattacks. The honeypot recorded **[TOTAL EVENTS]** attack events from **[UNIQUE IPs]** unique IP addresses across **[NUMBER]** countries. The majority of activity consisted of automated credential stuffing attacks targeting common username and password combinations. Post-login analysis revealed attacker behavior consistent with **[MAIN GOAL — e.g. cryptominer deployment / botnet recruitment]**. This report documents the attack patterns, attacker techniques, and security recommendations derived from the collected data.

---

## 2. Methodology

### 2.1 Honeypot Setup
- **Tool:** Cowrie SSH Honeypot v2.x
- **Host:** Oracle Cloud Free Tier VM — Ubuntu 22.04, Frankfurt Germany
- **Public IP:** 158.180.54.157
- **Exposed ports:** TCP 22 (redirected to Cowrie), TCP 23 (Telnet)
- **Collection period:** May 14, 2026 — May 28, 2026 (14 days)

### 2.2 Data Collection
Cowrie logged all interaction in JSON format to:
`/home/cowrie/cowrie/var/log/cowrie/cowrie.json`

Each event captures: timestamp, attacker IP, event type, credentials attempted, commands executed, and files downloaded.

### 2.3 Analysis Tools
| Tool | Purpose |
|---|---|
| parse_logs.py | Log parsing and event extraction |
| geo_analysis.py | IP to country mapping via ipinfo.io API |
| credential_analysis.py | Username and password frequency analysis |
| command_tracker.py | Post-login command frequency analysis |
| mitre_mapping.py | MITRE ATT&CK technique mapping |
| Wazuh SIEM | Real-time alerting and dashboard visualization |

---

## 3. Attack Overview

| Metric | Value |
|---|---|
| Total events | [INSERT] |
| Unique attacking IPs | [INSERT] |
| Countries of origin | [INSERT] |
| Collection period | 14 days |
| Peak attack day | [INSERT] |
| Peak attack hour (UTC) | [INSERT] |
| Unique usernames tried | [INSERT] |
| Unique passwords tried | [INSERT] |
| Post-login sessions | [INSERT] |
| Malware download attempts | [INSERT] |

### 3.1 Attack Volume Timeline
![Attack Timeline](../analysis/attack_timeline.png)

---

## 4. Attacker Profiling

### 4.1 Top 10 Countries of Origin
| Rank | Country | Attack Count | % of Total |
|---|---|---|---|
| 1 | [INSERT] | [INSERT] | [INSERT] |
| 2 | [INSERT] | [INSERT] | [INSERT] |
| 3 | [INSERT] | [INSERT] | [INSERT] |
| 4 | [INSERT] | [INSERT] | [INSERT] |
| 5 | [INSERT] | [INSERT] | [INSERT] |
| 6 | [INSERT] | [INSERT] | [INSERT] |
| 7 | [INSERT] | [INSERT] | [INSERT] |
| 8 | [INSERT] | [INSERT] | [INSERT] |
| 9 | [INSERT] | [INSERT] | [INSERT] |
| 10 | [INSERT] | [INSERT] | [INSERT] |

### 4.2 Top 10 Attacking IPs
| Rank | IP Address | Country | Attack Count | Known Malicious |
|---|---|---|---|---|
| 1 | [INSERT] | [INSERT] | [INSERT] | [YES/NO] |
| 2 | [INSERT] | [INSERT] | [INSERT] | [YES/NO] |
| 3 | [INSERT] | [INSERT] | [INSERT] | [YES/NO] |
| 4 | [INSERT] | [INSERT] | [INSERT] | [YES/NO] |
| 5 | [INSERT] | [INSERT] | [INSERT] | [YES/NO] |
| 6 | [INSERT] | [INSERT] | [INSERT] | [YES/NO] |
| 7 | [INSERT] | [INSERT] | [INSERT] | [YES/NO] |
| 8 | [INSERT] | [INSERT] | [INSERT] | [YES/NO] |
| 9 | [INSERT] | [INSERT] | [INSERT] | [YES/NO] |
| 10 | [INSERT] | [INSERT] | [INSERT] | [YES/NO] |

---

## 5. Credential Analysis

### 5.1 Top 20 Usernames Attempted
| Rank | Username | Attempts |
|---|---|---|
| 1 | [INSERT] | [INSERT] |
| 2 | [INSERT] | [INSERT] |
| 3 | [INSERT] | [INSERT] |
| 4 | [INSERT] | [INSERT] |
| 5 | [INSERT] | [INSERT] |
| 6 | [INSERT] | [INSERT] |
| 7 | [INSERT] | [INSERT] |
| 8 | [INSERT] | [INSERT] |
| 9 | [INSERT] | [INSERT] |
| 10 | [INSERT] | [INSERT] |
| 11 | [INSERT] | [INSERT] |
| 12 | [INSERT] | [INSERT] |
| 13 | [INSERT] | [INSERT] |
| 14 | [INSERT] | [INSERT] |
| 15 | [INSERT] | [INSERT] |
| 16 | [INSERT] | [INSERT] |
| 17 | [INSERT] | [INSERT] |
| 18 | [INSERT] | [INSERT] |
| 19 | [INSERT] | [INSERT] |
| 20 | [INSERT] | [INSERT] |

### 5.2 Top 20 Passwords Attempted
| Rank | Password | Attempts |
|---|---|---|
| 1 | [INSERT] | [INSERT] |
| 2 | [INSERT] | [INSERT] |
| 3 | [INSERT] | [INSERT] |
| 4 | [INSERT] | [INSERT] |
| 5 | [INSERT] | [INSERT] |
| 6 | [INSERT] | [INSERT] |
| 7 | [INSERT] | [INSERT] |
| 8 | [INSERT] | [INSERT] |
| 9 | [INSERT] | [INSERT] |
| 10 | [INSERT] | [INSERT] |
| 11 | [INSERT] | [INSERT] |
| 12 | [INSERT] | [INSERT] |
| 13 | [INSERT] | [INSERT] |
| 14 | [INSERT] | [INSERT] |
| 15 | [INSERT] | [INSERT] |
| 16 | [INSERT] | [INSERT] |
| 17 | [INSERT] | [INSERT] |
| 18 | [INSERT] | [INSERT] |
| 19 | [INSERT] | [INSERT] |
| 20 | [INSERT] | [INSERT] |

### 5.3 Observations
[INSERT — patterns noticed in credentials, e.g. default router passwords, common wordlist patterns, leaked breach credentials]

---

## 6. Command Analysis

### 6.1 Post-Login Command Frequency
| Rank | Command | Frequency | Purpose |
|---|---|---|---|
| 1 | [INSERT] | [INSERT] | [INSERT] |
| 2 | [INSERT] | [INSERT] | [INSERT] |
| 3 | [INSERT] | [INSERT] | [INSERT] |
| 4 | [INSERT] | [INSERT] | [INSERT] |
| 5 | [INSERT] | [INSERT] | [INSERT] |
| 6 | [INSERT] | [INSERT] | [INSERT] |
| 7 | [INSERT] | [INSERT] | [INSERT] |
| 8 | [INSERT] | [INSERT] | [INSERT] |
| 9 | [INSERT] | [INSERT] | [INSERT] |
| 10 | [INSERT] | [INSERT] | [INSERT] |

### 6.2 Attacker Behavior Summary
[INSERT — describe what attackers were trying to do after logging in]

### 6.3 Notable Session Replay
**Session 1 — [INSERT DATE] — IP: [INSERT]**
```
[INSERT — paste actual attacker commands from session]
```
**Analysis:** [INSERT — what this attacker was doing and why]

---

## 7. MITRE ATT&CK Mapping

| Observed Behavior | MITRE ID | Technique Name | Frequency |
|---|---|---|---|
| SSH brute force login attempts | T1110.001 | Brute Force: Password Guessing | [INSERT] |
| System info commands (whoami, uname) | T1082 | System Information Discovery | [INSERT] |
| File download via wget/curl | T1105 | Ingress Tool Transfer | [INSERT] |
| Adding SSH authorized keys | T1098 | Account Manipulation | [INSERT] |
| Cryptominer deployment | T1496 | Resource Hijacking | [INSERT] |
| [INSERT additional observed behavior] | [INSERT] | [INSERT] | [INSERT] |

---

## 8. Indicators of Compromise

### 8.1 Malicious IP Addresses
| IP Address | Country | Attack Count | AbuseIPDB Score |
|---|---|---|---|
| [INSERT] | [INSERT] | [INSERT] | [INSERT] |

### 8.2 Malware Download URLs
| URL | First Seen | File Type |
|---|---|---|
| [INSERT] | [INSERT] | [INSERT] |

### 8.3 File Hashes
| Hash (SHA256) | File Name | Type |
|---|---|---|
| [INSERT] | [INSERT] | [INSERT] |

---

## 9. Recommendations

1. **Disable password authentication on SSH** — All observed attacks used password brute force. Enforcing key-only authentication eliminates this attack vector entirely.

2. **Implement fail2ban or equivalent** — Automatically block IPs after a configurable number of failed login attempts. This reduces brute force effectiveness dramatically.

3. **Move SSH to a non-standard port** — Reduces automated scanner traffic significantly. Most bots only scan port 22.

4. **Monitor for post-compromise indicators** — Deploy a SIEM with rules detecting system enumeration commands (whoami, uname, id) which indicate a successful compromise.

5. **Threat feed integration** — Cross-reference all inbound connection IPs against threat intelligence feeds such as AbuseIPDB in real time to detect known malicious actors before they attempt authentication.

---

## 10. Conclusion

Over 14 days of operation, the honeypot demonstrated that internet-exposed SSH services face immediate and continuous attack from automated scanners and botnets. The collected data confirms that attackers primarily rely on credential stuffing using common username and password combinations, and that successful logins are rapidly followed by system enumeration and attempts to deploy malicious payloads. The findings underscore the importance of strong authentication controls, proactive monitoring, and threat intelligence integration in any production environment.

---

## Appendix

### A. Tools Used
| Tool | Version | Purpose |
|---|---|---|
| Cowrie | Latest | SSH Honeypot |
| Wazuh | 4.9.0 | SIEM and alerting |
| Filebeat | 8.x | Log shipping |
| Tailscale | Latest | Secure tunnel |
| Python | 3.10 | Log analysis scripts |

### B. References
- MITRE ATT&CK Framework: https://attack.mitre.org
- Cowrie Documentation: https://cowrie.readthedocs.io
- Wazuh Documentation: https://documentation.wazuh.com
- AbuseIPDB: https://www.abuseipdb.com
