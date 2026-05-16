# Threat Intelligence Report Template

**Project:** honeypot-soc-lab  
**Classification:** TLP:GREEN _(adjust as appropriate)_  
**Report ID:** HSL-YYYY-MM-###  
**Version:** 1.0

---

## 1. Cover Page

| Field | Value |
|-------|-------|
| **Report Title** | Honeypot Threat Intelligence Report — [Month YYYY] |
| **Author(s)** | _Name, role_ |
| **Organization** | _Organization / lab name_ |
| **Date Published** | YYYY-MM-DD |
| **Reporting Period** | YYYY-MM-DD to YYYY-MM-DD |
| **Honeypot Sensor** | cowrie-oracle-vps-01 |
| **Distribution** | _Internal / partners / public summary_ |

---

## 2. Executive Summary

> _One-page maximum. Written for non-technical leadership._

**Situation:** _Brief description of honeypot exposure and observation window._

**Key takeaways:**

- _Total sessions / unique IPs observed_
- _Primary threat types (e.g., credential stuffing, botnet propagation)_
- _Highest-risk finding (e.g., successful logins, malware downloads)_
- _Recommended immediate actions (1–3 bullets)_

**Risk rating:** ☐ Low  ☐ Medium  ☐ High  ☐ Critical

---

## 3. Methodology

### 3.1 Collection Environment

| Component | Detail |
|-----------|--------|
| Honeypot | Cowrie on Oracle Cloud VPS (Ubuntu 22.04) |
| SIEM | Wazuh (local), ingestion via Filebeat / agent over Tailscale |
| Log source | `cowrie.json` |
| Analysis tools | `analysis/*.py` scripts in this repository |

### 3.2 Data Handling

- Log retention period: _e.g., 90 days_
- PII / credential handling: _hashed / redacted / not shared_
- Legal and ethical constraints: _authorized research only_

### 3.3 Analysis Process

1. Export or query logs for reporting period
2. Run `parse_logs.py`, `geo_analysis.py`, `credential_analysis.py`, `command_tracker.py`, `mitre_mapping.py`
3. Correlate with Wazuh alerts and manual session review
4. Map behaviors to MITRE ATT&CK
5. Draft IOCs and recommendations

### 3.4 Limitations

- _Honeypot interaction is simulated; commands may not reflect full real-world TTPs_
- _GeoIP accuracy depends on ipinfo.io / database freshness_
- _Sampling bias: internet-wide scanners vs. targeted actors_

---

## 4. Attack Overview

### 4.1 Volume Metrics

| Metric | Count |
|--------|-------|
| Total connection events | |
| Unique source IP addresses | |
| Failed login attempts | |
| Successful logins (Cowrie) | |
| Commands executed | |
| File download attempts | |

### 4.2 Timeline

```
[Insert timeline chart or table: date → session count / notable events]
```

### 4.3 Attack Categories Observed

| Category | Percentage | Notes |
|----------|------------|-------|
| Automated scanning | | |
| Credential stuffing | | |
| Manual exploration | | |
| Malware staging | | |
| Other | | |

---

## 5. Attacker Profiling

### 5.1 Geographic Distribution

| Country | Sessions | % of Total |
|---------|----------|------------|
| | | |
| | | |

_Top ASN / hosting providers:_

| ASN | Organization | Count |
|-----|--------------|-------|
| | | |

### 5.2 Source IP Highlights

| IP Address | Country | Sessions | Notable Behavior |
|------------|---------|----------|------------------|
| | | | |

### 5.3 Persistence and Repeat Actors

- _IPs appearing across multiple days_
- _Credential or command patterns linking sessions_

---

## 6. Credential Analysis

### 6.1 Top Usernames Attempted

| Rank | Username | Attempt Count |
|------|----------|---------------|
| 1 | | |
| 2 | | |
| 3 | | |

### 6.2 Top Passwords Attempted

| Rank | Password | Attempt Count |
|------|----------|---------------|
| 1 | | |
| 2 | | |
| 3 | | |

### 6.3 Username / Password Pairs (Top Combinations)

| Username | Password | Count |
|----------|----------|-------|
| | | |

### 6.4 Observations

- _Default credentials (root/root, admin/admin)?_
- _Targeted vs. dictionary spray patterns?_
- _Successful login credentials (if any): REDACTED in public versions_

---

## 7. Command Analysis

### 7.1 Most Frequent Commands (Post-Login)

| Rank | Command | Count |
|------|---------|-------|
| 1 | | |
| 2 | | |
| 3 | | |

### 7.2 Command Categories

| Category | Examples | Count |
|----------|----------|-------|
| Reconnaissance | `uname -a`, `whoami` | |
| Download / execution | `wget`, `curl \| bash` | |
| Persistence | cron, systemd | |
| Cleanup | `history -c` | |

### 7.3 Notable Sessions

**Session ID:** _uuid_  
**Source IP:**  
**Summary:** _Narrative of interesting command sequence_

---

## 8. MITRE ATT&CK Mapping

| Technique ID | Technique Name | Tactic | Evidence (Event / Command) | Count |
|--------------|------------------|--------|------------------------------|-------|
| T1110 | Brute Force | Credential Access | `cowrie.login.failed` | |
| T1078 | Valid Accounts | Defense Evasion | `cowrie.login.success` | |
| T1059 | Command and Scripting Interpreter | Execution | `cowrie.command.input` | |
| | | | | |

**ATT&CK Navigator layer:** _Link or attach JSON layer file if published_

---

## 9. Indicators of Compromise (IOCs)

### 9.1 IP Addresses

```
# Format: ip|first_seen|last_seen|comment
```

### 9.2 File Hashes (if applicable)

| SHA256 | Filename | Context |
|--------|----------|---------|
| | | |

### 9.3 URLs / Domains

| Indicator | Type | Context |
|-----------|------|---------|
| | domain / url | |

### 9.4 YARA / Sigma (Optional)

```yaml
# Paste or reference detection rule
```

---

## 10. Recommendations

### 10.1 For Defenders

1. _Block or monitor top hostile ASNs / IPs at perimeter_
2. _Disable password SSH; enforce keys and MFA_
3. _Deploy deception / honeypot telemetry to internal SOC_

### 10.2 For This Lab

1. _Tune Wazuh rules: rule ID, threshold changes_
2. _Extend Cowrie output capture (e.g., virustotal integration)_
3. _Schedule automated monthly report generation_

### 10.3 Detection Engineering

| Priority | Rule / Control | Owner | Target Date |
|----------|----------------|-------|-------------|
| High | | | |
| Medium | | | |

---

## 11. Conclusion

_Summarize overall threat landscape observed during the period, whether objectives (research questions) were met, and planned next steps for the honeypot-soc-lab program._

**Next report date:** YYYY-MM-DD

---

## Appendices (Optional)

- **Appendix A:** Raw statistics export (CSV)
- **Appendix B:** Wazuh alert samples (sanitized)
- **Appendix C:** Glossary
- **Appendix D:** References and tools versions

---

## Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | YYYY-MM-DD | | Initial release |
