# Operations Runbook — honeypot-soc-lab

Step-by-step procedures for deploying, connecting, and verifying the honeypot-to-SIEM pipeline.

---

## Prerequisites

> _Placeholder — complete before starting deployment._

### Accounts and Access

- [ ] Oracle Cloud account with Always Free compute available
- [ ] Tailscale account; ability to install on VPS and local machine
- [ ] (Optional) ipinfo.io API token for geo analysis scripts

### Local Workstation

- [ ] Ubuntu 22.04+ or WSL2 with sufficient RAM (8 GB+ recommended for Wazuh)
- [ ] Docker and Docker Compose **or** native Wazuh installation
- [ ] Python 3.10+ with `pip` for analysis scripts
- [ ] Git, SSH client, text editor

### Network

- [ ] Home/router allows outbound connections (no inbound required for SIEM)
- [ ] Tailscale installed and authenticated on both endpoints
- [ ] Document Tailscale IPs: VPS `100.x.x.x` ___ | Local `100.x.x.x` ___

### Security Baseline

- [ ] Dedicated cloud project / compartment for honeypot only
- [ ] SSH key-based access to VPS; password auth disabled for admin
- [ ] Incident contact documented for abuse reports

---

## Honeypot Setup

> _Placeholder — see [honeypot/setup.md](../honeypot/setup.md) for full Cowrie documentation._

### Summary Checklist

- [ ] Provision Oracle Cloud VPS (Ubuntu 22.04)
- [ ] Apply system updates and configure UFW (allow 22, optional 23)
- [ ] Create `cowrie` system user; clone and install Cowrie
- [ ] Configure `cowrie.cfg` (hostname, sensor name, logging paths)
- [ ] Set iptables redirect: public 22 → Cowrie listener port
- [ ] Enable and start Cowrie via systemd
- [ ] Verify `cowrie.json` receives events after test SSH attempt

### Verification

```bash
# On VPS — confirm Cowrie is listening and logging
sudo systemctl status cowrie
tail -f /home/cowrie/cowrie/var/log/cowrie/cowrie.json
```

---

## SIEM Setup

> _Placeholder — see [siem/setup.md](../siem/setup.md) for full Wazuh documentation._

### Summary Checklist

- [ ] Install Wazuh manager, indexer, and dashboard (Docker or packages)
- [ ] Complete initial admin password and TLS setup
- [ ] Import custom decoders/rules from `siem/rules/`
- [ ] Create honeypot-specific dashboards and index patterns
- [ ] Confirm Dashboard accessible at `https://localhost` (or Tailscale IP)

### Verification

```bash
# On local machine — check Wazuh services
sudo systemctl status wazuh-manager   # if native install
# Or: docker compose ps               # if Docker stack
```

---

## Connecting the Pipeline

> _Placeholder — Filebeat + Tailscale + Wazuh agent integration._

### Tailscale

- [ ] Install Tailscale on VPS and local host; join same tailnet
- [ ] Record Tailscale IPs in runbook or secure notes
- [ ] (Optional) Configure Tailscale ACLs to allow VPS → manager ports only

### Log Shipping Options

**Option A — Wazuh Agent on VPS (recommended)**

- [ ] Install Wazuh agent on VPS
- [ ] Enroll agent to manager using manager Tailscale IP
- [ ] Configure `localfile` or integration to read `cowrie.json`

**Option B — Filebeat to Manager**

- [ ] Install Filebeat on VPS
- [ ] Configure output to Wazuh/logstash endpoint on manager Tailscale IP
- [ ] Enable JSON parsing for Cowrie log path

### Checklist

- [ ] Agent/Filebeat service enabled on boot
- [ ] Firewall on VPS allows outbound to manager Tailscale IP:1514
- [ ] Test event appears in Wazuh Dashboard within 5 minutes of honeypot activity

---

## Verification Steps

> _Placeholder — end-to-end validation after full deployment._

### 1. Honeypot Liveness

| Step | Expected Result |
|------|-----------------|
| SSH to VPS public IP (intentional test) | Connection to Cowrie banner |
| New line in `cowrie.json` | `cowrie.session.connect` event |

### 2. Log Shipping

| Step | Expected Result |
|------|-----------------|
| Trigger failed login on honeypot | `cowrie.login.failed` in raw log |
| Check agent/Filebeat status | Running, no errors in journal |
| Search Wazuh Dashboard | Event indexed with source IP and username |

### 3. Detection Rules

| Step | Expected Result |
|------|-----------------|
| Multiple failed logins from same IP | Brute-force rule alert (if configured) |
| Successful Cowrie login (if simulated) | High-severity alert |

### 4. Analysis Scripts

```bash
cd analysis/
python parse_logs.py --input ../honeypot/sample-logs/cowrie.json
python credential_analysis.py --input ../honeypot/sample-logs/cowrie.json
```

| Step | Expected Result |
|------|-----------------|
| Scripts run without error | Summary output printed |
| Counts match Dashboard | Rough parity on session/login counts |

### 5. Operational Health (Weekly)

- [ ] Disk usage on VPS log partition < 80%
- [ ] Cowrie and agent services active
- [ ] Wazuh indexer cluster green
- [ ] Review top alerts and update threat report draft

---

## Troubleshooting Quick Reference

| Symptom | Check |
|---------|-------|
| No logs on VPS | Cowrie service, file permissions, disk full |
| Logs on VPS but not in Wazuh | Agent enrollment, Tailscale connectivity, wrong manager IP |
| JSON not parsed | Decoder configuration, `log_format` in agent localfile |
| Dashboard empty | Index pattern, time range, indexer disk |

---

## Rollback

1. Stop Cowrie: `sudo systemctl stop cowrie`
2. Remove iptables redirect to restore normal SSH (if needed)
3. Disable Wazuh agent/Filebeat on VPS
4. Archive logs before decommission: `tar czf cowrie-logs-$(date +%F).tar.gz ...`

---

## Contacts and Escalation

| Role | Contact |
|------|---------|
| Lab owner | _name / email_ |
| Cloud provider abuse | Oracle Cloud support console |
| Tailscale admin | _tailnet admin_ |
