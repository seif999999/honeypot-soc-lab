# Wazuh SIEM Setup Guide

Complete deployment guide for the honeypot-soc-lab Wazuh stack on a Windows 11 analyst workstation. This document reflects the **production configuration** used in this project and is written so a security engineer can reproduce the environment from scratch.

---

## Overview

### What is Wazuh?

[Wazuh](https://wazuh.com/) is an open-source security platform that combines log analysis, intrusion detection, vulnerability detection, and compliance monitoring. In this lab it acts as the **Security Information and Event Management (SIEM)** layer: it receives honeypot telemetry, stores it for search and dashboards, and applies detection rules to generate alerts.

### What this setup achieves

| Goal | How Wazuh delivers it |
|------|------------------------|
| Centralize Cowrie logs | Filebeat on the Oracle VPS ships JSON logs to this host |
| Private ingestion | Traffic arrives over **Tailscale** — the manager is not exposed on the public internet |
| Visual analysis | **Wazuh Dashboard** at `https://localhost` for hunting and dashboards |
| Detection | Manager rules and decoders fire alerts on brute force, logins, commands |
| Lab reproducibility | Single-node **Docker Compose** stack, version **v4.9.0** |

### Deployment summary

| Component | Value |
|-----------|-------|
| Host | Lenovo Legion 5 — **Windows 11**, **16 GB RAM** |
| Install method | Official [wazuh-docker](https://github.com/wazuh/wazuh-docker) repository |
| Version | **v4.9.0** |
| Working directory | `C:\Users\smnam\wazuh-docker\single-node\` |
| Containers | `wazuh.manager`, `wazuh.indexer`, `wazuh.dashboard` |
| Dashboard URL | `https://localhost` |
| Default login | `admin` / `SecretPassword` |
| Tailscale IP (this host) | **100.104.212.88** |
| Filebeat ingestion port | **5044** (Logstash/Beats listener) |
| API port mapping | Host **56000** → container **55000** (Windows port fix) |

### Architecture in this lab

```
Oracle VPS (Cowrie + Filebeat)
        │
        │  Tailscale tunnel
        ▼
Legion 5 — 100.104.212.88:5044
        │
        ▼
┌───────────────────────────────────────┐
│  Docker: single-node (Wazuh v4.9.0)   │
│  wazuh.manager  ← Filebeat / Beats    │
│  wazuh.indexer  ← storage             │
│  wazuh.dashboard ← https://localhost  │
└───────────────────────────────────────┘
```

> **Warning:** Change the default `admin` password before any long-running or internet-adjacent deployment. This guide documents the initial lab credentials for reproducibility.

---

## Prerequisites

### Hardware and OS

| Requirement | This deployment |
|-------------|-----------------|
| OS | **Windows 11** (64-bit) |
| RAM | **16 GB** minimum recommended for Docker + Wazuh indexer |
| CPU | 4+ cores (Legion 5 meets this) |
| Disk | 50 GB+ free for Docker images and indexer data |

### Software

Install and verify **before** cloning Wazuh:

| Software | Version / notes |
|----------|-----------------|
| **Docker Desktop** | **29.0.1** (already installed in this lab) |
| **Git for Windows** | Latest from [git-scm.com](https://git-scm.com/download/win) |
| **WSL 2** (recommended) | Docker Desktop backend — enable in Docker Desktop settings |

### Docker Desktop checks

1. Start **Docker Desktop** and wait until the engine reports **Running**.
2. Open **PowerShell** and confirm:

```powershell
docker --version
docker compose version
```

Expected: Docker and Compose v2 commands succeed without error.

### Network

| Requirement | Purpose |
|-------------|---------|
| [Tailscale](https://tailscale.com/) account | Same tailnet as the honeypot VPS |
| Port **5044** available on the host | Filebeat ingestion from VPS |
| Port **443** / **5601** (dashboard) | Local HTTPS access — see `docker-compose.yml` |

### Repository access

```powershell
git --version
```

> **Warning:** Do not run Wazuh Docker on a machine that cannot sustain sustained RAM use. The indexer container is memory-heavy; close unnecessary applications during first startup.

---

## Wazuh Installation

All commands below assume **PowerShell** unless noted. Run Docker Desktop first.

### 1. Clone the official Wazuh Docker repository (v4.9.0)

Pin the stack to the version used in this lab at clone time (`v4.9.0` is a tag, not a branch — a detached HEAD after clone is expected):

```powershell
cd C:\Users\smnam
git clone https://github.com/wazuh/wazuh-docker.git -b v4.9.0
cd wazuh-docker
```

Verify:

```powershell
git describe --tags
```

Expected output includes `v4.9.0`.

### 2. Navigate to the single-node deployment

```powershell
cd C:\Users\smnam\wazuh-docker\single-node
```

All `docker compose` commands for this deployment run from this directory.

### 3. Generate SSL certificates for the indexer

Wazuh requires TLS certificates for the indexer and internal components. Generate them once before the first `up`:

```powershell
docker compose -f generate-indexer-certs.yml run --rm generator
```

Expected: certificate files appear under `wazuh-docker/single-node` (e.g. `wazuh-certs/` or paths referenced in `docker-compose.yml`).

> **Warning:** If you delete certificate volumes or change hostnames, regenerate certificates before starting the stack. Mismatched certs cause indexer bootstrap failures.

### 4. Apply the Windows port conflict fix (required)

See [Windows Port Conflict Fix](#windows-port-conflict-fix) — complete this **before** first startup on Windows.

### 5. Start the stack

```powershell
cd C:\Users\smnam\wazuh-docker\single-node
docker compose up -d
```

First startup may take **several minutes** while images pull and the indexer cluster initializes.

### 6. Confirm containers are created

```powershell
docker compose ps
```

Expected three containers in **running** or **healthy** state:

| Container name (typical) | Role |
|--------------------------|------|
| `wazuh.manager` | Analysis engine, rules, Logstash/Beats input |
| `wazuh.indexer` | OpenSearch-compatible storage |
| `wazuh.dashboard` | Web UI |

---

## Windows Port Conflict Fix

### The issue

On Windows, certain TCP port ranges are **excluded** from user applications and reserved by Hyper-V, WSL, or the Windows dynamic port range. In this lab, mapping the Wazuh API to host port **55000** failed because **55000** falls inside a reserved/excluded range.

Symptoms:

- `docker compose up` fails with a port bind error on `55000:55000`
- Or the API container exits immediately

Check Windows excluded ports:

```powershell
netsh interface ipv4 show excludedportrange protocol=tcp
```

Look for a range that includes **55000** (e.g. `54991–55090`).

### The fix

Edit `docker-compose.yml` in the single-node directory and change the **host** side of the Wazuh API mapping from **55000** to **56000**, while keeping the **container** port at **55000**:

**Before:**

```yaml
ports:
  - "55000:55000"
```

**After (as deployed in this lab):**

```yaml
ports:
  - "56000:55000"
```

Full path to the file:

```
C:\Users\smnam\wazuh-docker\single-node\docker-compose.yml
```

Apply the edit with your editor, then recreate the stack:

```powershell
cd C:\Users\smnam\wazuh-docker\single-node
docker compose down
docker compose up -d
```

### Accessing the API after the change

| Setting | Value |
|---------|-------|
| API from Windows host | `https://localhost:56000` |
| API inside Docker network | port **55000** (unchanged) |

> **Warning:** Document port **56000** for any scripts or API clients that assume the default `55000` on the host.

---

## Accessing the Dashboard

### URL and credentials

| Field | Value |
|-------|-------|
| URL | **https://localhost** |
| Username | `admin` |
| Password | `SecretPassword` |

Open in a browser:

```
https://localhost
```

### First login

1. Accept the browser **certificate warning** (self-signed / lab-generated certs are normal for local Docker).
2. Enter `admin` and `SecretPassword`.
3. On first login, Wazuh may prompt you to **change the password** — recommended for any non-disposable lab.

### What you see

| Area | Description |
|------|-------------|
| **Home / Overview** | Summary of agents, alerts, and cluster health |
| **Discover** | Search indexed alerts and archives |
| **Security events** | Alert feed from manager rules |
| **Modules** | Compliance, vulnerability, and integrity modules (optional) |
| **Indexer management** | Index patterns and cluster status |

### Index patterns (post-ingestion)

After Cowrie logs arrive, confirm or create index patterns for:

- `wazuh-alerts-*`
- `wazuh-archives-*` (if archival is enabled)

> **Warning:** If the dashboard loads but shows no data, the stack may be healthy while **no logs have been ingested yet**. Complete [Receiving Logs from Honeypot](#receiving-logs-from-honeypot) and start Filebeat on the VPS on analysis day.

---

## Tailscale Setup on Windows

Tailscale connects the Legion laptop and the Oracle honeypot VPS on a private mesh network so Filebeat can ship logs to **100.104.212.88** without exposing port **5044** to the internet.

### 1. Install Tailscale on Windows

Download and install from [tailscale.com/download/windows](https://tailscale.com/download/windows), or:

```powershell
winget install Tailscale.Tailscale
```

### 2. Sign in to the same tailnet as the VPS

1. Launch **Tailscale** from the system tray.
2. **Log in** with the same account/organization used on the honeypot VPS.
3. Confirm the machine appears in the [Tailscale admin console](https://login.tailscale.com/admin/machines).

### 3. Verify the Legion Tailscale IP

```powershell
tailscale ip -4
```

Expected (this deployment):

```
100.104.212.88
```

Also check status:

```powershell
tailscale status
```

The honeypot VPS should appear as **connected** in the peer list.

### 4. Confirm this IP matches honeypot Filebeat config

On the VPS, Filebeat must point to this address (see [honeypot/setup.md](../honeypot/setup.md)):

```yaml
output.logstash:
  hosts: ["100.104.212.88:5044"]
```

> **Warning:** Tailscale IPs are stable per machine but can change if you re-enroll a device. Update Filebeat and documentation if the Legion IP changes.

---

## Receiving Logs from Honeypot

### How ingestion works

1. **Cowrie** writes JSON lines to `cowrie.json` on the VPS.
2. **Filebeat** tails that file and sends events to the Logstash/Beats listener.
3. **Wazuh manager** (in Docker) receives data on port **5044**.
4. Events are decoded, matched against rules, and stored in the **indexer** for the dashboard.

### Listener details

| Setting | Value |
|---------|-------|
| Protocol | Beats / Logstash (Filebeat `output.logstash`) |
| Host (Tailscale) | **100.104.212.88** |
| Port | **5044** |
| Source | Honeypot VPS over Tailscale only |

### Verify port 5044 is published in Docker

From the single-node directory, inspect the manager service ports:

```powershell
cd C:\Users\smnam\wazuh-docker\single-node
docker compose ps
docker port wazuh.manager
```

Confirm **5044** is mapped to the host (exact mapping depends on `docker-compose.yml` for v4.9.0). If not exposed, add under the `wazuh.manager` service:

```yaml
ports:
  - "5044:5044"
```

Then restart:

```powershell
docker compose down
docker compose up -d
```

### Windows Firewall

Allow inbound **5044** from Tailscale interfaces only (recommended):

1. **Windows Defender Firewall → Advanced settings → Inbound Rules → New Rule**
2. Port **TCP 5044**
3. Scope: restrict to Tailscale subnet (e.g. `100.64.0.0/10`) if your environment supports it

> **Warning:** Do not forward port **5044** on your home router to the internet. Ingestion should occur **only** over Tailscale.

### Start log collection (analysis day)

On the **VPS** (not on Windows), start Filebeat when ready to collect:

```bash
sudo systemctl start filebeat
sudo systemctl status filebeat
```

On the **Legion**, watch manager logs:

```powershell
cd C:\Users\smnam\wazuh-docker\single-node
docker compose logs -f wazuh.manager
```

### Custom rules and decoders (repo)

Place custom Wazuh rules and decoders in this repository under:

```
honeypot-soc-lab/siem/rules/
```

Mount or copy them into the manager container per [Wazuh documentation](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml.html) when you extend detection beyond defaults.

---

## Starting and Stopping Wazuh

All commands must be run from the single-node directory:

```
C:\Users\smnam\wazuh-docker\single-node\
```

### Start Wazuh

```powershell
cd C:\Users\smnam\wazuh-docker\single-node
docker compose up -d
```

### Stop Wazuh

```powershell
cd C:\Users\smnam\wazuh-docker\single-node
docker compose down
```

`docker compose down` stops and removes containers but **retains volumes** (indexer data persists unless volumes are pruned).

### Restart after configuration changes

```powershell
cd C:\Users\smnam\wazuh-docker\single-node
docker compose down
docker compose up -d
```

### View logs without stopping the stack

```powershell
docker compose logs -f wazuh.manager
docker compose logs -f wazuh.indexer
docker compose logs -f wazuh.dashboard
```

> **Warning:** Always `cd` to `single-node` before compose commands. Running from the wrong directory will fail or start the wrong project.

---

## Verification

### 1. Docker Desktop and Compose

```powershell
docker info
docker compose version
```

Docker must report a running engine.

### 2. All containers running

```powershell
cd C:\Users\smnam\wazuh-docker\single-node
docker compose ps
```

| Check | Expected |
|-------|----------|
| `wazuh.manager` | State **running** |
| `wazuh.indexer` | State **running** / healthy |
| `wazuh.dashboard` | State **running** |

### 3. Container health details

```powershell
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
```

### 4. Dashboard reachable

- Open `https://localhost`
- Log in with `admin` / `SecretPassword`
- Confirm no persistent **red** cluster health indicators on the home page

### 5. API on remapped port (optional)

```powershell
curl -k -u admin:SecretPassword https://localhost:56000
```

A JSON response or auth challenge indicates the API is listening on the host-mapped port **56000**.

### 6. Tailscale connectivity

```powershell
tailscale ip -4
ping 100.104.212.88
```

From the **VPS** (after Tailscale is up on both sides):

```bash
nc -zv 100.104.212.88 5044
```

Expected: connection succeeded (when Wazuh is running and port 5044 is open).

### 7. End-to-end log test (analysis day)

| Step | Action |
|------|--------|
| 1 | Wazuh running: `docker compose up -d` |
| 2 | Start Filebeat on VPS: `sudo systemctl start filebeat` |
| 3 | Generate honeypot traffic (SSH to port 22 on VPS) |
| 4 | Wazuh Dashboard → **Discover** → search recent events |
| 5 | Confirm Cowrie-related fields (`src_ip`, `username`, `eventid`) appear |

---

## Troubleshooting

### Docker / startup

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `port is already allocated` | Another service or reserved range | See [Windows Port Conflict Fix](#windows-port-conflict-fix); change host port mapping |
| Bind error on **55000** | Windows excluded port range | Map `56000:55000` in `docker-compose.yml` |
| `Cannot connect to Docker daemon` | Docker Desktop not running | Start Docker Desktop; wait for Ready |
| Indexer exits / restart loop | Insufficient RAM or bad certs | Free RAM; regenerate certs with `generate-indexer-certs.yml` |
| Slow first start | Large image pull | Wait 5–15 minutes; `docker compose logs -f wazuh.indexer` |

### Dashboard

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| Browser certificate error | Self-signed TLS | Proceed for lab only; trust cert in browser if required |
| Login fails | Wrong password | Use `admin` / `SecretPassword` or password set on first login |
| Dashboard up, no events | Filebeat stopped or wrong IP | Start Filebeat on VPS; verify `100.104.212.88:5044` |
| Cluster red | Indexer not ready | `docker compose logs wazuh.indexer`; wait for green health |

### Log ingestion

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `nc -zv 100.104.212.88 5044` fails from VPS | Wazuh down, firewall, or port not mapped | `docker compose up -d`; check `docker port`; Windows Firewall |
| Filebeat connection refused | Manager not listening on 5044 | Expose `5044:5044` on manager; restart stack |
| Logs in Filebeat but not Dashboard | Decoder/index pattern | Check manager logs; verify index pattern `wazuh-alerts-*` |
| Tailscale works, no logs | Wrong Tailscale IP on VPS | `tailscale ip -4` on Legion; update Filebeat `hosts` |

### Windows-specific

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| WSL / Hyper-V port conflicts | Dynamic port exclusion | `netsh interface ipv4 show excludedportrange protocol=tcp`; remap ports |
| High memory usage | Indexer + Docker | Stop unused containers; increase WSL memory limit in `.wslconfig` if needed |

### Useful diagnostic commands

```powershell
cd C:\Users\smnam\wazuh-docker\single-node
docker compose ps
docker compose logs --tail=100 wazuh.manager
docker compose logs --tail=100 wazuh.indexer
netsh interface ipv4 show excludedportrange protocol=tcp
tailscale status
```

### Nuclear reset (lab only)

> **Warning:** This deletes indexed alert data.

```powershell
cd C:\Users\smnam\wazuh-docker\single-node
docker compose down -v
docker compose -f generate-indexer-certs.yml run --rm generator
docker compose up -d
```

---

## Maintenance notes

| Task | Command / location |
|------|-------------------|
| Upgrade version | New git tag in `wazuh-docker`, review release notes, backup volumes first |
| Backup indexer data | Export Docker volumes per Wazuh backup documentation |
| Change admin password | Dashboard → user menu, or Wazuh API |
| Repo custom rules | `honeypot-soc-lab/siem/rules/` |

---

## Related Documentation

- [Architecture](../docs/architecture.md) — full honeypot-to-SIEM pipeline
- [Runbook](../docs/runbook.md) — operational checklists
- [Honeypot setup](../honeypot/setup.md) — Cowrie, Filebeat, Tailscale on VPS
- [Threat report template](../docs/threat-report-template.md)

---

## References

- [Wazuh documentation](https://documentation.wazuh.com/)
- [Wazuh Docker repository](https://github.com/wazuh/wazuh-docker)
- [Wazuh Docker deployment guide](https://documentation.wazuh.com/current/deployment-options/docker/index.html)
- [Tailscale for Windows](https://tailscale.com/download/windows)
- [Docker Desktop for Windows](https://docs.docker.com/desktop/setup/install/windows-install/)
