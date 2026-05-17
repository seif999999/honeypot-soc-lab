# Cowrie SSH Honeypot Setup Guide

Complete deployment guide for the honeypot-soc-lab Cowrie sensor on Oracle Cloud Infrastructure (OCI). This document reflects the **production configuration** used in this project and is written so a security engineer can reproduce the environment from scratch.

---

## Overview

This honeypot exposes **TCP port 22** on the public internet. Traffic hitting port 22 is transparently redirected to **Cowrie** listening on **port 2222**, which emulates a vulnerable SSH server. Legitimate administration uses **real SSH on port 22222**.

| Component | Value |
|-----------|-------|
| Cloud provider | Oracle Cloud **Always Free** tier (no cost) |
| Region | **Germany Central (Frankfurt)** |
| Instance shape | `VM.Standard.E2.1.Micro` — 1 OCPU, 1 GB RAM |
| OS | Ubuntu **22.04** LTS |
| Honeypot software | [Cowrie](https://github.com/cowrie/cowrie) |
| Install path | `/home/cowrie/cowrie/` |
| Log file | `/home/cowrie/cowrie/var/log/cowrie/cowrie.json` |
| Decoy hostname | `webserver01` |
| Command capture | `interact_enabled = true` |
| Log shipping | Filebeat → Wazuh at `100.104.212.88:5044` (Tailscale) |

### Port layout

| Port | Purpose | Exposed to internet |
|------|---------|---------------------|
| **22** | Public SSH (iptables → Cowrie **2222**) | Yes |
| **2222** | Cowrie backend listener | Yes (Oracle security list) |
| **22222** | Real Ubuntu SSH (`sshd`) for admin | Yes (restrict by IP if possible) |

```
Internet ──► :22 ──[iptables NAT]──► Cowrie :2222
Admin    ──► :22222 ──────────────► OpenSSH (ubuntu user)
Filebeat ──► Tailscale ───────────► Wazuh 100.104.212.88:5044
```

> **Warning:** This VPS is intentionally exposed to hostile traffic. Do not store credentials, private keys, or production data on this host. Use a dedicated OCI compartment and SSH keys only.

---

## Prerequisites

### Accounts and tools

- [Oracle Cloud Free Tier](https://www.oracle.com/cloud/free/) account with Always Free capacity available
- SSH client on Windows (OpenSSH built into Windows 10/11, or PuTTY)
- OCI SSH key pair (`.key` or `.pem`) generated during instance creation
- Tailscale account (same tailnet as the Wazuh SIEM host)
- Wazuh manager listening on **5044** at Tailscale IP `100.104.212.88` (configured separately — see [siem/setup.md](../siem/setup.md))

### Local files to prepare

| Item | Notes |
|------|-------|
| OCI private key | e.g. `C:\Users\<you>\.ssh\oci-honeypot.key` |
| VPS public IP | From OCI instance details (changes if instance is recreated) |
| Tailscale auth key | One-time key from Tailscale admin console (optional; interactive login also works) |

### Knowledge checklist

- Basic Linux shell, `sudo`, and `systemctl`
- OCI Networking: VCN, subnet, security list / NSG
- Understanding that **port 22 on the internet will be attacked within minutes**

---

## Oracle Cloud VM Setup

### 1. Create a compute instance

1. Sign in to the [OCI Console](https://cloud.oracle.com/).
2. Navigate to **Compute → Instances → Create instance**.
3. Configure:

| Setting | Value |
|---------|-------|
| Name | `cowrie-honeypot` (or your naming standard) |
| Compartment | Dedicated lab compartment (recommended) |
| Region | **Germany Central (Frankfurt)** |
| Image | **Canonical Ubuntu 22.04** |
| Shape | **Virtual machine → Always Free-eligible → `VM.Standard.E2.1.Micro`** (1 OCPU, 1 GB RAM) |
| Networking | Create new VCN or use existing; assign public IPv4 |
| SSH keys | Upload your public key (generates access for user `ubuntu`) |

4. Click **Create**. Wait until the instance state is **Running**.
5. Note the **Public IP address** — referred to below as `VPS_IP`.

### 2. Configure the security list (ingress)

Open the VCN **Security List** attached to the instance subnet (or configure an NSG on the instance).

Add **Ingress** rules:

| Source CIDR | Protocol | Dest port | Description |
|-------------|----------|-----------|-------------|
| `0.0.0.0/0` | TCP | **22** | Honeypot (redirected to Cowrie) |
| `0.0.0.0/0` | TCP | **2222** | Cowrie direct (debugging; optional hardening) |
| `0.0.0.0/0` | TCP | **22222** | Admin SSH |

> **Warning:** Opening `22222` to `0.0.0.0/0` allows global SSH brute force against your real shell. Prefer restricting `22222` to your home/office IP in the security list, or access admin SSH only over Tailscale after Tailscale is installed.

### 3. Verify initial connectivity

Before changing SSH ports, confirm access on the default port **22**:

```powershell
ssh -i "C:\path\to\your-key.key" ubuntu@VPS_IP
```

If this fails, fix OCI security list, instance public IP, and key permissions before continuing.

---

## Connecting via SSH from Windows

After server preparation moves SSH to port **22222**, use this command for all admin sessions:

```powershell
ssh -i "C:\path\to\your-key.key" ubuntu@VPS_IP -p 22222
```

Replace:

- `C:\path\to\your-key.key` — path to your OCI private key
- `VPS_IP` — instance public IP from OCI console

### Key permissions (if SSH complains)

In PowerShell, restrict ACLs on the private key file so only your user can read it. OpenSSH on Windows will refuse overly permissive keys.

### Optional: SSH config entry

Create or edit `%USERPROFILE%\.ssh\config`:

```
Host honeypot-vps
    HostName VPS_IP
    User ubuntu
    Port 22222
    IdentityFile C:\path\to\your-key.key
```

Connect with:

```powershell
ssh honeypot-vps
```

> **Warning:** Never use port **22** for admin after iptables redirect is active — port 22 reaches Cowrie, not your real shell.

---

## Server Preparation

Connect as `ubuntu` on port 22 (first boot) or port **22222** (after SSH reconfiguration).

### 1. Update the system

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y git python3 python3-venv python3-dev \
    build-essential libssl-dev libffi-dev \
    iptables-persistent netfilter-persistent \
    curl ca-certificates gnupg
```

When `iptables-persistent` prompts to save current rules, you may accept defaults; rules are configured in a later section.

### 2. Move real SSH to port 22222

Edit the SSH daemon configuration:

```bash
sudo sed -i 's/^#Port 22/Port 22222/' /etc/ssh/sshd_config
sudo sed -i 's/^Port 22/Port 22222/' /etc/ssh/sshd_config
grep -q '^Port 22222' /etc/ssh/sshd_config || echo 'Port 22222' | sudo tee -a /etc/ssh/sshd_config
```

Validate and restart:

```bash
sudo sshd -t && sudo systemctl restart sshd
```

**Before closing your session**, open a **second terminal** and verify admin SSH on the new port:

```powershell
ssh -i "C:\path\to\your-key.key" ubuntu@VPS_IP -p 22222
```

> **Warning:** If you cannot connect on `22222`, do not proceed with iptables redirect until SSH is fixed. Locking yourself out requires OCI serial console or instance recovery.

### 3. Create the dedicated Cowrie user

```bash
sudo adduser --disabled-password --gecos "" cowrie
sudo usermod -aG sudo cowrie   # optional; omit for stricter isolation
```

### 4. Set timezone and hostname (optional)

```bash
sudo timedatectl set-timezone Europe/Berlin
sudo hostnamectl set-hostname cowrie-honeypot
```

---

## Cowrie Installation

All Cowrie commands run as the `cowrie` user unless noted.

### 1. Switch to the cowrie user

```bash
sudo su - cowrie
```

### 2. Clone Cowrie

```bash
cd ~
git clone https://github.com/cowrie/cowrie.git
cd cowrie
```

Pin a stable release (recommended for reproducibility):

```bash
git tag -l
git checkout tags/v2.5.0   # example — use latest stable tag from `git tag -l`
```

### 3. Create virtual environment and install dependencies

```bash
cd ~/cowrie
python3 -m venv cowrie-env
source cowrie-env/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Initial Cowrie configuration file

```bash
cp etc/cowrie.cfg.dist etc/cowrie.cfg
```

Remain logged in as `cowrie` for the configuration section below.

---

## Cowrie Configuration

Edit `/home/cowrie/cowrie/etc/cowrie.cfg` as the `cowrie` user:

```bash
nano ~/cowrie/etc/cowrie.cfg
```

### Required settings

**Hostname** — present as a plausible production server:

```ini
[honeypot]
hostname = webserver01
```

**SSH listener** — Cowrie binds to port **2222** (iptables sends public port 22 here):

```ini
[ssh]
listen_endpoints = tcp:2222:interface=0.0.0.0
```

**JSON logging** — default in modern Cowrie; confirm log path:

```ini
[output_jsonlog]
logfile = var/log/cowrie/cowrie.json
```

**Post-login command capture** — records attacker input after simulated login:

```ini
[shell]
interact_enabled = true
```

### Optional hardening and realism

```ini
[honeypot]
log_path = var/log/cowrie
download_path = var/lib/cowrie/downloads
contents_path = honeyfs/etc/issue.net
```

Create log directories if missing:

```bash
mkdir -p ~/cowrie/var/log/cowrie
mkdir -p ~/cowrie/var/lib/cowrie/downloads
```

### Verify configuration syntax

```bash
source ~/cowrie/cowrie-env/bin/activate
cd ~/cowrie
cowrie start
cowrie status
```

Check listening port:

```bash
ss -tlnp | grep 2222
```

Stop for now if you are still configuring iptables:

```bash
cowrie stop
```

Exit back to `ubuntu` when finished:

```bash
exit
```

---

## Port Redirection

Public traffic to **port 22** must reach Cowrie on **port 2222** using `iptables` NAT. Run as `root` (`ubuntu` with `sudo`).

### 1. Add PREROUTING redirect rule

```bash
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
```

### 2. Verify rules

```bash
sudo iptables -t nat -L PREROUTING -n -v
```

Expected: a rule redirecting `tcp dpt:22` to port `2222`.

### 3. Persist rules across reboot

```bash
sudo netfilter-persistent save
# or:
sudo sh -c 'iptables-save > /etc/iptables/rules.v4'
```

Ensure the service is enabled:

```bash
sudo systemctl enable netfilter-persistent
```

> **Warning:** If Cowrie is not running when traffic hits port 22, connections will fail or hang. Ensure auto-start (crontab) is configured before advertising the honeypot.

### 4. Test honeypot path (from external machine)

```powershell
ssh ubuntu@VPS_IP -p 22
```

You should see Cowrie’s SSH banner (not your real server). Use Ctrl+C to disconnect; do not log in with production credentials.

---

## Firewall Configuration

### Oracle Cloud (primary perimeter)

Ingress is controlled by the **OCI security list** (see [Oracle Cloud VM Setup](#oracle-cloud-vm-setup)). Confirm TCP **22**, **2222**, and **22222** are open.

### Optional: UFW on the instance

If enabling UFW, allow admin and honeypot ports **before** enabling:

```bash
sudo ufw allow 22222/tcp comment 'Admin SSH'
sudo ufw allow 22/tcp comment 'Honeypot redirect'
sudo ufw allow 2222/tcp comment 'Cowrie backend'
sudo ufw enable
sudo ufw status verbose
```

> **Warning:** Enabling UFW without allowing `22222` will lock you out of admin SSH.

---

## Auto-start Setup

Cowrie is configured to start automatically after reboot using a **crontab** entry for the `cowrie` user (as deployed in this lab).

### 1. Edit crontab

```bash
sudo su - cowrie
crontab -e
```

Add:

```cron
@reboot sleep 30 && cd /home/cowrie/cowrie && source cowrie-env/bin/activate && cowrie start >> /home/cowrie/cowrie/var/log/cowrie/cowrie-startup.log 2>&1
```

The `sleep 30` delay allows networking and iptables persistence to settle before Cowrie binds to port 2222.

### 2. Verify after reboot (maintenance window)

```bash
sudo reboot
```

After the instance returns, connect on port **22222** and check:

```bash
sudo su - cowrie -c 'cd /home/cowrie/cowrie && source cowrie-env/bin/activate && cowrie status'
ss -tlnp | grep 2222
tail -f /home/cowrie/cowrie/var/log/cowrie/cowrie.json
```

---

## Tailscale Setup

Tailscale provides an encrypted tunnel between the VPS and the local Wazuh SIEM without exposing the manager to the public internet.

### 1. Install Tailscale (as root/ubuntu)

```bash
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up
```

Follow the authentication URL printed in the terminal. Sign in with the **same tailnet** as the Wazuh host (`100.104.212.88`).

### 2. Verify connectivity

```bash
tailscale status
tailscale ip -4
```

From the VPS, test reachability to the Wazuh Tailscale IP:

```bash
ping -c 3 100.104.212.88
nc -zv 100.104.212.88 5044
```

> **Warning:** If port 5044 is unreachable, Filebeat will buffer or drop logs. Confirm Wazuh/Logstash is listening on the manager **before** starting Filebeat on analysis day.

### 3. Optional: Tailscale-only admin SSH

For stronger security, restrict OCI ingress on port `22222` to Tailscale CGNAT range or disable public `22222` after confirming `tailscale ssh` works.

---

## Filebeat Setup

Filebeat ships Cowrie JSON logs to the Wazuh stack over Tailscale.

| Setting | Value |
|---------|-------|
| Log input | `/home/cowrie/cowrie/var/log/cowrie/cowrie.json` |
| Output | `100.104.212.88:5044` |
| Transport | Tailscale (private) |
| Service | **enabled**, intentionally **not started** until analysis day |

### 1. Install Filebeat

```bash
curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elastic.gpg
echo "deb [signed-by=/usr/share/keyrings/elastic.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list
sudo apt update
sudo apt install -y filebeat
```

Use the Elastic major version matching your Wazuh/Logstash stack if different from 8.x.

### 2. Configure Filebeat

Back up the default config:

```bash
sudo cp /etc/filebeat/filebeat.yml /etc/filebeat/filebeat.yml.bak
sudo nano /etc/filebeat/filebeat.yml
```

Example configuration aligned with this deployment:

```yaml
filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /home/cowrie/cowrie/var/log/cowrie/cowrie.json
    json.keys_under_root: true
    json.add_error_key: true
    fields:
      data_source: cowrie
      sensor: webserver01
    fields_under_root: false

output.logstash:
  hosts: ["100.104.212.88:5044"]

logging.level: info
logging.to_files: true
logging.files:
  path: /var/log/filebeat
  name: filebeat
  keepfiles: 7
```

### 3. Permissions

Grant Filebeat read access to Cowrie logs:

```bash
sudo usermod -aG cowrie filebeat
sudo chmod 640 /home/cowrie/cowrie/var/log/cowrie/cowrie.json
sudo systemctl restart filebeat   # only after intentional go-live
```

Ensure the log file is readable on rotation (adjust logrotate if used).

### 4. Enable but do not start (analysis day)

As deployed in this lab, Filebeat is **enabled** at boot but **stopped** until log collection begins:

```bash
sudo systemctl enable filebeat
sudo systemctl stop filebeat
sudo systemctl is-enabled filebeat   # should print: enabled
sudo systemctl is-active filebeat    # should print: inactive
```

**On analysis day**, start shipping:

```bash
sudo systemctl start filebeat
sudo systemctl status filebeat
```

> **Warning:** Starting Filebeat before Wazuh port 5044 is ready will generate errors and possible log gaps. Confirm the receiver is up first.

---

## Verification

Complete this checklist before treating the sensor as production-ready.

### Honeypot and logging

| # | Check | Command / expected result |
|---|-------|----------------------------|
| 1 | Cowrie running | `sudo su - cowrie -c 'cd ~/cowrie && source cowrie-env/bin/activate && cowrie status'` → running |
| 2 | Cowrie listening | `ss -tlnp \| grep 2222` → cowrie/python |
| 3 | Port 22 reaches Cowrie | `ssh -p 22 VPS_IP` from external host → Cowrie banner |
| 4 | Admin SSH on 22222 | `ssh -p 22222 -i key ubuntu@VPS_IP` → Ubuntu shell |
| 5 | JSON logs growing | `tail -f /home/cowrie/cowrie/var/log/cowrie/cowrie.json` → events after test SSH |
| 6 | interact_enabled | Successful login events followed by `cowrie.command.input` |

### Network persistence

| # | Check | Command |
|---|-------|---------|
| 7 | iptables rule present | `sudo iptables -t nat -L PREROUTING -n -v` |
| 8 | Rules survive reboot | Reboot → repeat checks 1–4 |

### Tailscale and Filebeat (analysis day)

| # | Check | Command |
|---|-------|---------|
| 9 | Tailscale connected | `tailscale status` |
| 10 | Wazuh port open | `nc -zv 100.104.212.88 5044` |
| 11 | Filebeat ships logs | `sudo systemctl start filebeat` → events in Wazuh Dashboard |

### Generate a test event

From any external machine:

```powershell
ssh -o StrictHostKeyChecking=no -p 22 root@VPS_IP
```

Enter a fake password when prompted. On the VPS:

```bash
grep cowrie.login.failed /home/cowrie/cowrie/var/log/cowrie/cowrie.json | tail -1
```

---

## Log Format and Example

Cowrie writes **newline-delimited JSON** (one JSON object per line) to:

```
/home/cowrie/cowrie/var/log/cowrie/cowrie.json
```

### Common `eventid` values

| eventid | Description |
|---------|-------------|
| `cowrie.session.connect` | Inbound TCP/SSH connection |
| `cowrie.client.version` | SSH client version string |
| `cowrie.login.failed` | Failed authentication |
| `cowrie.login.success` | Successful honeypot login |
| `cowrie.command.input` | Command typed post-login (`interact_enabled`) |
| `cowrie.session.closed` | Session ended |
| `cowrie.session.file_download` | Malware or tool download attempt |

### Example log lines

**Connection:**

```json
{"eventid": "cowrie.session.connect", "src_ip": "203.0.113.42", "src_port": 49152, "dst_ip": "10.0.0.5", "dst_port": 22, "session": "a1b2c3d4e5f6", "protocol": "ssh", "timestamp": "2026-05-16T14:22:01Z"}
```

**Failed login:**

```json
{"eventid": "cowrie.login.failed", "username": "root", "password": "123456", "src_ip": "203.0.113.42", "session": "a1b2c3d4e5f6", "timestamp": "2026-05-16T14:22:05Z"}
```

**Command input (requires `interact_enabled = true`):**

```json
{"eventid": "cowrie.command.input", "input": "uname -a", "src_ip": "203.0.113.42", "session": "a1b2c3d4e5f6", "timestamp": "2026-05-16T14:23:10Z"}
```

### Offline analysis

Copy sanitized logs into the repository for Python analysis (do not commit live attacker data without review):

```bash
# On VPS
cp /home/cowrie/cowrie/var/log/cowrie/cowrie.json ~/cowrie-export.json

# On Windows (SCP example)
scp -i "C:\path\to\your-key.key" -P 22222 ubuntu@VPS_IP:~/cowrie-export.json .\honeypot\sample-logs\
```

Run analysis scripts from the repo root:

```bash
cd analysis
python parse_logs.py -i ../honeypot/sample-logs/cowrie.json
python credential_analysis.py -i ../honeypot/sample-logs/cowrie.json
python command_tracker.py -i ../honeypot/sample-logs/cowrie.json
```

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| Cannot SSH on 22 to admin | iptables redirect active | Use port **22222** |
| Port 22 connection refused | Cowrie not running | `cowrie start` as `cowrie` user (venv activated) |
| Empty `cowrie.json` | Wrong path or permissions | Check `cowrie.cfg` `[output_jsonlog]` |
| No commands logged | `interact_enabled` false | Set `interact_enabled = true`, restart Cowrie |
| Filebeat errors | Wazuh/5044 down or ACL | `nc -zv 100.104.212.88 5044`, start receiver |
| Lost after reboot | Crontab or iptables not saved | Re-check `@reboot` crontab and `netfilter-persistent` |

---

## Related Documentation

- [Architecture](../docs/architecture.md) — full pipeline to Wazuh
- [Runbook](../docs/runbook.md) — operational procedures
- [SIEM setup](../siem/setup.md) — Wazuh receiver configuration
- [Threat report template](../docs/threat-report-template.md)

---

## References

- [Cowrie documentation](https://docs.cowrie.org/)
- [Cowrie GitHub repository](https://github.com/cowrie/cowrie)
- [Oracle Cloud Free Tier](https://www.oracle.com/cloud/free/)
- [Tailscale install guide](https://tailscale.com/download/linux)
- [Filebeat documentation](https://www.elastic.co/guide/en/beats/filebeat/current/index.html)
