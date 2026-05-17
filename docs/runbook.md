# Security Operations Runbook
## Honeypot + SIEM Pipeline — Operational Guide

| | |
|---|---|
| **Author** | Seif Allah Nazmy |
| **Version** | 1.0 |
| **Last Updated** | May 2026 |
| **Classification** | Internal |

---

## 1. System Overview

This runbook covers the operation and maintenance of a two-component threat detection pipeline consisting of a Cowrie SSH honeypot deployed on Oracle Cloud Infrastructure and a Wazuh SIEM running locally via Docker. The honeypot captures real attack data from the public internet and ships it via Filebeat through a Tailscale encrypted tunnel to the Wazuh SIEM for real-time analysis, alerting, and threat intelligence generation.

**Pipeline:**
```
Internet Attackers → Cowrie (OCI Frankfurt) → Filebeat → Tailscale → Wazuh (Legion) → Dashboard
```

---

## 2. System Reference

### 2.1 Infrastructure Details
| Component | Value |
|---|---|
| Honeypot public IP | 158.180.54.157 |
| Honeypot Tailscale IP | 100.73.203.110 |
| SIEM Tailscale IP | 100.104.212.88 |
| Honeypot SSH port | 22222 |
| Cowrie listening port | 2222 |
| Filebeat → Wazuh port | 5044 |
| Wazuh dashboard | https://localhost |
| Wazuh dashboard port | 443 |
| Wazuh API port | 56000 |

### 2.2 Credentials
| System | Username | Password |
|---|---|---|
| Wazuh dashboard | admin | SecretPassword |
| Oracle VPS | ubuntu | key-based auth only |

### 2.3 Key File Locations
| File | Location |
|---|---|
| SSH private key | C:\Users\smnam\OneDrive\Documents\ssh key\ssh-keys\ssh-keys.key |
| Cowrie logs | /home/cowrie/cowrie/var/log/cowrie/cowrie.json |
| Cowrie config | /home/cowrie/cowrie/etc/cowrie.cfg |
| Filebeat config | /etc/filebeat/filebeat.yml |
| Wazuh docker files | C:\Users\smnam\wazuh-docker\single-node\ |

---

## 3. Connecting to Systems

### 3.1 Connect to Honeypot VPS
```powershell
ssh -i "C:\Users\smnam\OneDrive\Documents\ssh key\ssh-keys\ssh-keys.key" ubuntu@158.180.54.157 -p 22222
```

### 3.2 Switch to Cowrie User
```bash
sudo su - cowrie
cd cowrie
source cowrie-env/bin/activate
```

### 3.3 Access Wazuh Dashboard
Open browser → `https://localhost` → accept certificate warning → login with `admin` / `SecretPassword`

---

## 4. Daily Health Checks

Run these checks daily to confirm the pipeline is operating correctly.

### 4.1 Check Cowrie is Running
```bash
cowrie status
```
Expected output: `cowrie is running (PID: XXXXX)`

### 4.2 Check Events Being Collected
```bash
cat var/log/cowrie/cowrie.json | wc -l
```
Expected: number increasing daily. If static for 24+ hours → investigate.

### 4.3 Check Latest Events
```bash
tail -5 var/log/cowrie/cowrie.json
```
Expected: recent timestamps. If last event is hours old → Cowrie may have stopped.

### 4.4 Check Filebeat is Running (when active)
```bash
sudo systemctl status filebeat
```
Expected: `active (running)`

### 4.5 Check Tailscale Tunnel
```bash
sudo tailscale status
```
Expected: both `cowrie-honeypot` and `legion` showing as connected.

### 4.6 Check Wazuh Containers
```powershell
docker ps
```
Expected: three containers running — `wazuh.manager`, `wazuh.indexer`, `wazuh.dashboard`

---

## 5. Starting and Stopping Components

### 5.1 Start Cowrie
```bash
# As cowrie user with venv active
cowrie start
```

### 5.2 Stop Cowrie
```bash
cowrie stop
```

### 5.3 Restart Cowrie
```bash
cowrie restart
```

### 5.4 Start Wazuh
```powershell
cd C:\Users\smnam\wazuh-docker\single-node
docker compose up -d
```
Wait 2-3 minutes for all services to initialize before accessing dashboard.

### 5.5 Stop Wazuh
```powershell
cd C:\Users\smnam\wazuh-docker\single-node
docker compose down
```

### 5.6 Start Filebeat (Analysis Day Only)
```bash
sudo systemctl start filebeat
```
⚠️ Only run this when ready to begin ingestion. All historical logs will be shipped immediately.

### 5.7 Stop Filebeat
```bash
sudo systemctl stop filebeat
```

---

## 6. Activating the Full Pipeline

This procedure starts log ingestion from the honeypot into Wazuh. Run on analysis day only.

**Step 1:** Start Wazuh on Legion
```powershell
cd C:\Users\smnam\wazuh-docker\single-node
docker compose up -d
```

**Step 2:** Confirm Wazuh is ready
```powershell
docker ps
```
Wait until all 3 containers show `Up` status.

**Step 3:** SSH into VPS
```powershell
ssh -i "C:\Users\smnam\OneDrive\Documents\ssh key\ssh-keys\ssh-keys.key" ubuntu@158.180.54.157 -p 22222
```

**Step 4:** Verify Tailscale tunnel
```bash
ping 100.104.212.88 -c 4
```
Expected: 0% packet loss

**Step 5:** Start Filebeat
```bash
sudo systemctl start filebeat
```

**Step 6:** Confirm logs flowing in Wazuh
Open `https://localhost` → Security Events → confirm new events appearing

---

## 7. Incident Response Procedures

### 7.1 Cowrie Has Stopped
**Symptoms:** `cowrie status` returns not running. Log count not increasing.

**Response:**
1. Check for errors: `cat /home/cowrie/cowrie/var/log/cowrie/cowrie.log`
2. Restart Cowrie: `cowrie restart`
3. Verify restart: `cowrie status`
4. If still failing: check disk space `df -h`, check RAM `free -m`

**Severity:** Medium — data collection interrupted but no security risk.

---

### 7.2 Wazuh Dashboard Not Accessible
**Symptoms:** `https://localhost` not loading.

**Response:**
1. Check containers: `docker ps`
2. If containers stopped: `docker compose up -d`
3. Wait 3 minutes then retry
4. If containers running but dashboard unreachable: `docker compose restart`

**Severity:** Low — SIEM offline but honeypot still collecting.

---

### 7.3 Tailscale Tunnel Down
**Symptoms:** Ping to `100.104.212.88` fails. Filebeat not shipping logs.

**Response:**
1. On VPS: `sudo tailscale up`
2. Re-authenticate if prompted
3. Verify: `sudo tailscale status`
4. Test tunnel: `ping 100.104.212.88 -c 4`

**Severity:** Medium — log shipping interrupted when Filebeat is active.

---

### 7.4 Filebeat Not Shipping Logs
**Symptoms:** Wazuh dashboard shows no new events despite Filebeat running.

**Response:**
1. Check Filebeat status: `sudo systemctl status filebeat`
2. Check Filebeat logs: `sudo journalctl -u filebeat -n 50`
3. Verify Tailscale tunnel is up
4. Restart Filebeat: `sudo systemctl restart filebeat`

**Severity:** Medium — analysis data not flowing to SIEM.

---

## 8. Log Backup Procedure

Before analysis day, back up the raw Cowrie logs:

```bash
# On VPS — create a compressed backup
cp /home/cowrie/cowrie/var/log/cowrie/cowrie.json ~/cowrie-backup-$(date +%Y%m%d).json
gzip ~/cowrie-backup-$(date +%Y%m%d).json
```

To copy backup to Legion:
```powershell
scp -i "C:\Users\smnam\OneDrive\Documents\ssh key\ssh-keys\ssh-keys.key" -P 22222 ubuntu@158.180.54.157:~/cowrie-backup-*.json.gz C:\Users\smnam\Desktop\
```

---

## 9. Maintenance

### 9.1 Update Cowrie
```bash
sudo su - cowrie
cd cowrie
source cowrie-env/bin/activate
git pull
pip install -r requirements.txt
cowrie restart
```

### 9.2 Update Wazuh
```powershell
cd C:\Users\smnam\wazuh-docker\single-node
docker compose down
git pull
docker compose up -d
```

### 9.3 Rotate Logs
Cowrie rotates logs automatically. Manual rotation if needed:
```bash
mv var/log/cowrie/cowrie.json var/log/cowrie/cowrie-$(date +%Y%m%d).json
cowrie restart
```
