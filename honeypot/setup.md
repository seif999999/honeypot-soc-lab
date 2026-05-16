# Cowrie Honeypot Setup

> **Status:** Placeholder — full deployment documentation to be completed.

This guide will document end-to-end installation of [Cowrie](https://github.com/cowrie/cowrie) on an Oracle Cloud Ubuntu VPS for the honeypot-soc-lab project.

---

## Planned Sections

### 1. Oracle Cloud VPS Provisioning

- Compartment and VCN configuration
- Always Free compute instance sizing
- Security list / ingress rules (TCP 22, optional 23)
- SSH key injection and initial access

### 2. System Preparation

```bash
# Placeholder commands — to be expanded
sudo apt update && sudo apt upgrade -y
sudo ufw allow 22/tcp
sudo ufw enable
```

- Dedicated `cowrie` user
- Python virtual environment dependencies
- Git, build-essential, libssl-dev

### 3. Cowrie Installation

- Clone repository and stable branch/tag
- `pip install` requirements
- `cowrie.cfg` key settings:
  - `hostname`, `log_path`, `download_path`
  - `listen_endpoints` (SSH/Telnet ports)
  - JSON logging enabled

### 4. Network Redirect (iptables / nftables)

- Redirect public port 22 → Cowrie backend port
- Persist rules across reboot

### 5. systemd Service

- Unit file for Cowrie process
- Enable on boot; logging to journald optional

### 6. Validation

- Local test connection
- Confirm `cowrie.json` event stream
- Sample log export to `sample-logs/` for offline analysis

### 7. Hardening Checklist

- [ ] No sensitive data on honeypot host
- [ ] Automatic security updates
- [ ] Log rotation configured
- [ ] Backup/export procedure documented

---

## Related Documentation

- [Architecture](../docs/architecture.md)
- [Runbook](../docs/runbook.md)
- [SIEM setup](../siem/setup.md)

---

## References

- [Cowrie documentation](https://docs.cowrie.org/)
- [Oracle Cloud Free Tier](https://www.oracle.com/cloud/free/)
