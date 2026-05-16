# Wazuh SIEM Setup

> **Status:** Placeholder — full deployment documentation to be completed.

This guide will document local installation and configuration of the [Wazuh](https://wazuh.com/) stack for ingesting Cowrie honeypot telemetry in the honeypot-soc-lab project.

---

## Planned Sections

### 1. Deployment Options

| Method | Use Case |
|--------|----------|
| Docker Compose | Fast lab setup, isolated stack |
| Native packages (.deb / .rpm) | Production-like single host |
| Wazuh Cloud | Not in scope for this lab |

### 2. System Requirements

- CPU: 4+ cores recommended
- RAM: 8 GB minimum (16 GB preferred)
- Disk: 50 GB+ for indexer retention
- OS: Ubuntu 22.04 LTS (local or WSL2)

### 3. Docker Compose Installation (Placeholder)

```bash
# Placeholder — official Wazuh Docker documentation to be followed
# git clone https://github.com/wazuh/wazuh-docker
# cd wazuh-docker/single-node
# docker compose up -d
```

### 4. Initial Configuration

- Admin password and certificate trust
- Indexer cluster health check
- Dashboard first login

### 5. Cowrie Integration

- Custom decoders for JSON log fields
- Rules directory: `siem/rules/`
- Agent enrollment from honeypot VPS (Tailscale IP)
- `localfile` stanza for `cowrie.json`

### 6. Dashboards and Visualizations

- Index pattern for `wazuh-alerts-*` / archives
- Saved searches: failed logins, commands, downloads
- Import dashboard JSON (future artifact)

### 7. Alerting

- Email / webhook integration
- Severity thresholds for brute force and malware indicators

### 8. Validation

- Test alert from sample Cowrie event
- Verify indexer storage and retention policy

### 9. Maintenance

- Backup indexer snapshots
- Certificate renewal
- Version upgrade procedure

---

## Related Documentation

- [Architecture](../docs/architecture.md)
- [Runbook](../docs/runbook.md)
- [Honeypot setup](../honeypot/setup.md)

---

## References

- [Wazuh documentation](https://documentation.wazuh.com/)
- [Wazuh Docker deployment](https://documentation.wazuh.com/current/deployment-options/docker/index.html)
