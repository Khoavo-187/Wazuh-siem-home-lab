---
title: "SOC Home Lab —  Lab architecture and summary"
tags: [Blue Team, SOC Home Lab, Lab setup]
lang: en
breaks: true
---

# SOC Home Lab — Lab structure and setup infrastructure

[TOC]
---

## 0. Executive Summary

**Lab objective:** Build a SOC home Lab using Wazuh (SIEM/XDR), Suricata (IDS/IPS) , and pfsense (firewall/gateaway) to practice detection engineering - writing custom decoders/rules, simulating attacks mapped to MITRE ATT&CK, and validating rules against real log evidence.

 **Scope:**
- Baseline detection engineering: pfSense filterlog decoder, Suricata local rules, Sysmon/Windows Event Log mapping, VirusTotal threat intel integration.
- Full 12-stage attack simulation: Reconnaissance → Brute Force → Initial Access → Execution → Discovery → Payload Drop → Persistence → C2 → Credential Access → File Lifecycle → Cleanup/Anti-forensics → Exfiltration.
- Advanced correlation rules: linking brute force + successful login, LSASS access, log clearing.

**Overall status:** Most detections are confirmed by real log evidence. Several correlation-level rules (`100410`, `100411`, `100412`) and the exfiltration rule (`100413`) are still at the design stage / not fully verified with raw alerts — see Section 9.


---

## 1. Lab Architecture


The lab uses VMware VMs and includes the following components: 

| Component | Role |
|---|---|
| **Wazuh Server** | Runs the Wazuh manager, Indexer, and Dashboard. Collects & correlates logs from agents, Suricata, and pfSense |
| **Windows 11 Endpoint** | Runs the Wazuh Agent (system monitoring + log forwarding); the victim (target) machine |
| **Kali Linux (Attacker)** | Machine used to simulate attacks |
| **pfSense Firewall** | Provides firewall logs, integrated into Wazuh via syslog |
| **Suricata IDS/IPS** | Monitors network traffic, sends alerts to Wazuh based on custom rules |


![SOC home lab architecture](../architecture/Architecture-and-data-flow.png)


### Wazuh Architecture
- **Wazuh Agent**: a lightweight program installed on each monitored device (Linux/Windows/macOS), collects security data and forwards it to the Wazuh Server.
- **Wazuh Server**: receives the data, decodes and analyzes it against rules, generates alerts, and forwards them to the **Wazuh Indexer**.
- **Wazuh Indexer**: a search/analytics engine (built on Elasticsearch/OpenSearch) that indexes data for fast querying.
- **Wazuh Dashboard**: a web interface (built on Kibana) — real-time monitoring, compliance tracking, and investigation.

Installation: https://documentation.wazuh.com/current/quickstart.html

### IP / Role Table

| Component | IP Address | Role |
|---|---|---|
| Suricata IDS | (runs on Windows or Kali) | Host-based network IDS + IPS on pfSense |
| pfSense | 192.168.254.101 (WAN) / 192.168.60.254 (LAN) | Firewall/gateway (forwards logs via syslog) |
| Kali Linux | 192.168.254.100 (WAN) / 192.168.60.135 (LAN) | Attacker machine |
| Windows 11 | 192.168.60.1 | Wazuh agent (monitored endpoint) |
| Wazuh Server | 192.168.60.137 | Central SIEM (manager + indexer + dashboard) |

> ⚠️ **IP inconsistency note**: the source documents use `192.168.60.101` for the Windows11 endpoint in the baseline Detection Engineering section, but switch to `192.168.60.1` in the Full Attacking Chain section. The actual current IP of the Windows11 agent should be confirmed before reusing this report for a future test run.

---
