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


