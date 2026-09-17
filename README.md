# 🛡️ SOC Home Lab — Wazuh SIEM/XDR + Suricata IDS/IPS + pfSense + Sysmon

> A self-built Security Operations Center home lab for practicing detection engineering, MITRE ATT&CK-mapped attack simulation, and log correlation — built as a Blue Team portfolio project.

![Wazuh](https://img.shields.io/badge/SIEM-Wazuh-1e6d90)
![Suricata](https://img.shields.io/badge/IDS%2FIPS-Suricata-cc0000)
![pfSense](https://img.shields.io/badge/Firewall-pfSense-212121)
![MITRE ATT&CK](https://img.shields.io/badge/Mapped-MITRE%20ATT%26CK-orange)
![Status](https://img.shields.io/badge/Status-Active%20Lab-brightgreen)

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Tech Stack](#tech-stack)
- [Attack Chain & MITRE ATT&CK Coverage](#attack-chain--mitre-attck-coverage)
- [Detection Engineering Highlights](#detection-engineering-highlights)
- [Repository Structure](#repository-structure)
- [Lessons Learned & Troubleshooting](#lessons-learned--troubleshooting)
- [Author](#author)
- [License](#license)

---

## Overview

This repository documents a fully self-hosted SOC home lab built to practice **Blue Team detection engineering** end-to-end.

The project spans from writing custom Wazuh decoders and rules against raw pfSense and Suricata logs, to simulating a full 11-stage attack chain (**Reconnaissance → Exfiltration**) mapped to the MITRE ATT&CK framework.

The lab was built and debugged from scratch to demonstrate the actual workflow of a detection engineer:

1. Writing a rule
2. Generating the corresponding behavior
3. Analyzing false positives
4. Tuning the detection logic
5. Verifying the final alert

---

## Architecture

| Component | Role | IP |
|---|---|---|
| **Wazuh Manager** | SIEM/XDR — manager + indexer + dashboard | `192.168.60.137` |
| **Windows 11 Endpoint** | Wazuh Agent, Sysmon, victim machine | `192.168.60.1` |
| **Kali Linux** | Attacker machine | `192.168.60.135` |
| **pfSense** | Firewall/gateway, forwards `filterlog` via syslog | `192.168.60.254` |
| **Suricata (x2)** | IDS on pfSense WAN + IDS on Windows endpoint | — |

```text
Kali (Attacker)
      │
      ▼
pfSense (Firewall / Gateway)
      │
      ▼
Windows 11
(Wazuh Agent + Sysmon + Suricata IDS)
      │
      ▼
Wazuh Manager
(SIEM/XDR)
```

### Defense-in-Depth Design

The two-tier Suricata deployment follows a **defense-in-depth** strategy.

A single perimeter IDS on pfSense may miss **east-west traffic** between internal hosts. Therefore, a second Suricata instance runs directly on the monitored Windows endpoint to provide additional host-level network visibility.

---

## Tech Stack

### SIEM / XDR

- **Wazuh**

### Network Security

- **Suricata**
  - Custom local detection rules
- **pfSense**
  - Firewall
  - Syslog forwarding
  - Custom `filterlog` decoders

### Endpoint Security

- **Sysmon**
  - Process lineage monitoring
  - Registry monitoring
  - LSASS access monitoring

### Threat Intelligence

- **VirusTotal API**
  - File Integrity Monitoring (FIM) enrichment

### Virtualization

- **VMware**

### Attack / Simulation Tooling

- **Nmap**
- **Hydra**
- **Netcat**
- **PowerShell**
  - Encoded commands
  - Reverse shells
- **Procdump**

---

## Attack Chain & MITRE ATT&CK Coverage

A full simulation scenario was executed and validated against actual Wazuh alerts.

| Stage | Tactic | Technique | Detection Source |
|---|---|---|---|
| Reconnaissance | Reconnaissance | T1595, T1018 | Suricata, pfSense |
| Brute Force | Credential Access | T1110 | Suricata, Windows Event 4625 |
| Initial Access | Initial Access | T1078 | Windows Event Log, Correlation Rule |
| Execution | Execution | T1059.001, T1027 | Sysmon (Encoded PowerShell) |
| Discovery | Discovery | T1087, T1082, T1033 | Sysmon (Process Lineage, LOLBins) |
| Payload Delivery | Command and Control | T1105 | Suricata, FIM, VirusTotal |
| Persistence | Persistence | T1547.001 | Sysmon (Registry Run Key) |
| Command & Control | Command and Control | T1071 | Suricata (Reverse Shell) |
| Credential Access | Credential Access | T1003.001 | Sysmon (LSASS Memory Access) |
| Anti-Forensics | Defense Evasion | T1070.001 | Windows Event 1102 (Log Cleared) |
| Exfiltration | Exfiltration | T1041 | Sysmon (Network Connection) |

---

## Detection Engineering Highlights

Beyond writing standard rules, this project involved significant troubleshooting and logic tuning.

### Stateful Network Detection to Eliminate False Positives

Initially, Suricata reverse shell rules triggered on simple Nmap SYN scans because the rules matched on:

```text
flags:S
```

The rules were rewritten to require a successful TCP three-way handshake:

```text
flow:to_server,established
```

The `$HOME_NET` variable was also strictly scoped to exclude the attacker IP.

This eliminated the observed false positives caused by incomplete TCP connection attempts during reconnaissance.

---

### Resilient pfSense Decoders

A silent decoder failure was traced to variations in syslog headers, including cases where the hostname field was missing.

The pipeline was redesigned to avoid depending on:

```xml
<program_name>
```

Instead, the decoder relies on:

```xml
<prematch>
```

and uses:

```xml
offset="after_parent"
```

to accurately extract ICMP, TCP, and UDP fields regardless of upstream log formatting.

---

### Endpoint Whitelisting for LSASS Monitoring

Sysmon Event ID 10 (`ProcessAccess`) was tuned using regex-based whitelisting.

Legitimate processes such as:

```text
taskmgr.exe
MsMpEng.exe
```

were excluded where appropriate so that alerts focus on suspicious LSASS access patterns associated with credential-dumping activity.

---

### Overcoming Wazuh API Crashes

A recurring HTTP 500 error was observed on the Wazuh Dashboard's **Manage Rules** interface.

The root cause was traced to trailing commas in XML `<group>` tags, which caused the API's Python parser to fail.

The issue was resolved by enforcing strict XML syntax hygiene in the custom rules.

---

## Repository Structure

```text
wazuh-soc-home-lab/
├── README.md
│
├── architecture/
│   ├── network-topology.png
│   └── logical-data-flow.drawio
│
├── docs/
│   ├── 01-infrastructure-setup.md
│   ├── 02-log-ingestion-pipeline.md
│   ├── 03-detection-engineering.md
│   └── 04-threat-emulation-report.md
│
├── endpoints/
│   └── windows-11/
│       ├── sysmon-config.xml
│       └── ossec.conf
│
├── network/
│   ├── pfsense/
│   │   └── config-backup.xml
│   │
│   └── suricata/
│       ├── suricata.yaml
│       └── local.rules
│
├── siem-wazuh/
│   ├── decoders/
│   │   └── local_decoder.xml
│   │
│   ├── rules/
│   │   └── local_rules.xml
│   │
│   └── dashboards/
│       └── custom-soc-dashboard.ndjson
│
├── threat-emulation/
│   ├── attack-scripts/
│   └── sample-logs/
│
└── screenshots/
```

---

## Lessons Learned & Troubleshooting

### Verification is Mandatory

A rule that "looks correct" in XML isn't considered verified until tested via:

```bash
wazuh-logtest
```

against real or representative log samples.

Several custom rules were found to be silently overridden by Wazuh's default ruleset until properly prioritized and validated.

---

### API Sensitivity

The Wazuh Manager core (`wazuh-analysisd`) can be more forgiving of certain XML configuration issues than the Wazuh API.

The Dashboard's **Manage Rules** functionality proved significantly more sensitive to malformed XML syntax, reinforcing the importance of strict configuration validation.

---

### Behavior > Signatures

Hardcoding port `4444` for reverse shells or port `4445` for exfiltration creates blind spots.

Detection must focus on behavior rather than relying solely on fixed indicators.

For example:

- Standard web ports showing anomalous outbound activity
- Suspicious process-to-network relationships
- LOLBin network activity
- Unexpected outbound connections
- Abnormal data transfer behavior

This approach provides more resilient detection logic against simple indicator changes.

---

## Detection Workflow

The lab follows a repeatable detection-engineering workflow:

```text
Security Event / Attack Simulation
                │
                ▼
          Data Collection
                │
                ▼
       Decoder / Parser Logic
                │
                ▼
       Detection Rule Match
                │
                ▼
            Wazuh Alert
                │
                ▼
           Investigation
                │
                ▼
      False Positive Analysis
                │
                ▼
        Rule Tuning / Update
                │
                ▼
          Re-Test Detection
                │
                ▼
        Document Final Result
```

---

## Project Goals

This lab is designed to practice the following Blue Team capabilities:

- Security monitoring
- Log collection and analysis
- Detection engineering
- Custom Wazuh rule development
- Custom Wazuh decoder development
- Network IDS/IPS monitoring
- Endpoint telemetry analysis
- MITRE ATT&CK mapping
- Alert triage
- False-positive analysis
- Detection tuning
- Incident investigation
- Threat emulation

---

## Future Improvements

Planned improvements include:

- Expanding detection coverage
- Improving alert correlation
- Adding more endpoint telemetry sources
- Increasing MITRE ATT&CK coverage
- Automating detection testing
- Improving incident-response documentation
- Adding additional attack simulations
- Building reusable detection test cases

---

## Author

**Võ Minh Khoa**

2nd-Year Information Security Student at the University of Information Technology (UIT), Ho Chi Minh City.

Interested in:

- Blue Team Operations
- Security Operations Center (SOC)
- Detection Engineering
- Security Monitoring
- Self-hosted Security Infrastructure

---

## License

This project's documentation and configuration examples are released under the [MIT License](LICENSE).

Attack simulation content is strictly intended for **educational purposes and authorized testing within an isolated laboratory environment**.
