# 🛡️ SOC Home Lab — Wazuh SIEM/XDR + Suricata IDS/IPS + pfSense + Sysmon + Virustotal

> A self-built Security Operations Center home lab for practicing detection engineering, MITRE ATT&CK-mapped attack simulation, and log correlation — built as a Blue Team portfolio project by an Information Security student.

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
- [What This Lab Covers](#what-this-lab-covers)
- [Attack Chain / MITRE ATT&CK Coverage](#attack-chain--mitre-attck-coverage)
- [Detection Engineering Highlights](#detection-engineering-highlights)
- [Sample Detection](#sample-detection)
- [Repository Structure](#repository-structure)
- [Full Writeups](#full-writeups)
- [Lessons Learned](#lessons-learned)
- [Known Limitations / Future Work](#known-limitations--future-work)
- [Author](#author)
- [License](#license)

---

## Overview

This repository documents a fully self-hosted SOC home lab built to practice **Blue Team detection engineering** end-to-end: from writing custom Wazuh decoders/rules against raw pfSense and Suricata logs, to simulating a full 12-stage attack chain (Recon → Exfiltration) mapped to MITRE ATT&CK, to validating every detection against real captured evidence rather than assumptions.

The lab is deliberately built and debugged from scratch (no pre-made rulesets) to demonstrate the actual workflow of a detection engineer: write a rule → generate the real behavior → check if it fires → find out it didn't → figure out why → fix the decoder/rule → re-verify. Several real debugging stories from this process are documented below and in the full writeups.

## Architecture

| Component | Role | IP |
|---|---|---|
| **Wazuh Manager** | SIEM/XDR — manager + indexer + dashboard | `192.168.60.137` |
| **Windows 11 Endpoint** | Wazuh Agent, Sysmon, victim machine | `192.168.60.1` |
| **Kali Linux** | Attacker machine | `192.168.60.135` |
| **pfSense** | Firewall/gateway, forwards `filterlog` via syslog | `192.168.60.254` |
| **Suricata (x2 instances)** | IDS on pfSense WAN (IPS Legacy Blocking Mode) + IDS on Windows endpoint (host-based) | — |

```
Kali (attacker) ──► pfSense (firewall + Suricata IPS) ──► Windows 11 (Wazuh Agent + Sysmon + Suricata IDS)
                                                                        │
                                                                        ▼
                                                              Wazuh Manager (SIEM/XDR)
```

Two-tier Suricata deployment follows defense-in-depth: a single perimeter IDS/IPS on pfSense would miss east-west (LAN-to-LAN) traffic, so a second Suricata instance runs directly on the monitored endpoint.

## Tech Stack

- **SIEM/XDR:** Wazuh (Manager, Indexer, Dashboard)
- **Network IDS/IPS:** Suricata (custom local rules, dual deployment)
- **Firewall:** pfSense (custom `filterlog` decoder, Legacy Blocking IPS)
- **Host telemetry:** Sysmon (SwiftOnSecurity base config + custom rules), Windows Event Log
- **Threat Intel:** VirusTotal API integration
- **Hypervisor:** VMware
- **Attack tooling:** nmap, Hydra, netcat, PowerShell (reverse shell, encoded commands), procdump

## What This Lab Covers

1. **Baseline Detection Engineering** — custom pfSense filterlog decoder (TCP/UDP/ICMP/IGMP/IPv4-fallback/IPv6), Suricata local rules, Sysmon rule set (PowerShell obfuscation, LOLBins, persistence, credential access, anti-forensics), VirusTotal FIM enrichment.
2. **Full Attack Chain Simulation** — a 12-stage scenario from Reconnaissance to Exfiltration, each stage executed for real and validated against actual Wazuh alerts (not simulated JSON).
3. **Correlation Rules** — multi-event detection linking brute force → successful login, process → LSASS access, and log-clearing anti-forensics.
4. **Rule Verification Discipline** — every rule in this project is tagged as either confirmed by real evidence or still pending validation; see [Known Limitations](#known-limitations--future-work).

## Attack Chain / MITRE ATT&CK Coverage

| Stage | Tactic | Technique | Detection Source |
|---|---|---|---|
| Reconnaissance | Reconnaissance | T1595, T1018 | Suricata, pfSense |
| Brute Force | Credential Access | T1110 | Suricata, Windows Event 4625 |
| Initial Access | Initial Access | T1078 | Windows Event Log, correlation rule |
| Execution | Execution | T1059.001, T1027 | Sysmon (Encoded PowerShell) |
| Discovery | Discovery | T1087, T1082, T1033 | Sysmon (process lineage) |
| Payload Delivery | Command and Control | T1105 | Suricata, FIM, VirusTotal |
| Persistence | Persistence | T1547.001 | Sysmon (Registry Run key) |
| Command & Control | Command and Control | T1071 | Suricata (reverse shell) |
| Credential Access | Credential Access | T1003.001 | Sysmon (LSASS access) |
| Anti-Forensics | Defense Evasion | T1070.001 | Windows Event 1102 |
| Exfiltration | Exfiltration | T1041 | Sysmon (Network Connect) |

Full stage-by-stage evidence, raw logs, and correlation rule XML are in the [full writeups](#full-writeups).

## Detection Engineering Highlights

A few things worth highlighting beyond "wrote some rules":

- **Diagnosed a silent decoder failure in production.** A pfSense-side hostname inconsistency (some syslog messages arrive without a hostname token before `filterlog[pid]:`) caused the `<program_name>` field-based decoder to silently fail pre-decoding — meaning *zero* fields were ever extracted and every custom pfSense rule above the generic catch-all stopped firing, with no error thrown. Diagnosed via `wazuh-logtest` phase-by-phase output, root-caused to Wazuh's hostname/program_name parsing being upstream-dependent, and fixed by switching to a `<prematch>`-based parent decoder that matches on the literal `filterlog[\d+]:` token regardless of syslog header formatting.
- **Fixed a false-positive-prone correlation rule.** The original SYN-burst rule matched on `<same_dstport/>` alone, which meant a burst of plain UDP DNS queries (port 53) was being mislabeled as a "SYN flood." Added an explicit `<protocol>tcp</protocol>` constraint to correct it.
- **Built a fallback decoder chain with negative lookahead** (`pfsense-lab-ipv4`) to correctly bucket protocols outside TCP/UDP/ICMP/IGMP without needing a decoder per protocol.
- **Distinguished internal Wazuh activity from real attacker activity** using Sysmon process lineage + integrity level + working directory, rather than trusting the command line alone (see Sysmon comparison table in the writeup).

## Sample Detection

**Reverse Shell / C2 Outbound (Suricata)**

| Field | Value |
|---|---|
| Rule ID / Level | `100304` / 12 |
| MITRE | T1071 (Command and Control) |
| Source → Destination | `192.168.60.1:62602` → `192.168.60.135:4444` |
| Trigger | Outbound TCP to a known reverse-shell port list from a PowerShell TCPClient session |

**PowerShell Encoded Command (Sysmon)**

| Field | Value |
|---|---|
| Rule ID / Level | `100401` / 10 |
| MITRE | T1027, T1059.001 |
| Detection Logic | `parentImage` matches `powershell.exe` AND `commandLine` contains `-EncodedCommand` |
| Integrity Level | High (elevated) |

More detections with full raw evidence are cataloged in the writeups' Appendix.

## Repository Structure

> Adjust to match your actual folder layout.

```
.
├── README.md
├── docs/
│   ├── WU1-detection-engineering.md        # Baseline architecture, decoders, rules
│   ├── WU2-full-attack-chain.md            # 12-stage attack simulation
│   └── SOC-Home-Lab-Consolidated-Report.md # Merged report — IoC tables + appendix
├── rules/
│   ├── pfsense/
│   │   ├── decoders/local_decoder.xml
│   │   └── rules/local_rules.xml
│   ├── suricata/
│   │   └── local.rules
│   └── sysmon/
│       └── sysmonconfig.xml
├── screenshots/
│   └── *.png                               # Dashboard alert screenshots
└── LICENSE
```

## Full Writeups

- 📄 **[WU1 — Detection Engineering & Baseline Architecture]()** *(link to your hosted writeup)*
- 📄 **[WU2 — Full Attacking Chain]()** *(link to your hosted writeup)*
- 📄 **[Consolidated Report — condensed IoC tables + full raw log appendix]()** *(link to your hosted PDF/markdown)*

## Lessons Learned

- A rule that "looks correct" in XML isn't verified until `wazuh-logtest` confirms it against a **real** raw log — several custom rules in this lab were confirmed to be silently overridden by Wazuh's built-in ruleset and only caught by comparing expected vs. actual `rule.id` in the evidence.
- Detection logic that depends on upstream formatting assumptions (e.g., syslog hostname presence) is fragile by design — prefer matching on stable literal tokens over structured fields you don't control.
- Correlation rules (`if_matched_sid`) only apply field constraints to the *triggering* event, not to every event counted toward the frequency threshold — worth double-checking for rules meant to filter by protocol/action across a burst window.
- Full lessons-learned log (with root cause + fix for each issue) is in the consolidated report.

## Known Limitations / Future Work

- Several rules (RDP probe, SMB probe, DNS C2, exfiltration `100413`/`100414`) are defined but not yet validated against real captured traffic.
- Exfiltration detection is signature-based and port-scoped — acknowledged as a lab-scope simplification, not production-grade (real SOC environments need volume/behavior-based detection).
- pfSense IPS (Legacy Blocking Mode) is intentionally not enabled in this lab to avoid self-lockout risk; noted as future work.
- Full gap list with recommended fixes is tracked in the consolidated report's "Known Gaps" section.

## Author

Built by **Khoa** — Information Security student (UIT, Ho Chi Minh City), self-taught across DevOps/Cloud, Cybersecurity, DSA, and OOP.

## License

This project's documentation is released under the [MIT License](LICENSE) unless noted otherwise. Attack simulation content is for educational use in an isolated, authorized lab environment only.
README
