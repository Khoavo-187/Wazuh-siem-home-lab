# 🛡️ SOC Home Lab — Wazuh SIEM/XDR + Suricata IDS/IPS + pfSense + Sysmon + VirusTotal

> A self-built Security Operations Center home lab focused on detection engineering, endpoint telemetry, network monitoring, MITRE ATT&CK-mapped threat emulation, and multi-source alert correlation.

![Wazuh](https://img.shields.io/badge/SIEM-Wazuh-1e6d90)
![Suricata](https://img.shields.io/badge/IDS%2FIPS-Suricata-cc0000)
![pfSense](https://img.shields.io/badge/Firewall-pfSense-212121)
![Sysmon](https://img.shields.io/badge/Endpoint-Sysmon-0078D7)
![VirusTotal](https://img.shields.io/badge/Threat%20Intel-VirusTotal-394EFF)
![MITRE ATT&CK](https://img.shields.io/badge/Mapped-MITRE%20ATT%26CK-orange)
![VMware](https://img.shields.io/badge/Virtualization-VMware-607078)
![Status](https://img.shields.io/badge/Status-Active%20Lab-brightgreen)

---

## 📌 Project Overview

This project is a self-hosted SOC home lab built to practice:

- Security monitoring
- Detection engineering
- Custom Wazuh decoders and rules
- Network IDS monitoring with Suricata
- Firewall telemetry with pfSense
- Windows endpoint telemetry with Sysmon
- File Integrity Monitoring (FIM)
- VirusTotal threat-intelligence enrichment
- MITRE ATT&CK mapping
- Threat emulation and alert validation
- False-positive analysis and detection tuning

The main goal is not simply to deploy several security tools, but to reproduce the workflow of a detection engineer:

```text
Attack / Suspicious Behavior
            │
            ▼
       Data Collection
            │
            ▼
        Parsing / Decoder
            │
            ▼
       Detection Rule
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
       Rule Tuning
            │
            ▼
        Re-Test
            │
            ▼
      Final Evidence
```

---

# 🏗️ Current Lab Architecture

## Tested Environment

The majority of the current attack-chain testing was performed with the Kali attacker and Windows victim on the **same `192.168.60.0/24` LAN segment**.

This means that the main attack traffic used in the current threat-emulation runs is **east-west traffic** and does **not necessarily traverse pfSense**.
<img width="2136" height="1716" alt="mermaid-diagram" src="https://github.com/user-attachments/assets/af62cab1-d2f0-4097-bf22-800a6f821334" />


### Important Network Behavior

When Kali uses:

```text
192.168.60.135
```

to attack:

```text
192.168.60.1
```

both hosts are in the same `/24` subnet.

Therefore, the current attack path is conceptually:

```text
Kali
192.168.60.135
      │
      │ East-West traffic
      ▼
Windows
192.168.60.1
      │
      ├── Sysmon
      ├── Suricata
      ├── Wazuh Agent
      └── FIM
             │
             ▼
       Wazuh Manager
       192.168.60.137
```

The traffic above is **not expected to traverse the pfSense LAN interface simply because pfSense exists on the same network**.

pfSense instead acts as the firewall/gateway and telemetry source for traffic that actually crosses its interfaces.

---

# 🌐 Planned External-Attacker Scenario

The lab also contains a WAN-side network:

```text
192.168.254.0/24
```

with:

```text
pfSense WAN
192.168.254.101
```

and Kali can also use:

```text
192.168.254.100
```

A future external-attacker test will use a topology conceptually similar to:
<img width="1590" height="2458" alt="mermaid-diagram (1)" src="https://github.com/user-attachments/assets/1f712357-de46-46b6-a29c-c822900335da" />


This scenario has **not yet been fully validated as part of the attack chain**.

Therefore, this repository currently distinguishes between:

| Scenario | Status |
|---|---|
| Kali `192.168.60.135` → Windows `192.168.60.1` | ✅ Tested |
| East-west detection on Windows Suricata | ✅ Tested |
| Windows endpoint telemetry via Sysmon/Wazuh | ✅ Tested |
| pfSense firewall telemetry | ✅ Tested |
| External attacker → pfSense → Windows | ⚠️ Planned / not fully validated |
| Full attack chain through the pfSense perimeter | ⚠️ Not yet validated |

---

# 🧩 Components

| Component | Role | Current Address |
|---|---|---|
| **Wazuh Manager** | Central SIEM/XDR, rule engine, alert processing | `192.168.60.137` |
| **Wazuh Indexer** | Alert indexing and search backend | `192.168.60.137` |
| **Wazuh Dashboard** | Investigation and visualization | `192.168.60.137` |
| **Windows 11** | Victim endpoint, Wazuh Agent, Sysmon, Suricata | `192.168.60.1` |
| **Kali Linux** | Attack / threat-emulation host | `192.168.60.135` |
| **pfSense** | Firewall / gateway / network telemetry source | WAN `192.168.254.101`, LAN `192.168.60.254` |
| **Suricata** | Network IDS | Windows endpoint + pfSense deployment |
| **Sysmon** | Windows endpoint telemetry | Windows 11 |
| **VirusTotal** | File reputation enrichment | Wazuh Manager integration |
| **VMware** | Virtualization platform | — |

---

# 🔍 Detection Architecture

The lab uses multiple telemetry layers instead of relying on a single detection source.

```text
                         ┌──────────────────────┐
                         │      Kali Linux      │
                         │      Attacker        │
                         └──────────┬───────────┘
                                    │
                         Attack / Suspicious Activity
                                    │
                  ┌─────────────────┴─────────────────┐
                  │                                   │
                  ▼                                   ▼
        ┌──────────────────┐                ┌──────────────────┐
        │     pfSense      │                │ Windows Endpoint │
        │ Firewall / WAN   │                │                  │
        │ / LAN telemetry  │                │ Sysmon           │
        └────────┬─────────┘                │ Suricata         │
                 │                          │ FIM              │
                 │ Syslog                   └────────┬─────────┘
                 │                                    │
                 │                                    │
                 └────────────────┬───────────────────┘
                                  │
                                  ▼
                        ┌────────────────────┐
                        │   Wazuh Manager    │
                        │                    │
                        │ Predecoder         │
                        │ Decoder            │
                        │ Detection Rules    │
                        │ Correlation        │
                        └─────────┬──────────┘
                                  │
                                  ▼
                        ┌────────────────────┐
                        │   Wazuh Indexer    │
                        └─────────┬──────────┘
                                  │
                                  ▼
                        ┌────────────────────┐
                        │ Wazuh Dashboard    │
                        └────────────────────┘
```

---

# 📡 Telemetry Sources

## 1. pfSense

pfSense provides:

- Firewall logs
- Allowed/blocked connection telemetry
- Network metadata
- Syslog forwarding to Wazuh

The current pfSense configuration forwards logs to:

```text
Wazuh Manager
192.168.60.137:514
```

The custom decoder parses pfSense `filterlog` records into fields such as:

```text
srcip
dstip
srcport
dstport
protocol
action
interface
```

Custom pfSense rules provide detection for:

- Multiple firewall blocks
- Possible port scanning
- Ping sweeps
- TCP connection bursts

### Important limitation

pfSense is not assumed to observe every packet in the lab.

For example:

```text
Kali 192.168.60.135
        │
        │ same LAN
        ▼
Windows 192.168.60.1
```

does not automatically mean the traffic crosses:

```text
pfSense 192.168.60.254
```

Therefore, pfSense alerts must be interpreted according to the actual network path.

---

# 🛰️ 2. Suricata

Suricata is used as a network detection layer.

The Windows deployment provides visibility into:

> **East-west traffic involving the monitored Windows endpoint.**

The current custom rules include detections for:

| SID | Detection |
|---|---|
| `1000002` | Possible port scan |
| `1000003` | Repeated SSH connection attempts |
| `1000004` | RDP connection attempt |
| `1000005` | SMB port probe |
| `1000006` | Suspicious reverse-shell / C2 ports |
| `1000007` | Suspicious curl User-Agent |
| `1000008` | EICAR test file over HTTP |
| `1000009` | Suspicious DNS test domain |
| `1000010` | Windows shell banner pattern |
| `1000011` | Curl download of script/executable |

Suricata writes EVE JSON events to:

```text
C:\Program Files\Suricata\log\eve.json
```

The Wazuh Agent consumes this telemetry.

---

# 🖥️ 3. Windows / Sysmon

Sysmon provides endpoint telemetry including:

- Process creation
- Process command lines
- Network connections
- File creation
- Registry modifications
- LSASS access

Important Event IDs used by this project include:

```text
Event ID 1   → Process Creation
Event ID 3   → Network Connection
Event ID 10  → Process Access
Event ID 11  → File Creation
Event ID 13  → Registry Value Modification
```

Windows Security logs are also collected for events such as:

```text
4624 → Successful logon
4625 → Failed logon
4740 → Account lockout
1102 → Security log cleared
```

---

# 🗂️ 4. File Integrity Monitoring

Wazuh FIM monitors selected Windows directories including:

```text
C:\Users\LENOVO\Downloads\virustotaltest
C:\Users\LENOVO\tmp
```

This provides visibility into:

- File creation
- File modification
- File deletion
- Hash changes

FIM is especially useful when combined with Suricata and VirusTotal during payload-delivery scenarios.

---

# 🦠 5. VirusTotal Integration

When FIM identifies a relevant file, the Wazuh manager can use its hash for VirusTotal enrichment.

The resulting telemetry can provide:

```text
MD5
SHA1
SHA256
Malicious / suspicious reputation
Detection count
```

This creates a multi-layer detection chain:

```text
Network Transfer
      │
      ▼
Suricata
      │
      ├───────────────┐
      ▼               ▼
     FIM          File Hash
      │               │
      │               ▼
      │         VirusTotal
      │               │
      └───────┬───────┘
              ▼
         Wazuh Alert
```

---

# ⚙️ Detection Engineering

The project uses custom Wazuh decoders and rules for multiple telemetry sources.

## Custom Decoder

```text
siem-wazuh/custom-decoder/local_decoder.xml
```

The pfSense decoder parses the `filterlog` format and extracts network fields into structured Wazuh fields.

---

## Custom Wazuh Rules

### pfSense

```text
siem-wazuh/custom-rules/pfsense_rules.xml
```

Examples:

```text
100100 → Base pfSense event
100102 → Multiple firewall blocks
100130 → Possible port scan
100140 → TCP connection burst
100201 → Ping sweep
```

### Suricata

```text
siem-wazuh/custom-rules/suricata_rules.xml
```

Examples:

```text
100300 → Possible port scan
100301 → Repeated SSH attempts
100304 → Possible reverse shell / C2
100306 → EICAR file download
100307 → Suspicious DNS test domain
```

### Sysmon / Windows

```text
siem-wazuh/custom-rules/sysmon_rules.xml
```

Examples:

```text
100401 → Encoded PowerShell
100402 → Discovery binaries
100404 → Suspicious PowerShell / CMD network connection
100406 → Registry Run key persistence
100408 → Failed login burst
100410 → Successful login after failed-login burst
100411 → Suspicious LSASS access
100412 → Security log cleared
100413 → Suspicious outbound connection on port 4445
100414 → Suspicious LOLBin traffic on web ports
```

---

# 🧪 Threat Emulation

The project contains an attack chain mapped to MITRE ATT&CK.

The current chain includes:

```text
Reconnaissance
      ↓
Brute Force
      ↓
Initial Access
      ↓
Execution
      ↓
Discovery
      ↓
Payload Delivery
      ↓
Persistence
      ↓
Command & Control
      ↓
Credential Access
      ↓
File Lifecycle
      ↓
Anti-Forensics
      ↓
Exfiltration
```

---

# 🎯 Current Attack Chain Validation

The current validation results should be interpreted carefully.

| Stage | Technique | Current Evidence |
|---|---|---|
| 1 | Reconnaissance | ⚠️ Re-test required; endpoint Suricata is the expected sensor |
| 2 | Brute Force | ✅ Suricata + Windows failed-logon telemetry |
| 3 | Successful Access | ⚠️ Successful `4624` not yet conclusively demonstrated |
| 4 | Encoded PowerShell | ✅ Custom detection observed |
| 5 | Discovery | ⚠️ Built-in Wazuh rule observed; custom rule needs verification |
| 6 | Payload Delivery | ✅ Suricata + FIM + VirusTotal evidence |
| 7 | Persistence | ⚠️ Built-in Sysmon rule observed; custom rule needs verification |
| 8 | Command & Control | ✅ Network detection observed; current rule revision requires re-test |
| 8b | LSASS Access | ⚠️ Needs raw Sysmon Event ID 10 evidence |
| 9 | File Lifecycle | ⚠️ Screenshot evidence exists; raw JSON should be preserved |
| 10 | Anti-Forensics | ✅ Windows Event 1102 observed |
| 11 | Exfiltration | ⚠️ Detection and raw evidence still need validation |

The project intentionally documents detection gaps rather than treating every planned rule as already verified.

---

# 🧭 Stage 1 — Reconnaissance

The current Stage 1 test is:

```bash
nmap -sS -T4 -p- 192.168.60.1
ping -c 5 192.168.60.1
```

### Current network path

```text
Kali
192.168.60.135
      │
      │ TCP SYN
      │
      ▼
Windows Victim
192.168.60.1
```

The expected network sensor for this traffic is the **Suricata instance running on the Windows endpoint**.

The corresponding Suricata SID is:

```text
1000002
```

and the Wazuh wrapper rule is:

```text
100300
```

### Why pfSense may not alert on this scan

The current attacker and victim are on the same LAN subnet:

```text
192.168.60.0/24
```

Therefore, the traffic does not automatically cross the pfSense gateway.

A pfSense alert observed during the same test window must therefore be checked carefully before being attributed to the Nmap scan.

For example, loopback traffic such as:

```text
127.0.0.1 → 127.0.0.1:53
```

is not evidence that pfSense detected the Kali scan.

---

# 📊 Detection Philosophy

The project emphasizes **behavior-based detection** instead of relying exclusively on static indicators.

For example, a reverse shell should not be detected only because it uses:

```text
4444
```

The project therefore combines:

```text
Network indicators
+
Process telemetry
+
Connection behavior
+
File activity
+
Registry activity
+
Authentication events
```

This allows the same behavior to be investigated from multiple independent telemetry sources.

---

# 🛡️ Defense-in-Depth Examples

## Example 1 — Brute Force

```text
Kali / Hydra
      │
      ▼
Suricata
      │
      └── Repeated SSH connection attempts
                  │
                  ▼
            Windows Security
                  │
                  └── Event 4625
                         │
                         ▼
                   Wazuh
```

## Example 2 — Payload Delivery

```text
Kali HTTP Server
      │
      ▼
Windows victim
      │
      ├── Suricata
      │      └── EICAR download
      │
      ├── FIM
      │      └── New file detected
      │
      └── VirusTotal
             └── Hash reputation
                    │
                    ▼
                 Wazuh
```

## Example 3 — Persistence

```text
reg.exe
   │
   ▼
Registry Run Key modified
   │
   ├── Sysmon Event 13
   │
   └── Wazuh detection
```

---

# 📁 Repository Structure

```text
Wazuh-siem-home-lab/
│
├── README.md
│
├── architecture/
│   └── Architecture-and-data-flow.png
│
├── docs/
│   ├── 01-infrastructure-setup.md
│   ├── 02-log-ingestion-pipeline.md
│   ├── 03-Detection-engineering.md
│   └── 04-threat-emulation-report.md
│
├── endpoints/
│   ├── manager/
│   │   └── m_ossec.conf
│   │
│   └── windows-11/
│       ├── ossec.conf
│       └── sysmon_config.xml
│
├── network/
│   ├── pfsense_config/
│   │   └── config_backup.xml
│   │
│   └── Suricata_configuration/
│       ├── local.rules
│       └── suricata.yaml
│
├── siem-wazuh/
│   ├── custom-decoder/
│   │   └── local_decoder.xml
│   │
│   └── custom-rules/
│       ├── pfsense_rules.xml
│       ├── suricata_rules.xml
│       └── sysmon_rules.xml
│
└── screenshot/
    ├── Stage1_recon.png
    ├── Stage2_bruteforce.png
    ├── Stage3_access.png
    ├── Stage5_discovery.png
    ├── Stage6_payload1.png
    ├── Stage6_payload2.png
    ├── Stage6_payload3.png
    ├── Stage7_persistence.png
    ├── Stage8_C2.png
    └── Stage9_fim.png
```

---

# 📚 Documentation

## Infrastructure

[`docs/01-infrastructure-setup.md`](docs/01-infrastructure-setup.md)

Documents:

- VMware topology
- Wazuh installation
- Windows endpoint setup
- pfSense setup
- Suricata setup
- Wazuh Agent integration
- Network connectivity validation

## Log Ingestion

[`docs/02-log-ingestion-pipeline.md`](docs/02-log-ingestion-pipeline.md)

Documents:

- pfSense syslog ingestion
- Custom pfSense decoder
- Suricata EVE JSON ingestion
- Windows Event Channel ingestion
- Sysmon telemetry
- FIM
- VirusTotal integration

## Detection Engineering

[`docs/03-Detection-engineering.md`](docs/03-Detection-engineering.md)

Documents:

- Custom decoders
- Custom Wazuh rules
- Suricata rules
- Sysmon rules
- Correlation logic
- False positives
- Detection limitations
- Tuning decisions

## Threat Emulation Report

[`docs/04-threat-emulation-report.md`](docs/04-threat-emulation-report.md)

Documents:

- Attack chain
- MITRE ATT&CK mapping
- Attack commands
- Observed telemetry
- Alert analysis
- Detection gaps
- Re-test requirements
- Evidence status

---

# 🔬 Verification Methodology

A detection is not considered fully validated simply because the XML rule looks correct.

The project follows:

```text
1. Create detection logic
        ↓
2. Generate the behavior
        ↓
3. Collect telemetry
        ↓
4. Inspect raw event
        ↓
5. Run wazuh-logtest where appropriate
        ↓
6. Verify the final Wazuh rule ID
        ↓
7. Investigate false positives
        ↓
8. Tune the rule
        ↓
9. Re-test
        ↓
10. Preserve evidence
```

This is especially important for correlation rules where built-in Wazuh rules may match before a custom rule.

---

# ⚠️ Current Known Limitations

## 1. External Attacker Scenario Not Yet Fully Tested

The current attack chain was primarily tested with:

```text
Kali    192.168.60.135
Windows 192.168.60.1
```

on the same LAN.

The external attacker scenario:

```text
Kali
  ↓
pfSense
  ↓
Windows
```

still requires a dedicated validation run.

## 2. Some Custom Rules Are Not Yet Proven

Several stages are currently detected by built-in Wazuh/Sysmon rules rather than the intended custom rules.

Examples include:

```text
100402
100406
100410
100411
100412
100413
```

These require additional testing and raw alert evidence.

## 3. Raw Evidence Coverage Is Incomplete

Some historical stages rely on:

- Screenshots
- Condensed JSON excerpts
- Earlier rule revisions

The final version of the project should preserve raw JSON evidence whenever possible.

## 4. Suricata Visibility Depends on Sensor Placement

A network IDS cannot observe traffic that does not traverse the interface being monitored.

Therefore:

```text
Same-LAN traffic
```

and:

```text
Traffic crossing pfSense
```

must be treated as different visibility scenarios.

---

# 🚧 Future Improvements

Planned improvements include:

- Validate the external-attacker topology through pfSense
- Complete raw evidence collection for every attack stage
- Re-test correlation rules
- Improve endpoint network detections
- Tune Suricata EVE ingestion to reduce unnecessary telemetry
- Expand MITRE ATT&CK coverage
- Build a Wazuh SOC dashboard for the full attack chain
- Preserve reusable threat-emulation scripts and raw evidence
- Improve investigation and incident-response documentation

---

# 🎯 Project Goals

This project is designed to demonstrate practical Blue Team skills in:

- SOC monitoring
- Detection engineering
- Network IDS
- Endpoint telemetry
- SIEM configuration
- Log parsing
- Custom Wazuh rules
- Custom Wazuh decoders
- MITRE ATT&CK mapping
- Threat emulation
- Alert triage
- Correlation
- False-positive analysis
- Detection tuning
- Evidence-based validation

---

# 🧠 Key Lessons Learned

### 1. Sensor placement matters

A firewall can only detect traffic that reaches it.

A host-based network sensor can provide visibility into east-west traffic that may bypass the perimeter firewall.

### 2. A detection must be validated against real telemetry

A rule that looks logically correct can still fail because of:

- Decoder behavior
- Rule precedence
- Event structure
- Missing fields
- Telemetry configuration
- Network path
- Traffic direction

### 3. Multiple telemetry sources provide stronger evidence

A single event may be ambiguous.

Combining:

```text
Suricata
+
pfSense
+
Sysmon
+
Windows Security
+
FIM
+
VirusTotal
```

provides much stronger investigation context.

### 4. Documentation must match the real network

The attack path should be documented according to the traffic that actually exists, rather than assuming that every attacker-to-victim connection passes through the firewall.

---

# 📌 Current Project Status

> **Status: Active / Iterative Detection Engineering Lab**

The project has successfully demonstrated multi-source detection across:

```text
Network
Endpoint
Authentication
File Integrity
Threat Intelligence
SIEM Correlation
```

The current attack-chain evidence is strongest for the **same-LAN east-west scenario**.

The next major validation milestone is to test an attacker positioned outside the victim LAN and verify the complete:

```text
Kali
  ↓
pfSense
  ↓
Windows
  ↓
Suricata / Sysmon / Wazuh
```

path.

---

# 👤 Author

**Võ Minh Khoa**

Information Security / Cybersecurity Student  
University of Information Technology (UIT)

Focused on:

- SOC / Blue Team
- Detection Engineering
- DFIR
- Network Security
- SIEM
- Threat Emulation
