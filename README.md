# 🛡️ SOC Home Lab — Wazuh SIEM/XDR + Suricata IDS + pfSense + Sysmon + VirusTotal

> A self-built Security Operations Center home lab focused on detection engineering, endpoint telemetry, network monitoring, MITRE ATT&CK-mapped threat emulation, and multi-source alert correlation.

![Wazuh](https://img.shields.io/badge/SIEM-Wazuh-1e6d90)
![Suricata](https://img.shields.io/badge/IDS-Suricata-cc0000)
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

-**The Windows 11 victim is the physical Windows host running VMware Workstation, not a separate virtual machine. Kali Linux, Wazuh and pfSense run as VMware virtual machines. The Windows host participates in the internal lab network through VMware Network Adapter VMnet1.**

## Tested Environment

The majority of the current attack-chain testing was performed with the Kali attacker and Windows victim on the **same `192.168.60.0/24` LAN segment**.

The Windows victim is the `physical VMware host`. Direct `Kali-to-Windows communication` occurs over VMnet1 without requiring pfSense to route the traffic.

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
| **Windows 11 Physical Host** | VMware host and victim endpoint; runs Wazuh Agent, Sysmon, Suricata and FIM | VMnet1: `192.168.60.1` |
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
| `1000010` | Windows CMD banner pattern |
| `1000011` | Curl download of script/executable |
| `1000012` | PowerShell HTTP POST to a non-HOME_NET destination (Stage 11; pending validation) |

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
100300 → Possible port scan (SID 1000002)
100301 → Repeated SSH connection attempts (SID 1000003)
100302 → RDP connection attempts (SID 1000004)
100303 → SMB port probe (SID 1000005)
100304 → Possible reverse shell / C2 port (SID 1000006)
100305 → curl User-Agent (SID 1000007)
100306 → EICAR download (SID 1000008)
100307 → Suspicious DNS test domain (SID 1000009)
100308 → Windows CMD banner (SID 1000010)
100309 → curl download of script/executable (SID 1000011)
100310 → Stage 11 HTTP POST upload (SID 1000012; pending validation)
```

### Sysmon / Windows

```text
siem-wazuh/custom-rules/sysmon_rules.xml
```

Examples:

```text
100400 → Shell-spawned child process
100401 → Encoded PowerShell command (current XML level 13)
100402 → Discovery binaries (whoami, systeminfo, tasklist, nltest, net/net1, arp)
100403 → certutil/bitsadmin execution (base signal)
100404 → PowerShell/CMD outbound network connection
100405 → File creation under Temp/AppData Roaming
100406 → Registry Run/RunOnce persistence (parents 92300 OR 92302)
100407 → Correlation: multiple discovery binaries
100408 → Failed-logon burst (4625 / 60122)
100410 → Successful 4624 after prior failed-logon activity (pending correlation validation)
100411 → Suspicious LSASS ProcessAccess (positive validation pending)
100412 → Security log cleared (current parent 63103; retest pending)
100413 → PowerShell Invoke-WebRequest activity (Event 4103; pending validation)
100414 → PowerShell/certutil network connection on ports 80/443
100415 → certutil/bitsadmin with download/decode arguments
100416 → LSASS access with suspicious call trace
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

The table separates evidence from an earlier test/revision from validation of the current committed configuration.

| Stage | Technique / activity | Evidence in repository | Current status |
|---|---|---|---|
| 1 | Reconnaissance | A baseline Suricata `100300` alert exists, but the original chain's pfSense `100140` alert is unrelated loopback DNS; no matching Stage 1 chain alert is preserved. | ⚠️ Stage-specific retest required |
| 2 | Brute Force | Suricata `100301`, Windows `60122`, and custom `100408` evidence; the 2026-10-10 retest records source IP `192.168.60.135`. | ✅ Evidence observed; retest current config if changed |
| 3 | Successful Access | A successful Windows `4624` was classified by built-in `92657` on 2026-10-10. No current-revision custom `100410` alert is preserved. | ⚠️ `100410` correlation pending validation |
| 4 | Encoded PowerShell | Historical custom `100401` alert exists at level 10. Current XML is level 13 and must be retested to validate the current revision/severity. | ✅ Historical evidence; current revision retest recommended |
| 5 | Discovery | Custom `100407` correlation and `100400` evidence exist; the saved ARP event matched historical `100400`. Current XML now routes ARP to `100402`, so the interaction needs regression testing. | ✅ Historical evidence; current rule interaction pending retest |
| 6 | Payload delivery | Suricata `100306` raw alert and VirusTotal `87105` evidence exist; the VirusTotal sample is from an earlier baseline run. FIM evidence is not preserved as a raw JSON record in the evidence index. | ✅ Network/reputation evidence observed; same-run correlation not established |
| 7 | Persistence | Custom `100406` raw alert exists from 2026-10-13. The current XML allows parent `92300` or `92302`; the preserved retest documents the `92302` path. | ✅ Historical positive evidence; alternate parent `92300` not separately tested |
| 8 | Command & Control | Custom `100304` alert exists from SID `1000006` revision 2. Current Suricata SID revision 3 requires an established flow. | ⚠️ Historical detection; current revision retest required |
| 8b | LSASS access | A real Windows Defender ProcessAccess event reached Wazuh and built-in `92900` fired. No positive `100411`/`100416` test is preserved. | ⚠️ Telemetry observed; positive detection not validated |
| 9 | File lifecycle | Screenshot evidence for FIM modified/deleted events; no raw Stage 9 JSON is preserved. | ✅ Screenshot only; raw evidence needed |
| 10 | Anti-forensics | Historical custom `100412` alert exists from 2026-10-13. Current XML now uses parent `63103`; that exact revision has not been retested. | ✅ Historical positive evidence; current parent revision pending |
| 11 | HTTP transfer / exfiltration simulation | Windows/Kali scripts, Sysmon ZIP FileCreate filter, Suricata SID `1000012`, Wazuh wrapper `100310`, and Wazuh rule `100413` are implemented/configured. No capture, hash comparison, Event 4103 or positive alert is preserved. | ❌ Not evidenced end-to-end |

Full stage-by-stage provenance and limitations are in [`docs/04-threat-emulation-report.md`](docs/04-threat-emulation-report.md). A rule is not considered validated merely because its XML exists.

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
├── threat-emulation/
│   ├── attack-scripts/
│   │   ├── README.md
│   │   ├── 00-preparation_kali.sh
│   │   ├── 01-reconnaissance_kali.sh
│   │   ├── 02-bruteforce_kali.sh
│   │   ├── 03-successful-access_kali.sh
│   │   ├── 04-execution_windows.ps1
│   │   ├── 05-discovery_windows.cmd
│   │   ├── 06-payload-drop_kali.sh
│   │   ├── 06-payload-drop_windows.cmd
│   │   ├── 07-persistence_windows.cmd
│   │   ├── 08-command-control_kali.sh
│   │   ├── 08-command-control_windows.ps1
│   │   ├── 08b-credential-access_windows.cmd
│   │   ├── 09-file-lifecycle_windows.ps1
│   │   ├── 10-anti-forensics_windows.ps1
│   │   ├── 11-exfiltration_kali.sh
│   │   └── 11-exfiltration_windows.ps1
│   └── evidence-logs/
│       ├── README.md
│       ├── baseline-*.json
│       └── stage*-*.json
│
│
└── screenshot/
    ├── Stage1_recon.png
    ├── Stage2_bruteforce.png
    ├── stage2_rule.png          — 2026-10-09 preliminary re-test
    ├── Stage3_access.png
    ├── Stage5_discovery.png
    ├── stage5_evidence.png      — 2026-10-13 re-test
    ├── Stage6_payload1.png
    ├── Stage6_payload2.png
    ├── Stage6_payload3.png
    ├── Stage7_persistence.png
    ├── stage7_new.png           — 2026-10-13 re-test
    ├── Stage8_C2.png
    ├── stage8b_dump.png         — Windows Defender false positive
    ├── Stage9_fim.png
    └── stage10_cleanup.png      — 2026-10-13 re-test
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

[`docs/04-threat-emulation-report.md`](docs/04-threat-emulation-report.md) — raw evidence and attack scripts referenced from it live in [`threat-emulation/`](threat-emulation/)

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

## 1. Evidence is revision-specific

Several saved alerts were produced by earlier versions of the rule files. They demonstrate that the earlier rule revision fired, but do not automatically validate the current XML. This applies in particular to:

- `100401`: the archived alert is level 10; the current XML is level 13.
- Stage 5: the archived ARP alert matched `100400`; current XML excludes ARP from `100400` and includes it in `100402`.
- `100304`: archived Stage 8 evidence is from SID `1000006` revision 2; the current signature requires an established flow (revision 3).
- `100412`: the archived custom alert predates the current parent `63103`.
- `100406`: the current XML has parent alternatives `92300` and `92302`; only the `92302` path is represented by the documented historical retest.

## 2. Important detections remain pending validation

| Rule / stage | Current gap |
|---|---|
| Stage 1 / `100300` | A baseline `100300` alert exists, but the original attack-chain scan has no clean, attributable Stage 1 alert. Retest the Windows endpoint sensor. |
| `100410` | Current stateful correlation (`60122` history, `92651` OR `92657` current-event parent, six matches / 200 seconds / same source IP) has no positive raw alert from this revision. |
| `100411` / `100416` | Event 10 telemetry is visible, but no true-positive LSASS access test validates the custom filters or call-trace escalation. |
| `100412` | Historical custom alerts exist, but the current `63103` parent revision needs a separate positive replay/test. |
| `100413` | PowerShell Operational channel is configured; Module Logging/Event 4103 activation, ingestion, decoded fields, parent `91801` and positive custom alert remain unverified. |
| SID `1000012` / Wazuh `100310` | HTTP POST detection is implemented for Stage 11 but has no preserved positive Suricata/Wazuh alert. |
| Stage 11 transfer | No preserved HTTP capture, extracted ZIP body, matching SHA256, or confirmed receipt exists. |

## 3. Stage 11 is an implemented procedure, not a completed exfiltration test

The Windows script creates `C:\Windows\Temp\exfil_test.zip` and sends an HTTP POST to Kali TCP/4445. The Kali Netcat process captures a raw HTTP request stream, not a clean ZIP file or a normal HTTP upload response. The request body must be extracted before comparing its SHA256 with the Windows archive. A PowerShell response error alone does not prove that no bytes were sent.

The current detection layers are:

- Sysmon Event 11 for the ZIP file creation (the committed Sysmon config includes a `C:\Windows\Temp` + `.zip` FileCreate condition).
- Wazuh FIM on `C:\Windows\Temp` restricted to `.zip` files.
- Suricata SID `1000012` and Wazuh wrapper `100310` for the HTTP POST to TCP/4445.
- PowerShell Event 4103 and Wazuh rule `100413` for `Invoke-WebRequest` activity.

All four require separate runtime validation. A file-created alert, HTTP request alert, PowerShell activity alert, and verified file receipt are different claims.

## 4. Network visibility is sensor-dependent

Kali `192.168.60.135` and Windows `192.168.60.1` share `192.168.60.0/24`. Direct east-west traffic between them does not normally traverse pfSense. Use Windows Suricata for that path. Test pfSense separately with traffic that actually crosses one of its interfaces; do not claim that the firewall detected a same-subnet scan without matching evidence.

## 5. Environment reproducibility is incomplete

- `endpoints/manager/m_ossec.conf` is a sanitized skeleton containing `...` placeholders; it is not a deployable full Manager configuration (already modified and adding in the `/manger` folder).
- The exact Wazuh build and pfSense version are not recorded in `docs/01`.
- The monitored Windows 11 endpoint is the physical VMware host, not a disposable guest. Destructive tests should use a separate disposable Windows VM.
- The external-attacker / pfSense-routed attack path is planned but not demonstrated end-to-end.
- Some stages rely on screenshots, abbreviated excerpts, or historical rule revisions instead of full raw evidence.

## 6. Suricata scope

- The committed Suricata configuration runs in IDS mode. `HOME_NET` excludes Kali (`192.168.60.135`) to make the attacker appear as `$EXTERNAL_NET` for the current rules. The second pfSense-side Suricata instance is not configured/evidenced in this repository. The committed EVE file is the Windows endpoint sensor's `eve.json`.
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

The repository contains a multi-source SOC lab with Wazuh, Windows Sysmon/Security telemetry, endpoint Suricata, pfSense syslog, FIM and VirusTotal enrichment. Several custom detections have dated raw-alert evidence, including brute-force, discovery correlation, payload delivery, registry persistence, reverse-shell network activity and historical Security-log clearing.

The strongest demonstrated scenario is the **same-LAN Kali-to-Windows east-west path**. The repository does not yet establish an uninterrupted, fully detected attack chain. Stage 1 attribution, current revisions of `100410`, `100412` and SID `1000006`, positive LSASS detection, raw Stage 9 evidence, and Stage 11 transfer/detection remain open validation items.

The next milestone is to close those evidence gaps and align every result with the exact rule/configuration revision that produced it.


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
