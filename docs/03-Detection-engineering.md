---
title: "SOC Home Lab — Detection Engineering"
tags: [Blue Team, SOC Home Lab, Detection engineering]
lang: en
breaks: true
---

# 03 — Detection Engineering: Decoders & Rules

> Reference for every custom **decoder** and **rule** in the lab: **pfSense** (firewall), **Suricata** (network IDS) and **Sysmon / Windows Event Log** (endpoint).
> For each entry: *what it matches, why it is written that way, and where it can fail.*

**File origin**

| Type | File |
|---|---|
| Decoder (pfSense) | [`local_decoder.xml`](https://github.com/Khoavo-187/Wazuh-siem-home-lab/blob/main/siem-wazuh/custom-decoder/local_decoder.xml) |
| Wazuh rules (pfSense) | [`pfsense_rules.xml`](https://github.com/Khoavo-187/Wazuh-siem-home-lab/blob/main/siem-wazuh/custom-rules/pfsense_rules.xml) |
| Wazuh rules (Suricata wrappers) | [`suricata_rules.xml`](https://github.com/Khoavo-187/Wazuh-siem-home-lab/blob/main/siem-wazuh/custom-rules/suricata_rules.xml) |
| Wazuh rules (Sysmon & Windows events) | [`sysmon_rules.xml`](https://github.com/Khoavo-187/Wazuh-siem-home-lab/blob/main/siem-wazuh/custom-rules/sysmon_rules.xml) |
| Suricata rules | [`local.rules`](https://github.com/Khoavo-187/Wazuh-siem-home-lab/blob/main/network/Suricata_configuration/local.rules) |
| Suricata configuration | [`suricata.yaml`](https://github.com/Khoavo-187/Wazuh-siem-home-lab/blob/main/network/Suricata_configuration/suricata.yaml) |
| Sysmon configuration | [`sysmon_config.xml`](https://github.com/Khoavo-187/Wazuh-siem-home-lab/blob/main/endpoints/windows-11/sysmon_config.xml) (SwiftOnSecurity, source version 74) |
| Wazuh agent configuration | [`ossec.conf`](https://github.com/Khoavo-187/Wazuh-siem-home-lab/blob/main/endpoints/windows-11/ossec.conf) |

---

## 0. Overview

### 0.1 Data flow

```mermaid
flowchart LR
  PF["pfSense<br/>filterlog (remote syslog)"] --> MGR

  subgraph EP["Windows 11 endpoint"]
    WIN["Windows Event Channel<br/>Security + Sysmon"] --> AG["Wazuh agent"]
    SU["Suricata<br/>eve.json"] --> AG
    FIM["FIM (realtime syscheck)"] --> AG
  end

  AG --> MGR["Wazuh manager<br/>predecoder → decoder → rules"]
  MGR <-->|"hash lookup"| VT["VirusTotal API"]
  MGR --> DASH["Indexer / Dashboard"]
```

| Source | Transport | Decoder | Parent rule |
|---|---|---|---|
| pfSense | Remote syslog to the manager (`192.168.60.137:514`, RFC 3164) | `pfsense-lab` + 5 child decoders (custom) | `100100` (custom) |
| Suricata (Windows endpoint) | `eve.json` → agent `localfile` (JSON) | Built-in JSON decoder | `86601` (built-in Suricata alert rule) |
| Sysmon / Security | Event Channel → agent | `windows_eventchannel` (built-in) | Built-in Sysmon / Windows rules (`sysmon_event*` groups, `60106`, `60117`, `60122`) |

### 0.2 ID ranges

| Wazuh rule IDs | Source | Content |
|---|---|---|
| `100100`–`100140` | pfSense | Base, block/pass, scan, burst |
| `100200`–`100201` | pfSense | ICMP, ping sweep |
| `100300`–`100307` | Suricata | Wrappers for sids `1000002`–`1000009` |
| `100400`–`100414` | Sysmon / Windows Security | Process, network, file, registry, credential, anti-forensics |
| `1000002`–`1000011` | Suricata **sids** (not Wazuh IDs) | Network-side detections |

### 0.3 Rule attributes used in this document

| Attribute | Meaning |
|---|---|
| `if_sid` / `if_group` | Child rule: evaluated only when the parent rule (or any rule of the group) matched **on the same event** |
| `if_matched_sid` + `frequency` / `timeframe` | Correlation: fires when the target rule matched ≥ N times within T seconds |
| `same_source_ip`, `same_field`, `different_*` | Events in a correlation chain must share (or differ in) the given field |
| `ignore` | After firing, mute the rule for N seconds |
| `options no_log` | Match for chaining/correlation only; no alert is generated |

> `frequency` thresholds follow Wazuh's counting and can be off by ±1 event from the figures quoted below.

---

## 1. pfSense

### 1.1 `filterlog` format

pfSense forwards firewall logs to the manager over syslog (`logall`, RFC 3164). The syslog header is not consistent: in some events the hostname is missing and Wazuh's predecoder puts `filterlog[pid]:` into the `hostname` field. That is why the parent decoder matches on the **message content** and not on `program_name`.

Sample line (IPv4 TCP):

```text
Aug  8 10:53:29 filterlog[63489]: 80,,,100000101,em1,match,pass,in,4,0x0,,128,33199,0,DF,6,tcp,52,192.168.60.101,162.159.197.3,61197,443,0,S,1576499639,,65535,,mss;nop;wscale;nop;nop;sackOK
```

| # | filterlog field | Example | Wazuh field |
|---|---|---|---|
| 1 | rule number | `80` | `pfsense.rulenum` |
| 2 | sub-rule | *(empty)* | skipped (the `,,,` in the regex) |
| 3 | anchor | *(empty)* | skipped |
| 4 | tracker | `100000101` | `pfsense.tracker` |
| 5 | interface | `em1` | `pfsense.interface` |
| 6 | reason | `match` | `pfsense.reason` |
| 7 | action | `pass` | **`action`** (static) |
| 8 | direction | `in` | `pfsense.direction` |
| 9 | IP version | `4` | `pfsense.ipversion` |
| 10 | TOS | `0x0` | `pfsense.tos` |
| 11 | ECN | *(empty)* | `pfsense.ecn` |
| 12 | TTL | `128` | `pfsense.ttl` |
| 13 | IP ID | `33199` | `pfsense.id` |
| 14 | fragment offset | `0` | `pfsense.offset` |
| 15 | IP flags | `DF` | `pfsense.flags` |
| 16 | protocol ID | `6` | `pfsense.protocol_number` |
| 17 | protocol text | `tcp` | **`protocol`** (static) |
| 18 | length | `52` | `pfsense.length` |
| 19 | source IP | `192.168.60.101` | **`srcip`** (static) |
| 20 | destination IP | `162.159.197.3` | **`dstip`** (static) |
| 21 | source port | `61197` | **`srcport`** (static) |
| 22 | destination port | `443` | **`dstport`** (static) |
| 23 | data length | `0` | `pfsense.data_length` |
| 24+ | TCP flags, seq, ack, window, options | `S,1576499639,…` | **not decoded** |

Bold fields are Wazuh *static fields*: rules can use them directly (`<action>`, `<protocol>`, `<same_source_ip/>`, `$(srcip)`). All other fields live under `data.pfsense.*`.

Interfaces seen in the lab logs: `em1` (LAN `192.168.60.0/24`), `em0` (WAN side `192.168.254.0/24`), `lo0` (loopback).

### 1.2 Decoder tree

```text
pfsense-lab                      (parent: recognises every filterlog line)
├── pfsense-lab-ports            IPv4 TCP / UDP
├── pfsense-lab-icmp             IPv4 ICMP
├── pfsense-lab-igmp             IPv4 IGMP
├── pfsense-lab-ipv4             IPv4, any other protocol (fallback)
└── pfsense-lab-ipv6             IPv6
```

| Decoder | Prematch (short) | Extra fields (beyond the common prefix) |
|---|---|---|
| `pfsense-lab` | `filterlog\[\d+\]:\s*` | none (parent only) |
| `pfsense-lab-ports` | IPv4 + `tcp` or `udp` | `srcport`, `dstport`, `pfsense.data_length` |
| `pfsense-lab-icmp` | IPv4 + `icmp` | `pfsense.icmp_type`, `pfsense.icmp_id`, `pfsense.icmp_seq` |
| `pfsense-lab-igmp` | IPv4 + `igmp` | none (stops at `dstip`) |
| `pfsense-lab-ipv4` | IPv4, protocol ∉ {tcp, udp, icmp, igmp} | none (stops at `dstip`) |
| `pfsense-lab-ipv6` | IPv6 (`,6,`) | `pfsense.class`, `pfsense.flowlabel`, `pfsense.hoplimit` |

#### `pfsense-lab` — parent
- PCRE2 prematch `filterlog\[\d+\]:\s*` finds `filterlog[<pid>]:` anywhere in the line.
- Children use `offset="after_parent"`: their regex starts **after** `filterlog[pid]: `, so the (variable) syslog header never needs to be parsed.

#### `pfsense-lab-ports` — IPv4 TCP / UDP
- Prematch: `\d+,,,.*?,4,.*?,(?:tcp|udp),` — rule number followed by `,,,` (empty sub-rule and anchor), version `4`, protocol `tcp` or `udp`.
- The regex has 21 capture groups mapped one-to-one to the 21 names in `<order>`.
- The `(tcp|udp)` group fills the static field `protocol`, which lets rule `100140` filter on `^tcp$`.
- UDP example: `76,,,1000002661,em0,match,pass,out,4,0x0,,63,4250,0,none,17,udp,64,192.168.254.101,8.8.8.8,20455,53,44` → `srcip=192.168.254.101`, `dstip=8.8.8.8`, `dstport=53`, `pfsense.data_length=44`.

#### `pfsense-lab-icmp` — IPv4 ICMP
- After `dstip`, an ICMP echo carries three fields: type (`request` / `reply`), id, sequence.
- Example: `74,,,1000002565,em1,match,pass,out,4,0x0,,64,40058,0,none,1,icmp,84,192.168.60.254,192.168.60.101,request,40169,064` → `pfsense.icmp_type=request`, `pfsense.icmp_id=40169`, `pfsense.icmp_seq=064`.

#### `pfsense-lab-igmp` — IPv4 IGMP
- Extracts up to `dstip` and ignores the options that follow. Purpose: multicast traffic (`224.0.0.x`) is decoded instead of falling through to the generic fallback.

#### `pfsense-lab-ipv4` — IPv4 fallback
- Catches every remaining IPv4 protocol (ESP, GRE, OSPF, …).
- The protocol group uses a negative lookahead `((?!(?:tcp|udp|icmp|igmp),)[^,]+)` to **exclude** the four protocols that already have a dedicated decoder, so the child decoders never overlap.

#### `pfsense-lab-ipv6` — IPv6
- Differences from IPv4: after the version come `class`, `flowlabel`, `hoplimit`, and the **protocol text comes before the protocol ID** (reverse of IPv4). The regex mirrors that with `([^,]+),(\d+)`.
- Extracts up to `srcip` / `dstip`; no ports.

#### Decoder limitations

| # | Limitation | Consequence |
|---|---|---|
| 1 | TCP flags (`S`, `SA`, `F`, …) are not extracted | SYN cannot be told apart from other packets; `100140` counts logged `pass` events rather than SYNs |
| 2 | The ICMP decoder only matches echo (`type,id,seq`) | Other ICMP types (unreachable, time-exceeded, …) use a different layout and would need their own decoder to get `srcip`/`dstip` — *confirm with `wazuh-logtest`* |
| 3 | `sub-rule` and `anchor` must be empty (`,,,`) | Events from rules inside an anchor are not decoded |
| 4 | No ports for IPv6 | IPv6 port scans are invisible |
| 5 | Loose prematch (`.*?,4,` can match by accident) | Harmless, because the regex that follows pins every position; anchoring with `^` would be a cheap optimisation |

### 1.3 pfSense rules

```text
filterlog ─► 100100 (base, no_log)
              ├─► 100101 block ──► 100102  ≥10 blocks / 60s, same source
              ├─► 100110 pass  ──► 100140  ≥15 connections / 10s, same src → dst:port (TCP)
              ├─► 100200 ICMP  ──► 100201  ≥8 ICMP / 30s, same source, many destinations
              └─► 100130  ≥15 events / 30s, same source, many different dst ports (any action)
```

| ID | Level | Condition | Correlation | MITRE |
|---|---|---|---|---|
| `100100` | 1 (`no_log`) | `decoded_as pfsense-lab` | none | none |
| `100101` | 5 | `action = block` | none | none |
| `100102` | 10 | rule `100101` | ≥10 / 60s, `same_source_ip`, `ignore 120` | T1046 |
| `100110` | 3 (`no_log`) | `action = pass` | none | none |
| `100130` | 10 | any `100100` event | ≥15 / 30s, `same_source_ip`, `different_dstport`, `ignore 120` | T1046 |
| `100140` | 6 | rule `100110` + `protocol = tcp` + `dstport` in `{22,23,445,3389,5900,1433,3306}` | ≥15 / 10s, same src, dst, dstport, `ignore 60` | none |
| `100200` | 3 (`no_log`) | `protocol = icmp` | none | none |
| `100201` | 8 | rule `100200` | ≥8 / 30s, `same_source_ip`, `different_dstip`, `ignore 120` | T1018 |

#### `100100` — Firewall log detected (level 1, `no_log`)
Root of the whole pfSense tree. `no_log` keeps thousands of level-1 alerts out of the index, while the rule still serves as the parent for the `if_sid` / `if_matched_sid` rules below.

#### `100101` — Traffic blocked (level 5)
- `if_sid 100100` + `<action>block</action>` (`action` is the static field from column 7 of filterlog).
- One alert per blocked packet; the description carries the 5-tuple `$(srcip):$(srcport) -> $(dstip):$(dstport)`.
- Limitation: only `block` is matched; `reject` (pfSense answers with RST/ICMP) is not covered.

#### `100102` — Multiple firewall blocks (level 10)
- Correlation on `100101`: ≥10 packets blocked from the same `srcip` within 60s → scan or brute force against closed ports. Mapped to T1046.
- `ignore 120` mutes the rule for 120s after it fires.

#### `100110` — Traffic allowed (level 3, `no_log`)
Not meant to alert. It is the link that lets `100140` count allowed connections.

#### `100130` — Possible port scan, many destination ports (level 10)
- Correlation over **all** pfSense events (`100100`, pass and block): same `srcip`, ≥15 different `dstport` values within 30s. Mapped to T1046.
- Detects scans by **behaviour** (diversity of destination ports) instead of by action, so it still fires when ports are open and traffic is passed (where `100102` sees nothing).
- Limitation: an internal host legitimately reaching many services at once can cross the threshold.
- Lab trigger: `nmap -sS -p1-1000 <target>` from Kali.

#### `100200` — ICMP ping detected (level 3, `no_log`)
- `if_sid 100100` + `<protocol>^icmp$</protocol>`.
- Purpose: record pings and feed `100201`. Fixed to level 3 + `no_log` (was level 7, alerting on every ICMP packet including pfSense's own gateway monitoring) — only `100201` (the correlation) now alerts.

#### `100201` — Ping sweep (level 8)
- Correlation on `100200`: same `srcip`, ≥8 different `dstip` within 30s. Mapped to T1018 (Remote System Discovery).
- Lab trigger: `nmap -sn 192.168.60.0/24`.

#### `100140` — TCP connection burst (level 6)
- Correlation on `100110`: same `srcip`, `dstip`, `dstport`, `protocol = tcp`, `dstport` restricted to administrative services (`22` SSH, `23` Telnet, `445` SMB, `3389` RDP, `5900` VNC, `1433` MSSQL, `3306` MySQL), ≥15 events within 10s.
- Meaning: flood or brute force against **one** admin service. pfSense is stateful and logs only the packet that creates the state, so the number of `pass` events approximates the number of new connections.
- "SYN burst" is only approximate, because TCP flags are not decoded (limitation #1).
- Fixed: originally matched *any* destination port, which made ordinary HTTPS bursts to a single CDN endpoint (e.g. a browser opening many parallel connections to one server on port 443) cross the threshold. Restricting `dstport` to the admin-service list above removed that false positive; re-check this list if new internal services are added.

---

## 2. Suricata

### 2.1 Sensor and configuration

The rules and configuration published in this repo belong to the Suricata instance running on the **Windows 11 endpoint** (`default-rule-path: C:\Program Files\Suricata\rules\`). The second instance on the pfSense WAN interface is not part of the repo.

Settings in [`suricata.yaml`](https://github.com/Khoavo-187/Wazuh-siem-home-lab/blob/main/network/Suricata_configuration/suricata.yaml) that shape every rule below:

| Setting | Value | Effect |
|---|---|---|
| `HOME_NET` | `[192.168.60.0/24, !192.168.60.135]` | The whole LAN **except Kali** (`.135`) |
| `EXTERNAL_NET` | `!$HOME_NET` | In practice: Kali plus the Internet |
| `rule-files` | `local.rules` only | No Emerging Threats or other rule sets — every alert comes from the custom rules |
| `eve-log` | enabled (`alert`, `http`, `dns`, `tls`, `files`, …) → `eve.json` | `eve.json` is the file the Wazuh agent tails |

Why `HOME_NET` excludes Kali: with Kali inside `$HOME_NET`, rules written as `$HOME_NET → any` (reverse shell ports) fired on Nmap scans run **from** the attacker. Removing the attacker from `$HOME_NET` makes it an `$EXTERNAL_NET` source, so the inbound rules (`1000002`, `1000003`) fire on Kali and the outbound rules no longer fire on Kali's own traffic.

### 2.2 Rule inventory

| sid | Detection | Match | Wazuh rule | Level | MITRE |
|---|---|---|---|---|---|
| `1000002` | Port scan | SYNs from `$EXTERNAL_NET` to `$HOME_NET`, ≥15 in 10s per source | `100300` | 5 | T1595 |
| `1000003` | SSH attempts | SYNs to port 22, ≥5 in 60s per source | `100301` | 8 | T1110 |
| `1000004` | RDP attempt | SYNs to port 3389, ≥5 in 60s per source | `100302` | 6 | T1133 |
| `1000005` | SMB probe | SYNs to port 445, ≥5 in 60s per source | `100303` | 6 | T1046 |
| `1000006` | Reverse shell ports | Established outbound traffic to `4444, 1337, 31337, 5555` | `100304` | 12 | T1071 |
| `1000007` | curl user-agent | Any HTTP request whose User-Agent contains `curl` | `100305` | 5 | T1592 |
| `1000008` | EICAR download | HTTP response body contains the EICAR prefix | `100306` | 10 | T1105 |
| `1000009` | DNS test domain | DNS query for `malware-test.local` | `100307` | 9 | T1071.004 |
| `1000010` | Windows shell banner | Outbound payload contains the `cmd.exe` banner | `100308` | 12 | T1071 |
| `1000011` | curl download of script/binary | `curl` user-agent + URI ending in `.sh/.ps1/.exe/.bat/.dll` | `100309` | 8 | T1105 |

### 2.3 Anatomy of a rule (sid 1000002)

```text
alert tcp $EXTERNAL_NET any -> $HOME_NET any (
  msg:"LOCAL Possible Port Scan - Multiple SYN in short time";
  flow:to_server; flags:S;
  threshold:type both, track by_src, count 15, seconds 10;
  classtype:attempted-recon;
  metadata:mitre_tactic_id TA0043, mitre_technique_id T1595;
  sid:1000002; rev:3;)
```

| Part | Meaning |
|---|---|
| `alert tcp $EXTERNAL_NET any -> $HOME_NET any` | Action, protocol, source (address, port) → destination (address, port) |
| `flow:to_server` | Client-to-server direction only |
| `flags:S` | Exactly SYN — excludes SYN-ACK, so only connection **initiations** count |
| `threshold:type both, track by_src, count 15, seconds 10` | Alert once when a source reaches 15 matches within 10s, then stay quiet until the window ends |
| `classtype` | Category used for Suricata's priority and reporting |
| `metadata` | MITRE tags, carried into `eve.json` under `alert.metadata` |
| `sid` / `rev` | Rule identifier (local range ≥ 1,000,000) and revision |

### 2.4 Rule by rule

#### `1000002` — Possible port scan
Counts SYN-only packets: ≥15 from one source within 10s. Depends on `$EXTERNAL_NET` — only Kali (or the Internet) can trigger it. Trigger: `nmap -sS <target>` from Kali.

#### `1000003` — Repeated SSH connection attempts
Same idea, destination port 22, lower threshold (5 per 60s). It counts **connection attempts**, not failed logins, so it fits brute-force tooling such as Hydra. Mapped to T1110.

#### `1000004` — RDP connection attempt
Source is `any`, so internal hosts are covered too. Counts SYNs to 3389 (≥5 per 60s). Mapped to T1133 (External Remote Services).

#### `1000005` — SMB port probe
Same pattern on port 445. The metadata pairs T1046 (Network Service Discovery) with `TA0043`, but T1046 belongs to **Discovery (TA0007)**, not Reconnaissance — fix the tactic ID.

#### `1000006` — Possible reverse shell, suspicious outbound port
- Source `$HOME_NET` → any, ports `4444` (Metasploit default), `1337`, `31337`, `5555`.
- Revision 3 replaced `flags:S` with `flow:to_server,established`, so only connections that completed the handshake match. This removed the false positives caused by Nmap SYN scans (a half-open probe never reaches `established`).
- Add `threshold:type limit, track by_dst, count 1, seconds 60` to get one alert per flow window.
- Port lists are easy to evade (see *Behaviour over signatures* in the README); `1000010` complements it.

#### `1000007` — Recon tool user-agent (curl)
Matches `curl` in the HTTP User-Agent for any source and destination. Low fidelity: `curl` is also a legitimate admin and developer tool, so treat the alert as context, not a verdict.

#### `1000008` — EICAR test file over HTTP
`file_data` inspects the HTTP response body; the content match `X5O!P%@AP[4` is the beginning of the standard EICAR string. Direction `to_client` towards `$HOME_NET` means a host in the lab **downloaded** the file. HTTP only: HTTPS bodies are not visible.

#### `1000009` — DNS query to suspicious test domain
`dns.query` buffer, `nocase` match on `malware-test.local`. It is a lab marker for the C2-over-DNS pattern (T1071.004), not a real indicator. It sees only DNS that crosses the sensor.

#### `1000010` — Reverse shell banner (Windows)
- Behavioural rule: matches the banner a Windows `cmd.exe` prints when a shell starts (`Microsoft Windows [Version …]` followed within 100 bytes by `(c) Microsoft Corporation`), sent **outbound** on an established connection, on **any port** (so it still works when the shell uses 80 or 443).
- Limits: plain-text traffic only; matches the `cmd.exe` banner, not the PowerShell one (`Windows PowerShell` / `Copyright (C)`), even though the message says "CMD/Powershell"; a reverse shell that prints no banner is not seen.

#### `1000011` — Suspicious download via curl
`curl` user-agent plus a URI ending in `.sh`, `.ps1`, `.exe`, `.bat` or `.dll`, from `$HOME_NET` to `$EXTERNAL_NET` (in the lab: the endpoint pulling a payload from Kali). The `$` anchor means a trailing query string (`?x=1`) defeats the match. It overlaps with `1000007`, so one request can raise both alerts.

### 2.5 Wazuh wrapper rules

Every wrapper has the same shape:

```xml
<rule id="100300" level="5">
  <if_sid>86601</if_sid>
  <field name="alert.signature_id">1000002</field>
  <description>Suricata: Possible Port Scan from $(src_ip)</description>
  <mitre><id>T1595</id></mitre>
  <group>recon,network_scan</group>
</rule>
```

- `86601` is Wazuh's built-in parent for Suricata `alert` events; the wrapper narrows it to a single `alert.signature_id`.
- `$(src_ip)` and `$(dest_port)` come from the JSON fields of `eve.json`.
- Level and MITRE ID are assigned here (not in Suricata), so severity can be tuned without touching the sensor.
- The `field` value is a pattern match, not an equality test. Anchor it (`^1000002$`) so a future sid such as `10000021` cannot match by accident.

#### `100308` / `100309` — wrappers for sids `1000010` and `1000011`
Added after the initial baseline review (both sids originally had no Wazuh wrapper, so their alerts were unclassified and unscored):

```xml
<rule id="100308" level="12">
  <if_sid>86601</if_sid>
  <field name="alert.signature_id">1000010</field>
  <description>Suricata: Windows shell banner sent outbound - possible reverse shell from $(src_ip) to $(dest_ip):$(dest_port)</description>
  <mitre><id>T1071</id></mitre>
  <group>command_and_control,reverse_shell</group>
</rule>

<rule id="100309" level="8">
  <if_sid>86601</if_sid>
  <field name="alert.signature_id">1000011</field>
  <description>Suricata: curl download of script or executable from $(src_ip)</description>
  <mitre><id>T1105</id></mitre>
  <group>command_and_control,download_execution</group>
</rule>
```

Same shape as the other eight wrappers; `100308` maps the banner rule (T1071, level 12 — a reverse shell banner is a strong signal), `100309` maps the curl-download rule (T1105, level 8).

---

## 3. Sysmon & Windows Security events

### 3.1 Telemetry requirements

A Wazuh rule can only fire if the event exists. The Sysmon configuration is [`sysmon_config.xml`](https://github.com/Khoavo-187/Wazuh-siem-home-lab/blob/main/endpoints/windows-11/sysmon_config.xml) (SwiftOnSecurity, source version 74, Sysmon 13+). The agent ships the `Microsoft-Windows-Sysmon/Operational`, `Security`, `System` and `Application` channels (see [`ossec.conf`](https://github.com/Khoavo-187/Wazuh-siem-home-lab/blob/main/endpoints/windows-11/ossec.conf)).

| Event | Used by | What `sysmon_config.xml` does | Effect on the rules |
|---|---|---|---|
| **1** ProcessCreate | `100400`–`100403`, `100407` | `onmatch="exclude"`: everything is logged except the listed noise | Covered |
| **3** NetworkConnect | `100404`, `100413`, `100414` | Include list: specific images (`powershell.exe`, `cmd.exe`, `certutil.exe`, `bitsadmin.exe`, `nc.exe`, …), any binary under `C:\Users`, `C:\ProgramData`, `C:\Windows\Temp`, and a port list (22, 3389, 4444, 5900, …). Excludes Defender, Teams, `*.microsoft.com`, loopback | `100404` and `100414` are covered because PowerShell / cmd / certutil are included. `100413` (port 4445) is logged only when the process matches the include list — port 4445 itself is **not** in the list |
| **10** ProcessAccess | `100411`, `100416` | `include` filter on `\lsass.exe` (fixed — was empty) | EID 10 ingestion confirmed from Defender / built-in `92900`; custom positive not verified |
| **11** FileCreate | `100405` | Include by extension and folder (`.exe`, `.dll`, `.ps1`, `.bat`, `\Downloads\`, `\Startup\`, …); no generic `\Temp\` or `\AppData\Roaming\` filter | The rule only sees files already selected by extension/folder, so in practice it flags **executables and scripts** written to Temp or Roaming |
| **13** RegistryEvent | `100406` | Includes `CurrentVersion\Run` (covers `Run`, `RunOnce`, …) | Covered |
| Security **4625 / 4624 / 1102** | `100408`, `100410`, `100412` | Not Sysmon — Windows Security log | Needs the `Security` channel (present) and the matching audit policy |

> SwiftOnSecurity's `name=` tags use the legacy technique IDs of 2021 (for example `T1060`, today `T1547.001`). Use the MITRE IDs from the Wazuh rules, not those tags.

### 3.2 Field names

Wazuh's `windows_eventchannel` decoder exposes Sysmon and Security data under `win.eventdata.*` and `win.system.*` with a lower-case first letter: `parentImage`, `image`, `commandLine`, `user`, `targetFilename`, `targetObject`, `destinationIp`, `destinationPort`, `sourceImage`, `targetImage`, `ipAddress`, and `win.system.eventID`.

The rules chain on built-in groups whose names are not consistent (`sysmon_event1`, `sysmon_event3`, but `sysmon_event_10`, `sysmon_event_11`, `sysmon_event_13`). Verify them against your Wazuh version (see §6).

### 3.3 Rules

| ID | Level | Trigger | Correlation | MITRE |
|---|---|---|---|---|
| `100400` | 5 | Sysmon EID 1, shell parent `powershell`/`pwsh`/`cmd`/`net` (four discovery executables excluded) | none | none |
| `100401` | 10 | EID 1, `image` ends with `powershell.exe`, command line matches an encoded-command switch (`-e`/`-ec`/`-en…`) followed by ≥20 non-space chars | none | T1027, T1059.001 |
| `100402` | 6 | EID 1, image `whoami`, `systeminfo`, `tasklist`, `nltest`, `net` or `net1` | none | T1033, T1082, T1087 |
| `100403` | 8 | EID 1, image `certutil` or `bitsadmin` | none | T1105 |
| `100415` | 12 | Child of `100403`, command line matches a download/decode switch (`urlcache`, `verifyctl`, `decode[hex]`, `transfer`, `addfile`, `setnotifycmdline`) | none | T1105 |
| `100404` | 7 | EID 3, image `powershell` or `cmd` | none | T1071 |
| `100405` | 7 | EID 11, path contains `\Temp\` or `\AppData\Roaming\` | none | T1105 |
| `100406` | 10 | Child of built-in `92302`, key `…\CurrentVersion\Run` or `RunOnce` | none | T1547.001 |
| `100407` | 12 | Rule `100402` | ≥3 / 120s, `same_field` user | T1087 |
| `100408` | 10 | Rule `60122` (event 4625) with `ipAddress` ≠ `-` | ≥5 / 60s, `same_field` `ipAddress`, `ignore 120` | T1110 |
| `100410` | 13 | Intended Security `4624` after `100408`; `if_sid=60106` | Current XML `frequency=2`, `timeframe=200`, `same_field ipAddress`; **unverified** | T1110, T1078 |
| `100411` | 14 | EID 10, LSASS target, source-path exclusions, exact access masks | Positive custom alert not verified | T1003.001 |
| `100416` | 15 | Child of `100411`, `callTrace` contains `dbghelp.dll`/`dbgcore.dll` or `UNKNOWN` | none | T1003.001 |
| `100412` | 15 | Windows Security event 1102 under parent `60002` | **Raw custom alert confirmed 2026-10-13** | T1070.001 |
| `100413` | 12 | EID 3, destination port `4445` | none | T1041 |
| `100414` | 12 | EID 3, image `powershell` or `certutil`, port `80` or `443` | none | T1041, T1105 |

#### `100400` — Shell spawned child process (level 5)

The committed XML matches Sysmon Event ID 1 when `parentImage` ends with `powershell.exe`, `pwsh.exe`, `cmd.exe`, or `net.exe`. A negated child-image condition excludes `whoami.exe`, `systeminfo.exe`, `tasklist.exe`, and `nltest.exe`, which are instead detected under `100402`. **`net.exe` and `net1.exe` are not included in this exclusion, even though they appear in `100402`**, so overlapping candidate matches remain possible. `100400` and `100401` are independent rules, not parent/child. The full [2026-10-13 `100400` alert](../threat-emulation/evidence-logs/stage05-rule-100400-shell-child-arp.json) confirms an `ARP.EXE` child of PowerShell, including correctly rendered parent, image, command line and user. A shell spawning ARP is a context signal, not proof of malicious behavior.

#### `100401` — Encoded PowerShell command (level 10)
Fixed: originally a child of `100400` (only fired when the process was *started by PowerShell*, missing `cmd.exe → powershell -enc …` or `explorer.exe → powershell -enc …`) and only matched `-enc`/`-encodedcommand`/`-e`, missing abbreviations like `-ec`/`-en`. Now independent (`if_group sysmon_event1`, no parent dependency) with a wider switch pattern:

```xml
<field name="win.eventdata.image" type="pcre2">(?i)powershell\.exe$</field>
<field name="win.eventdata.commandLine" type="pcre2">(?i)(?:^|\s)[-/](?:e|ec|en[a-z]*)\s+\S{20,}</field>
```

`[-/](?:e|ec|en[a-z]*)` accepts `-e`, `-ec`, `-enc`, `-encodedcommand`, and the `/` variant; `\S{20,}` requires a long non-space payload after the switch, so it still needs the Base64-looking argument to avoid matching ordinary short flags. Encoding hides the payload from simple string detection (T1027) while running PowerShell (T1059.001).

#### `100402` — Reconnaissance binary (level 6)

The **current XML** image regex covers `whoami.exe`, `systeminfo.exe`, `tasklist.exe`, `nltest.exe`, `net.exe`, and `net1.exe`. It **does not include `arp.exe`**. `dir` is a shell built-in and is not detected as a standalone process by this regex. The October 13 re-test displayed `100402` rows for discovery binaries, while the preserved full [custom `100407` correlation alert](../threat-emulation/evidence-logs/stage05-rule-100407-recon-burst.json) confirms three discovery events from one user within 120 seconds. [Custom `100400` evidence](../threat-emulation/evidence-logs/stage05-rule-100400-shell-child-arp.json) separately confirms ARP triggered the broader process-lineage detector. These executables are also used by legitimate administrators; each event requires context.

#### `100403` — LOLBin download/decode (level 8)
EID 1 for `certutil.exe` or `bitsadmin.exe`, both able to fetch or decode files (T1105). The rule does not inspect arguments, so legitimate certificate operations also match — kept deliberately low-fidelity as a base signal; `100415` below adds the high-fidelity child.

#### `100415` — LOLBin with download/decode arguments (level 12)
Child of `100403` (`if_sid 100403`). Narrows to command lines containing `urlcache`, `verifyctl`, `decode`/`decodehex`, `transfer`, `addfile` or `setnotifycmdline` — the switches `certutil`/`bitsadmin` actually use to fetch or persist a payload (T1105; see the dedicated walkthrough of how each switch is abused, covered earlier in this project). Still argument-only: it does not check the URL or output path, so a legitimate `-decode` in an install script can still match.

#### `100404` — Outbound connection from PowerShell / cmd (level 7)
EID 3 where the image is `powershell.exe` or `cmd.exe`. Shells rarely need direct network access, so any connection is worth a look (T1071). `sysmon_config.xml` includes these images, so the event is available for any destination port.

#### `100405` — File created in a sensitive path (level 7)
EID 11 with `targetFilename` containing `\Temp\` or `\AppData\Roaming\`. As explained in §3.1, Sysmon only logs executable/script extensions and a few folders, so the effective detection is *"executable or script dropped into Temp/Roaming"* (T1105).

#### `100406` — Registry Run key persistence (level 10)

The current XML is a child of built-in `92302` (`<if_sid>92302</if_sid>`), and additionally requires a target registry object matching `\CurrentVersion\Run\` or `\CurrentVersion\RunOnce\` (MITRE T1547.001). It therefore inherits the detection scope of `92302`; it is not a universal registry-persistence detector.

**Evidence update:** the historical [built-in `92302` alert](../threat-emulation/evidence-logs/stage07-sysmon-registry-runkey.json) and a later **full [custom `100406` level-10 alert](../threat-emulation/evidence-logs/stage07-sysmon-registry-custom-rule.json)** are both preserved. The custom event is dated **2026-10-13**, and contains `reg.exe` modifying the `HKU\<SID>\Software\Microsoft\Windows\CurrentVersion\Run\UpdaterSvc` value. These are separate test events; they do **not** establish that two alert IDs appear simultaneously for one event. The registry write is confirmed, but execution on a later user logon was not verified.

#### `100407` — Multiple reconnaissance commands (level 12)
Correlation on `100402`: ≥3 recon binaries from the same `win.eventdata.user` within 120s. A single `whoami` is routine; a burst of discovery commands is **active enumeration** (T1087). It depends on `100402` actually being the rule that fires for those events (see precedence note, §5 item 2).

#### `100408` — Failed logon burst (level 10)
Correlation on rule `60122` (failed logon, event 4625): ≥5 failures from the same `ipAddress` within 60s. Entries with `ipAddress` equal to `-` (local logons without a source address) are excluded by a negated field match. Mapped to T1110. It fits network logons (RDP, SMB, OpenSSH for Windows).

#### `100410` — Successful logon after a failed-logon burst (level 13)

**Intended:** correlate a successful Security Event `4624` after an IP-attributed failed-logon burst (`100408`). **Actual committed XML:** `if_sid=60106`, `if_matched_sid=100408`, `frequency="2"`, `timeframe="200"`, and `same_field=win.eventdata.ipAddress`. This differs from older prose claiming `frequency="1"`. A full October 10 SMB re-test confirms custom `100408` followed by a genuine `4624` classified as **built-in `92657`**, not as `100410`. The [file named `stage03-rule-100410-correlation-excerpt.json`](../threat-emulation/evidence-logs/stage03-rule-100410-correlation-excerpt.json) is condensed and lacks full source-event provenance; do not count it as end-to-end confirmation of the custom correlation. Competing built-in rules are a hypothesis, not a proven sole explanation. A controlled event-order, same-IP/different-IP test is required. Failed attempts followed by a successful login can indicate suspicious access but do not by themselves prove password cracking.

#### `100411` — Suspicious LSASS ProcessAccess (level 14)

The current XML uses **`<if_group>sysmon_event_10</if_group>`**, not `<if_sid>92900</if_sid>`. It matches a target ending in `lsass.exe`, excludes selected legitimate executable **paths** (including Microsoft Defender), and requires one of eight exact access masks: `0x1010`, `0x1410`, `0x1438`, `0x143a`, `0x1f0fff`, `0x1f1fff`, `0x1f3fff`, `0x1fffff`. This exact-mask test may miss other suspicious access combinations; paths alone do not prove a binary's identity. The current alert description uses “Unauthorized”, although the XML does not prove authorization status or successful credential extraction.

**Confirmed telemetry, not a true positive:** the full [Stage 8b event](../threat-emulation/evidence-logs/stage08b-rule-100411-lsass-false-positive-windowsdefender.json) is a **built-in `92900`** alert (level 12) for `MsMpEng.exe` under `C:\ProgramData\Microsoft\Windows Defender\Platform\...` accessing `lsass.exe` with `grantedAccess=0x101000`. Its call trace contains many Defender `mpengine.dll` frames. The event is **consistent with legitimate Defender activity, likely benign/false-positive candidate**. It cannot prove that ProcDump accessed LSASS or dumped credentials. The Defender source path is excluded by `100411` and `0x101000` is not one of its accepted exact masks. Therefore, the current custom rule should **not** select this event. The custom exclusion does **not** suppress built-in `92900`.

The old [short `100411` excerpt](../threat-emulation/evidence-logs/stage08b-rule-100411-lsass-excerpt.json) lacks complete agent, decoder, timestamp, access mask and call-trace evidence. It is an **unverified illustration** rather than a full positive event.

#### `100416` — LSASS call-trace escalation (level 15)

Child of `100411`, with `callTrace` matching `dbghelp.dll`, `dbgcore.dll`, or the literal token `UNKNOWN`. The Defender event does not contain these patterns. An `UNKNOWN` frame by itself is not proof of malicious dumping. **No complete true-positive `100416` alert has been preserved**.

#### `100412` — Windows Security log cleared (level 15)

The current XML uses `<if_sid>60002</if_sid>` and checks `win.system.eventID=1102` (T1070.001). **A full custom level-15 [rule `100412` alert](../threat-emulation/evidence-logs/stage10-rule-100412-excerpt.json) is now available from 2026-10-13.** Its filename includes `excerpt`, but its content contains full Wazuh event metadata and a timestamp. The original 2026-08-29 [built-in `63103` alert](../threat-emulation/evidence-logs/stage10-windows-1102-log-cleared.json) is a **separate** event, not proof that both rules fired for one event. The alerts establish that clearing was detected; they do not restore deleted on-host records.

#### `100413` — Connection to port 4445 (level 12)
EID 3 with `destinationPort` equal to `4445`. This is a **lab-specific indicator** for the exfiltration stage (T1041). As the README notes (*Behavior > signatures*), a hard-coded port is easy to change; `100404` and `100414` cover the behaviour. In addition, EID 3 for this port is only logged when the process matches the Sysmon include list.

#### `100414` — PowerShell / certutil on web ports (level 12)
EID 3 where the image is `powershell.exe` or `certutil.exe` and the port is 80 or 443. Standard web ports blend into normal traffic; a scripting engine or LOLBin using them is the signal (T1041, T1105). Expect some noise from legitimate scripts; baseline and exclude known destinations.

### 3.4 Correlation chains and observed results

```text
Discovery:        Sysmon EID 1 → 100402 → repeated events / same user → 100407 [RAW CUSTOM CONFIRMED]
Authentication:   Windows 4625 → 60122 → 100408 [RAW CUSTOM CONFIRMED]
                  Windows 4624 → 92657 [RAW BUILT-IN CONFIRMED]; intended 100410 [NOT PROVEN]
Persistence:      Sysmon EID 13 → 92302 [EARLIER BUILT-IN] / 100406 [LATER RAW CUSTOM]
Credential access:Sysmon EID 10 → Defender MsMpEng.exe → 92900 [LIKELY BENIGN]
                  Suspicious 100411 / 100416 [NOT PROVEN]
Anti-forensics:   Security 1102 → 63103 [EARLIER BUILT-IN] / 100412 [LATER RAW CUSTOM]
```

The historical built-in and newer custom alert files belong to **different test timestamps**. A chain indicates rule hierarchy/intent, not multiple independent alerts for every event.

### 3.5 File Integrity Monitoring & VirusTotal

These detections use **built-in Wazuh rules**; no custom rule is involved. What this lab contributes is the configuration and the pipeline that connects them.

**Pipeline**

```text
File created/modified in a monitored folder
  └─► Wazuh agent (syscheck, realtime) ─► FIM alert  (syscheck rule range `550`–`593`, e.g. `554` new file / `550` integrity checksum changed — exact ID not yet confirmed against a raw alert, see docs/04 Stage 9)
        └─► Manager VirusTotal integration (hash lookup)
              └─► Rule 87105: engines flagged the file  (level 12)
```

| Layer | Configuration | Location |
|---|---|---|
| FIM | `<syscheck>` with `realtime="yes"` on `C:\Users\<user>\Downloads\virustotaltest`; `report_changes="yes"` and `recursion_level="2"` on `...\tmp`; other paths scanned every 12 h (`frequency 43200`) | Agent [`ossec.conf`](https://github.com/Khoavo-187/Wazuh-siem-home-lab/edit/main/endpoints/windows-11/ossec.conf) |
| VirusTotal | `<integration>` block restricted to syscheck alerts, API key redacted | Manager [`ossec.conf`](https://github.com/Khoavo-187/Wazuh-siem-home-lab/edit/main/endpoints/manager/m_ossec.conf)  |

**Evidence** (from the EICAR test, see `docs/02`): rule `87105`, level 12, `data.virustotal.positives: 62`, `malicious: 1`, `location: virustotal` (generated by the manager, not by the endpoint).

**Why it matters:** in the payload-delivery stage the same file is seen three times: Suricata flags the download on the network (rule `100306`, sid `1000008`), FIM records that it landed on disk, and VirusTotal adds a reputation verdict. This is the same defence-in-depth idea as the two Suricata sensors.

**Limitations**
- Realtime FIM covers only the folders listed; everything else is scanned every 12 hours.
- Only the hash is sent to VirusTotal. Files unknown to VirusTotal return no verdict — the rule ID for that "not found" case has not been captured yet.
- Free-tier API limits (about 4 requests per minute) can delay or drop lookups during bursts.

---

## 4. MITRE ATT&CK coverage

| Tactic | Technique | Rules |
|---|---|---|
| Reconnaissance | T1595 Active Scanning | `100300` (sid `1000002`) |
| Reconnaissance | T1592 Gather Victim Host Information | `100305` (sid `1000007`) |
| Discovery | T1046 Network Service Discovery | `100102`, `100130`, `100303` |
| Discovery | T1018 Remote System Discovery | `100201` |
| Discovery | T1033 / T1082 / T1087 | `100402`, `100407` |
| Initial Access | T1133 External Remote Services | `100302` |
| `100410` | 13 | Intended Security `4624` after `100408`; `if_sid=60106` | Current XML `frequency=2`, `timeframe=200`, `same_field ipAddress`; **unverified** | T1110, T1078 |
| Credential Access | T1110 Brute Force | `100301`, `100408`, `100410` |
| `100411` | 14 | EID 10, LSASS target, source-path exclusions, exact access masks | Positive custom alert not verified | T1003.001 |
| Execution | T1059.001 PowerShell | `100401` |
| Defense Evasion | T1027 Obfuscated Files or Information | `100401` |
| `100412` | 15 | Windows Security event 1102 under parent `60002` | **Raw custom alert confirmed 2026-10-13** | T1070.001 |
| Persistence | T1547.001 Registry Run Keys | `100406` |
| Command and Control | T1071 / T1071.004 | `100304`, `100307`, `100404`, `100308` (sid `1000010`) |
| Command and Control | T1105 Ingress Tool Transfer | `100306`, `100403`, `100415`, `100405`, `100414`, `100309` (sid `1000011`) |
| Credential Access | T1003.001 LSASS Memory (call-trace escalation) | `100416` |
| Exfiltration | T1041 Exfiltration Over C2 Channel | `100413`, `100414` |

---

## 5. Known issues and recommendations

| Topic | Current evidence | Interpretation |
|---|---|---|
| `100406` persistence | Earlier built-in `92302`; **later complete custom `100406`** | Custom rule **validated** for the observed Run-key write. |
| `100412` log clearing | Earlier built-in `63103`; **later complete custom `100412`** | Custom rule **validated** for Security Event 1102. |
| `100410` correlation | Full `100408` and full built-in `92657`, but only condensed `100410` excerpt | Custom positive correlation **not independently validated**; current `frequency=2`. |
| `100411` / `100416` | Full Defender-related EID 10 / built-in `92900`; only partial `100411` excerpt | **LSASS telemetry works; no ProcDump-sourced true positive.** Defender is likely benign. |
| `100400` / `100402` overlap | `100400` excludes four of six `100402` binaries | `net.exe` / `net1.exe` can overlap; `arp.exe` is only in `100400` for a shell parent. |
| `100415` | XML has child of `100403` | No separate positive alert confirmed here. |
| Multi-line PCRE2 | Some current field values contain indentation/newlines | Test behavior with `wazuh-logtest`; avoid assuming exact matching from code formatting alone. |
| `100401` description | A stray `CMD"` appears in XML | Cosmetic text issue, not a detection result. |
| Network attribution | Same-LAN traffic, pfSense routing, possible NAT hairpin | Verify path and source IP before attributing a pfSense block alert to Kali. |
| Suricata / stage 8 | Preserved alert uses older Suricata signature revision | Raw event validates **that revision only**. |
| Stage 11 | No verified completed transfer | Port `4445` indicator alone cannot prove exfiltration. |

**Reporting convention:** A rule written in XML is **configured**, a raw source event is **telemetry confirmed**, a full event with the actual custom rule ID is **custom-validated**, and a complete attacker objective requires **separate outcome evidence**. Never promote a likely benign event or condensed illustrative excerpt to a proven true positive.

## 6. Validation

```bash
# Syntax check of decoders and rules (run after every edit)
sudo /var/ossec/bin/wazuh-analysisd -t

# Interactive test: paste a raw log line and read the phases (decoder, rule)
sudo /var/ossec/bin/wazuh-logtest

# Confirm the built-in Sysmon group names in this Wazuh version
sudo grep -rl "sysmon_event_11" /var/ossec/ruleset/rules/
```

```powershell
# Which Sysmon event IDs are actually being produced?
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 500 |
  Group-Object Id | Sort-Object Name | Select-Object Name, Count

# Configuration Sysmon is running right now (it can differ from the file in the repo)
sysmon64.exe -c
```

Quick lab triggers (isolated lab VM only):

| Rule | Trigger |
|---|---|
| `100401` | From a PowerShell window: `$e=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('whoami')); powershell -enc $e` |
| `100402` / `100407` | `whoami`, `systeminfo`, `tasklist` within 120 seconds |
| `100403` | `certutil -urlcache -f http://<kali>/test.txt test.txt` |
| `100406` | `reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v LabTest /t REG_SZ /d calc.exe /f` (remove with `reg delete`) |
| `100408` | 5 wrong passwords from Kali against RDP or SSH |
| `100410` / `92657` | ...then one correct login with the same `targetUserName`. Confirmed 2026-10-10: `100408` fires correctly; the event that follows is built-in `92657`, not `100410` (see §5, item 2) |
| `100412` / `63103` | `wevtutil cl Security` (clears the log on the VM) |

Raw-log evidence for each rule (alert JSON, screenshots) belongs in the threat-emulation report.

---
