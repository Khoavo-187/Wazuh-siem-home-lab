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
    WIN["Windows Event Channels<br/>Security + Sysmon + PowerShell"] --> AG["Wazuh agent"]
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
| Sysmon / Security / PowerShell | Event Channel → agent | `windows_eventchannel` (built-in) | Built-in Sysmon / Windows rules (`sysmon_event*` groups, `60002`, `60106`, `60122`, `92302`, `92657`, `63103`) |

### 0.2 ID ranges

| Wazuh rule IDs | Source | Content |
|---|---|---|
| `100100`–`100140` | pfSense | Base, block/pass, scan, burst |
| `100200`–`100201` | pfSense | ICMP, ping sweep |
| `100300`–`100309` | Suricata | Wrappers for sids `1000002`–`1000011` |
| `100400`–`100416` | Sysmon / Windows Security | Process, network, file, registry, credential, anti-forensics |
| `1000002`–`1000011` | Suricata **sids** (not Wazuh IDs) | Network-side detections |

### 0.3 Rule attributes used in this document

| Attribute | Meaning |
|---|---|
| `if_sid` / `if_group` | Child rule: evaluated only when the parent rule (or any rule of the group) matched **on the same event** |
| `if_matched_sid` + `frequency` / `timeframe` | Correlation: fires when the target rule matched ≥ N times within T seconds |
| `same_source_ip`, `same_field`, `different_*` | Events in a correlation chain must share (or differ in) the given field |
| `ignore` | After firing, mute the rule for N seconds |
| `options no_log` | Match for chaining/correlation only; no alert is generated |
| *Evaluation order* | One event produces **at most one alert**. Wazuh walks the rule tree, takes the first matching sibling (load order: built-in rules before custom ones, then file order) and then evaluates that rule's children; the deepest match is the one reported. A parent therefore never "also fires" — it is only a precondition. Put specific rules before generic ones, or chain them with `if_sid` |

> `frequency` thresholds follow Wazuh's counting and can be off by ±1 event from the figures quoted below.

---

## 1. pfSense

### 1.1 `filterlog` format

pfSense forwards firewall logs to the manager over syslog (remote logging set to *everything*, `logall` in pfSense's `config.xml`; RFC 3164). The syslog header is not consistent: in some events the hostname is missing and Wazuh's predecoder puts `filterlog[pid]:` into the `hostname` field. That is why the parent decoder matches on the **message content** and not on `program_name`.

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
| `rule-files` | `local.rules` (the committed file also lists `emerging-all-fixed.rules` — confirm whether it is loaded in the validated runs) | Alerts from other rule sets are not wrapped by the custom rules; all evidence in this repo comes from sids `1000002`–`1000011` |
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
Same pattern on port 445. The committed `local.rules` maps T1046 to **Discovery (TA0007)**; this corrects an earlier `TA0043` mapping.

#### `1000006` — Possible reverse shell, suspicious outbound port
- Source `$HOME_NET` → any, ports `4444` (Metasploit default), `1337`, `31337`, `5555`.
- Revision 3 replaced `flags:S` with `flow:to_server,established`, so only connections that completed the handshake match. This removed the false positives caused by Nmap SYN scans (a half-open probe never reaches `established`).
- The committed rule already contains `threshold:type limit, track by_dst, count 1, seconds 60` to reduce repeated alerts per destination within a 60-second window (not necessarily one alert per individual flow).
- Port lists are easy to evade (see the README's *Detection Philosophy*); `1000010` complements it.

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

A Wazuh rule can only fire if the event exists. The Sysmon configuration is [`sysmon_config.xml`](https://github.com/Khoavo-187/Wazuh-siem-home-lab/blob/main/endpoints/windows-11/sysmon_config.xml) (SwiftOnSecurity, source version 74, Sysmon 13+). The agent is configured to collect the `Microsoft-Windows-Sysmon/Operational`, `Microsoft-Windows-PowerShell/Operational`, `Security`, `System` and `Application` channels (see [`ossec.conf`](https://github.com/Khoavo-187/Wazuh-siem-home-lab/blob/main/endpoints/windows-11/ossec.conf)).

| Event | Used by | What `sysmon_config.xml` does | Effect on the rules |
|---|---|---|---|
| **1** ProcessCreate | `100400`–`100403`, `100407` | `onmatch="exclude"`: everything is logged except the listed noise | Covered |
| **3** NetworkConnect | `100404`, `100414` | Include list: specific images (`powershell.exe`, `cmd.exe`, `certutil.exe`, `bitsadmin.exe`, `nc.exe`, …), any binary under `C:\Users`, `C:\ProgramData`, `C:\Windows\Temp`, and a port list (22, 3389, 4444, 5900, …). Excludes Defender, Teams, `*.microsoft.com`, loopback | `100404` and `100414` are covered because PowerShell / cmd / certutil are included. `100413` does not use this Sysmon event; it relies on PowerShell Module Logging (4103) |
| **10** ProcessAccess | `100411`, `100416` | `include` filter on `\lsass.exe` (fixed — was empty) | Covered, and now confirmed live by a false-positive test (see §3.3, `100411`) |
| **11** FileCreate | `100405` | Include by extension and folder (`.exe`, `.dll`, `.ps1`, `.bat`, `\Downloads\`, `\Startup\`, …); no generic `\Temp\` or `\AppData\Roaming\` filter | The rule only sees files already selected by extension/folder, so in practice it flags **executables and scripts** written to Temp or Roaming |
| **13** RegistryEvent | `100406` | Includes `CurrentVersion\Run` (covers `Run`, `RunOnce`, …) | Covered |
| Security **4625 / 4624 / 1102** | `100408`, `100410`, `100412` | Not Sysmon — Windows Security log | Needs the `Security` channel (configured) and the matching audit policy |
| PowerShell **4103** (Module Logging) | `100413` | Windows PowerShell policy; not controlled by Sysmon | Operational channel configured in the agent; Module Logging and alert generation **not yet verified** |
| PowerShell **4104** (Script Block Logging) | Future PowerShell-content detections | Windows PowerShell policy; independent of Sysmon | Channel configured; Script Block Logging and ingestion **not yet verified** |

> SwiftOnSecurity's `name=` tags use the legacy technique IDs of 2021 (for example `T1060`, today `T1547.001`). Use the MITRE IDs from the Wazuh rules, not those tags.

### 3.2 Field names

Wazuh's `windows_eventchannel` decoder exposes Sysmon and Security data under `win.eventdata.*` and `win.system.*` with a lower-case first letter: `parentImage`, `image`, `commandLine`, `user`, `targetFilename`, `targetObject`, `destinationIp`, `destinationPort`, `sourceImage`, `targetImage`, `ipAddress`, and `win.system.eventID`.

The rules chain on built-in groups whose names are not consistent (`sysmon_event1`, `sysmon_event3`, but `sysmon_event_10`, `sysmon_event_11`, `sysmon_event_13`). Verify them against your Wazuh version (see §6).

### 3.3 Rules

| ID | Level | Trigger | Correlation | MITRE |
|---|---|---|---|---|
| `100400` | 5 | EID 1, `parentImage` ends with `powershell.exe`, `pwsh.exe`, `cmd.exe` or `net.exe`; excludes `image` `whoami`, `systeminfo`, `tasklist`, `nltest`, `curl`, `bitsadmin`, `certutil` | none | none |
| `100401` | 10 | EID 1, `image` ends with `powershell.exe`, command line matches an encoded-command switch (`-e`/`-ec`/`-en…`) followed by ≥20 non-space chars | none | T1027, T1059.001 |
| `100402` | 6 | EID 1, image `whoami`, `systeminfo`, `tasklist`, `nltest`, `net` or `net1` | none | T1033, T1082, T1087 |
| `100403` | 8 | EID 1, image `certutil` or `bitsadmin` | none | T1105 |
| `100415` | 12 | Child of `100403`, command line matches a download/decode switch (`urlcache`, `verifyctl`, `decode[hex]`, `transfer`, `addfile`, `setnotifycmdline`) | none | T1105 |
| `100404` | 7 | EID 3, image `powershell` or `cmd` | none | T1071 |
| `100405` | 7 | EID 11, path contains `\Temp\` or `\AppData\Roaming\` | none | T1105 |
| `100406` | 10 | Child of built-in `92302`, key `…\CurrentVersion\Run` or `RunOnce` | none | T1547.001 |
| `100407` | 12 | Rule `100402` | ≥3 / 120s, `same_field` user | T1087 |
| `100408` | 10 | Rule `60122` (event 4625) with `ipAddress` ≠ `-` | ≥5 / 60s, `same_field` `ipAddress`, `ignore 120` | T1110 |
| `100410` | 13 | Windows Security Event 4624, matching built-in rule 92657, following a previous 100408 brute-force detection | if_matched_sid=100408, frequency=2, timeframe=200, same_field=win.eventdata.ipAddress. Configuration is syntactically within the documented frequency range, but the intended single-success detection sequence remains unvalidated. | T1110, T1078 |
| `100411` | 14 | EID 10, `targetImage` ends with `lsass.exe`, `sourceImage` not in the full-path allow-list, `grantedAccess` in a memory-read mask list | none | T1003.001 |
| `100416` | 15 | Child of `100411`, `callTrace` contains `dbghelp.dll`/`dbgcore.dll` or `UNKNOWN` | none | T1003.001 |
| `100412` | 15 | Child of built-in `60002` (Security-channel base), `eventID = 1102` | none | T1070.001 |
| `100413` | 9 | Child of built-in `60009`; event with PowerShell module-logging fields (`contextInfo` containing `Invoke-WebRequest`, plus `payload`) — **PowerShell Operational channel is configured; Module Logging, parent matching and alert generation are unverified** | none | T1059.001, T1567.002 |
| `100414` | 12 | EID 3, image `powershell` or `certutil`, port `80` or `443` | none | T1041, T1105 |

#### `100400` — Shell spawned child process (level 5)
`if_group sysmon_event1` plus a PCRE2 match on `parentImage`. The description shows parent, child, command line and user, which gives the process lineage in one line. **No longer a parent of `100401`** (see below — that rule is now independent). Scheduled tasks and management agents that wrap a shell also trigger it, so keep it at a low level.

Fixed, 2026-10-13: the `description` field was missing a closing `)` on `$(win.eventdata.user` (truncated the rendered alert text; cosmetic, rule logic was unaffected) — confirmed fixed via a raw re-test alert (`docs/04`, Stage 5). Renamed from "PowerShell spawned process" / group `powershell_child` to "Shell spawned child process" / group `shell_child`, and `parentImage` is **confirmed widened** to `(?i)(?:powershell|pwsh|cmd|net)\.exe$` (was `(?i)powershell\.exe$` only) — a `100400` alert with `cmd.exe` as parent is captured in `docs/04`, Stage 10 (Figure 16). A negated `image` field excludes `whoami`, `systeminfo`, `tasklist`, `nltest`, `curl`, `bitsadmin` and `certutil` so that the more specific rules are not shadowed by `100400` (the XML comment still says \"handled by 100402\", which is no longer accurate for the last three).

#### `100401` — Encoded PowerShell command (level 10)
Fixed: originally a child of `100400` (only fired when the process was *started by PowerShell*, missing `cmd.exe → powershell -enc …` or `explorer.exe → powershell -enc …`) and only matched `-enc`/`-encodedcommand`/`-e`, missing abbreviations like `-ec`/`-en`. Now independent (`if_group sysmon_event1`, no parent dependency) with a wider switch pattern:

```xml
<field name="win.eventdata.image" type="pcre2">(?i)powershell\.exe$</field>
<field name="win.eventdata.commandLine" type="pcre2">(?i)(?:^|\s)[-/](?:e|ec|en[a-z]*)\s+\S{20,}</field>
```

`[-/](?:e|ec|en[a-z]*)` accepts `-e`, `-ec`, `-enc`, `-encodedcommand`, and the `/` variant; `\S{20,}` requires a long non-space payload after the switch, so it still needs the Base64-looking argument to avoid matching ordinary short flags. Encoding hides the payload from simple string detection (T1027) while running PowerShell (T1059.001).

#### `100402` — Reconnaissance binary (level 6)
EID 1 where `image` ends with `whoami`, `systeminfo`, `tasklist`, `nltest`, `net` or `net1`. These are standard discovery tools (T1033 system owner, T1082 system information). Individually they are normal admin activity, hence the low level and the correlation in `100407`.

**Scope widened, 2026-10-13.** Originally missed `net.exe`/`net1.exe`/`arp.exe` (the account-discovery and network-neighbour commands actually run in the Stage 5 emulation) — this was a scope gap, not a precedence issue (unlike `100406`/`100410`/`100412` above). `net.exe`/`net1.exe` are now confirmed in the pattern via a raw-alert re-test (`docs/04`, Stage 5). **Confirmed absent**: `arp.exe` is not in the pattern (current rule XML reviewed directly) — in the re-test it only triggered the generic `100400` ("Shell spawned child process"), not `100402`. Add `arp` to the pattern if parity with `net`/`net1` is wanted; one token.

**Precedence caveat (verify).** One event produces one alert and Wazuh stops at the first matching sibling. In the live XML `100400` comes before `100402` and its exclusion list does **not** contain `net`/`net1`, so a `net`/`net1` process started from PowerShell, `cmd` or `net.exe` should be reported as `100400`, not `100402`, and `100407` would not count it. The 2026-10-13 alerts (net/net1 → `100402`) predate the current exclusion list. Either add `net` and `net1` to `100400`'s exclusion, or place `100402` before `100400`, then re-run Stage 5 and confirm with `wazuh-logtest`.

#### `100403` — LOLBin download/decode (level 8)
EID 1 for `certutil.exe` or `bitsadmin.exe`, both able to fetch or decode files (T1105). The rule does not inspect arguments, so legitimate certificate operations also match — kept deliberately low-fidelity as a base signal; `100415` below adds the high-fidelity child.

#### `100415` — LOLBin with download/decode arguments (level 12)
Child of `100403` (`if_sid 100403`). Narrows to command lines containing `urlcache`, `verifyctl`, `decode`/`decodehex`, `transfer`, `addfile` or `setnotifycmdline` — the switches `certutil`/`bitsadmin` actually use to fetch or persist a payload (T1105; see the dedicated walkthrough of how each switch is abused, covered earlier in this project). Still argument-only: it does not check the URL or output path, so a legitimate `-decode` in an install script can still match.

#### `100404` — Outbound connection from PowerShell / cmd (level 7)
EID 3 where the image is `powershell.exe` or `cmd.exe`. Shells rarely need direct network access, so any connection is worth a look (T1071). `sysmon_config.xml` includes these images, so the event is available for any destination port.

#### `100405` — File created in a sensitive path (level 7)
EID 11 with `targetFilename` containing `\Temp\` or `\AppData\Roaming\`. As explained in §3.1, Sysmon only logs executable/script extensions and a few folders, so the effective detection is *"executable or script dropped into Temp/Roaming"* (T1105).

#### `100406` — Registry Run key persistence (level 10)
`targetObject` matching `(?i)\\CurrentVersion\\(?:Run|RunOnce)(?:\\|$)` (T1547.001). Covers both HKLM and HKCU. Other autostart locations (`Winlogon`, `Policies\Explorer\Run`, services) are logged by Sysmon but not matched by this rule.

**Chained under the built-in rule, not a sibling of it.** The first version used `<if_group>sysmon_event_13</if_group>`, making it a sibling of Wazuh's own built-in registry-Run-key rule (`92302`, same group). A 2026-08-28 test run showed `92302` firing instead of `100406` for a real Run-key write — Wazuh evaluates sibling rules under one group and settles on a single match, and the built-in rule won. The fix: `<if_sid>92302</if_sid>` instead of the group tag, so `100406` is only evaluated **after** `92302` has already matched (a child, not a competitor). **Confirmed working, 2026-10-13**: a re-test produced a raw `100406` alert (level 10). A built-in `92041` ("Base64-like pattern") alert appears about 1 ms earlier; one event yields one alert, so these are most likely two separate Sysmon events — compare their `eventRecordID`s (the exported `100406` record is `2875786`). Only the deepest matching rule alerts, so no separate `92302` alert is expected. See `docs/04`, Stage 7.

#### `100407` — Multiple reconnaissance commands (level 12)
Correlation on `100402`: ≥3 recon binaries from the same `win.eventdata.user` within 120s. A single `whoami` is routine; a burst of discovery commands is **active enumeration** (T1087). It depends on `100402` actually being the rule that fires for those events (see precedence note, §5 item 2).

#### `100408` — Failed logon burst (level 10)
Correlation on rule `60122` (failed logon, event 4625): ≥5 failures from the same `ipAddress` within 60s. Entries with `ipAddress` equal to `-` (local logons without a source address) are excluded by a negated field match. Mapped to T1110. It fits network logons (RDP, SMB, OpenSSH for Windows).

#### `100410` — Successful Logon After a Failed-Logon Burst (Level 13)

**Detection objective.**Rule 100410 is intended to identify a potentially successful authentication attempt following a previously detected brute-force burst.

The detection correlates two security events:

A sequence of failed Windows authentication attempts (Security Event ID 4625) that trigger custom rule 100408

A subsequent successful Windows authentication event (Security Event ID 4624) associated with the same source IP address.

The objective is to identify possible successful password guessing or subsequent use of valid credentials (MITRE ATT&CK T1110 / T1078).

A matching sequence indicates suspicious authentication behavior. It does not independently establish credential compromise.

**Committed design (not confirmed operational):**

```xml
<rule id="100410" level="13" frequency="2" timeframe="200">
  <if_sid>92657</if_sid>
  <if_matched_sid>100408</if_matched_sid>
  <field name="win.system.eventID">^4624$</field>
  <field name="win.eventdata.ipAddress" type="pcre2" negate="yes">^-$</field>
  <same_field>win.eventdata.ipAddress</same_field>
  <!-- description / MITRE / groups omitted -->
</rule>
```

**Correlation logic:**

100408: Detects repeated failed logons (4625) from the same source IP.

92657: Built-in rule observed matching the subsequent successful logon (4624).

if_matched_sid=100408: References the preceding brute-force detection.

frequency=2, timeframe=200: Configured correlation threshold and 200-second window.

same_field=win.eventdata.ipAddress: Correlates events using the same source IP.

**Validation and limitations:**

Confirmed (2026-10-10): An SMB/NTLM test triggered 100408, followed by a successful 4624 event classified under built-in rule 92657.

Configuration updated: The original parent 60106 was replaced with 92657. No positive 100410 alert has been preserved after this change.

Frequency limitatioof one brute-force alert followed by one sucn: frequency=2 is supported by Wazuh (2–9999), but the intended sequence cessful logon has not been validated. Changing to frequency=1 is not a supported fix.

**Detection scope**: Depends on built-in rule 92657 and source-IP correlation. Matching IP addresses does not guarantee that the same account was targeted or compromised.

**Next validation**: Verify rule loading and replay the 4625 → 100408 → 4624 sequence using wazuh-logtest and a live SMB/NTLM test. Preserve the raw 100410 alert if generated; otherwise, revise the correlation logic.

**Status**:Implemented — Positive correlation not validated.
#### `100411` — LSASS memory access (level 14)
EID 10 where `targetImage` ends with `lsass.exe` (T1003.001). Two conditions narrow it, both tightened since the first draft:
- `sourceImage` allow-list by **full executable path** (`C:\Windows\System32\svchost.exe`, `taskmgr.exe`, `wininit.exe`, `csrss.exe`, `services.exe`, `wbem\WmiPrvSE.exe`, plus the Defender `MsMpEng.exe` paths) — fixed from an earlier version that matched by file name only (`(?:taskmgr|svchost|MsMpEng)\.exe$`), which a malicious binary could trivially spoof by using the same name in a different folder.
- `grantedAccess` restricted to a list of access masks that allow reading process memory (`0x1010`, `0x1410`, `0x1438`, `0x143a`, `0x1f0fff`, `0x1f1fff`, `0x1f3fff`, `0x1fffff`) — excludes masks like `0x1000`/`0x1400` that only query process information.

**Telemetry fixed and confirmed live, 2026-10-13 — filters not yet proven.** `sysmon_config.xml`'s `ProcessAccess` section was empty (no EID 10 logged at all) — it now has an `include` filter on `\lsass.exe`, and a false-positive test (Windows Defender's `MsMpEng.exe` reading `lsass.exe` during a routine scan) shows the event reaching the rule engine: the built-in `92900` fired and `100411` stayed silent (`docs/04`, Stage 8b). **Silence is not proof that each filter works.** Three independent things could explain it: the `grantedAccess` mask (`0x101000` is not in the list — the only cause proven), the `sourceImage` allow-list, or the `if_group` name `sysmon_event_10` not matching at all. The exported alert also shows doubled backslashes in `eventdata` (`C:\\ProgramData\\Microsoft\\…` after JSON decoding, while `message` has single ones) whereas the allow-list expects single ones (`^C:\\ProgramData\\…`), so the allow-list may never match and benign allow-listed processes using a listed mask would alert at level 14. **Test it with `wazuh-logtest`**: feed the stored `full_log` of the Defender event unchanged (expect `92900`), then again with `sourceImage` replaced by a non-allow-listed path and `grantedAccess` set to `0x1fffff` (expect `100411`). If the stored path really contains doubled backslashes, loosen each separator to `\\+`. No real dump tool has been run (`procdump.exe` is not staged), so Stage 8b in `docs/04` remains ⚠️.

#### `100416` — LSASS access with memory-dump call trace (level 15)
Child of `100411` (`if_sid 100411`). Raises severity when `callTrace` contains `dbghelp.dll` or `dbgcore.dll` (the DLLs behind `MiniDumpWriteDump`) or the literal string `UNKNOWN` (code running from unbacked memory — also seen with JIT'd .NET code, so treat `UNKNOWN` alone as weaker signal than the DLL match). Not yet exercised by a real test — the one `ProcessAccess` event captured so far (Defender's own scan) stays entirely inside `mpengine.dll` and system DLLs, so it would not have triggered `100416` even if `100411` had fired for it.

#### `100412` — Security log cleared (level 15)
`win.system.eventID = 1102` (audit log cleared). Clearing the log is anti-forensics (T1070.001), hence the highest level in the set.

**Parent reference was wrong, now corrected.** The rule originally chained from `60117` — this turned out not to be a confirmed ancestor of eventchannel Security events, so `100412` may never have been reached in the rule tree at all for the real `1102` event (a different problem from sibling precedence: the parent itself likely never matched). Per Wazuh's own documented eventchannel chain (all eventchannel logs → `60000` → Security channel specifically → `60002`), `if_sid` is now `60002`, a confirmed real ancestor. **Confirmed working, 2026-10-13.** The built-in `63103` fired instead of `100412` in the original 2026-08-28 evidence (captured when the rule still used `60117`); after the `if_sid=60002` fix, a re-test produced two raw `100412` alerts at the intended level 15, with no `63103` row visible in the same Discover view. See `docs/04`, Stage 10.

#### `100413` — PowerShell `Invoke-WebRequest` Activity (Level 9)

100413 — PowerShell Invoke-WebRequest Activity (Level 9)

Detection objective: Identify PowerShell Invoke-WebRequest activity through Module Logging (Event ID 4103), providing visibility into potentially suspicious HTTP transfers (T1059.001).

Proposed configuration — not yet deployed or validated:
```xml=
<rule id="100413" level="9">
  <if_sid>60009</if_sid>

  <field name="win.system.channel" type="pcre2">^Microsoft-Windows-PowerShell/Operational$</field>
  <field name="win.system.eventID">^4103$</field>
  <field name="win.eventdata.payload" type="pcre2">(?i)Invoke-WebRequest</field>

  <description>PowerShell: Invoke-WebRequest activity detected - review for suspicious HTTP transfer</description>

  <mitre><id>T1059.001</id></mitre>
  <group>powershell,web_request,suspicious_activity,</group>
</rule>
```
**Detection logic:**
Parent 60009: Wazuh's generic Windows informational-event rule, not a rule exclusive to Event ID 4104. Its use with PowerShell Module Logging is supported by Wazuh's published detection examples.

Event 4103: Explicitly restricts matching to PowerShell Module Logging in the Operational channel.

Payload matching: Searches decoded module-logging content for Invoke-WebRequest. Field availability and content must be confirmed against actual events.

**Validation and limitations:**
The Windows Wazuh agent already collects the PowerShell Operational channel, but Module Logging activation, Event 4103 ingestion, and positive rule matching remain unverified.

PowerShell Module Logging may distribute command and parameter information across multiple records; the proposed rule only matches individual events containing the target string in payload.

Detection of Invoke-WebRequest does not independently establish data exfiltration. The previous T1567.002 cloud-storage mapping is not applicable to the lab's Kali-hosted HTTP endpoint.

The Stage 11 script uses `Invoke-WebRequest` `-Method Post` `-InFile`, but no raw 100413 alert has been preserved.

**Next validation**: Confirm local Event 4103 generation, inspect actual contextInfo/payload values, verify the parent rule through wazuh-logtest, and preserve a raw 100413 alert before claiming detection success.

**Status**: Rule revision proposed — PowerShell telemetry and positive detection pending validation.

#### `100414` — PowerShell / certutil on web ports (level 12)
EID 3 where the image is `powershell.exe` or `certutil.exe` and the port is 80 or 443. Standard web ports blend into normal traffic; a scripting engine or LOLBin using them is the signal (T1041, T1105). Expect some noise from legitimate scripts; baseline and exclude known destinations.

### 3.4 Correlation chains

```text
Brute force → compromise
  4625 ─► 60122 ─► 100408  (≥5 failures / 60s, same ipAddress)  — confirmed firing, 2026-10-10
                         └─► 4624 ─► built-in 92657 ─► 100410 (current intended chain; XML updated, NOT revalidated)

Active enumeration
  EID 1: whoami / systeminfo / tasklist / nltest / net / net1 ─► 100402 ─► 100407  (≥3 / 120s, same user; see the §3.3 precedence caveat for net/net1)

Persistence
  EID 13: reg.exe writes \CurrentVersion\Run ─► built-in 92302 ─► child 100406  (confirmed firing together, 2026-10-13 re-test)

Anti-forensics
  Security 1102 (log cleared) ─► 60002 ─► child 100412  (confirmed firing, twice, 2026-10-13 re-test; built-in 63103 not observed alongside)

PowerShell / shell lineage (100400 and 100401 are now independent rules, not chained)
  EID 1: parent powershell.exe / pwsh.exe / cmd.exe / net.exe ─► 100400
  EID 1: image powershell.exe, encoded switch ─► 100401
```

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

**Why it matters:** in the payload-delivery stage the same file is seen three times: Suricata flags the download on the network (rule `100306`, sid `1000008`), FIM records that it landed on disk, and VirusTotal adds a reputation verdict. This illustrates defence in depth across network alerts, endpoint FIM and reputation enrichment. Only the Windows-endpoint Suricata sensor is documented and evidenced in this repository; the separate pfSense Suricata sensor is not reproducible from committed files.

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
| Initial Access / Defense Evasion | T1078 Valid Accounts | `100410` |
| Credential Access | T1110 Brute Force | `100301`, `100408`, `100410` |
| Credential Access | T1003.001 LSASS Memory | `100411` |
| Execution | T1059.001 PowerShell | `100401` |
| Defense Evasion | T1027 Obfuscated Files or Information | `100401` |
| Defense Evasion | T1070.001 Clear Windows Event Logs | `100412` |
| Persistence | T1547.001 Registry Run Keys | `100406` |
| Command and Control | T1071 / T1071.004 | `100304`, `100307`, `100404`, `100308` (sid `1000010`) |
| Command and Control | T1105 Ingress Tool Transfer | `100306`, `100403`, `100415`, `100405`, `100414`, `100309` (sid `1000011`) |
| Credential Access | T1003.001 LSASS Memory (call-trace escalation) | `100416` |
| Exfiltration | T1041 Exfiltration Over C2 Channel | `100414` |
| Execution | T1059.001 PowerShell web-request activity | `100413` (not yet validated; requires Event 4103) |
| Exfiltration (emulation objective, not verified by `100413`) | T1048.003 if HTTP is a non-C2 channel, or T1041 if the C2 channel is reused | Stage 11 script (mapping conditional on test architecture) |

- Validation status for `T1078 Valid Accounts`: Intended detection coverage only; no preserved custom 100410 alert
-  Validation status for `T1110 Brute Force`: 100408 confirmed; 100410 correlation unvalidated
---

## 5. Known issues and recommendations

These items distinguish **a change committed in a configuration file** from **a detection confirmed by new raw evidence**. Historical fixes remain documented because they explain design decisions; an item is not "validated" solely because its XML was edited.

| # | Finding | Current status / action |
|---|---|---|
| 1 | Sysmon EID 10 was unavailable when the `ProcessAccess` include filter was empty | **Collection fixed / observed:** `\lsass.exe` filter committed; 2026-10-13 Defender event confirms telemetry reaches Wazuh. **Positive detection pending** for `100411`/`100416`. |
| 2 | Built-in / custom rule interaction for `100406`, `100412`, `100410` | `100406` (parent `92302`) and `100412` (parent `60002`) were confirmed with new raw alerts. `100410` parent is **now `92657`**, but positive correlation after this edit remains **unvalidated**. |
| 3 | Rule `100401` previously depended on parent `100400` | **Configuration fixed:** independent Sysmon EID 1 matching and broader encoded-switch regex. Historical evidence predates some revisions; verify any new changes independently. |
| 4 | Suricata sids `1000010`/`1000011` previously lacked Wazuh wrappers | **Configuration fixed:** rules `100308` and `100309` are committed. |
| 5 | 	Rule 100410 uses `if_matched_sid=100408` with frequency="2" and timeframe="200". Although frequency=2 is within Wazuh's documented supported range, the correlation has not been demonstrated to trigger on one brute-force detection followed by a single successful authentication. | Detection-logic limitation — validation pending. Keep the implemented correlation separate from its intended behavior. Do not change frequency to 1, which is outside Wazuh's documented supported range. Validate rule loading, source-IP matching, and the exact event sequence. Redesign the detection if the existing configuration cannot satisfy the one-success authentication use case. Preserve raw positive evidence before marking rule 100410 as operational. |
| 6 | Suricata sid `1000006` previously flooded alerts | **Configuration fixed:** `threshold:type limit, track by_dst, count 1, seconds 60` is committed. |
| 7 | Suricata sid `1000005` previously used tactic `TA0043` for T1046 | **Configuration fixed:** current `local.rules` uses `TA0007` (Discovery). |
| 8 | Some XML `<field>` regular expressions span multiple lines | **Pending controlled test:** whitespace/line-break handling should be checked with actual decoded events, especially rules `100403`, `100405`, `100411`; do not assume every expression is normalized. |
| 9 | Windows agent configuration previously monitored Suricata `eve.json` repeatedly | **Configuration fixed:** one `localfile` declaration remains. |
| 10 | pfSense ICMP/TCP-burst noise | **Configuration fixed:** `100200` is low level with `no_log`; `100140` is restricted to administrative TCP destination ports. Historical UDP/loopback evidence comes from an earlier rule revision. |
| 11 | Rule `100413` uses generic informational-event parent `60009` to inspect PowerShell Module Logging fields. The parent is not restricted to Event 4104, but the current rule lacks an explicit Event 4103 filter, and its contextInfo/payload conditions have not been validated. | **Rule refinement proposed / validation pending**: Restrict matching to PowerShell Operational Event 4103, verify decoded field contents, and test the actual rule path. Stage 11 uses Invoke-WebRequest, but no positive 100413 alert is preserved. |
| 12 | Suricata sid `1000011` matches only a limited URI extension list | **Unresolved tuning:** `.com` and other extensions, and URIs with query parameters, are not covered. Extend only if the intended scope requires it; validate false positives. |
| 13 | Rule `100400` formerly had an invalid field substitution in its description | **Fixed / confirmed:** corrected `$(win.eventdata.user)` in an Oct 13 raw alert. |
| 14 | Rule `100401` still contains a stray quotation mark in its description | **Cosmetic XML fix pending:** normalize `CMD:` when modifying the rule. |
| 15 | Rule `100308` contains spelling mistakes ("send", "possble") | **Cosmetic XML fix pending:** use "sent" / "possible". |
| 16 | Outer group `<group name="sysmon_local,windows">` and nested group names may merge unexpectedly in Wazuh alerts | **Investigate before changing separators:** preserved `rule.groups` for `100406`/`100412` reportedly contains merged entries (`windowspersistence`, `windowslog_cleared`). Prefer verifying `rule.groups`, then test adding a comma to the outer group name; do not assume rule-level trailing commas alone caused Dashboard HTTP 500. |
| 17 | Rule `100411` full-path allow-list and escaped Windows paths | **Filter not proved:** compare decoded `sourceImage` to the regex with `wazuh-logtest`; the Defender event was suppressed by the unmatched access mask `0x101000`, not proof that the allow-list itself works. |
| 18 | Rule `100400` can shadow `100402` for `net.exe` / `net1.exe` started from a shell | **Unresolved precedence/tuning:** either exclude `net`/`net1` from the generic rule or prove the specific rule wins after the change; preserve a fresh raw test. |
| 19 | Suricata wrapper `<field name="alert.signature_id">` uses unanchored numeric patterns | **Optional hardening:** prefer `^SID$` for each exact SID to avoid accidental partial matches. |
| 20 | Rule `100413` currently maps Invoke-WebRequest activity to T1567.002, although the documented HTTP endpoint is Kali-hosted rather than cloud storage. | **ATT&CK mapping correction pending in XML**: Retain T1059.001 for PowerShell activity. Map the Stage 11 transfer separately according to the verified communication channel and transfer outcome.|

**Rule IDs and source of truth:** For executable detection logic, inspect the committed XML/Suricata files in the table at the top of this document. For test outcome, inspect the raw alert's `rule.id`, `full_log`, `data` fields and timestamp. See `docs/04` for dates and evidence provenance.

**Selected current configuration examples (not proof of successful alerts):**

```xml
<!-- Sysmon: encoded PowerShell detection, already committed -->
<rule id="100401" level="10">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.image" type="pcre2">(?i)powershell\.exe$</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)(?:^|\s)[-/](?:e|ec|en[a-z]*)\s+\S{20,}</field>
  <description>Sysmon: Encoded Powershell command from $(win.eventdata.user) - possible command obfuscation | parent:$(win.eventdata.parentImage) | CMD" $(win.eventdata.commandLine)</description>
  <mitre><id>T1027</id><id>T1059.001</id></mitre>
</rule>
```

```xml
<!-- Current 100410 parent/threshold; still awaiting compatibility and end-to-end checks -->
<rule id="100410" level="13" frequency="2" timeframe="200">
  <if_sid>92657</if_sid>
  <if_matched_sid>100408</if_matched_sid>
  <!-- remaining conditions omitted; full rule lives in sysmon_rules.xml -->
</rule>
```

## 6. Validation

**A. Confirm committed configurations load on the actual manager.** Syntax validation is necessary but not sufficient to prove correlation semantics or data-field matching.

```bash
sudo /var/ossec/bin/wazuh-analysisd -t
sudo /var/ossec/bin/wazuh-logtest
sudo grep -rn 'id="60009"\|id="92657"' /var/ossec/ruleset/rules/
sudo grep -rl 'sysmon_event_11' /var/ossec/ruleset/rules/
```

```powershell
# Windows: confirm actual Sysmon events and active configuration.
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 500 |
  Group-Object Id | Sort-Object Name | Select-Object Name, Count
sysmon64.exe -c

# Windows: verify Module Logging / Script Block Logging telemetry separately.
Get-WinEvent -FilterHashtable @{
  LogName = 'Microsoft-Windows-PowerShell/Operational'
  Id = 4103,4104
  StartTime = (Get-Date).AddHours(-1)
} -ErrorAction SilentlyContinue | Select-Object TimeCreated, Id, Message
```

**B. Minimal non-destructive test matrix.** Run only inside the authorized lab and retain original `full_log` plus `rule.id`, timestamp and agent identity. A test that matches a built-in rule is not confirmation of the custom child.

| Rule | Safe test approach | Current evidence status |
|---|---|---|
| `100401` | Start a benign encoded PowerShell command in a controlled console. | Historical raw alert exists; verify against current XML after edits. |
| `100402` / `100407` | Run several benign discovery binaries on the endpoint and inspect individual rule IDs. | Oct 13 custom evidence exists; re-test `net`/`net1` overlap after any XML change. |
| `100403` / `100415` | Use an approved test command line for `certutil`/`bitsadmin`; review command-line regex without downloading an untrusted binary. | XML committed; validate detailed argument matching separately. |
| `100406` | Write and delete a benign disposable registry Run key on a **dedicated lab endpoint**, not a daily-use host. | Custom raw alert confirmed Oct 13. |
| `100408` | Use previously recorded failed-logon events or a controlled isolated test account. | Confirmed Oct 10 on SMB/NTLM. |
| `100410` | Replay representative failed/successful logon samples in `wazuh-logtest`, then perform an isolated end-to-end re-test only after correcting any invalid rule syntax. |
| `100411` / `100416` | Replay sanitized Sysmon EID 10 samples and inspect allowed vs suspicious masks/paths; do not dump credentials on the physical host to validate a README claim. | Event collection observed; positive match unconfirmed. |
| `100412` | Replay a saved Security EID 1102 in a disposable test environment; do not clear the physical host's Security log again for documentation. | Confirmed Oct 13. |
| `100413` | Enable Windows Module Logging, run a **benign** `Invoke-WebRequest`, confirm Event 4103, then verify decoded Wazuh fields and parent rule. | Channel configured; EID 4103, parent and rule match **unconfirmed**. |
| `100414` | Generate an approved benign PowerShell connection on a monitored web port and examine rule precedence against `100404`. | Custom precedence not confirmed. |

**C. Evidence handling.** Keep evidence from an older rule revision clearly labeled *historical*. Wazuh Dashboard `wazuh-alerts-4.x-*` does not necessarily store every collected Event 4103/4104: a missing alert alone does not prove ingestion failed. Check the local event channel, agent logs, raw archives if enabled, decoder output and the rule engine separately.

**D. Reference:** Wazuh Rules Syntax: <https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html>. In particular, the published `frequency` range is 2–9999; verify actual manager behavior before declaring `100410` fixed.
