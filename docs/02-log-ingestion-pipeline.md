# 02 — Log Ingestion Pipeline

> [!NOTE]
> How telemetry and security events travel from the endpoint and network devices to Wazuh, and which custom parsing each source needs. JSON snippets are **abridged** copies of alerts stored in `threat-emulation/evidence-logs/`; the file each one comes from is named under it.

| Source | Transport | Decoder | Parent / custom detection path | Current evidence status |
|---|---|---|---|---|
| pfSense firewall | Syslog UDP/514 → Manager | Custom `pfsense-lab` plus five child decoders | Custom base `100100`; source-specific child/correlation rules | Decoder and several rules have baseline evidence; Stage 1 scan attribution remains unproven |
| Suricata endpoint | `eve.json` → Agent `localfile` (`json`) | Built-in JSON decoder | Built-in `86601` → custom wrappers `100300`–`100310` | Wrappers are configured; SID `1000012` / wrapper `100310` are pending validation |
| Windows Security / Sysmon / OpenSSH | Windows Event Channels → Agent (`eventchannel`) | Built-in `windows_eventchannel` | Built-in Windows/Sysmon rules → custom rules in `sysmon_rules.xml` | Multiple historical custom alerts exist; current-revision status varies by rule |
| PowerShell Operational | Windows Event Channel → Agent (`eventchannel`) | Built-in `windows_eventchannel`; intended parent `91801` | Event 4103 → custom `100413` | Channel configured; Module Logging, event ingestion and positive rule match pending validation |
| FIM | Agent syscheck → Manager | Built-in syscheck rules | Built-in `550`–`593` family | Historical screenshot/evidence exists; Stage 9 raw JSON is absent; Temp ZIP watch is configured |
| VirusTotal | Manager integration triggered by syscheck/hash event | Integration output | `87105` | Historical positive reputation alert exists; this sample is from an earlier baseline run |

## 1. pfSense syslog and the custom decoder

pfSense sends `filterlog` lines (comma-separated, RFC 3164) to the manager over UDP/514 (`192.168.60.137:514`; see `docs/01` §3 for the listener). Wazuh has no stock decoder for this layout, so custom decoders in `siem-wazuh/custom-decoder/local_decoder.xml` extract the fields that rules need (`srcip`, `dstip`, `srcport`, `dstport`, `protocol`, `action`).

| Decoder | Purpose |
|---|---|
| `pfsense-lab` | Parent: recognises any `filterlog[pid]:` line |
| `pfsense-lab-ports` | IPv4 TCP/UDP (has ports) |
| `pfsense-lab-icmp` | IPv4 ICMP echo |
| `pfsense-lab-igmp`, `pfsense-lab-ipv4`, `pfsense-lab-ipv6` | Fallbacks for other protocols |

```xml
<decoder name="pfsense-lab-ports">
    <parent>pfsense-lab</parent>
    <prematch type="pcre2" offset="after_parent">\d+,,,.*?,4,.*?,(?:tcp|udp),</prematch>
    <regex type="pcre2" offset="after_parent">(\d+),,,(\d+),([^,]+),([^,]+),([^,]+),([^,]+),(4),([^,]*),([^,]*),(\d+),(\d+),(\d+),([^,]+),(\d+),(tcp|udp),(\d+),([^,]+),([^,]+),(\d+),(\d+),(\d+)</regex>
    <order>pfsense.rulenum,pfsense.tracker,pfsense.interface,pfsense.reason,action,pfsense.direction,pfsense.ipversion,pfsense.tos,pfsense.ecn,pfsense.ttl,pfsense.id,pfsense.offset,pfsense.flags,pfsense.protocol_number,protocol,pfsense.length,srcip,dstip,srcport,dstport,pfsense.data_length</order>
</decoder>
```

**Evidence** (abridged from `stage01-pfsense-synburst.json`): `location` is the sender's address (`192.168.60.254`, pfSense) and the decoder is the custom one.

```json
{
  "_index": "wazuh-archives-4.x-2026.08.09",
  "_source": {
    "data": {
      "protocol": "udp",
      "srcip": "192.168.254.101",
      "pfsense": {
        "reason": "match",
        "rulenum": "76",
        "interface": "em0",
        "ttl": "63",
        "direction": "out"
      },
      "dstport": "53",
      "action": "pass",
      "srcport": "20455",
      "dstip": "8.8.8.8"
    },
    "rule": {
      "firedtimes": 1791,
      "level": 3,
      "description": "pfSense: Traffic allowed 192.168.254.101:20455 -> 8.8.8.8:53",
      "groups": ["pfsense", "firewall_pass"],
      "id": "100110"
    },
    "decoder": { "name": "pfsense-lab" },
    "full_log": "Aug 9 05:56:36 filterlog[63489]: 76,,,1000002661,em0,match,pass,out,4,0x0,,63,4250,0,none,17,udp,64,192.168.254.101,8.8.8.8,20455,53,44",
    "timestamp": "2026-08-09T05:56:36.860+0000"
  }
}
```

> [!NOTE]
> This sample is loopback DNS traffic on the firewall itself (see `docs/04`, Stage 1), shown only to prove decoding, not as a detection of the scan. Its syslog header is about 17.5 hours older than the arrival time, so check pfSense's clock before correlating firewall events with endpoint events.

## 2. Suricata on the endpoint

Suricata runs on the Windows endpoint and inspects traffic on its VMnet1 adapter, providing visibility into east-west traffic to and from that host. It writes alerts to `C:\Program Files\Suricata\log\eve.json`; the Agent tails that file (`<localfile>` with `log_format json`), and Wazuh's built-in rule `86601` classifies `event_type: alert` events. The committed custom wrapper range is **`100300`–`100310`**, mapping Suricata SIDs **`1000002`–`1000012`** one-to-one. SID `1000012` / wrapper `100310` is the Stage 11 HTTP POST detector and remains pending validation. The second Suricata instance sometimes discussed in the lab topology is not configured or evidenced by the files in this repository; the committed EVE pipeline documents the Windows endpoint sensor only.

**Evidence** (abridged from `stage08-suricata-reverse-shell-baseline-test.json`): `location` is the file path on the endpoint.

```json
{
  "agent": { "ip": "192.168.60.1", "name": "window11Host", "id": "001" },
  "data": { "src_ip": "192.168.60.1", "dest_port": "31337",
            "alert": { "signature": "LOCAL Possible Reverse Shell - Suspicious Outbound Port" } },
  "rule": { "id": "100304", "level": 12 },
  "location": "C:\\Program Files\\Suricata\\log\\eve.json",
  "decoder": { "name": "json" }
}
```

`eve.json` also carries `stats`, `flow`, `http`, `dns` and other event types; only `alert` events match the wrappers. The extra volume is a known tuning item.

## 3. Windows Event Log and Sysmon

The agent reads channels directly (`log_format eventchannel`): `Security`, `System`, `Application`, `Microsoft-Windows-OpenSSH/Operational`, `Microsoft-Windows-Sysmon/Operational`, and `Microsoft-Windows-PowerShell/Operational`. The Windows audit policies and the Sysmon install are in `docs/01` §5.

| Telemetry | Needs | Used by |
|---|---|---|
| Security `4624` / `4625` | Audit *Logon* success + failure | `100408` (failed-logon burst); `100410` (successful `4624` after prior `60122` failures, same source IP, current-event parent `92651` or `92657`; six matches / 200s, pending validation) |
| Security `1102` | always logged | `100412` |
| Sysmon EID 1 | Sysmon process-creation include/exclude filters | `100400`–`100403`, `100407`, `100415` (the last is a child of `100403`) |
| Sysmon EID 3 | include list in `sysmon_config.xml` | `100404`, `100414` |
| Sysmon EID 10 | `ProcessAccess` include on `lsass.exe` | `100411`, `100416` |
| Sysmon EID 11 | FileCreate filters include executable/script extensions and `C:\Windows\Temp\*.zip` | `100405` for matching Temp/AppData paths; Stage 11 ZIP creation is configured but not yet supported by a preserved positive raw alert |
| Sysmon EID 13 | `CurrentVersion\Run` include | `100406` |
| PowerShell EID 4103 | PowerShell Module Logging enabled by policy; agent channel subscription | `100413` (intended; pending validation) |
| PowerShell EID 4104 | PowerShell Script Block Logging enabled by policy; agent channel subscription | Additional script-content telemetry; not the current trigger for `100413` |

> [!WARNING]
> The committed Windows agent `ossec.conf` already subscribes to
> `Microsoft-Windows-PowerShell/Operational` with `log_format: eventchannel`;
> do not add a duplicate `<localfile>` block. This configuration only tells
> the agent which channel to read — it does **not** enable Windows PowerShell
> logging. Module Logging (Event ID 4103) must be enabled separately through
> Group Policy (module name list: `*`) for the intended `100413` detection.
> Script Block Logging (Event ID 4104) is a separate policy and does not
> replace 4103 for the current rule.
>
> End-to-end collection has not yet been verified: confirm that a 4103 event
> is generated on Windows, forwarded by the agent, and decoded by the manager.
> The committed `100413` rule currently checks `win.eventdata.payload` for
> `Invoke-WebRequest` under parent `91801`; inspect an actual decoded event
> before changing the field match. Until 4103 generation and ingestion are
> confirmed, treat `100413` as **pending validation**, not as a working
> detection. Even when it fires, the rule indicates PowerShell web-request
> activity, not proof that a file transfer completed.

**Evidence** (abridged from `stage04-sysmon-encoded-powershell.json`; the event was produced by an earlier revision of `100401`).

```json
{
  "agent": { "ip": "192.168.60.1", "name": "window11Host", "id": "001" },
  "data": { "win": {
    "eventdata": { "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                   "commandLine": "\"...powershell.exe\" -NoProfile -EncodedCommand dwBoAG8AYQBt..." },
    "system": { "eventID": "1", "channel": "Microsoft-Windows-Sysmon/Operational" } } },
  "rule": { "id": "100401", "level": 10 },
  "decoder": { "name": "windows_eventchannel" }
}
```

## 4. File integrity monitoring and VirusTotal

The Windows Agent's syscheck module monitors these project paths:

| Path | Configuration | Intended use |
|---|---|---|
| `C:\Users\LENOVO\Downloads\virustotaltest` | `check_all="yes"`, `realtime="yes"` | EICAR payload delivery and subsequent file modification/deletion |
| `C:\Users\LENOVO\tmp` | `check_all="yes"`, `realtime="yes"`, `report_changes="yes"`, recursion level 2 | General file lifecycle/change monitoring |
| `C:\Windows\Temp` | `realtime="yes"`, restricted to `.zip` files at recursion level 0 | Stage 11 archive creation (`exfil_test.zip`) |

The project also uses Sysmon Event ID 11 to observe selected file-creation events. The committed Sysmon FileCreate filter includes a condition for a `.zip` file under `C:\Windows\Temp`; the Wazuh custom rule `100405` can match file-creation events whose path contains `\Temp\` or `\AppData\Roaming\`. These are separate telemetry paths: Sysmon Event 11 and Wazuh FIM must be tested and recorded independently.

When syscheck identifies a relevant file, it reports file hashes. The Manager's VirusTotal integration (restricted to `syscheck` alerts) can look up the hash. The reputation alert is generated **on the Manager**, which is why its `location` is `virustotal`.

**Evidence** (abridged from `stage06-virustotal-malicious-detected.json`, an earlier EICAR baseline run on 2026-08-17):

```json
{
  "agent": { "ip": "192.168.60.1", "name": "window11Host" },
  "data": { "integration": "virustotal",
            "virustotal": { "malicious": "1", "found": "1", "positives": "62",
              "source": { "file": "c:\\\\users\\\\lenovo\\\\downloads\\\\virustotaltest\\\\eicar-facebook.com",
                          "md5": "44d88612fea8a8f36de82e1278abb02f" } } },
  "rule": { "id": "87105", "level": 12 },
  "location": "virustotal"
}
```

This VirusTotal sample is **supplementary historical evidence**, not proof that the same Stage 6 execution generated the current Suricata and FIM signals in one correlated run. No raw Stage 9 FIM alert or Stage 11 ZIP-FIM alert is currently indexed in `threat-emulation/evidence-logs/`.

Limits: only hashes are sent; unknown files may return no verdict; API quotas can delay lookups in bursts. Do not store the VirusTotal API key in this repository.
