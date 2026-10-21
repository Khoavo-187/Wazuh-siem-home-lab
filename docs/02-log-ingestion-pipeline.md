# 02 — Log Ingestion Pipeline

> [!NOTE]
> How telemetry and security events travel from the endpoint and network devices to Wazuh, and which custom parsing each source needs. JSON snippets are **abridged** copies of alerts stored in `threat-emulation/evidence-logs/`; the file each one comes from is named under it.

| Source | Transport | Decoder | Parent of the custom rules |
|---|---|---|---|
| pfSense firewall | Syslog UDP/514 → manager | custom `pfsense-lab` (+5 children) | `100100` |
| Suricata (endpoint) | `eve.json` → agent `localfile` (json) | built-in JSON decoder | `86601` |
| Windows Security / Sysmon / OpenSSH | Event Log channels → agent (`eventchannel`) | built-in `windows_eventchannel` | built-in Windows/Sysmon rules |
| FIM and VirusTotal | agent syscheck → manager integration | built-in | `550`–`593` range → `87105` |

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
      "groups": [
        "pfsense",
        "firewall_pass"
      ],
      "id": "100110"
    },
    "decoder": {
      "name": "pfsense-lab"
    },
    "full_log": "Aug 9 05:56:36 filterlog[63489]: 76,,,1000002661,em0,match,pass,out,4,0x0,,63,4250,0,none,17,udp,64,192.168.254.101,8.8.8.8,20455,53,44",
    "timestamp": "2026-08-09T05:56:36.860+0000"
  }
}
```

> [!NOTE]
> This sample is loopback DNS traffic on the firewall itself (see `docs/04`, Stage 1), shown only to prove decoding, not as a detection of the scan. Its syslog header is about 17.5 hours older than the arrival time, so check pfSense's clock before correlating firewall events with endpoint events.

## 2. Suricata on the endpoint

Suricata runs on the Windows endpoint and inspects traffic on its VMnet1 adapter, so it sees **east-west traffic to and from that host**. It writes alerts to `C:\Program Files\Suricata\log\eve.json`; the agent tails that file (`<localfile>` with `log_format json`, see `endpoints/windows-11/ossec.conf`) and the manager's built-in rule `86601` classifies `event_type: alert` events. Custom wrappers (`100300`–`100309`, `siem-wazuh/custom-rules/suricata_rules.xml`) select a single `alert.signature_id` each and assign level and MITRE ID.

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

The agent reads channels directly (`log_format eventchannel`): `Security`, `System`, `Application`, `Microsoft-Windows-OpenSSH/Operational` and `Microsoft-Windows-Sysmon/Operational`. The Windows audit policies and the Sysmon install are in `docs/01` §5.

| Telemetry | Needs | Used by |
|---|---|---|
| Security `4624` / `4625` | Audit *Logon* success + failure | `100408`, `100410` |
| Security `1102` | always logged | `100412` |
| Sysmon EID 1 | Sysmon; command-line fields | `100400`–`100403`, `100407` |
| Sysmon EID 3 | include list in `sysmon_config.xml` | `100404`, `100414` |
| Sysmon EID 10 | `ProcessAccess` include on `lsass.exe` | `100411`, `100416` |
| Sysmon EID 11 | include by extension/folder | `100405` |
| Sysmon EID 13 | `CurrentVersion\Run` include | `100406` |

> [!WARNING]
> The **PowerShell Operational channel (events 4103/4104) is configured into ossec.conf  (although it is not verified by testing)** by the committed agent configuration, and PowerShell module/script-block logging is not documented as enabled. Rule `100413` depends on that telemetry (see `docs/03`); until it is added to the agent and enabled by policy, that rule cannot fire.

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

The agent's syscheck module watches `C:\Users\LENOVO\Downloads\virustotaltest` in real time (and `C:\Users\LENOVO\tmp`, with change reporting); other paths are scanned every 12 hours. When a file is added or changed, syscheck reports its hashes, and the manager's VirusTotal integration (restricted to `syscheck` alerts) looks them up. The reputation alert is generated **on the manager**, which is why its `location` is `virustotal`.

**Evidence** (abridged from `stage06-virustotal-malicious-detected.json`, an earlier run of the same EICAR test on 2026-08-17):

```json
{
  "agent": { "ip": "192.168.60.1", "name": "window11Host" },
  "data": { "integration": "virustotal",
            "virustotal": { "malicious": "1", "found": "1", "positives": "62",
              "source": { "file": "c:\\users\\lenovo\\downloads\\virustotaltest\\eicar-facebook.com",
                          "md5": "44d88612fea8a8f36de82e1278abb02f" } } },
  "rule": { "id": "87105", "level": 12 },
  "location": "virustotal"
}
```

Limits: only hashes are sent; unknown files return no verdict; the free API tier (about 4 requests/minute) can delay lookups in bursts.
