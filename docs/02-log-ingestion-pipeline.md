---
title: "SOC Home Lab — Log ingestion
tags: [Blue Team, SOC Home Lab, log ingestion]
lang: en
breaks: true
---

# 02 - Log Ingestion Pipeline


:::info
This document outline how telementry and security events are routed from different endpoints and network devices to the central Wazuh SIEM. It covers log sources , requiring custom configurations and custom data parsing(decoders)
:::

## Network telementry (Pfsense Syslog & decoders)

- Pfsense firewall logs are forwarded to Wazuh server via `Syslog` over UDP port `514`.Because pfsense use the comma-seperated format (`filterlog`), custom decoders are required to `parse the raw strings` into `queryable fields` (e.g: `srcip`, `dstip`,`dstport`,`srcport`).
- Therefore, `regex-based decoding` is used to `extract` and `map` the relevant fields from raw pfSense filterlog messages into `structured fields` that can be used for `detection` and `investigation`.


**Custom Decoders Implemented**:

* `pfsense-lab`: The base decoder identifying pfsense filterlogs
* `pfsense-lab-ports`: Parses TCP/UDP traffic raw logs containing port numbers
* `pfsense-lab-icmp`: Parses ICMP traffic (pings and sweeps)
* `pfsense-lab-igmp/pfsense-lab-ipv4/pfsense-lab-ipv6`: Fallback decoders for other traffics and protocols

**Example of Decoder snippet(TCP/UDP)**
```xml=
<decoder name="pfsense-lab-ports">
    <parent>pfsense-lab</parent>
    <prematch type="pcre2" offset="after_parent">\d+,,,.*?,4,.*?,(?:tcp|udp),</prematch>
    <regex type="pcre2" offset="after_parent">(\d+),,,(\d+),([^,]+),([^,]+),([^,]+),([^,]+),(4),([^,]*),([^,]*),(\d+),(\d+),(\d+),([^,]+),(\d+),(tcp|udp),(\d+),([^,]+),([^,]+),(\d+),(\d+),(\d+)</regex>
    <order>pfsense.rulenum,pfsense.tracker,pfsense.interface,pfsense.reason,action,pfsense.direction,pfsense.ipversion,pfsense.tos,pfsense.ecn,pfsense.ttl,pfsense.id,pfsense.offset,pfsense.flags,pfsense.protocol_number,protocol,pfsense.length,srcip,dstip,srcport,dstport,pfsense.data_length</order>
</decoder>
```
**Ingestion evidence**

- When Wazuh receive the log, the `location` field is automatically assigned to the `register IP address` that pinpoint to and extract all required parameter fields that match the base decoders.
```json=
{
  "data": {
    "protocol": "udp", 
    "srcip": "127.0.0.1",
    "pfsense": { "reason": "match", "action": "pass" }
  },
  "rule": { "id": "100140", "level": 6 },
  "location": "192.168.60.254", 
  "decoder": { "name": "pfsense-lab" },
  "timestamp": "2026-08-28T05:32:14.075+0000"
}
```
:::spoiler
(Note: location shows `192.168.60.254`, the pfSense gateway IP, and decoder confirms our custom pfsense-lab decoder parsed it).
:::

## Host-based Network IDS: Suricata intergration

- Suricata take responsible for `monitoring` and `detecting` the `Wazuh agent service` (Window 11) in `local/internal` network. This one can actually visualize the `east-west traffic` and take control `host-level network activity`.

- **Ingestion method**: The Wazuh agent is configured to continiuosly read `Suricata's alert` output file located in the `ossec_agent` folder
- **Log format**: Eve.json (JSON formatted alerts containing `signature_id` and metadata)

:point_right: **Ingestion Evidence**

The raw Wazuh alert explicitly shows the `location` pointing to the `physical file path` on the `Window endpoint`

```json=
{
  "agent": { "ip": "192.168.60.1", "name": "window11Host", "id": "001" },
  "data": {
    "src_ip": "192.168.60.1",
    "dest_port": "31337",
    "alert": { "signature": "LOCAL Possible Reverse Shell - Suspicious Outbound Port" }
  },
  "rule": { "id": "100304", "level": 12 },
  "location": "C:\\Program Files\\Suricata\\log\\eve.json",
  "decoder": { "name": "json" }
}
```
:::spoiler
Note: `location` confirms the agent is successfully reading from `C:\Program Files\Suricata\log\eve.json`
:::

## Windows Endpoint Telemetry: Event logs & Sysmon

:::info
To ensure sufficient evidence capture for techniques like `brute force` and `lateral movement` , the Windows endpoint requires specific logging configurations before Wazuh can ingest the data
:::

Required Window audit Policies:
- Audit logon (Success + Failure): captures Event 4624 (Success) & 4625 (Failure) for brute force detection
- Audit Process Creation: Capture Event 4688 (requires enabling Command line auditing in Group Policy)

**Sysmon ingestion scope**
1. The Wazuh Agent reads native `Windows Event Logs`and `Sysmon logs` via the `Window_eventchannel` API rather than reading a flat text file

2. Sysmon is deployed to provide deep process visibility. The Wazuh Agent ingest the following key Sysmon Event IDs from the `Microsoft-Windows-Sysmon/operartional` channel:
    - Event ID 3(Network connect): Tracks outbound connections from suspicious processes (Used for C2 and exfiltration detection)
    - Event ID 10(ProcessAccess): Monitors access to lsass.exe for crediential dumping detection
    - Event ID 11(file create): Monitors executables dropped in sensitive data paths (e.g: \Temp\)
    - Event ID 13(registry Event): Monitors persistence mechanism(e.g: \CurrentVersion\Run)
    - Event ID 1(Process create): Captures process lineage (e.g:Powershell.exe,cmd.exe spawning net.exe) and command-line arguments(e.g: EncondedCommand) 

```json=
{
  "agent": { "ip": "192.168.60.1", "name": "window11Host", "id": "001" },
  "data": {
    "win": {
      "eventdata": {
        "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "commandLine": "\"powershell.exe\" -NoProfile -EncodedCommand dwBoAG8AYQ..."
      },
      "system": {
        "eventID": "1", 
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "providerName": "Microsoft-Windows-Sysmon"
      }
    }
  },
  "rule": { "id": "100401", "level": 10 },
  "decoder": { "name": "windows_eventchannel" }
}
```


## File Intergrity and Threat Intelligence (VirusTotal)

File lifecycle events are ingested natively using Wazuh's File integrity Monitoring (FIM) module (Syscheck)

- FIM Real-Time monitoring: `the <directories realtime="yes">` tag is configured on the Window agent to monitor specific folders (e.g: download directories)
- VirusTotal Pipeline: When FIM detects a file `creation` or `modification`, it generates a hash (MD5,SHA1,SHA256). This hash is ingested by Wazuh Manager's Virustotal intergration module, queried against the `VT API`, and enriched with a `reputation score`(e.g: `malicious > 0`)


**Ingestion evidence**

```json=
{
  "agent": { "ip": "192.168.60.1", "name": "window11Host" },
  "data": {
    "integration": "virustotal",
    "virustotal": {
      "malicious": "1", "found": "1", "positives": "62",
      "source": {
        "file": "c:\\users\\lenovo\\downloads\\virustotaltest\\eicar-facebook.com",
        "md5": "44d88612fea8a8f36de82e1278abb02f"
      }
    }
  },
  "rule": { "id": "87105", "level": 12 },
  "location": "virustotal"
}
```

:::spoiler
Note: location shows virustotal, indicating this alert was generated internally by the Wazuh manager's API intergration , not directly from the endpoint file
:::
