---
title: "SOC Home Lab —  Lab architecture and summary"
tags: [Blue Team, SOC Home Lab, Lab setup]
lang: en
breaks: true
---

# SOC Home Lab — Lab structure and setup infrastructure

[TOC]
---

## 0. Executive Summary

**Lab objective:** Build a SOC home Lab using Wazuh (SIEM/XDR), Suricata (IDS/IPS) , and pfsense (firewall/gateaway) to practice detection engineering - writing custom decoders/rules, simulating attacks mapped to MITRE ATT&CK, and validating rules against real log evidence.

 **Scope:**
- Baseline detection engineering: pfSense filterlog decoder, Suricata local rules, Sysmon/Windows Event Log mapping, VirusTotal threat intel integration.
- Full 12-stage attack simulation: Reconnaissance → Brute Force → Initial Access → Execution → Discovery → Payload Drop → Persistence → C2 → Credential Access → File Lifecycle → Cleanup/Anti-forensics → Exfiltration.
- Advanced correlation rules: linking brute force + successful login, LSASS access, log clearing.

**Overall status:** Most detections are confirmed by real log evidence. Several correlation-level rules (`100410`, `100411`, `100412`) and the exfiltration rule (`100413`) are still at the design stage / not fully verified with raw alerts — see Section 9.


---

## 1. Lab Architecture


The lab uses VMware VMs and includes the following components: 

| Component | Role |
|---|---|
| **Wazuh Server** | Runs the Wazuh manager, Indexer, and Dashboard. Collects & correlates logs from agents, Suricata, and pfSense |
| **Windows 11 Endpoint** | Runs the Wazuh Agent (system monitoring + log forwarding); the victim (target) machine |
| **Kali Linux (Attacker)** | Machine used to simulate attacks |
| **pfSense Firewall** | Provides firewall logs, integrated into Wazuh via syslog |
| **Suricata IDS/IPS** | Monitors network traffic, sends alerts to Wazuh based on custom rules |


![SOC home lab architecture](../architecture/Architecture-and-data-flow.png)


### Wazuh Architecture
- **Wazuh Agent**: a lightweight program installed on each monitored device (Linux/Windows/macOS), collects security data and forwards it to the Wazuh Server.
- **Wazuh Server**: receives the data, decodes and analyzes it against rules, generates alerts, and forwards them to the **Wazuh Indexer**.
- **Wazuh Indexer**: a search/analytics engine (built on Elasticsearch/OpenSearch) that indexes data for fast querying.
- **Wazuh Dashboard**: a web interface (built on Kibana) — real-time monitoring, compliance tracking, and investigation.

Installation: https://documentation.wazuh.com/current/quickstart.html

### Wazuh server setup configuration 

- Network Mode: NAT (Network Address Translation)
- Host Platform: VMware
- Target Agent OS: Windows

### Wazuh agent setup configuration
**Step 1:** 

Platform support:
- Windows
- Linux
- macOS

**Step 2:**
Deploying new Agent:

- Visit the official Wazuh download page: https://documentation.wazuh.com/current/
installation-guide/wazuh-agent/wazuh-agent-package-windows.html
- Download the Windows .msi installer for the Wazuh agent.
- Run the installer to begin the installation process.

**Step 3:**
Agent settings configuration
 
- Navigate to the Endpoints tab.
- Click on Deploy new agent.
- Enter the Server Address — the IP address of your Wazuh Manager (192.168.60.137).
- Specify a unique Agent Name (e.g., PC1)

==>  Wazuh will generate registration commands. These commands must be executed in
PowerShell to link the agent with the manager.
• Open Windows PowerShell as Administrator.
• Paste and execute the provided commands
### IP / Role Table

| Component | IP Address | Role |
|---|---|---|
| Suricata IDS | (runs on Windows or Kali) | Host-based network IDS + IPS on pfSense |
| pfSense | 192.168.254.101 (WAN) / 192.168.60.254 (LAN) | Firewall/gateway (forwards logs via syslog) |
| Kali Linux | 192.168.254.100 (WAN) / 192.168.60.135 (LAN) | Attacker machine |
| Windows 11 | 192.168.60.1 | Wazuh agent (monitored endpoint) |
| Wazuh Server | 192.168.60.137 | Central SIEM (manager + indexer + dashboard) |

> ⚠️ **IP inconsistency note**: the source documents use `192.168.60.101` for the Windows11 endpoint in the baseline Detection Engineering section, but switch to `192.168.60.1` in the Full Attacking Chain section. The actual current IP of the Windows11 agent should be confirmed before reusing this report for a future test run.

---

### Pfsense Firewall Configuration

**Step 1:**
1. Virtual Machine Software → VMware Workstation Pro (used in this guide, but VirtualBox also
works).
2. pfSense ISO → Download the latest version from the official pfSense website.
3. Wazuh Manager → Running and accessible in your lab environment

**Step 2: Creating a Virtual Machine for pfSense**
1. Open VMware
- Navigate to File → New Virtual Machine.
2. Select the Installation Media
- Choose Installer disc image file (ISO) and browse for the downloaded pfSense ISO.
3.  Name Your VM
- Use a descriptive name such as pfSense and pick a save location.
4. Allocate Disk Space
- 20 GB minimum (store as a single file recommended)
5. Customize Hardware
- RAM:1GB minimum (2 GB recommended).
- CPU: 1 vCPU (2 cores recommended).
- Network Adapters:– Adapter 1 (WAN) → NAT (simulates internet access).– Adapter 2 (LAN) → Host-only (isolated internal lab network).
6. Assign Interfaces
- WAN(em0) →Configured via DHCP (IP in 192.68.254.101/24 range).
- LAN (em1) →Static IP 192.168.60.254/24.

**Step 3: Accessing the pfSense Web Interface**
1. Open a browser from a VM (e.g., Kali Linux) connected to the LAN network.
2. Go to: https://192.168.60.254/
3. Log in with default credentials:
• Username: admin
• Password: pfsense

**Step 4: Why Combine pfSense with Wazuh?**
- pfSense acts as the network security gateway, generating logs on traffic, connections, and blocked
events.
- Wazuh functions as the Security Information and Event Management (SIEM) platform,
collecting and analyzing logs to detect suspicious activity.
==> Together, they form a mini SOC environment, where firewall events are monitored and correlated
with endpoint activity.

 **Step 5: Configuring pfSense Logs in Wazuh**
1. Enable Remote Logging in pfSense
- Goto Status → System Logs → Settings.
- Check Enable Remote Logging.
- Add your Wazuh server’s IP (e.g., 192.168.68.137) under Remote Syslog Servers.
- Set Port to 514 (default syslog).
- Select log categories to forward: System, Firewall, VPN, DHCP, DNS


### Suricata IDS configuration

**IDS vs IPS Overview**
1. IDS (Intrusion Detection System):
– Detects threats by inspecting traffic using:
- Signatures (rules)
- IoCs (hashes, domains, URLs, TLS/SSH fingerprints)
- Lua scripting– Generates alerts and logs but does not block traffic.
2. IPS (Intrusion Prevention System):
– Takes proactive action by dropping or allowing traffic based on inspection results

**Download and Install**
1. Visit: https://suricata.io/download/
2. Download the Windows installer (.msi)
3. Run the installer with default settings
Suricata installs to:
```bash=
C:\Program Files\Suricata\
```

Contents include:
• suricata.exe– the main executable
• suricata.yaml– configuration file
• rules\– rule files directory
• log\– log output folder

**Install and Verify Npcap**
Suricata requires Npcap to capture network traffic.
**Step 1: Download from https://npcap.com/#download**

During installation:
• Enable WinPcap API-compatible mode
• Enable startup at boot
Step 2: Verify that Npcap is running:
```bash=
Get-Service-Name npcap
```
Expected output:
```bash=
Status Name DisplayName--------------------
Running npcap Npcap Packet Driver (NPCAP)
```
If not running:
```bash=
Start-Service-Name npcap
```

3. Configure Suricata
**Open Configuration**
```bash=
C:\Program Files\Suricata\suricata.yaml
```
**Define Network Interface**
To view interfaces:
```bash=
Get-NetAdapter | Select Name, Status
```

Example config snippet:
```bash=
af-packet:
   - interface: Wi-Fi
```


**Enable JSON Logging**
Enable EVE JSON output:
```json=
outputs:
- eve-log:
	enabled: yes
	filetype: regular
	filename: eve.json
```

4. Running Suricata
In PowerShell (Admin):
**We are using the Host-only network from the VMware machine (VMnet1) so our interface is: \Device\NPF_{B030E396-B937-4B1A-ADC6-B02699BCBC95}**


```bash=
cd "C:\Program Files\Suricata\"
suricata.exe -c suricata.yaml -i "\Device\NPF_{B030E396-B937-4B1A-ADC6-B02699BCBC95}"
```
**Suricata Log Files**
```bash=
C:\Program Files\Suricata\log\
```
Important files:
- eve.json– JSON alerts
- fast.log– quick alerts
- stats.log– system stats


## VMware Virtual Machine Resources

| VM | vCPU | RAM | Network |
|---|---:|---:|---|
| Wazuh Server | 4 | 8 GB | NAT + Host-only |
| pfSense | 2 | 2 GB | NAT + Host-only |
| Kali Linux | 2 | 4 GB | Host-only |
| Windows 11 | 4 | 8 GB | Host-only |


## Connectivity Validation

Verify connectivity between the lab components before configuring detection rules.

From Windows:

```powershell=
ping 192.168.60.137
```

From Kali

```powershell=
ping 192.168.60.254
ping 192.168.60.137
ping <WINDOWS-IP>
```

## Data Flow Validation

### Windows Endpoint

Windows Event Logs / Sysmon
↓
Wazuh Agent
↓
Wazuh Server
↓
Wazuh Indexer
↓
Wazuh Dashboard

### Network Traffic

Network Traffic
↓
Suricata
↓
`eve.json`
↓
Wazuh Server
↓
Wazuh Dashboard

### Firewall Logs

pfSense
↓
Syslog (UDP/514)
↓
Wazuh Server
↓
Wazuh Dashboard

### Agent Connectivity Validation

Verify the Wazuh agent status from:

**Wazuh Dashboard → Agents management → Summary**

The Windows endpoint should appear as **Active** after successful agent enrollment and connectivity.
