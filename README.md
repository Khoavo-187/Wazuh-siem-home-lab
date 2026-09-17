# Wazuh SOC Home Lab

A hands-on Security Operations Center (SOC) home lab built to practice
security monitoring, log analysis, detection engineering, and incident response.

## Overview

This project simulates a small SOC environment using:

- Wazuh SIEM
- pfSense firewall
- Suricata IDS/IPS
- Kali Linux
- Ubuntu Server

The main goal is to collect security telemetry, create detections,
investigate alerts, and document the incident-response workflow.

## Architecture

![Network Architecture](architecture/network-diagram.png)

### Components

| Component | Role |
|---|---|
| Wazuh | SIEM / security monitoring |
| pfSense | Firewall / network gateway |
| Suricata | Network IDS/IPS |
| Kali Linux | Security testing |
| Ubuntu Server | Wazuh infrastructure |

## Network

| Host | IP | Role |
|---|---|---|
| Kali | 192.168.x.x | Security testing |
| pfSense | 192.168.x.x | Firewall |
| Wazuh | 192.168.x.x | SIEM |

> Example IP addresses are documented for lab purposes.

## Features

- Centralized log collection
- pfSense log ingestion
- Custom Wazuh decoders
- Custom Wazuh detection rules
- Network intrusion detection with Suricata
- Alert investigation
- MITRE ATT&CK mapping
- Incident-response documentation

## Detection Use Cases

### 1. ICMP Activity

Description...

### 2. Suspicious Network Activity

Description...

### 3. Firewall Events

Description...

## Lab Workflow

```text
Attack / Event
      ↓
pfSense / Suricata
      ↓
Log Collection
      ↓
Wazuh
      ↓
Decoder
      ↓
Detection Rule
      ↓
Alert
      ↓
Investigation
      ↓
Incident Response
