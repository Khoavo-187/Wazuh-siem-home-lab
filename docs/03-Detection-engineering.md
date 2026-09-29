---
title: "SOC Home Lab — Detection Engineering"
tags: [Blue Team, SOC Home Lab, Detection engineering]
lang: en
breaks: true
---

# 03 - Detection engineering 

- This is the `brain` of this homelab where the raw logs are being sent from outsider to the 
Wazuh Dashboard for investigation 
- From that, the custom `rule sets` or `decoders` take 
responsible for decoding huge line of raw logs that can help SOC analyst to read the logs 
easier 
- This can be very useful because these detection can automcatically identify and 
analyse the severity of website, information or networking just base on a single log with 
suitable custom decoder 
- It can also inspect what kind of attack scenario or 
vulnerabilities and assign it to suitable `MITRE ATT&CK` ID

	This document covers the "Detection Engineering" phase of the SOC lab. It details how raw logs collected from the ingestion pipeline are parsed using custom **Decoders** and how malicious behavior is identified using custom **Rules** mapped to the MITRE ATT&CK framework.
