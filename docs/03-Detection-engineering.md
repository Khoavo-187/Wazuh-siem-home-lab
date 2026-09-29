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

	**This document covers the "Detection Engineering" phase of the SOC lab. It details how raw logs collected from the ingestion pipeline are parsed using custom **Decoders** and how malicious behavior is identified using custom **Rules** mapped to the MITRE ATT&CK framework.**

## 1. Custom Decoders (Parsing PFsense logs)

Since Pfsense forwards logs in a comma-seperated format (`filterlog`) , Wazuh needs custom decoders to extract fields like Source IP, Destination IP, Protocols and ports

**FIle Path**: Add these to `/var/ossec/etc/decoders/local_decoders.xml` on the Wazuh server 

**How it works**
*	`<prematch>`: Acts as a filter. Wazuh looks for the string `filterlog[...]:` to quickly identify pfsense logs without processing unnecessary data.
*	`<regex>`: Use regular Expression (PCRE2) to capture specific comma-seperated values
*	`<order>`: Maps the captured regex groups to Wazuh's internal field name (e.g: `srcip`,`dstip`,..)

```xml=
<!-- Parent Decoder: Tìm chuỗi filterlog[...] ở bất kỳ đâu trong header -->
<decoder name="pfsense-lab">
    <prematch type="pcre2">filterlog\[\d+\]:\s*</prematch>
</decoder>

<!-- ========================================================= -->
<!-- 1. IPv4 TCP / UDP                                         -->
<!-- ========================================================= -->
<decoder name="pfsense-lab-ports">
    <parent>pfsense-lab</parent>
    <prematch type="pcre2" offset="after_parent">\d+,,,.*?,4,.*?,(?:tcp|udp),</prematch>
    <regex type="pcre2" offset="after_parent">(\d+),,,(\d+),([^,]+),([^,]+),([^,]+),([^,]+),(4),([^,]*),([^,]*),(\d+),(\d+),(\d+),([^,]+),(\d+),(tcp|udp),(\d+),([^,]+),([^,]+),(\d+),(\d+),(\d+)</regex>
    <order>pfsense.rulenum,pfsense.tracker,pfsense.interface,pfsense.reason,action,pfsense.direction,pfsense.ipversion,pfsense.tos,pfsense.ecn,pfsense.ttl,pfsense.id,pfsense.offset,pfsense.flags,pfsense.protocol_number,protocol,pfsense.length,srcip,dstip,srcport,dstport,pfsense.data_length</order>
</decoder>

<!-- ========================================================= -->
<!-- 2. IPv4 ICMP                                              -->
<!-- ========================================================= -->
<decoder name="pfsense-lab-icmp">
    <parent>pfsense-lab</parent>
    <prematch type="pcre2" offset="after_parent">\d+,,,.*?,4,.*?,icmp,</prematch>
    <regex type="pcre2" offset="after_parent">(\d+),,,(\d+),([^,]+),([^,]+),([^,]+),([^,]+),(4),([^,]*),([^,]*),(\d+),(\d+),(\d+),([^,]+),(\d+),(icmp),(\d+),([^,]+),([^,]+),([^,]+),(\d+),(\d+)</regex>
    <order>pfsense.rulenum,pfsense.tracker,pfsense.interface,pfsense.reason,action,pfsense.direction,pfsense.ipversion,pfsense.tos,pfsense.ecn,pfsense.ttl,pfsense.id,pfsense.offset,pfsense.flags,pfsense.protocol_number,protocol,pfsense.length,srcip,dstip,pfsense.icmp_type,pfsense.icmp_id,pfsense.icmp_seq</order>
</decoder>

<!-- ========================================================= -->
<!-- 3. IPv4 IGMP                                              -->
<!-- ========================================================= -->
<decoder name="pfsense-lab-igmp">
    <parent>pfsense-lab</parent>
    <prematch type="pcre2" offset="after_parent">\d+,,,.*?,4,.*?,igmp,</prematch>
    <regex type="pcre2" offset="after_parent">(\d+),,,(\d+),([^,]+),([^,]+),([^,]+),([^,]+),(4),([^,]*),([^,]*),(\d+),(\d+),(\d+),([^,]+),(\d+),(igmp),(\d+),([^,]+),([^,]+)</regex>
    <order>pfsense.rulenum,pfsense.tracker,pfsense.interface,pfsense.reason,action,pfsense.direction,pfsense.ipversion,pfsense.tos,pfsense.ecn,pfsense.ttl,pfsense.id,pfsense.offset,pfsense.flags,pfsense.protocol_number,protocol,pfsense.length,srcip,dstip</order>
</decoder>

<!-- ========================================================= -->
<!-- 4. IPv4 Fallback (Giao thức khác)                         -->
<!-- ========================================================= -->
<decoder name="pfsense-lab-ipv4">
    <parent>pfsense-lab</parent>
    <prematch type="pcre2" offset="after_parent">\d+,,,.*?,4,</prematch>
    <regex type="pcre2" offset="after_parent">(\d+),,,(\d+),([^,]+),([^,]+),([^,]+),([^,]+),(4),([^,]*),([^,]*),(\d+),(\d+),(\d+),([^,]+),(\d+),((?!(?:tcp|udp|icmp|igmp),)[^,]+),(\d+),([^,]+),([^,]+)</regex>
    <order>pfsense.rulenum,pfsense.tracker,pfsense.interface,pfsense.reason,action,pfsense.direction,pfsense.ipversion,pfsense.tos,pfsense.ecn,pfsense.ttl,pfsense.id,pfsense.offset,pfsense.flags,pfsense.protocol_number,protocol,pfsense.length,srcip,dstip</order>
</decoder>

<!-- ========================================================= -->
<!-- 5. IPv6                                                   -->
<!-- ========================================================= -->
<decoder name="pfsense-lab-ipv6">
    <parent>pfsense-lab</parent>
    <prematch type="pcre2" offset="after_parent">\d+,,,.*?,6,</prematch>
    <regex type="pcre2" offset="after_parent">(\d+),,,(\d+),([^,]+),([^,]+),([^,]+),([^,]+),(6),([^,]+),([^,]+),(\d+),([^,]+),(\d+),(\d+),([^,]+),([^,]+)</regex>
    <order>pfsense.rulenum,pfsense.tracker,pfsense.interface,pfsense.reason,action,pfsense.direction,pfsense.ipversion,pfsense.class,pfsense.flowlabel,pfsense.hoplimit,protocol,pfsense.protocol_number,pfsense.length,srcip,dstip</order>
</decoder>
```


## 2. Custom detection rules 

Why do we need these custom rules?
- While Wazuh has built-in rules, they are generic. Custom rules allow us to define exact thresholds for our specific environment (e,g: how many fail logins equal a brute force attack) and map them to the **MITRE ATT&CK** framework for better threat interlligence visualization.

**File Path:** add these to `/var/ossec/etc/rules/` for adding rules for different framwworks that you want to intergrated to your Wazuh 
Restart the manager(`sudo systemctl restart wazuh-manager`) after saving

### 2.1 Pfsense firewall rules
- **Objective**: Monitor network perimeter activity. We want to silently log allowed traffic, but trigger alerts for blocked traffic, ICMP pings, and volumetric attacks like SYN floods. Notice how Rule `100140` uses `frequency` and `timeframes` to detect a burst of connections over time.

```xml=
<group name="pfsense">

  <!-- Base rule -->
  <rule id="100100" level="1">
    <decoded_as>pfsense-lab</decoded_as>
    <description>pfSense: Firewall log detected</description>
    <options>no_log</options>
  </rule>


<rule id="100130" level="10" frequency="15" timeframe="30" ignore="120">
    <if_matched_sid>100100</if_matched_sid>
    <same_source_ip />
    <different_dstport />
    <description>pfSense: Possible port scan from $(srcip) -
      nhieu destination port khac nhau</description>
    <mitre>
      <id>T1046</id>
    </mitre>

    <group>network_scan,recon</group>
</rule>


  <!-- Block -->
  <rule id="100101" level="5">
    <if_sid>100100</if_sid>
    <action>block</action>

    <description>
      pfSense: Traffic blocked
      $(srcip):$(srcport) -> $(dstip):$(dstport)
    </description>

    <group>firewall_drop</group>
  </rule>

<!-- Ping sweep -->
<rule id="100201" level="8" frequency="8" timeframe="30" ignore="120">
    <if_matched_sid>100200</if_matched_sid>
    <same_source_ip />
    <different_dstip />
    <description>
      pfSense: Possible ping sweep from $(srcip) -
      nhieu destination host khac nhau
    </description>
    <mitre>
      <id>T1018</id>
    </mitre>
    <group>network_scan,ping_sweep</group>
</rule>


  <!-- Multiple blocks -->
  <rule id="100102" level="10" frequency="10" timeframe="60" ignore="120">
    <if_matched_sid>100101</if_matched_sid>
    <same_source_ip />

    <description>
      pfSense: Multiple firewall blocks from $(srcip) -
      possible scan/bruteforce
    </description>

    <mitre>
      <id>T1046</id>
    </mitre>

    <group>multiple_blocks,network_scan</group>
  </rule>


  <!-- Pass -->
  <rule id="100110" level="3">
    <if_sid>100100</if_sid>
    <action>pass</action>

    <description>
      pfSense: Traffic allowed
      $(srcip):$(srcport) -> $(dstip):$(dstport)
    </description>

    <options>no_log</options>

    <group>firewall_pass</group>
  </rule>



  <!-- ICMP -->
  <rule id="100200" level="7">
    <if_sid>100100</if_sid>
    <protocol>^icmp$</protocol>

    <description>
      pfSense: ICMP Ping detected
    </description>

    <group>icmp,ping,network_scan</group>
  </rule>
  <!-- TCP burst -->
<rule id="100140" level="6" frequency="15" timeframe="10" ignore="60">
    <if_matched_sid>100110</if_matched_sid>
    <same_source_ip />
    <same_dstip />
    <same_dstport />
    <protocol>^tcp$</protocol>
    <description>
      pfSense: Burst of TCP connections from
      $(srcip) to $(dstip):$(dstport) -
      Possible TCP connection flood
    </description>
    <group>connection_flood</group>
</rule>

</group>
```

 
