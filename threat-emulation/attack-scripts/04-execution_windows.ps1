# Stage 4 — Execution (T1059.001, T1027)
# Host: Windows 11 victim (run inside the SSH session)
# Base64-encodes a command string and runs it via -EncodedCommand to test
# Sysmon/Wazuh detection of obfuscated PowerShell (rule 100401).

$cmd    = 'whoami; hostname; ipconfig /all'
$bytes  = [System.Text.Encoding]::Unicode.GetBytes($cmd)
$encoded = [Convert]::ToBase64String($bytes)

powershell.exe -NoProfile -EncodedCommand $encoded
