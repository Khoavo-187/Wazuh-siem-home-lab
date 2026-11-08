# Attack Scripts

One script per stage of the chain documented in
[`docs/04-threat-emulation-report.md`](../../docs/04-threat-emulation-report.md).
File names carry the host they run on: `_kali` (attacker) or `_windows`
(victim). Stages that need an action on both hosts have two files, run in the
order implied by their numbering (e.g. start `06-payload-drop_kali.sh` before
`06-payload-drop_windows.cmd`).

The scripts document the emulation procedures and their host-side commands:
`.cmd` for commands run through `cmd.exe` and `.ps1` for PowerShell.
Some procedures were executed and have supporting evidence; others remain
planned or pending re-validation. A committed script is not proof that it was
run. The scripts are not signed or production hardened; review them before use.

**Run only inside the isolated lab network described in `docs/01`.**
The currently documented Windows victim is the physical VMware host, not a
disposable Windows guest, so it cannot be restored with a guest-VM snapshot.
For destructive or high-impact tests, use a separate disposable Windows guest
and take a snapshot before testing. Do not run those tests on the daily-use
physical host merely because the network segment is isolated. See `docs/04`,
Appendix B, for the artifact inventory and cleanup notes.

| Script | Stage | Host | Technique |
|---|---|---|---|
| `00-preparation_kali.sh` | 0 | Kali | — |
| `01-reconnaissance_kali.sh` | 1 | Kali | T1595, T1018 |
| `02-bruteforce_kali.sh` | 2 | Kali | T1110 |
| `03-successful-access_kali.sh` | 3 | Kali | T1078 |
| `04-execution_windows.ps1` | 4 | Windows | T1059.001, T1027 |
| `05-discovery_windows.cmd` | 5 | Windows | T1087, T1082, T1033 |
| `06-payload-drop_kali.sh` | 6 | Kali | T1105 |
| `06-payload-drop_windows.cmd` | 6 | Windows | T1105 |
| `07-persistence_windows.cmd` | 7 | Windows | T1547.001 |
| `08-command-control_kali.sh` | 8 | Kali | T1071 |
| `08-command-control_windows.ps1` | 8 | Windows | T1071 |
| `08b-credential-access_windows.cmd` | 8b | Windows | T1003.001 |
| `09-file-lifecycle_windows.ps1` | 9 | Windows | — (FIM) |
| `10-anti-forensics_windows.ps1` | 10 | Windows | T1070.001 |
| `11-exfiltration_kali.sh` | 11 | Kali | T1048.003 (conditional) |
| `11-exfiltration_windows.ps1` | 11 | Windows | T1059.001; T1048.003 (conditional) |

Stage 11 has four intended telemetry/detection paths: Sysmon Event 11 for ZIP creation, Wazuh FIM on `C:\Windows\Temp\*.zip`, Suricata SID `1000012` → Wazuh wrapper `100310` for the HTTP POST, and PowerShell Module Logging Event 4103 → Wazuh `100413` for `Invoke-WebRequest` activity. The PowerShell Operational channel subscription already exists in the committed Agent configuration, but Group Policy Module Logging, Event 4103 generation/forwarding, and both custom alert paths remain pending validation.

For Stage 11, the Windows script sends an HTTP POST to the Kali Netcat listener on TCP port `4445`. The listener captures the raw HTTP request stream (headers and body), not a clean ZIP file and not a normal HTTP response. Extract the body before comparing its SHA256 with the Windows archive. A PowerShell response error alone does not prove that no request body reached Kali.

`T1048.003` is conditional on demonstrating an unencrypted non-C2 transfer. Use `T1041` only if data actually travels over the existing C2 channel.
