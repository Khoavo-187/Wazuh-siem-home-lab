# Attack Scripts

One script per stage of the chain documented in
[`docs/04-threat-emulation-report.md`](../../docs/04-threat-emulation-report.md).
File names carry the host they run on: `_kali` (attacker) or `_windows`
(victim). Stages that need an action on both hosts have two files, run in the
order implied by their numbering (e.g. start `06-payload-drop_kali.sh` before
`06-payload-drop_windows.cmd`).

Scripts for the Windows side are provided as the plain commands that were
run — `.cmd` where the original command is a `cmd.exe` builtin (`reg`,
`net`, `dir`), `.ps1` where it is PowerShell. They are not signed or
production hardened; review before running.

**Run only inside the isolated lab network described in `docs/01`.**
Snapshot the Windows VM first. See `docs/04`, Appendix B, for the cleanup
command for every artifact these scripts create.

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
| `11-exfiltration_kali.sh` | 11 | Kali | T1041 |
| `11-exfiltration_windows.ps1` | 11 | Windows | T1041 |

Prerequisites specific to a stage (e.g. `procdump.exe` pre-staged before
Stage 8b) are noted as comments inside the script itself.
