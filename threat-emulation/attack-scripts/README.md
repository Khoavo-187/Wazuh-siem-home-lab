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

Stage-specific prerequisites and limitations are noted in the scripts and
in `docs/04`. Stage 11 requires PowerShell Module Logging (Event 4103) for
the intended `100413` detection; the agent's PowerShell Operational channel
is already present in the committed `ossec.conf`, but 4103 activation and
ingestion still require verification.

For Stage 11, the Windows script sends an HTTP POST to the Kali Netcat listener
on TCP port `4445`. The listener captures the raw HTTP request stream
(headers and body), not a clean ZIP file. Compare file hashes only after the
HTTP body has been extracted from the capture. `T1048.003` is conditional on
an unencrypted, non-C2 transfer; use `T1041` only if data actually travels
over the existing C2 channel.
