# Evidence Logs

This folder contains Wazuh alert JSON exports and explicitly labelled excerpts from the lab. `stageNN-*.json` files map to stages in [`docs/04-threat-emulation-report.md`](../../docs/04-threat-emulation-report.md). `baseline-*.json` files are supplementary tests and are not part of the numbered attack-chain timeline.

A JSON file may be a full alert export, a compact alert export, or a deliberately condensed excerpt. The index below identifies its evidentiary scope. A saved alert proves only that the recorded rule ID appeared for that test; it does not automatically validate the current committed rule revision.

## Stage evidence

| File | Stage | Rule(s) | Status |
|---|---|---|---|
| `stage01-pfsense-synburst.json` | 1 — Reconnaissance | `100140` | ⚠️ Not attributable to the scan — loopback DNS traffic (see docs/04) |
| `stage02-suricata-ssh-bruteforce.json` | 2 — Brute Force | `100301` | ✅ Verified |
| `stage02-windows-4625-failed-logon.json` | 2 — Brute Force | `60122` | ✅ Verified |
| `stage02-rule-100408-bruteforce-retest.json` | 2 — Brute Force | `100408` | ✅ Verified (2026-10-10 re-test) — correlation rule confirmed firing, correct `ipAddress` (`192.168.60.135`) |
| `stage03-windows-4740-account-locked.json` | 3 — Successful Access | `60115` | ⚠️ Evidence is a lockout, not a logon (original 2026-08-28 run) |
| `stage03-rule-100410-correlation-excerpt.json` | 3 — Successful Access | `100410` | ⚠️ Condensed excerpt from an early rule version; not validation evidence for the current `if_sid=92651,92657` / `if_matched_sid=60122` / `frequency=6` configuration |
| `stage03-rule-92657-successful-logon.json` | 3 — Successful Access | `92657` (built-in) | ✅ Verified (2026-10-10 re-test) — real `4624`, but a built-in rule fired instead of custom `100410` |
| `stage04-sysmon-encoded-powershell.json` | 4 — Execution | `100401` | ⚠️ Historical alert is level 10; current XML is level 13. Retest the current rule revision before marking it current-revision validated |
| `stage05-sysmon-net1-discovery.json` | 5 — Discovery | `92031` (built-in) | ⚠️ Original run (2026-08-28) — custom rules not proven |
| `stage05-rule-100400-shell-child-arp.json` | 5 — Discovery | `100400` | ⚠️ Historical ARP event matched the older generic rule. Current XML excludes ARP from `100400` and includes it in `100402`; fresh regression evidence is required |
| `stage05-rule-100407-recon-burst.json` | 5 — Discovery | `100407` | ✅ Historical correlation alert is preserved (2026-10-13); retest the current `100400`/`100402` interaction after the latest exclusion/pattern changes |
| `stage06-suricata-eicar-download.json` | 6 — Payload Drop | `100306` | ✅ Verified |
| `stage06-virustotal-malicious-detected.json` | 6 — Payload Drop | `87105` | ✅ Verified (earlier baseline run, same technique) |
| `stage07-sysmon-registry-runkey.json` | 7 — Persistence | `92302` (built-in) | ⚠️ Original run (2026-08-28) — custom rule not proven |
| `stage07-sysmon-registry-custom-rule.json` | 7 — Persistence | `100406` | ✅ Historical custom alert is preserved (2026-10-13) on the documented `92302` / `reg.exe` path; current XML also permits parent `92300`, which is not separately tested |
| `stage08-suricata-reverse-shell.json` | 8 — Command and Control | `100304` | ⚠️ Verified for SID `1000006` revision 2 only; current SID revision 3 requires an established-flow retest |
| `stage08b-rule-100411-lsass-excerpt.json` | 8b — Credential Access | `100411` | ⚠️ Condensed excerpt, missing standard alert fields |
| `stage08b-rule-100411-lsass-false-positive-windowsdefender.json` | 8b — Credential Access | `92900` (built-in) | ⚠️ Real raw alert, but a **false positive** from Windows Defender (`MsMpEng.exe`, `grantedAccess 0x101000`); `100411` correctly did not fire. Not a true positive |
| `stage10-windows-1102-log-cleared.json` | 10 — Anti-Forensics | `63103` (built-in) | ⚠️ Original 2026-08-29 Event 1102 alert; confirms built-in detection, not the current custom `100412` parent chain |
| `stage10-rule-100412-excerpt.json` | 10 — Anti-Forensics | `100412` | ✅ Historical custom alert is a full alert export despite the filename; it predates the current parent `63103`, so it does not validate the current parent revision |

No raw Stage 9 FIM alert is currently preserved (the stage has screenshot evidence only). No Stage 11 raw event, Suricata SID `1000012` / Wazuh `100310` alert, PowerShell `100413` alert, HTTP request capture, extracted ZIP body or matching SHA256 is preserved. See the Gap Analysis in `docs/04` for the required retests.

**Two dates in this folder.** Most Stage 1–10 files are from the original
chain run (2026-08-28 → 2026-08-29). `stage02-rule-100408-bruteforce-retest.json`
`stage03-rule-92657-successful-logon.json` and the two `stage05-rule-*.json`
files are from later, standalone re-tests (Stages 2–3 on 2026-10-10 UTC,
Stage 5 on 2026-10-13 UTC). Timestamps inside the files are UTC;
Kibana/Discover screenshots taken from the lab render in local time (UTC+7),
one calendar day ahead.

## Baseline / supplementary

Captured during the detection-engineering baseline work, cited in `docs/03`
and `docs/04` for context but not part of the chain timeline.

| File | What it shows |
|---|---|
| `baseline-pfsense-udp-allowed.json` | Example of pfSense `100110`, allowed UDP traffic |
| `baseline-pfsense-icmp-mismatch.json` | pfSense ICMP alert whose `rule.id`/`decoder.name` don't match the rules defined in `docs/03` |
| `baseline-pfsense-synburst-example1.json` | First pfSense SYN-burst test |
| `baseline-pfsense-synburst-e2e.json` | pfSense SYN-burst from an earlier end-to-end run |
| `baseline-suricata-portscan.json` | Suricata port-scan test, agent → manager |
| `stage08-suricata-reverse-shell-baseline-test.json` | First reverse-shell rule test, before the chain run |
