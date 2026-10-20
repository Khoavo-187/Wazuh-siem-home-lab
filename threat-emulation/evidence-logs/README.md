# Evidence Logs

Raw Wazuh alert JSON collected during the lab. `stageNN-*.json` files map to
a stage in [`docs/04-threat-emulation-report.md`](../../docs/04-threat-emulation-report.md).
`baseline-*.json` files are supplementary tests from the detection-engineering
baseline work, not tied to a specific chain stage.

Every file is plain JSON (one alert per file); its status (verified, condensed
excerpt, rule mismatch) is recorded in the index below.

## Stage evidence

| File | Stage | Rule(s) | Status |
|---|---|---|---|
| `stage01-pfsense-synburst.json` | 1 — Reconnaissance | `100140` | ⚠️ Not attributable to the scan — loopback DNS traffic (see docs/04) |
| `stage02-suricata-ssh-bruteforce.json` | 2 — Brute Force | `100301` | ✅ Verified |
| `stage02-windows-4625-failed-logon.json` | 2 — Brute Force | `60122` | ✅ Verified |
| `stage02-rule-100408-bruteforce-retest.json` | 2 — Brute Force | `100408` | ✅ Verified (2026-10-10 re-test) — correlation rule confirmed firing, correct `ipAddress` (`192.168.60.135`) |
| `stage03-windows-4740-account-locked.json` | 3 — Successful Access | `60115` | ⚠️ Evidence is a lockout, not a logon (original 2026-08-28 run) |
| `stage03-rule-100410-correlation-excerpt.json` | 3 — Successful Access | `100410` | ⚠️ Condensed excerpt, early rule version |
| `stage03-rule-92657-successful-logon.json` | 3 — Successful Access | `92657` (built-in) | ✅ Verified (2026-10-10 re-test) — real `4624`, but a built-in rule fired instead of custom `100410` |
| `stage04-sysmon-encoded-powershell.json` | 4 — Execution | `100401` | ✅ Verified |
| `stage05-sysmon-net1-discovery.json` | 5 — Discovery | `92031` (built-in) | ⚠️ Original run (2026-08-28) — custom rules not proven |
| `stage05-rule-100400-shell-child-arp.json` | 5 — Discovery | `100400` | ✅ Verified (2026-10-13 re-test) — rule widened to "Shell spawned child process"; fixes a previously-flagged `$(win.eventdata.user` truncation bug |
| `stage05-rule-100407-recon-burst.json` | 5 — Discovery | `100407` | ✅ Verified (2026-10-13 re-test) — correlation fired correctly on 3 recon binaries within ~4.2s |
| `stage06-suricata-eicar-download.json` | 6 — Payload Drop | `100306` | ✅ Verified |
| `stage06-virustotal-malicious-detected.json` | 6 — Payload Drop | `87105` | ✅ Verified (earlier baseline run, same technique) |
| `stage07-sysmon-registry-runkey.json` | 7 — Persistence | `92302` (built-in) | ⚠️ Original run (2026-08-28) — custom rule not proven |
| `stage07-sysmon-registry-custom-rule.json` | 7 — Persistence | `100406` | ✅ Verified (2026-10-13 re-test, child of `92302`); `rule.groups` shows the merged name `windowspersistence` (see docs/03 §5, item 16) |
| `stage08-suricata-reverse-shell.json` | 8 — Command and Control | `100304` | ✅ Verified (rule rev 2) |
| `stage08b-rule-100411-lsass-excerpt.json` | 8b — Credential Access | `100411` | ⚠️ Condensed excerpt, missing standard alert fields |
| `stage08b-rule-100411-lsass-false-positive-windowsdefender.json` | 8b — Credential Access | `92900` (built-in) | ⚠️ Real raw alert, but a **false positive** from Windows Defender (`MsMpEng.exe`, `grantedAccess 0x101000`); `100411` correctly did not fire. Not a true positive |
| `stage10-windows-1102-log-cleared.json` | 10 — Anti-Forensics | `63103` (built-in) | ⚠️ Custom rule `100412` not proven |
| `stage10-rule-100412-excerpt.json` | 10 — Anti-Forensics | `100412` | ✅ Verified (2026-10-13 re-test) — now a full raw alert (level 15, `firedtimes 2`) despite the file name; `rule.groups` shows the merged name `windowslog_cleared` |

No raw log exists yet for **Stage 9** (File Lifecycle — screenshot only) or
**Stage 11** (Exfiltration — not yet evidenced). See the Gap Analysis in
`docs/04` for the re-test plan.

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
