# Evidence Logs

Raw Wazuh alert JSON collected during the lab. `stageNN-*.json` files map to
a stage in [`docs/04-threat-emulation-report.md`](../../docs/04-threat-emulation-report.md).
`baseline-*.json` files are supplementary tests from the detection-engineering
baseline work, not tied to a specific chain stage.

Every file is plain, valid JSON (one alert per file), so it can be fed straight to
`jq`, `wazuh-logtest` or a script. Annotations such as "condensed excerpt" or
"rule did not match the real event" live in the status column below, not inside
the files.

## Stage evidence

| File | Stage | Rule(s) | Status |
|---|---|---|---|
| `stage01-pfsense-synburst.json` | 1 — Reconnaissance | `100140` | ⚠️ Not attributable to the scan — loopback DNS traffic (see docs/04) |
| `stage02-suricata-ssh-bruteforce.json` | 2 — Brute Force | `100301` | ✅ Verified |
| `stage02-windows-4625-failed-logon.json` | 2 — Brute Force | `60122` | ✅ Verified |
| `stage03-windows-4740-account-locked.json` | 3 — Successful Access | `60115` | ⚠️ Evidence is a lockout, not a logon |
| `stage03-rule-100410-correlation-excerpt.json` | 3 — Successful Access | `100410` | ⚠️ Condensed excerpt, early rule version |
| `stage04-sysmon-encoded-powershell.json` | 4 — Execution | `100401` | ✅ Verified |
| `stage05-sysmon-net1-discovery.json` | 5 — Discovery | `92031` (built-in) | ⚠️ Custom rules `100400`/`100402` not proven |
| `stage06-suricata-eicar-download.json` | 6 — Payload Drop | `100306` | ✅ Verified |
| `stage06-virustotal-malicious-detected.json` | 6 — Payload Drop | `87105` | ✅ Verified (earlier baseline run, same technique) |
| `stage07-sysmon-registry-runkey.json` | 7 — Persistence | `92302` (built-in) | ⚠️ Custom rule `100406` not proven |
| `stage08-suricata-reverse-shell.json` | 8 — Command and Control | `100304` | ✅ Verified (rule rev 2) |
| `stage08b-rule-100411-lsass-excerpt.json` | 8b — Credential Access | `100411` | ⚠️ Condensed excerpt, missing standard alert fields |
| `stage10-windows-1102-log-cleared.json` | 10 — Anti-Forensics | `63103` (built-in) | ⚠️ Custom rule `100412` not proven |
| `stage10-rule-100412-excerpt.json` | 10 — Anti-Forensics | `100412` | ⚠️ Condensed excerpt, rule not matched by the real event |

No raw log exists yet for **Stage 9** (File Lifecycle — screenshot only) or
**Stage 11** (Exfiltration — not yet evidenced). See the Gap Analysis in
`docs/04` for the re-test plan.

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
