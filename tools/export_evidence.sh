#!/usr/bin/env bash
# export_evidence.sh <rule_id> <output.json> [alerts_file] [agent_id]
# Run on the Wazuh manager. Saves the original matching JSON line without jq re-serialization.
# By default this selects the last matching line in the supplied alerts file.
set -euo pipefail

RULE_ID="${1:?usage: $0 <rule_id> <output.json> [alerts_file] [agent_id]}"
OUT="${2:?usage: $0 <rule_id> <output.json> [alerts_file] [agent_id]}"
ALERTS="${3:-/var/ossec/logs/alerts/alerts.json}"
AGENT_ID="${4:-}"

command -v jq >/dev/null 2>&1 || { echo "jq is required" >&2; exit 1; }
[[ -r "$ALERTS" ]] || { echo "cannot read alerts file: $ALERTS" >&2; exit 1; }
mkdir -p "$(dirname "$OUT")"
[[ ! -e "$OUT" ]] || { echo "refusing to overwrite existing evidence file: $OUT" >&2; exit 1; }

LINE_NUMBER="$(jq -r --arg id "$RULE_ID" --arg agent "$AGENT_ID" \
    'select(((.rule.id // "") | tostring) == $id and ($agent == "" or (((.agent.id // "") | tostring) == $agent))) | input_line_number' \
    "$ALERTS" | tail -n 1)"
[[ "$LINE_NUMBER" =~ ^[0-9]+$ ]] || { echo "no alert found for rule.id=$RULE_ID agent.id=${AGENT_ID:-<any>}" >&2; exit 2; }
LINE="$(sed -n "${LINE_NUMBER}p" "$ALERTS")"
[[ -n "$LINE" ]] || { echo "matched alert line $LINE_NUMBER could not be read" >&2; exit 2; }
printf '%s\n' "$LINE" > "$OUT"

SHA="$(sha256sum "$OUT" | awk '{print $1}')"
TS="$(jq -r '.timestamp // "unknown"' <<<"$LINE")"
WVER="unknown"
if [[ -x /var/ossec/bin/wazuh-control ]]; then
    WVER="$(/var/ossec/bin/wazuh-control info 2>/dev/null | awk -F'"' '/WAZUH_VERSION/ {print $2; exit}' || true)"
fi
MAN="$(dirname "$OUT")/MANIFEST.tsv"
if [[ ! -e "$MAN" ]]; then
    printf 'file\trule_id\tagent_id\talert_timestamp\texported_utc\twazuh_version\tsha256\n' > "$MAN"
fi
printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$(basename "$OUT")" "$RULE_ID" "${AGENT_ID:-any}" "$TS" "$(date -u +%FT%TZ)" "${WVER:-unknown}" "$SHA" >> "$MAN"
echo "exported $OUT (rule $RULE_ID, agent ${AGENT_ID:-any}, sha256 ${SHA:0:12}...)"
