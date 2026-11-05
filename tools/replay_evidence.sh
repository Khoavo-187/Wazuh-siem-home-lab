#!/usr/bin/env bash
# replay_evidence.sh <evidence.json> <log_format> [location] [expected_rule_id]
# Single-event check only. This does NOT replay multi-event correlations/frequency chains.
# Supply log_format explicitly: syslog, json, eventchannel, etc. Do not infer it from location.
# Env: WAZUH_API (default https://localhost:55000), WAZUH_USER, WAZUH_PASS, optional WAZUH_API_CA
set -euo pipefail

FILE="${1:?usage: $0 <evidence.json> <log_format> [location] [expected_rule_id]}"
FORMAT="${2:?log_format is required (for example: json, syslog, eventchannel)}"
API="${WAZUH_API:-https://localhost:55000}"
API="${API%/}"
USER_="${WAZUH_USER:?set WAZUH_USER}"
PASS_="${WAZUH_PASS:?set WAZUH_PASS}"
# The default -k is for the local self-signed Wazuh API certificate. Set WAZUH_API_CA to verify TLS.
CURL_TLS=(-k)
if [[ -z "${WAZUH_API_CA:-}" && "$API" != https://localhost* && "$API" != https://127.0.0.1* ]]; then
    echo "For a non-local API, set WAZUH_API_CA to verify the server certificate" >&2
    exit 1
fi
if [[ -n "${WAZUH_API_CA:-}" ]]; then
    [[ -r "$WAZUH_API_CA" ]] || { echo "cannot read WAZUH_API_CA: $WAZUH_API_CA" >&2; exit 1; }
    CURL_TLS=(--cacert "$WAZUH_API_CA")
fi

command -v jq >/dev/null 2>&1 || { echo "jq is required" >&2; exit 1; }
command -v curl >/dev/null 2>&1 || { echo "curl is required" >&2; exit 1; }
[[ -r "$FILE" ]] || { echo "cannot read evidence file: $FILE" >&2; exit 1; }
jq -e . "$FILE" >/dev/null || { echo "invalid JSON: $FILE" >&2; exit 1; }

EVENT="$(jq -r '((._source // .).full_log // empty)' "$FILE")"
LOCATION="${3:-$(jq -r '((._source // .).location // empty)' "$FILE")}"
EXPECTED="${4:-$(jq -r '((._source // .).rule.id // "") | tostring' "$FILE")}"
EXPECTED="${EXPECTED//[[:space:]]/}"
[[ -n "$EVENT" ]] || { echo "evidence has no full_log field; cannot replay it" >&2; exit 2; }
[[ -n "$LOCATION" ]] || { echo "location is missing; pass it as argument 3" >&2; exit 2; }
[[ -n "$EXPECTED" ]] || { echo "expected rule ID is missing; pass it as argument 4" >&2; exit 2; }

TOKEN="$(curl -sS "${CURL_TLS[@]}" -u "$USER_:$PASS_" -X POST "$API/security/user/authenticate?raw=true")"
[[ -n "$TOKEN" ]] || { echo "Wazuh API authentication returned an empty token" >&2; exit 3; }

BODY="$(jq -n --arg e "$EVENT" --arg f "$FORMAT" --arg l "$LOCATION" \
    '{event:$e, log_format:$f, location:$l}')"
RESP="$(curl -sS "${CURL_TLS[@]}" -X PUT "$API/logtest?pretty=true" \
    -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' -d "$BODY")"
jq -e '.error == 0' >/dev/null <<<"$RESP" || { echo "Logtest API returned an error:" >&2; jq . <<<"$RESP" >&2; exit 3; }
GOT="$(jq -r '.data.output.rule.id // "none" | tostring' <<<"$RESP")"

if [[ "$GOT" == "$EXPECTED" ]]; then
    echo "PASS $(basename "$FILE"): rule $GOT"
else
    echo "FAIL $(basename "$FILE"): expected $EXPECTED, got $GOT" >&2
    exit 1
fi
