#!/usr/bin/env bash
# Stage 11 — Netcat receiver for Windows Invoke-WebRequest POST
# Host: Kali Linux — isolated lab network only

set -euo pipefail

LISTEN_PORT=4445

OUTPUT_FILE="stage11-http-request.bin"

nc -lvnp "$LISTEN_PORT" > "$OUTPUT_FILE"
