#!/usr/bin/env bash
# Stage 11 — Exfiltration (T1059.001, T1567.002), part 1/2
# Host: Kali Linux — simple HTTP listener to receive the POST upload
set -euo pipefail

python3 -m http.server 8000
# Note: the stock http.server module does not save POST bodies to disk.
# For a receiving endpoint that actually writes the uploaded file, swap in
# a small Flask/http.server subclass, or use `nc -lvnp 8000` and inspect
# the raw HTTP request manually.
