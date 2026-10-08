#!/usr/bin/env bash
# Stage 6 — Payload Drop (T1105), part 1/2
# Host: Kali Linux — Terminal 1
# Serves the EICAR test file for the victim to download.
set -euo pipefail

# Place a standard EICAR test file (known hash, so VirusTotal returns a verdict)
# named eicar-facebook.com in this directory before starting the server.
python3 -m http.server 8000
