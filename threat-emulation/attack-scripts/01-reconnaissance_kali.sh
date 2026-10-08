#!/usr/bin/env bash
# Stage 1 — Reconnaissance (T1595, T1018)
# Host: Kali Linux (attacker) -> Windows 11 victim
set -euo pipefail

TARGET="192.168.60.1"

nmap -sS -T4 -p- "$TARGET"
ping -c 5 "$TARGET"
