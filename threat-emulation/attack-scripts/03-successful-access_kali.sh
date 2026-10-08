#!/usr/bin/env bash
# Stage 3 — Successful Access (T1078)
# Host: Kali Linux (attacker) -> Windows 11 victim
# Use the credentials recovered in Stage 2.
# NOTE (docs/04, Stage 3 analysis): if the account locked out during Stage 2,
# unlock it first (`net user <user> /active:yes` on the Windows host) or this
# will fail / produce another lockout event instead of a 4624 logon.
set -euo pipefail

ssh lenovo@192.168.60.1
