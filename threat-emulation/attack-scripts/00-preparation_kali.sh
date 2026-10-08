#!/usr/bin/env bash
# Stage 0 — Preparation
# Host: Kali Linux (attacker)
# Run before starting the chain.
set -euo pipefail

# Clear any leftover Hydra session so Stage 2 starts clean
rm -f hydra.restore

# Start a full packet capture for the entire chain (stop with Ctrl+C or `kill %1`)
sudo tcpdump -i eth0 -w "full_chain_$(date +%Y%m%d_%H%M).pcap" host 192.168.60.1 &

echo "[*] Capture started. Record the start time for Discover correlation:"
date -u
