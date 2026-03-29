#!/bin/bash
# Reset the multi-ECU simulation to fresh state.
# Kills all processes and removes NV store.
set -euo pipefail

fuser -k 4000/tcp 4001/tcp 9100/tcp 2>/dev/null || true
pkill -9 -f "example-ecu|sovdd|vm-sovd|sovd-security-helper" 2>/dev/null || true
sleep 2
rm -f /tmp/sumo-sovd-sim-nv.bin
echo "[reset] simulation stopped, NV cleared"
