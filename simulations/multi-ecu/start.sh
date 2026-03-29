#!/bin/bash
# =============================================================================
# multi-ecu campaign simulation
#
# Launches a mixed vehicle network:
#   - SOVDd gateway (port 4000) — aggregates all ECUs
#   - vm-mgr os1 (port 4001) — VM bank set via SOVD
#   - engine_ecu (vcan1) — UDS ECU via SOVDd
#   - body_ecu (vcan1) — UDS ECU via SOVDd
#   - Security helper (port 9100) — key derivation for all ECUs
#
# Then runs campaign tests via sumo-sovd-orchestrator.
#
# Prerequisites:
#   - SOVDd built: ~/dev/SOVDd
#   - vm-mgr built: ~/dev/vm-mgr
#   - SOVD security helper installed
#
# Usage: ./start.sh
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
SOVDD_DIR="${SOVDD_DIR:-$HOME/dev/SOVDd}"
VMMGR_DIR="${VMMGR_DIR:-$HOME/dev/vm-mgr}"

CONFIG="$SCRIPT_DIR/config"
LOG_DIR="$SCRIPT_DIR/logs"
mkdir -p "$LOG_DIR"

# Ports
GATEWAY_PORT=4000
VMMGR_PORT=4001
HELPER_PORT=9100

# NV store for vm-mgr
NV_PATH="/tmp/sumo-sovd-sim-nv.bin"

# PIDs for cleanup
PIDS=()

cleanup() {
    echo "[sim] cleaning up..."
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null && wait "$pid" 2>/dev/null || true
    done
}
trap cleanup EXIT

# =============================================================================
# Build everything
# =============================================================================

echo "[sim] building SOVDd..."
(cd "$SOVDD_DIR" && cargo build --quiet)

echo "[sim] building vm-mgr..."
(cd "$VMMGR_DIR" && cargo build --quiet)

# Generate SUIT keys + firmware if not present
if [ ! -f "$VMMGR_DIR/example/keys/signing.pub" ]; then
    echo "[sim] generating SUIT keys and firmware..."
    (cd "$VMMGR_DIR" && cargo run --example build --quiet)
fi

# =============================================================================
# Setup vCAN
# =============================================================================

if ! ip link show vcan1 &>/dev/null; then
    echo "[sim] setting up vcan1..."
    sudo modprobe vcan 2>/dev/null || true
    sudo ip link add dev vcan1 type vcan
    sudo ip link set up vcan1
fi

# =============================================================================
# Start UDS ECUs on vCAN
# =============================================================================

SOVDD_BIN="$SOVDD_DIR/target/debug"

echo "[sim] starting engine_ecu on vcan1..."
"$SOVDD_BIN/example-ecu" --config "$SOVDD_DIR/simulations/basic_uds/config/ecu-engine.toml" \
    > "$LOG_DIR/engine_ecu.log" 2>&1 &
PIDS+=($!)

echo "[sim] starting body_ecu on vcan1..."
"$SOVDD_BIN/example-ecu" --config "$SOVDD_DIR/simulations/basic_uds/config/ecu-body.toml" \
    > "$LOG_DIR/body_ecu.log" 2>&1 &
PIDS+=($!)

sleep 1

# =============================================================================
# Start vm-mgr SOVD server
# =============================================================================

echo "[sim] starting vm-mgr on port $VMMGR_PORT..."
rm -f "$NV_PATH"

# Factory init
"$VMMGR_DIR/target/debug/vm-diagserver" "$NV_PATH" factory-init \
    "$VMMGR_DIR/example/factory" \
    --runner-path "$VMMGR_DIR/target/debug/vm-runner" \
    > "$LOG_DIR/vmmgr-init.log" 2>&1

"$VMMGR_DIR/target/debug/vm-sovd" "$NV_PATH" \
    "$VMMGR_DIR/example/keys/signing.pub" \
    --device-key "$VMMGR_DIR/example/keys/device.key" \
    "0.0.0.0:$VMMGR_PORT" \
    > "$LOG_DIR/vmmgr.log" 2>&1 &
PIDS+=($!)

sleep 0.5

# =============================================================================
# Start SOVDd gateway (aggregates UDS ECUs + vm-mgr proxy)
# =============================================================================

echo "[sim] starting SOVDd gateway on port $GATEWAY_PORT..."
"$SOVDD_BIN/sovdd" --config "$CONFIG/gateway.toml" \
    --did-dir "$SOVDD_DIR/simulations/basic_uds/config" \
    > "$LOG_DIR/gateway.log" 2>&1 &
PIDS+=($!)

sleep 1

# =============================================================================
# Start security helper
# =============================================================================

HELPER_BIN=""
if [ -x "$VMMGR_DIR/target/tools/bin/sovd-security-helper" ]; then
    HELPER_BIN="$VMMGR_DIR/target/tools/bin/sovd-security-helper"
elif command -v sovd-security-helper &>/dev/null; then
    HELPER_BIN="sovd-security-helper"
fi

if [ -n "$HELPER_BIN" ]; then
    echo "[sim] starting security helper on port $HELPER_PORT..."
    "$HELPER_BIN" --port "$HELPER_PORT" --config "$CONFIG/secrets.toml" --token dev-secret-123 \
        > "$LOG_DIR/helper.log" 2>&1 &
    PIDS+=($!)
fi

# =============================================================================
# Status
# =============================================================================

sleep 1

echo ""
echo "=== Multi-ECU Simulation Running ==="
echo ""
echo "Gateway:         http://localhost:$GATEWAY_PORT"
echo "  ├── os1        → vm-mgr (port $VMMGR_PORT)"
echo "  ├── engine_ecu → vcan1 UDS"
echo "  └── body_ecu   → vcan1 UDS"
echo ""
echo "Security helper: http://localhost:$HELPER_PORT (token: dev-secret-123)"
echo ""
echo "SOVD Explorer:   connect to http://localhost:$GATEWAY_PORT"
echo ""
echo "Logs: $LOG_DIR/"
echo ""
echo "Test firmware: $VMMGR_DIR/example/output/"
echo ""
echo "Press Ctrl+C to stop"

# Wait for any child to exit
wait
