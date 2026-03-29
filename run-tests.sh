#!/bin/bash
# Run the full campaign integration test suite.
# Manages simulation lifecycle automatically.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "[test] resetting simulation..."
bash "$SCRIPT_DIR/simulations/multi-ecu/reset.sh"

echo "[test] building..."
cargo build --manifest-path "$SCRIPT_DIR/Cargo.toml" --quiet

echo "[test] running campaign tests..."
RUST_LOG=warn cargo run --manifest-path "$SCRIPT_DIR/Cargo.toml" --example campaign_test

echo "[test] cleaning up..."
bash "$SCRIPT_DIR/simulations/multi-ecu/reset.sh"
