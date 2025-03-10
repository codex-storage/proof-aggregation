#!/bin/bash

# Source parameters
source "params.sh"

# Move to the project root
cd "$(dirname "$0")/.." || { echo "Failed to change directory"; exit 1; }

# Build silently
cargo build --release > /dev/null 2>&1 || { echo "cargo build failed"; exit 101; }

# 1) sampling circuit - build
echo "Running sampling circuit - build..."
/usr/bin/time -l bash -c 'cargo run --bin build_circ --features "parallel" >/dev/null 2>/dev/null'

# 2) sampling circuit - prove
echo "Running sampling circuit - prove..."
cargo run --bin gen_input >/dev/null 2>/dev/null || { echo "gen_input.sh: cargo run failed"; exit 102; }
/usr/bin/time -l bash -c 'cargo run --bin prove --features "parallel" >/dev/null 2>/dev/null'

# 3) sampling circuit - aggregate
K_VALUE=${1:-128}
echo "Running sampling circuit - aggregate (${K_VALUE} proofs)..."
/usr/bin/time -l bash -c "cargo run --bin aggregate --features 'parallel' -- '${K_VALUE}' >/dev/null 2>/dev/null"

