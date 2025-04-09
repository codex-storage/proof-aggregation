#!/bin/bash

# Source the parameters from the scripts directory
source "params.sh"

# Change to the parent directory of the script
cd "$(dirname "$0")/.." || { echo "Failed to change directory"; exit 1; }

# Build
cargo build --release || { echo "build_circuit.sh: cargo build failed"; exit 101; }

# Run the Rust executable
cargo run --bin build_circ --features "parallel" || { echo "build_circuit.sh: cargo run failed"; exit 102; }

