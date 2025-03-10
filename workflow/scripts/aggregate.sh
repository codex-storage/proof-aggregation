#!/bin/bash

# Source the parameters from the scripts directory
source "params.sh"

# Change to the parent directory of the script
cd "$(dirname "$0")/.." || { echo "Failed to change directory"; exit 1; }

# Build
cargo build --release || { echo "prove.sh: cargo build failed"; exit 101; }

# Run the Rust executable
K_VALUE=${1:-4}
cargo run --bin aggregate --features "parallel" -- "$K_VALUE" || { echo "prove.sh: cargo run failed"; exit 102; }
