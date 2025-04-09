#!/bin/bash

# Source the parameters from params.sh
source ./circ_params.sh

# Change to the parent directory of the script
cd "$(dirname "$0")/.." || { echo "Failed to change directory"; exit 1; }

# Build
cargo build --release || { echo "prove.sh: cargo build failed"; exit 101; }

# Run the Rust executable
cargo run --bin prove --features "parallel" || { echo "prove.sh: cargo run failed"; exit 102; }
