#!/bin/bash

# Source the parameters from params.sh
source ./params.sh

# Change to the parent directory of the script
cd "$(dirname "$0")/.." || { echo "Failed to change directory"; exit 1; }

# Build
cargo build --release || { echo "gen_input.sh: cargo build failed"; exit 101; }

# Run the Rust executable
cargo run --bin gen_input --features "parallel" || { echo "gen_input.sh: cargo run failed"; exit 102; }
