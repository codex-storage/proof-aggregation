#!/bin/bash

# Source the parameters from params.sh
source ./circ_params.sh

# Build
cargo build --release || { echo "prove.sh: cargo build failed"; exit 101; }

# Run the Rust executable
cargo run --bin prove || { echo "prove.sh: cargo run failed"; exit 102; }
