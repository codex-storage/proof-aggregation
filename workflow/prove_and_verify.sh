#!/bin/bash

# Source the parameters from params.sh
source ./circ_params.sh

# Build
cargo build --release || { echo "prove_and_verify.sh: cargo build failed"; exit 101; }

# Run the Rust executable
cargo run --bin prove_and_verify || { echo "prove_and_verify.sh: cargo run failed"; exit 102; }
