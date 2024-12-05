#!/bin/bash

# Source the parameters from params.sh
source ./params.sh

# Build
cargo build --release || { echo "build_circuit.sh: cargo build failed"; exit 101; }

# Run the Rust executable
cargo run --bin build_circ  || { echo "build_circuit.sh: cargo run failed"; exit 102; }
