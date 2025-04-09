#!/bin/bash

# Source the parameters
source ./params.sh
source ./circ_params.sh

# Change to the parent directory of the script
cd "$(dirname "$0")/.." || { echo "Failed to change directory"; exit 1; }

# Build
cargo build --release > /dev/null 2>&1 || { echo "prove_and_verify.sh: cargo build failed"; exit 101; }

# Run all steps
echo "START"

echo "Generating Input"
start=$(date +%s)
cargo run --bin gen_input --features "parallel" > /dev/null 2>&1 || { echo "gen_input.sh: cargo run failed"; exit 102; }
end=$(date +%s)
echo "Generating Input took $((end - start)) seconds."

echo "Building the circuit"
start=$(date +%s)
cargo run --bin build_circ --features "parallel" > /dev/null 2>&1 || { echo "build_circuit.sh: cargo run failed"; exit 102; }
end=$(date +%s)
echo "Building the circuit took $((end - start)) seconds."

echo "Generating a proof"
start=$(date +%s)
cargo run --bin prove --features "parallel" > /dev/null 2>&1 || { echo "prove.sh: cargo run failed"; exit 102; }
end=$(date +%s)
echo "Generating a proof took $((end - start)) seconds."

echo "Verifying the proof"
start=$(date +%s)
cargo run --bin verify --features "parallel" > /dev/null 2>&1 || { echo "verify.sh: cargo run failed"; exit 102; }
end=$(date +%s)
echo "Verifying the proof took $((end - start)) seconds."

echo "DONE"


