#!/bin/bash

# Source the parameters from params.sh
source ./circ_params.sh

# Build
cargo build --release

# Run the Rust executable
cargo run --bin prove_and_verify
