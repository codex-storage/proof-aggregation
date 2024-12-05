#!/bin/bash

# Source the parameters from params.sh
source ./params.sh

# Build
cargo build --release || { echo "gen_input.sh: cargo build failed"; exit 101; }

# Run the Rust executable
cargo run --bin gen_input || { echo "gen_input.sh: cargo run failed"; exit 102; }
