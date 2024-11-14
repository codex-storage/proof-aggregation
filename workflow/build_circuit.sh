#!/bin/bash

# Source the parameters from params.sh
source ./params.sh

# Build
cargo build --release

# Run the Rust executable
cargo run --bin build_circ
