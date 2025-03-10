#!/bin/bash

# Change to the parent directory of the script
cd "$(dirname "$0")/.." || { echo "Failed to change directory"; exit 1; }

echo "Running bench for the sampling circuit with multithreading..."
cargo bench --bench sample_cells --features "parallel" || { echo "Benchmark 'sample_cells' with multithreading failed"; exit 101; }

echo "Running bench for the sampling circuit with single-thread..."
cargo bench --bench sample_cells || { echo "Benchmark 'sample_cells' with single-thread failed"; exit 102; }

echo "Running bench for the tree recursion circuit with multithreading..."
cargo bench --bench uniform_recursion --features "parallel" || { echo "Benchmark 'uniform_recursion' with multithreading failed"; exit 103; }

echo "Running bench for the tree recursion circuit with single-thread..."
cargo bench --bench uniform_recursion || { echo "Benchmark 'uniform_recursion' with single-thread failed"; exit 104; }
