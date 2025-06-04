#!/usr/bin/env bash
set -euo pipefail

# Usage: ./compile.sh <circuit_dir> <data_dir> <proof_system> <dummy_setup>
CIRCUIT_DIR=${1:-"$PWD/testdata/dummy"}      # path to your Plonky2 JSON folder
DATA_DIR=${2:-"$PWD/gnark_output"}            # where to save gnark outputs
PROOF_SYSTEM=${3:-"groth16"}       # "plonk" or "groth16"
DUMMY=${4:-"false"}                 # dummy or real setup

echo "Building verifier binary..."
go build -o verifier .

echo "Compiling circuit ($PROOF_SYSTEM)…"
./verifier \
  -circuit "${CIRCUIT_DIR}" \
  -data    "${DATA_DIR}" \
  -proof-system "${PROOF_SYSTEM}" \
  -dummy="${DUMMY}" \
  -compile
