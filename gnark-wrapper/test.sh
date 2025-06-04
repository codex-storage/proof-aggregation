#!/usr/bin/env bash
set -euo pipefail

# Usage: ./test.sh <circuit_dir> <data_dir> <proof_system> <dummy_setup>

CIRCUIT_DIR=${1:-"$PWD/testdata/dummy"} # path to your Plonky2 JSON folder
DATA_DIR=${2:-"$PWD/gnark_output"} # where to save gnark outputs
PROOF_SYSTEM=${3:-"groth16"} # "plonk" or "groth16"
DUMMY=${4:-"false"} # dummy or real setup

echo "Running full test: compile → prove → verify"
./compile.sh "${CIRCUIT_DIR}" "${DATA_DIR}" "${PROOF_SYSTEM}" "${DUMMY}"
./prove.sh   "${CIRCUIT_DIR}" "${DATA_DIR}" "${PROOF_SYSTEM}" "${DUMMY}"
./verify.sh  "${CIRCUIT_DIR}" "${DATA_DIR}" "${PROOF_SYSTEM}" "${DUMMY}"
