#!/usr/bin/env bash
# current dir
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export CIRCUIT_DIR="$BASE_DIR/../output/wrap/verifier_data"
export DATA_DIR="$BASE_DIR/../output/gnark_output"
export PROOF_SYSTEM="groth16"
export DUMMY="false"
