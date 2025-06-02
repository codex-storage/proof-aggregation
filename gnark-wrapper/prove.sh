#!/usr/bin/env bash
set -euo pipefail

# Usage: ./prove.sh <circuit_dir> <data_dir> [proof_system]
CIRCUIT_DIR=${1:-"$PWD/testdata/dummy"}
DATA_DIR=${2:-"$PWD/gnark_output"}
PROOF_SYSTEM=${3:-"groth16"}
DUMMY=${4:-"false"}

echo "Generating proof ($PROOF_SYSTEM)…"
./verifier \
  -circuit "${CIRCUIT_DIR}" \
  -data    "${DATA_DIR}" \
  -proof-system "${PROOF_SYSTEM}" \
  -dummy="${DUMMY}" \
  -prove
