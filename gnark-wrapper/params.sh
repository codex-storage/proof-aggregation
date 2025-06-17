#!/bin/bash

export CIRCUIT_DIR="$PWD/testdata/dummy"     # path to Plonky2 JSON files
export DATA_DIR="$PWD/gnark_output"          # where to save gnark outputs
export PROOF_SYSTEM="groth16"                # "plonk" or "groth16"
export DUMMY="false"                         # dummy or real setup