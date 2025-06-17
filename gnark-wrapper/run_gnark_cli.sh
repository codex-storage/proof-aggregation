#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<EOF
Usage: $(basename "$0") [options]

Options:
  -P, --params-file FILE    Path to params.sh file (default: same directory as this script)
  -c, --circuit-dir DIR     Path to Plonky2 JSON circuit folder (default to params.sh \$CIRCUIT_DIR)
  -d, --data-dir DIR        Directory to save gnark outputs (default to params.sh \$DATA_DIR)
  -s, --proof-system SYS    Proof system: "plonk" or "groth16" (default to params.sh \$PROOF_SYSTEM)
  --dummy                   Use dummy setup (sets DUMMY to "true")
  --no-dummy                Use real setup (sets DUMMY to "false")
  --compile                 Compile the circuit
  --prove                   Generate the proof
  --verify                  Verify the proof
  -h, --help                Show this help message

If no operation flags (--compile, --prove, --verify) are provided, all steps are run.
EOF
}

# Default params file
PARAMS_FILE="$(dirname "$0")/params.sh"
# Pre-parse for custom params file, shifting out -P/--params-file
_original_args=("$@")
args=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    -P|--params-file)
      PARAMS_FILE="$2"; shift 2;;
    *)
      args+=("$1"); shift;;
  esac
done
# Restore remaining args
if (( ${#args[@]} )); then
  set -- "${args[@]}"
else
  set --
fi

# Load defaults from params.sh
if [[ -f "$PARAMS_FILE" ]]; then
  source "$PARAMS_FILE"
else
  echo "Error: params file not found at $PARAMS_FILE" >&2
  exit 1
fi

# Initialize flags
do_compile=false
do_prove=false
do_verify=false

# Parse command-line arguments for operations and options
while [[ $# -gt 0 ]]; do
  case "$1" in
    -c|--circuit-dir)
      CIRCUIT_DIR="$2"; shift 2;;
    -d|--data-dir)
      DATA_DIR="$2"; shift 2;;
    -s|--proof-system)
      PROOF_SYSTEM="$2"; shift 2;;
    --dummy)
      DUMMY="true"; shift;;
    --no-dummy)
      DUMMY="false"; shift;;
    --compile)
      do_compile=true; shift;;
    --prove)
      do_prove=true; shift;;
    --verify)
      do_verify=true; shift;;
    -h|--help)
      usage; exit 0;;
    *)
      echo "Error: Unknown option: $1" >&2; usage; exit 1;;
  esac
done

# If no operations are specified, perform all
if ! $do_compile && ! $do_prove && ! $do_verify; then
  do_compile=true
  do_prove=true
  do_verify=true
fi

# Build verifier binary
if $do_compile || $do_prove || $do_verify; then
  echo "Building verifier binary..."
  go build -o verifier .
fi

# Helper to run gnark verifier with a specific operation
run_verifier() {
  local mode_flag="$1"
  local action_name="$2"
  echo "${action_name} (${PROOF_SYSTEM})…"
  ./verifier \
    -circuit "${CIRCUIT_DIR}" \
    -data    "${DATA_DIR}" \
    -proof-system "${PROOF_SYSTEM}" \
    -dummy="${DUMMY}" \
    "${mode_flag}"
}

# Execute requested operations
if $do_compile; then
  run_verifier "-compile" "Compiling circuit"
fi

if $do_prove; then
  run_verifier "-prove" "Generating proof"
fi

if $do_verify; then
  run_verifier "-verify" "Verifying proof"
fi
