#!/usr/bin/env bash
set -euo pipefail

# script to invoke run_gnark_cli.sh

# path to this directory
WRAPPER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Path to run_gnark_cli.sh
SCRIPT="$WRAPPER_DIR/../../gnark-wrapper/run_gnark_cli.sh"

if [[ ! -x "$SCRIPT" ]]; then
  echo "Error: Cannot find or execute run_gnark_cli.sh at $SCRIPT" >&2
  exit 1
fi

# params file in current working directory
PARAMS_FILE="$(pwd)/gnark_params.sh"
if [[ ! -f "$PARAMS_FILE" ]]; then
  echo "Error: params.sh not found in current directory ($PARAMS_FILE)" >&2
  exit 1
fi

# Save CWD and switch into gnark-wrapper directory
TARGET_DIR="$(dirname "$SCRIPT")"
cd "$TARGET_DIR"

# Build and run the command
cmd=("$SCRIPT" -P "$PARAMS_FILE" "$@")
echo "Running in $TARGET_DIR: ${cmd[*]}"
exec "${cmd[@]}"
