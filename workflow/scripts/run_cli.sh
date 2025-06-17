#!/usr/bin/env bash
set -euo pipefail

# Load global and circuit-specific parameters
source "$(dirname "$0")/params.sh"
source "$(dirname "$0")/circ_params.sh"

usage() {
  cat <<EOF
Usage: $(basename "$0") [OPTIONS]

OPTIONS:
  --gen-input             Generate witness inputs
  --build                 Compile/build the circuit
  --prove                 Run the prover
  --aggregate             Aggregate proofs
  --aggregate-and-compress  Aggregate proofs and compress
  --wrap-sampling         Wrap sampling proof
  --wrap-tree             Wrap tree proof
  --wrap-compress         Wrap compressed-tree proof
  --verify-sampling       Verify sampling proof
  --verify-tree           Verify tree proof
  --verify-compressed     Verify compressed-tree proof
  --verify-wrapped        Verify wrapped proof
  --all                   Run the full pipeline in order
  -h, --help              Show this help and exit
EOF
  exit 1
}

# operation flags
DO_GEN=false DO_BUILD=false DO_PROVE=false DO_AGG=false DO_AGG_COMP=false
DO_WRAP_SAMP=false DO_WRAP_TREE=false DO_WRAP_COMP=false
DO_VER_SAMP=false DO_VER_TREE=false DO_VER_COMP=false DO_VER_WRAP=false

# parse args
while [[ $# -gt 0 ]]; do
  case $1 in
    --gen-input)             DO_GEN=true; shift ;;
    --build)                 DO_BUILD=true; shift ;;
    --prove)                 DO_PROVE=true; shift ;;
    --aggregate)             DO_AGG=true; shift ;;
    --aggregate-and-compress) DO_AGG_COMP=true; shift ;;
    --wrap-sampling)         DO_WRAP_SAMP=true; shift ;;
    --wrap-tree)             DO_WRAP_TREE=true; shift ;;
    --wrap-compress)         DO_WRAP_COMP=true; shift ;;
    --verify-sampling)       DO_VER_SAMP=true; shift ;;
    --verify-tree)           DO_VER_TREE=true; shift ;;
    --verify-compressed)     DO_VER_COMP=true; shift ;;
    --verify-wrapped)        DO_VER_WRAP=true; shift ;;
    --all)
      DO_GEN=true; DO_BUILD=true; DO_PROVE=true
      DO_AGG=true;
      DO_WRAP_TREE=true;
      DO_VER_SAMP=true; DO_VER_TREE=true; DO_VER_WRAP=true
      shift
      ;;
    -h|--help)               usage ;;
    *)                       echo "Unknown option: $1"; usage ;;
  esac
done

# If nothing selected, show help
if ! $DO_GEN && ! $DO_BUILD && ! $DO_PROVE && ! $DO_AGG && ! $DO_AGG_COMP \
   && ! $DO_WRAP_SAMP && ! $DO_WRAP_TREE && ! $DO_WRAP_COMP \
   && ! $DO_VER_SAMP && ! $DO_VER_TREE && ! $DO_VER_COMP && ! $DO_VER_WRAP; then
  echo "No stages selected."
  usage
fi

# Ensure the Rust binary is built
echo "[build] Compiling Rust CLI…"
cargo build --release --features parallel

# run a named subcommand
run_cmd() {
  local name=$1
  local cmd=$2
  echo "[$name] Starting"
  echo "[run] $name"
  cargo run -q --release --features parallel -- $cmd #> /dev/null
  echo "[$name] Completed"
}

$DO_GEN        && run_cmd "GenInput"           gen-input
$DO_BUILD      && run_cmd "Build"              build
$DO_PROVE      && run_cmd "Prove"              prove
$DO_AGG        && run_cmd "Aggregate"          aggregate
$DO_AGG_COMP   && run_cmd "AggregateAndCompress" aggregate-and-compress
$DO_WRAP_SAMP  && run_cmd "WrapSampling"       wrap
$DO_WRAP_TREE  && run_cmd "WrapTree"           wrap-tree
$DO_WRAP_COMP  && run_cmd "WrapCompress"       wrap-compress
$DO_VER_SAMP   && run_cmd "VerifySampling"     verify
$DO_VER_TREE   && run_cmd "VerifyTree"         verify-tree
$DO_VER_COMP   && run_cmd "VerifyCompressed"   verify-compressed
$DO_VER_WRAP   && run_cmd "VerifyWrapped"      verify-wrapped

echo "All requested steps done."
