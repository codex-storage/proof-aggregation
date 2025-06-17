# Workflow of the Storage Proof Circuits
WARNING: This is a work-in-progress prototype, and has not received careful code review. This implementation is NOT ready for production use.

This crate guides you through generating the circuit input, 
building the circuit, 
running the circuits to generate a proof, aggregating multiple proofs, and finally verify the proof.

This crate can be used to:

- Generate circuit input from **fake data** with given params.
- Build the Plonky2 codex storage proof circuits. 
- Generate a proof with given proof input in JSON file.
- Aggregate multiple proofs with 2-to-1 tree like aggregation to generate a final proof (with optional compression).
- Wrapping proof with BN254 Poseidon Hash.
- Verify the proof.
- Wrap the proof with Gnark-plonky2-verifier to get a final succinct Groth16 proof.

## Usage

### Prerequisites

- **Rust Toolchain**: Ensure you have Rust installed. If not, install it from [rustup.rs](https://rustup.rs/).

- **Rust nightly**:: This crate requires the Rust nightly compiler. To install the nightly toolchain, use `rustup`:

```bash
rustup install nightly
```

To ensure that the nightly toolchain is used when building this crate, you can set the override in the project directory:

```bash
rustup override set nightly
```

- Go 1.22+ (for the GNARK-based verifier)

### Generate Circuit Input
The steps to generate circuit input with **fake data** are the following:

#### Step 1: Setting Up Parameters
- Input params: parameters for generating the circuit input can be defined in [`params.sh`](scripts/params.sh).
You can customize the test parameters by setting the following environment variables:

```bash
export MAXDEPTH=32        # Maximum depth of the slot tree
export MAXSLOTS=256       # Maximum number of slots
export CELLSIZE=2048      # Cell size in bytes
export BLOCKSIZE=65536    # Block size in bytes
export NSAMPLES=100         # Number of samples to prove

export ENTROPY=1234567    # External randomness
export SEED=12345         # Seed for creating fake data

export NSLOTS=11          # Number of slots in the dataset
export SLOTINDEX=3        # Which slot to prove (0..NSLOTS-1)
export NCELLS=512         # Number of cells in this slot
```
- Circuit parameters: Edit [`circ_params.sh`](./scripts/circ_params.sh) for:

```bash
export MAX_DEPTH=32                # maximum depth of the slot tree
export MAX_LOG2_N_SLOTS=8          # Depth of the dataset tree = ceiling_log2(max_slots)
export BLOCK_TREE_DEPTH=5          # depth of the mini tree (block tree)
export N_FIELD_ELEMS_PER_CELL=272  # number of field elements per cell
export N_SAMPLES=100               # number of samples to prove

export T=4 # number of proofs to aggregate
```
- GNARK-verifier params [`gnark_params.sh`](./scripts/gnark_params.sh): 
```bash
export CIRCUIT_DIR="$BASE_DIR/../output/wrap/verifier_data"
export DATA_DIR="$BASE_DIR/../output/gnark_output"
export PROOF_SYSTEM="groth16"
export DUMMY="false"
```

#### Step 2: Run the Rust CLI
All steps are unified under [`run_cli.sh`](./scripts/run_cli.sh) By default, it will run nothing until you specify the operations.
```bash
# Show help and list all available flags
./scripts/run_cli.sh -h

# Generate inputs, build, prove, aggregate, wrap & verify—all in one:
./scripts/run_cli.sh --all

# Or pick individual operations:
./scripts/run_cli.sh \
  --gen-input \
  --build \
  --prove \
  --aggregate \
  --wrap-tree \
  --verify-tree
```

#### Step 3: Go/GNARK CLI workflow
To compile, prove, or verify wrapped Plonky2 circuits via GNARK, use:
```bash
./scripts/run_gnark_cli.sh -h

# run all steps (compile, prove, verify) with defaults:
./scripts/run_gnark_cli.sh

# or individually:
./scripts/run_gnark_cli.sh --compile
./scripts/run_gnark_cli.sh --prove
./scripts/run_gnark_cli.sh --verify
```
