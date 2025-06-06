# Workflow of the Storage Proof Circuits
WARNING: This is a work-in-progress prototype, and has not received careful code review. This implementation is NOT ready for production use.

This crate guides you through generating the circuit input, 
building the circuit, 
running the circuits to generate a proof, aggregating multiple proofs, and finally verify the proof.

This crate can be used to:

- Generate circuit input from **fake data** with given params.
- Build the Plonky2 codex storage proof circuits. 
- Generate a proof with given proof input in JSON file.
- Aggregate multiple proofs with 2-to-1 tree like aggregation to generate a final proof.
- Verify the proof.

## Code organization

- [`gen_input`](./src/bin/gen_input.rs) contains the main function to generate input with the given params as environment variables. 

- [`build_circ`](./src/bin/build_circ.rs) contains the main function to build the storage proof (Sampling) circuits.

- [`prove`](./src/bin/prove.rs) contains the main function to generate a single proof.

- [`aggregate`](./src/bin/aggregate.rs) contains the main function to aggregate `k` (default = 4) proofs.

- [`verify`](./src/bin/verify) contains the main function to verify the storage proof (Sampling) proof.

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

### Generate Circuit Input
The steps to generate circuit input with **fake data** are the following:

#### Step 1: Setting Up Parameters
Parameters for generating the circuit input can be defined in [`params.sh`](scripts/params.sh).
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

#### Step 2: Run the Script
Once the params are set, you can run the script to generate the circuit input (with fake data).

```bash
sudo bash ./scripts/gen_input.sh
```

### Build the Circuit
To build the circuit and measure the time to build, you can simply run the script:
```bash
sudo bash ./scripts/build_circuit.sh
```
To see the source code of how to build the circuit, see [`build_circ`](./src/bin/build_circ.rs).

### Generate the Proof
After generating the circuit input (in a JSON file), you can run the circuits to generate the proofs.
First make sure you have the circuit data and input from previous scripts then follow the steps:

#### Step 1: Setting Up Circuit Parameters
Parameters for the circuit can be defined in [`circ_params.sh`](scripts/circ_params.sh).
You can customize the test parameters by setting the following environment variables:
```bash
export MAX_DEPTH=32        # maximum depth of the slot tree
export MAX_LOG2_N_SLOTS=8 # Depth of the dataset tree = ceiling_log2(max_slots)
export BLOCK_TREE_DEPTH=5 # depth of the mini tree (block tree)
export N_FIELD_ELEMS_PER_CELL=272 # number of field elements per cell
export N_SAMPLES=100 # number of samples to prove
```

#### Step 2: Run the Script
Once the params are set, you can run the script to generate the proof.
You can also see the time taken to generate the proof. 

```bash
sudo bash ./scripts/prove.sh
```

### Verify the proof
To verify the generated proof, run the following script. 
Make sure that you generate the circuit data and proof prior to this.

```bash
sudo bash ./scripts/verify.sh
```

### Build, Prove, and Verify
To automate the whole process, you can run the following script 
the script builds the circuit, loads the JSON circuit input, generates the proof, and verifies it. 
It also shows the time taken for each step. 
Make sure that you generate the circuit input prior to this so that you have the [`JSON input file`](./input.json) and set the [`circ_params.sh`](scripts/circ_params.sh).

```bash
sudo bash ./scripts/prove_and_verify.sh
```
This script simply runs all previous scripts. 

### Aggregate K Proofs
To do this, you can run the following script. 
Note that we don't actually generate `K` proofs but rather just clone the single generated proof which is enough for testing. 
Make sure a proof is already generated using the script for proving above. 

```bash
sudo bash ./scripts/aggregate.sh
```


or the following if you want to specify the number of proofs to be aggregated
```bash
sudo bash ./scripts/aggregate.sh -- "$K_VALUE"
```


