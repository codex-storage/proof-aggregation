## Benchmarks

In here we show the preliminary benchmarks of codex storage proofs circuits.

## Running Benchmarks

To run the benchmarks for safe merkle tree circuit, you can use the following command:

```bash
cargo bench --bench safe_circuit
```

To run the benchmarks for sampling circuit, you can use the following command:
Note: make sure to adjust the parameters as need in ....

```bash
cargo bench --bench sample_cells
```

The following operations were benchmarked:

- **Build Circuit**: Time taken to construct the circuit for the specified params.
- **Prove Circuit**: Time taken to generate a proof for the constructed circuit.
- **Verify Circuit**: Time taken to verify the generated proof.

## Bench Results
The following is the result of running the codex storage proof circuit (sample_cells).
The bench uses the Goldilocks field and Poseidon2 Hash. All results were run on Mac Mini with M2 Pro and 16GB RAM. 

### Bench params
The benchmark runs with the default params which are the following:

```bash
export MAXDEPTH=32        # Maximum depth of the slot tree
export MAXSLOTS=256       # Maximum number of slots
export CELLSIZE=2048      # Cell size in bytes
export BLOCKSIZE=65536    # Block size in bytes
export NSAMPLES=5         # Number of samples to prove

export ENTROPY=1234567    # External randomness
export SEED=12345         # Seed for creating fake data

export NSLOTS=11          # Number of slots in the dataset
export SLOTINDEX=3        # Which slot to prove (0..NSLOTS-1)
export NCELLS=512         # Number of cells in this slot
```

### Build Time
Build time for plonky2 circuits is 39.644 ms.
Baseline Groth16 with same params: 61 seconds for the circuit specific setup.

### Prove Time
Prove time for plonky2 circuits is 53.940 ms.
Baseline Groth16 with same params: 4.56 seconds using snarkjs

improvement: approx 80x

### Verify Time
To be done once recursion is added to the codebase.

### Proof Size
Plonky Proof size: 116008 bytes
This is without recursion or Groth16 wrapper.

### Peak Memory Usage
To be done.
