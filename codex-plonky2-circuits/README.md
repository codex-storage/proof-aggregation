# Codex Plonky2 Circuits
WARNING: This is a work-in-progress prototype, and has not received careful code review. This implementation is NOT ready for production use.

This crate is an implementation of the [codex storage proofs circuits](https://github.com/codex-storage/codex-storage-proofs-circuits) for the plonky2 proof system.

## Code organization

- [`merkle_circuit`](./src/circuits/merkle_circuit) is the Plonky2 Circuit implementation of "safe" merkle tree.

- [`sample_cells`](./src/circuits/sample_cells.rs) is the Plonky2 Circuit implementation for sampling cells in dataset merkle tree.

- [`keyed_compress`](./src/circuits/keyed_compress.rs) is the compression function used in the construction (and reconstruction) of the Merkle tree root. The function takes 2 hash digest (4 Goldilocks field elements each) and a key, then outputs a single hash digest. 

- [`sponge`](./src/circuits/sponge.rs) contains the hash function (with and without padding) used to hash cells and during sampling. 

- [`params`](./src/circuits/params.rs) is the parameters used in the circuits.

- [`utils`](./src/circuits/utils.rs) contains helper functions.

- [`circuit_helper`](./src/circuit_helper) contains a general trait for all Plonky2 circuit to automate the building and proving.

- [`error`](./src/error.rs) contains the list of error related to the circuits.

- [`uniform recursion`](./src/recursion/uniform) contains the uniform (2-to-1 tree) recursion circuits for aggregating proofs.


## Usage
see [`workflow`](../workflow) for how to use the circuits and run them. 

## Benchmarks
see [`BENCHMARKS.md`](../workflow/BENCHMARKS.md)
