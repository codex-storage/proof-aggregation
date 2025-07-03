# Codex Plonky2 Circuits

This crate is an implementation of the [codex storage proofs circuits](https://github.com/codex-storage/codex-storage-proofs-circuits) for the plonky2 proof system.

## Code organization

- [`circuit_trait`](./src/circuit_trait) contains a general trait for all Plonky2 circuit to automate the building and proving.

- [`circuits`](./src/circuits/) is the Plonky2 Circuit implementation for sampling cells in dataset merkle tree.

- [`recursion`](./src/recursion/) contains the (2-to-1 tree) recursion circuits for aggregating proofs.

- [`bn254_wrapper`](./src/bn254_wrapper/) contains the poseidon hash implementation for bn254 curve. 

- [`serialization`](./src/serialization.rs) contains functions for serializing and deserializing the circuit data and proofs.

- [`error`](./src/error.rs) contains the list of error related to the circuits.



