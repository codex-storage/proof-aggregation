Proof Aggregation
================================

This repository contains all work related to the Codex storage proof system which supports proof aggregation (currently only local proof aggregation).

## Quick Usage
see [`codex-storage-proofs-circuits`](./codex-plonky2-circuits) to look at the circuits.

see [`proof-input`](./proof-input) to test the circuits.

see [`workflow`](./workflow) for an overview of the whole workflow and how to use the circuits and run them.

Repository organization
-----------------

- [`plonly2_poseidon2`](./plonky2_poseidon2) is the poseidon2 hash function for Plonky2.

- [`codex-plonky2-circuits`](./codex-plonky2-circuits) contains the Plonky2 codex storage proof circuits. These circuits have the functionality as those in [**here**](https://github.com/codex-storage/codex-storage-proofs-circuits)

- [`plonky2-monolith`](./plonky2-monolith) contains the Monolith hash function for Plonky2.

- [`proof-input`](./proof-input) contains the code to generate proof input for the circuit from fake dataset + some tests for the circuits.

- [`gnark-wrapper`](./gnark-wrapper) contains a Go-based CLI for compiling, proving, and verifying Plonky2-wrapped circuits using our version of [gnark-plonky2-verifier](https://github.com/codex-storage/gnark-plonky2-verifier)

- [`workflow`](./workflow) contains the scripts and example code to generate input, run the circuits, generate a proof, and verify the proof.

Documentation
-----------------
See the write-ups on [plonky2 storage proofs](https://hackmd.io/@NQdG6IOmQE6astjwhJ6ACw/rJSsScfAR).

**WARNING**: This repository contains work-in-progress prototypes, and has not received careful code review. It is NOT ready for production use.

