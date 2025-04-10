Proof Aggregation
================================
**WARNING**: This repository contains work-in-progress prototypes, and has not received careful code review. It is NOT ready for production use.


This repository contains all work related to the Codex proof system which supports proof aggregation (currently only local proof aggregation).

## Quick Usage
see [`codex-storage-proofs-circuits`](../codex-storage-proofs-circuits) to look at the circuits.
see [`proof-input`](./proof-input) to test the circuits.
see [`workflow`](../workflow) for an overview of the whole workflow and how to use the circuits and run them.

Repository organization
-----------------

- [`plonly2_poseidon2`](./plonky2_poseidon2) is the crate for plonky2 which supports the poseidon2 hash function.

- [`codex-plonky2-circuits`](./codex-plonky2-circuits) contains the codex proof circuits tailored specifically for plonky2. These circuits have the functionality as those in [**here**](https://github.com/codex-storage/codex-storage-proofs-circuits)

- [`proof-input`](./proof-input) contains the lib code to generate proof input for the circuit from fake dataset.

- [`workflow`](./workflow) contains the scripts and example code to generate input, run the circuits, generate a proof, and verify the proof.

- [`goldibear_experiments`](./goldibear_experiments) contains experiments with using [Plonky2_Goldibear](https://github.com/telosnetwork/plonky2_goldibear/tree/main).

- [`recursion_experiments`](./recursion_experiments) contains experiment with multiple recursion approaches prior to settling with the uniform 2-to-1 tree aggregation.

Documentation
-----------------
See the write-ups on [plonky2 storage proofs](https://hackmd.io/@NQdG6IOmQE6astjwhJ6ACw/rJSsScfAR).

