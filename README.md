Proof Aggregation
================================

This repository contains all work related to proof aggregation (currently only local proof aggregation).

Repository organization
-----------------

- [`plonly2_poseidon2`](./plonky2_poseidon2) is the crate for plonky2 which supports the poseidon2 hash function.

- [`codex-plonky2-circuits`](./codex-plonky2-circuits) contains the codex proof circuits tailored specifically for plonky2. These circuits have the functionality as those in [**here**](https://github.com/codex-storage/codex-storage-proofs-circuits)

- [`proof-input`](./proof-input) contains the lib code to generate proof input for the circuit from fake dataset.

- [`workflow`](./workflow) contains the scripts and example code to generate input, run the circuits, generate a proof, and verify the proof.

Documentation
-----------------
See the write-ups on [plonky2 storage proofs](https://hackmd.io/@NQdG6IOmQE6astjwhJ6ACw/rJSsScfAR) and [proof recursion](https://hackmd.io/@NQdG6IOmQE6astjwhJ6ACw/rk85D2HX1e)

**WARNING**: This repository contains work-in-progress prototypes, and has not received careful code review. It is NOT ready for production use.
