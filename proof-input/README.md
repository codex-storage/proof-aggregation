# Input Generator for the Plonky2 Circuit
WARNING: This is a work-in-progress prototype, and has not received careful code review. This implementation is NOT ready for production use.

This crate generates input to the proof circuit based on the test parameters. The proof input generated can be ported into
the [`plonky2 codex proof circuits`](../codex-plonky2-circuits). Currently only generates fake data for testing.

## Code organization 

- [`merkle_tree`](./src/merkle_tree) is the implementation of "safe" merkle tree used in codex, consistent with the one [here](https://github.com/codex-storage/nim-codex/blob/master/codex/merkletree/merkletree.nim).

- [`data_structs`](./src/data_structs.rs) contains the data structures for the codex storage, this is used to generate proof input.

- [`gen_input`](./src/gen_input.rs) contains the necessary function to generate the proof input. 

- [`recursion`](./src/recursion) contains the tests for the uniform (2-to-1 tree) recursion.

- [`serialization`](./src/serialization) contains the serialization functions to read and write circuit data, input, and proofs. 

- [`params`](./src/params.rs) is the test parameters used to generate the input.

- [`sponge`](./src/sponge.rs) contains the non-circuit version of hash function (with and without padding) used to hash cells and during sampling.

- [`utils`](./src/utils.rs) contains helper functions.

## Usage
see [`workflow`](../workflow) for how to generate proof input.

## Benchmarks
see [`BENCHMARKS.md`](../workflow/BENCHMARKS.md)
