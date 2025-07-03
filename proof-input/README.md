# Input Generator for the Plonky2 Circuit

This crate generates input to the proof circuit based on the test parameters. The proof input generated can be ported into
the [`plonky2 codex proof circuits`](../codex-plonky2-circuits). Currently only generates fake data for testing.

## Code organization 

- [`merkle_tree`](./src/merkle_tree) is the implementation of "safe" merkle tree used in codex, consistent with the one [here](https://github.com/codex-storage/nim-codex/blob/master/codex/merkletree/merkletree.nim).

- [`input_generator`](./src/input_generator) contains the necessary function to generate the proof input. 

- [`params`](./src/params.rs) is the test parameters used to generate the input.

- [`hash`](./src/hash) contains the non-circuit version of hash (with and without padding) used to hash cells and during sampling.

## Tests
See [`tests`](./tests) for all tests. 
To run a specific test, use:
```bash
cargo test --features parallel --test <test_file_name>
```
Or for more specific tests, use:
```bash
cargo test --features parallel --test  <test_file_name> -- <test_name>
```

