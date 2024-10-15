# Codex Plonky2 Circuits
WARNING: This is a work-in-progress prototype, and has not received careful code review. This implementation is NOT ready for production use.

This crate is an implementation of the [codex storage proofs circuits](https://github.com/codex-storage/codex-storage-proofs-circuits) for the plonky2 proof system.

## Code organization

- [`capped_tree`](./src/merkle_tree/capped_tree.rs) is an adapted implementation of Merkle tree based on the original plonky2 merkle tree implementation.

- [`capped_tree_circuit`](./src/circuits/capped_tree_circuit.rs) is the circuit implementation for regular merkle tree implementation (non-safe version) based on the above merkle tree implementation.

- [`merkle_safe`](./src/merkle_tree/merkle_safe.rs) is the implementation of "safe" merkle tree used in codex, consistent with the one [here](https://github.com/codex-storage/nim-codex/blob/master/codex/merkletree/merkletree.nim).

- [`safe_tree_circuit`](./src/circuits/safe_tree_circuit.rs) is the Plonky2 Circuit implementation of "safe" merkle tree above.

- [`prove_single_cell`](./src/circuits/prove_single_cell.rs) is the Plonky2 Circuit implementation for proving a single cell in slot merkle tree. 

## Usage
TODO!

## Benchmarks
In here we show the preliminary benchmarks of codex storage proofs circuits. 

### Running benchmarks
To run the benchmarks for safe merkle tree circuit, you can use the following command:

```bash
cargo bench --bench safe_circuit
```
To run the benchmarks for proving cells circuit, you can use the following command:
Note: make sure to asjust the parameters as need in [`prove_single_cell`](./src/circuits/prove_single_cell.rs)

```bash
cargo bench --bench prove_cells
```

### Results
Benchmark results for safe Merkle Tree depth 16 with and 5 samples

| Operation | Time (ms)        |
|-----------|------------------|
| **Build** | 19.353 ms        |
| **Prove** | 29.699 ms        |
| **Verify**| 2.0137 ms        |

Circuit size: 2<sup>9</sup> gates
Proof size: 103,372 bytes

Benchmark results for proving 5 cells in a Merkle tree with max depth 16 with and 5 samples
Note: the small tree (block tree) is of depth 5 so 32 cells in each block

| Operation | Time (ms)        |
|-----------|------------------|
| **Build** | 17.835 ms        |
| **Prove** | 28.743 ms        |
| **Verify**| 1.9792 ms        |

Circuit size: 2<sup>9</sup> gates
Proof size: 103,372 bytes
