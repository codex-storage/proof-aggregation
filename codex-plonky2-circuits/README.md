# Codex Plonky2 Circuits
WARNING: This is a work-in-progress prototype, and has not received careful code review. This implementation is NOT ready for production use.

This crate is an implementation of the [codex storage proofs circuits](https://github.com/codex-storage/codex-storage-proofs-circuits) for the plonky2 proof system.

## Code organization

- [`capped_tree`](./src/merkle_tree/capped_tree.rs) is an adapted implementation of Merkle tree based on the original plonky2 merkle tree implementation.

- [`capped_tree_circuit`](./src/circuits/capped_tree_circuit.rs) is the circuit implementation for regular merkle tree implementation (non-safe version) based on the above merkle tree implementation.

- [`merkle_safe`](./src/merkle_tree/merkle_safe.rs) is the implementation of "safe" merkle tree used in codex, consistent with the one [here](https://github.com/codex-storage/nim-codex/blob/master/codex/merkletree/merkletree.nim).

- [`safe_tree_circuit`](./src/circuits/safe_tree_circuit.rs) is the Plonky2 Circuit implementation of "safe" merkle tree above.

- [`prove_single_cell`](./src/circuits/prove_single_cell.rs) is the Plonky2 Circuit implementation for proving a single cell in slot merkle tree. 

- [`sample_cells`](./src/circuits/sample_cells.rs) is the Plonky2 Circuit implementation for sampling cells in dataset merkle tree.

- [`params`](./src/circuits/params.rs) is the parameters used in the circuits.

- [`utils`](./src/circuits/utils.rs) contains helper functions.

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
Note: make sure to adjust the parameters as need in [`params`](./src/circuits/params.rs)

```bash
cargo bench --bench prove_cells
```

To run the benchmarks for sampling circuit, you can use the following command:
Note: make sure to adjust the parameters as need in [`params`](./src/circuits/params.rs)

```bash
cargo bench --bench sample_cells
```

### Results
Benchmark results for proving 10 cells (10 samples) in a Slot Merkle tree with max depth 16 with 
the small tree (block tree) is of depth 5 so 32 cells in each block. Cell data size is 2048 bytes (256 field elements)

| Operation | Time (ms) |
|-----------|-----------|
| **Build** | 34.4 ms   |
| **Prove** | 50.3 ms   |
| **Verify**| 2.4 ms    |

Circuit size: 2<sup>10</sup> gates

Proof size: 116,008 bytes
