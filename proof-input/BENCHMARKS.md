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

#### Build Time


#### Prove Time


#### Verify Time


#### Proof Size


#### Peak Memory Usage


### Remarks
