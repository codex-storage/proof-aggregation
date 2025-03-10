## Benchmarks

In here we show the preliminary benchmarks of codex storage proofs circuits.

## Running Benchmarks

**Runtime Benchmarks**

To run the benchmarks for sampling circuit and aggregation, you can use the following commands:

```bash
cd bench_scripts
bash ./bench_runtime
```

The following operations were benchmarked for sampling and recursion circuits (both single-thread and multi-thread):

- **Build Circuit**: Time taken to construct the circuit for the specified params.
- **Prove Circuit**: Time taken to generate a proof for the constructed circuit.
- **Verify Circuit**: Time taken to verify the generated proof.

**Memory Benchmarks**
To run the memory benchmarks for sampling circuit and aggregation, you can use the following commands:

```bash
cd bench_scripts
bash ./bench_memory
```
Note: The memory usage is quite difficult to replicate as it depends on the operating system, 
but on macOS look for the "maximum resident set size" to get the peak memory usage.

## Bench Results
See this [document](https://hackmd.io/@NQdG6IOmQE6astjwhJ6ACw/Bk-SopNj1g) for full benchmark results.
