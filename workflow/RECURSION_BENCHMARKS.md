## Benchmarks

In here we show the benchmarks results when using Plonky2 recursion for the codex storage proofs.

## Running Benchmarks

To run the benchmarks, you can use the following command with `x` replaced with the benchmark name (for the list of all benchmarks, see [benches](./benches)):

```bash
cargo bench --bench x
```

## Benchmark Results:
We implemented and experimented with various recursion approaches:
- Simple Recursion
- Simple Tree Recursion
- Cyclic Recursion
- Tree Recursion (Approach1)
- Tree Recursion (Approach2)
- Hybrid Recursion (Simple + Tree)

For more details on each of these approaches see this [writeup](https://hackmd.io/@NQdG6IOmQE6astjwhJ6ACw/rk85D2HX1e)

Here we show the benchmark results of running Hybrid recursion approaches and compare it to simple recursion.
Based on our experimentation, the hybrid approach gives the best results, compared to others.
The Params for the hybrid approach must be adjusted based on the number of proofs to be aggregated to give optimal results.

There are various parameters to consider before benchmarking. 
First the circuit and test parameters we used are the following:

```bash
export MAXDEPTH=32        # Maximum depth of the slot tree
export MAXSLOTS=256       # Maximum number of slots
export CELLSIZE=2048      # Cell size in bytes
export BLOCKSIZE=65536    # Block size in bytes
export NSAMPLES=100         # Number of samples to prove

export ENTROPY=1234567    # External randomness
export SEED=12345         # Seed for creating fake data

export NSLOTS=11          # Number of slots in the dataset
export SLOTINDEX=3        # Which slot to prove (0..NSLOTS-1)
export NCELLS=512         # Number of cells in this slot
```

As can be seen above we set the number of samples (`NSAMPLES=100`) which should be sufficient. 

Additionally, we vary the number of proofs to be aggregated (`P = {4,8,16,32,64,128}`).
There are also the `N` and `M` parameters for the tree-structure recursion.
These params mean different things for each approach (refer to [writeup](https://hackmd.io/@NQdG6IOmQE6astjwhJ6ACw/rk85D2HX1e))
In the Hybrid approach, these values are 
- `M`: Number of proof aggregated in the leaf 
- `N`: Number of proofs aggregated in the nodes of the tree

**Build Circuit**

| **P**   | ** Recursion Build time (s)** |
|---------|-------------------------------|
| **4**   | 0.967                         | 
| **8**   | 1.613                         |
| **16**  | 2.977                         |
| **32**  | 5.847                         | 
| **64**  | 12.533                        | 
| **128** | 26.930                        | 


**Prove Circuit**

| **P** | **Simple Recursion (s)** | **Hybrid Recursion (s)** |
|-------|--------------------------|--------------------------|
| **4** | 0.769                    | 0.612                    |
| **8** | 1.549                    | 1.227                    |
| **16** | 3.212                    | 2.691                    |
| **32** | 6.574                    | 6.225                    |
| **64** | 15.107                   | 14.654                   |
| **128** | 34.617                   | 29.189                   |

