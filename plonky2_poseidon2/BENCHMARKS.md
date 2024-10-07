## Benchmark Results

Benchmarks comparing the performance of Poseidon and Poseidon2 hash functions within the Plonky2 proving system. The benchmarks measure the time taken to build the circuit, generate the proof, and verify the proof for different numbers of permutations (from 2<sup>10</sup> to 2<sup>13</sup> permutations).

## Running Benchmarks

To run the benchmarks provided in this crate, you can use the following command:

```bash
cargo bench --bench poseidon2_perm
```

The following operations were benchmarked:

- **Build Circuit**: Time taken to construct the circuit for the specified number of permutations.
- **Prove Circuit**: Time taken to generate a proof for the constructed circuit.
- **Verify Circuit**: Time taken to verify the generated proof.

#### Build Time

| Number of Permutations | Poseidon Build Time (ms) | Poseidon2 Build Time (ms) |
|------------------------|------------------|------------------|
| 2<sup>10</sup> (1024)  | 52.5             | 59.2             |
| 2<sup>11</sup> (2048)  | 114.5            | 120.5            |
| 2<sup>12</sup> (4096)  | 250.4            | 253.6            |
| 2<sup>13</sup> (8192)  | 524.3            | 525.2            |

#### Prove Time

| Number of Permutations | Poseidon Prove Time (ms) | Poseidon2 Prove Time (ms) |
|------------------------|------------------|-------------------|
| 2<sup>10</sup> (1024)  | 90.5             | 96.4              |
| 2<sup>11</sup> (2048)  | 184.3            | 193.9             |
| 2<sup>12</sup> (4096)  | 334.6            | 355.9             |
| 2<sup>13</sup> (8192)  | 733.4            | 713.0             |

#### Verify Time

| Number of Permutations | Poseidon Verify Time (ms) | Poseidon2 Verify Time (ms) |
|------------------------|-------------------|--------------------|
| 2<sup>10</sup> (1024)  | 2.7               | 2.8                |
| 2<sup>11</sup> (2048)  | 2.9               | 3.0                |
| 2<sup>12</sup> (4096)  | 3.0               | 3.2                |
| 2<sup>13</sup> (8192)  | 3.4               | 3.7                |

#### Circuit Size

| Number of Permutations | Circuit Size (Gates)         |
|------------------------|------------------------------|
| 2<sup>10</sup> (1024)  | 2<sup>11</sup> (2048) gates  |
| 2<sup>11</sup> (2048)  | 2<sup>12</sup> (4096) gates  |
| 2<sup>12</sup> (4096)  | 2<sup>13</sup> (8192) gates  |
| 2<sup>13</sup> (8192)  | 2<sup>14</sup> (16384) gates |

#### Proof Size

| Number of Permutations | Proof Size (bytes) |
|------------------------|--------------------|
| 2<sup>10</sup> (1024)  | 121,608            |
| 2<sup>11</sup> (2048)  | 127,112            |
| 2<sup>12</sup> (4096)  | 132,744            |
| 2<sup>13</sup> (8192)  | 146,276            |

#### Peak Memory Usage
The peak memory usage for both poseidon and poseidon2 is similar and shown in the table:
Memory usage varies between runs, the following values represent the average of 5 runs.

| Number of Permutations | Build Memory Usage | Build & Prove Memory Usage |
|------------------------|--------------------|----------------------------|
| 2^10                   | 355.70 MB          | 441.61 MB                  |
| 2^11                   | 336.00 MB          | 445.07 MB                  |
| 2^12                   | 342.52 MB          | 459.70 MB                  |
| 2^13                   | 499.73 MB          | 714.11 MB                  |


### Remarks

- **Build Circuit Time**: Poseidon2 shows a bit higher build times compared to Poseidon, especially at smaller circuit sizes.
- **Prove Circuit Time**: Both hash functions have similar prove times - Poseidon2 sometimes a little faster at larger sizes.
- **Verify Circuit Time**: Verification times are slightly higher for Poseidon2, but the difference is not much.

Overall, this is just preliminary results and can/should be optimized further.
