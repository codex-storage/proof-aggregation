# Poseidon2 Plonky2
WARNING: This is a work-in-progress prototype, and has not received careful code review. This implementation is NOT ready for production use.

This crate is an implementation of the Poseidon2 Hash that can be employed in the [Plonky2 proving system](https://github.com/0xPolygonZero/plonky2). Poseidon2 hash function is a new zk-friendly hash function, and provides good performance.
The hash and gate implementations are based on the plonky2 Poseidon [hash](https://github.com/0xPolygonZero/plonky2/blob/main/plonky2/src/hash/poseidon.rs) and [gate](https://github.com/0xPolygonZero/plonky2/blob/main/plonky2/src/gates/poseidon.rs). 

The Poseidon2 Hash implementation is consistent with that in here: https://github.com/HorizenLabs/poseidon2

## Code Organization
This crate include:

- [**Poseidon2 Gate**](./src/gate/poseidon2.rs)
- [**Poseidon2 Hash**](./src/poseidon2_hash/poseidon2.rs)
- [**Poseidon2 Config**](./src/config/mod.rs)
- [**Benchmarks**](./benches/poseidon2_perm.rs)

This crate can be used to:

- Generate Plonky2 proofs employing the Poseidon2 hash function
- Write Plonky2 circuits computing Poseidon2 hashes

## Building

This crate requires the Rust nightly compiler due to the use of certain unstable features. To install the nightly toolchain, use `rustup`:

```bash
rustup install nightly
```

To ensure that the nightly toolchain is used when building this crate, you can set the override in the project directory:

```bash
rustup override set nightly
```

Alternatively, you can specify the nightly toolchain when building:

```bash
cargo +nightly build
```

## Usage

The Poseidon2 hash can be used directly to compute hash values over an array of field elements. Below is a simplified example demonstrating how to use the Poseidon2 hash function:

```rust
use crate::poseidon2_hash::poseidon2::{Poseidon2, SPONGE_WIDTH};
use plonky2_field::goldilocks_field::GoldilocksField as F;
use plonky2_field::types::Field;

fn main() {
    // Create an input array of field elements for hashing
    let mut input = [F::ZERO; SPONGE_WIDTH];
    // [0,1,2,3,4,5,6,7,8,9,10,11]
    for i in 0..SPONGE_WIDTH {
        input[i] = F::from_canonical_u64(i as u64);
    }
    // Compute the Poseidon2 hash
    let output = F::poseidon2(input);
    // Print the input values
    for i in 0..SPONGE_WIDTH {
        println!("input {} = {}", i, input[i]);
    }
    // Print the output values
    for i in 0..SPONGE_WIDTH {
        println!("out {} = {}", i, output[i]);
    }
}
```

## Benchmark Results

Benchmark results are shown in [BENCHMARKS.md](./BENCHMARKS.md)