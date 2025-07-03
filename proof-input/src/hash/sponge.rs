use plonky2::hash::hash_types::{HashOut, NUM_HASH_OUT_ELTS, RichField};
use plonky2_field::extension::Extendable;
use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2;
use plonky2::plonk::config::Hasher;
use plonky2::hash::hashing::PlonkyPermutation;

/// sponge function similar to the in-circuit one
/// used here for testing / sanity check
pub fn hash_n_with_padding<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    H: Hasher<F>
>(
    inputs: &[F],
) -> HashOut<F>{
    HashOut::<F>::from_vec(hash_n_to_m_with_padding::<F,D,H::Permutation>(inputs, NUM_HASH_OUT_ELTS))
}

pub fn hash_n_to_m_with_padding<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    P: PlonkyPermutation<F>
>(
    inputs: &[F],
    num_outputs: usize,
) -> Vec<F> {
    let rate = P::RATE;
    let width = P::WIDTH; // rate + capacity
    let zero = F::ZERO;
    let one = F::ONE;
    let mut perm = P::new(core::iter::repeat(zero).take(width));

    // Set the domain separator at index 8
    let domsep_value = F::from_canonical_u64(rate as u64 + 256 * 12 + 65536 * 63);
    perm.set_elt(domsep_value, 8);

    let input_n = inputs.len();
    let num_chunks = (input_n + rate) / rate; // Calculate number of chunks with 10* padding
    let mut input_iter = inputs.iter();

    // Process all chunks except the last one
    for _ in 0..(num_chunks - 1) {
        let mut chunk = Vec::with_capacity(rate);
        for _ in 0..rate {
            if let Some(&input) = input_iter.next() {
                chunk.push(input);
            } else {
                // should not happen here
                panic!("Insufficient input elements for chunk; expected more elements.");
            }
        }
        // Add the chunk to the state
        for j in 0..rate {
            perm.set_elt(perm.as_ref()[j] + chunk[j],j);
        }
        // Apply permutation
        perm.permute();
    }

    // Process the last chunk with 10* padding
    let rem = num_chunks * rate - input_n; // Number of padding elements (0 < rem <= rate)
    let ofs = rate - rem;            // Offset where padding starts

    let mut last_chunk = Vec::with_capacity(rate);
    // Absorb remaining inputs
    for _ in 0..ofs {
        if let Some(&input) = input_iter.next() {
            last_chunk.push(input);
        } else {
            last_chunk.push(zero);
        }
    }
    // Add the '1' padding bit
    last_chunk.push(one);
    // Pad with zeros to reach the full rate
    while last_chunk.len() < rate {
        last_chunk.push(zero);
    }

    // Add the last chunk to the state
    for j in 0..rate {
        perm.set_elt(perm.as_ref()[j] + last_chunk[j],j);
    }
    // Apply permutation
    perm.permute();

    // Squeeze outputs until we have the desired number
    let mut outputs = Vec::with_capacity(num_outputs);
    loop {
        for &item in perm.squeeze() {
            outputs.push(item);
            if outputs.len() == num_outputs {
                return outputs;
            }
        }
        perm.permute();
    }
}

/// sponge function for hashing without padding
/// expects the input to be divisible by rate
/// note: rate is fixed at 8 for now
/// used here for input generation and testing / sanity check
pub fn hash_n_no_padding<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    H: Hasher<F>
>(
    inputs: &[F],
) -> HashOut<F>{
    HashOut::<F>::from_vec(hash_n_to_m_no_padding::<F, D, H::Permutation>(inputs, NUM_HASH_OUT_ELTS))
}

pub fn hash_n_to_m_no_padding<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    P: PlonkyPermutation<F>
>(
    inputs: &[F],
    num_outputs: usize,
) -> Vec<F> {
    let rate = P::RATE;
    let width = P::WIDTH; // rate + capacity
    let zero = F::ZERO;
    let mut perm = P::new(core::iter::repeat(zero).take(width));

    // Set the domain separator at index 8
    let domsep_value = F::from_canonical_u64(rate as u64 + 256 * 12 + 65536 * 8);
    perm.set_elt(domsep_value, 8);

    let n = inputs.len();
    assert_eq!(n % rate, 0, "Input length ({}) must be divisible by rate ({})", n, rate);
    let num_chunks = n / rate; // Calculate number of chunks
    let mut input_iter = inputs.iter();

    // Process all chunks
    for _ in 0..num_chunks {
        let mut chunk = Vec::with_capacity(rate);
        for _ in 0..rate {
            if let Some(&input) = input_iter.next() {
                chunk.push(input);
            } else {
                // should not happen here
                panic!("Insufficient input elements for chunk; expected more elements.");
            }
        }
        // Add the chunk to the state
        for j in 0..rate {
            perm.set_elt(perm.as_ref()[j] + chunk[j],j);
        }
        // Apply permutation
        perm.permute();
    }

    // Squeeze outputs until we have the desired number
    let mut outputs = Vec::with_capacity(num_outputs);
    loop {
        for &item in perm.squeeze() {
            outputs.push(item);
            if outputs.len() == num_outputs {
                return outputs;
            }
        }
        perm.permute();
    }
}

/// sponge function for bytes
/// note: rate is fixed at 8 for now
/// used here for testing / sanity check
pub fn hash_bytes<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    H: Hasher<F>
>(
    inputs: &[u8],
) -> HashOut<F>{
    HashOut::<F>::from_vec(hash_bytes_with_padding::<F,D,H::Permutation>(inputs, NUM_HASH_OUT_ELTS))
}

pub fn hash_bytes_with_padding<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    P: PlonkyPermutation<F>
>(
    inputs: &[u8],
    num_outputs: usize,
) -> Vec<F> {
    let rate = P::RATE;
    let width = P::WIDTH; // rate + capacity
    let zero = F::ZERO;
    let mut perm = P::new(core::iter::repeat(zero).take(width));

    // Set the domain separator at index 8
    let domsep_value = F::from_canonical_u64(rate as u64 + 256 * 12 + 65536 * 63);
    perm.set_elt(domsep_value, 8);

    let byte_rate = 62;
    let input_n = inputs.len();
    let num_chunks = (input_n + byte_rate) / byte_rate; // Calculate number of chunks with 10* padding
    let mut input_iter = inputs.iter();

    // Process all chunks except the last one
    for _ in 0..(num_chunks - 1) {
        let mut chunk = Vec::with_capacity(byte_rate);
        for _ in 0..byte_rate {
            if let Some(&input) = input_iter.next() {
                chunk.push(input);
            } else {
                panic!("Insufficient input elements for chunk; expected more elements.");
            }
        }
        let chunk_felts = convert_bytes_to_field_rate8(&chunk);
        // Add the chunk to the state
        for j in 0..rate {
            perm.set_elt(perm.as_ref()[j] + chunk_felts[j],j);
        }
        // Apply permutation
        perm.permute();
    }

    // Process the last chunk with 10* padding
    let rem = num_chunks * byte_rate - input_n; // Number of padding elements (0 < rem <= rate)
    let ofs = byte_rate - rem;            // Offset where padding starts

    let mut last_chunk = Vec::with_capacity(byte_rate);
    // Absorb remaining inputs
    for _ in 0..ofs {
        if let Some(&input) = input_iter.next() {
            last_chunk.push(input);
        } else {
            panic!("Insufficient input elements for last chunk; expected more elements!");
        }
    }
    // Add the '1' padding bit
    last_chunk.push(1u8);
    // Pad with zeros to reach the full rate
    while last_chunk.len() < byte_rate {
        last_chunk.push(0u8);
    }

    let last_chunk_felts = convert_bytes_to_field_rate8(&last_chunk);

    // Add the last chunk to the state
    for j in 0..rate {
        perm.set_elt(perm.as_ref()[j] + last_chunk_felts[j],j);
    }
    // Apply permutation
    perm.permute();

    // Squeeze outputs until we have the desired number
    let mut outputs = Vec::with_capacity(num_outputs);
    loop {
        for &item in perm.squeeze() {
            outputs.push(item);
            if outputs.len() == num_outputs {
                return outputs;
            }
        }
        perm.permute();
    }
}

/// Convert 31 little-endian bytes into 4 field element limbs (62 bits each).
fn convert_31_bytes_to_4_felts(ptr: &[u8]) -> [u64; 4] {
    assert!(ptr.len() >= 31, "Need at least 31 bytes, got {}", ptr.len());
    // Read 8-byte chunks as little-endian
    let q0  = u64::from_le_bytes(ptr[0..8].try_into().unwrap());
    let q7  = u64::from_le_bytes(ptr[7..15].try_into().unwrap());
    let q15 = u64::from_le_bytes(ptr[15..23].try_into().unwrap());
    let q23 = u64::from_le_bytes(ptr[23..31].try_into().unwrap());
    const MASK: u64 = 0x3fffffffffffffff;
    let mut felts = [0u64; 4];
    felts[0] = q0 & MASK;
    felts[1] = (q7 >> 6) | ((ptr[15] as u64 & 0x0f) << 58);
    felts[2] = (q15 >> 4) | ((ptr[23] as u64 & 0x03) << 60);
    felts[3] = q23 >> 2;
    felts
}

/// Convert 62 bytes (rate 8) into 8 field element limbs by two 31-byte conversions.
pub fn convert_bytes_to_field_rate8<F: RichField + Extendable<D> + Poseidon2, const D: usize>(ptr: &[u8]) -> [F; 8] {
    assert!(ptr.len() >= 62, "Need at least 62 bytes for rate 8, got {}", ptr.len());
    let mut felts = [F::ZERO; 8];
    let a = convert_31_bytes_to_4_felts(&ptr[0..31]);
    let a_felts = a.map(|x| F::from_canonical_u64(x));
    let b = convert_31_bytes_to_4_felts(&ptr[31..62]);
    let b_felts = b.map(|x| F::from_canonical_u64(x));
    felts[0..4].copy_from_slice(&a_felts);
    felts[4..8].copy_from_slice(&b_felts);
    felts
}