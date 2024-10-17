use plonky2::hash::hash_types::{HashOut, RichField};
use plonky2::plonk::config::{GenericHashOut, Hasher};
use crate::circuits::params::{HF, MAX_DEPTH};

// --------- helper functions ---------

/// Converts an index to a vector of bits (LSB first) with padding.
pub(crate) fn usize_to_bits_le_padded(index: usize, bit_length: usize) -> Vec<bool> {
    let mut bits = Vec::with_capacity(bit_length);
    for i in 0..bit_length {
        bits.push(((index >> i) & 1) == 1);
    }
    // If index requires fewer bits, pad with `false`
    while bits.len() < bit_length {
        bits.push(false);
    }
    bits
}

pub(crate) fn calculate_cell_index_bits<F: RichField>(p0: usize, p1: HashOut<F>, p2: usize) -> Vec<bool> {
    let p0_field = F::from_canonical_u64(p0 as u64);
    let p2_field = F::from_canonical_u64(p2 as u64);
    let mut inputs = Vec::new();
    inputs.extend_from_slice(&p1.elements);
    inputs.push(p0_field);
    inputs.push(p2_field);
    let p_hash = HF::hash_no_pad(&inputs);
    let p_bytes = p_hash.to_bytes();

    let p_bits = take_n_bits_from_bytes(&p_bytes, MAX_DEPTH);
    p_bits
}
pub(crate) fn take_n_bits_from_bytes(bytes: &[u8], n: usize) -> Vec<bool> {
    bytes.iter()
        .flat_map(|byte| (0..8u8).map(move |i| (byte >> i) & 1 == 1))
        .take(n)
        .collect()
}
/// Converts a vector of bits (LSB first) into an index (usize).
pub(crate) fn bits_le_padded_to_usize(bits: &[bool]) -> usize {
    bits.iter().enumerate().fold(0usize, |acc, (i, &bit)| {
        if bit {
            acc | (1 << i)
        } else {
            acc
        }
    })
}