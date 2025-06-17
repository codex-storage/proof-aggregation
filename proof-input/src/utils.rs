use plonky2::hash::hash_types::{HashOut, RichField};
use plonky2_field::extension::Extendable;
use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2;
use crate::params::HF;
use crate::sponge::hash_n_with_padding;

// --------- helper functions ---------

/// Converts an index to a vector of bits (LSB first) no padding.
pub fn usize_to_bits_le(index: usize, bit_length: usize) -> Vec<bool> {
    // Assert that the index can fit within the given bit length.
    assert!(
        index < (1 << bit_length),
        "Index ({}) does not fit in {} bits",
        index,
        bit_length
    );

    let mut bits = Vec::with_capacity(bit_length);
    for i in 0..bit_length {
        bits.push(((index >> i) & 1) == 1);
    }

    // No padding
    bits
}

/// returns the first bit_length bits of index
pub fn low_bits(index: usize, bit_length: usize) -> Vec<bool> {

    let mut bits = Vec::with_capacity(bit_length);

    for i in 0..bit_length {
        // get the i-th bit and push its bool value
        bits.push(((index >> i) & 1) == 1);
    }

    bits
}

/// calculate the sampled cell index from entropy, slot root, and counter
/// this is the non-circuit version for testing
pub fn calculate_cell_index_bits<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize
>(entropy: &Vec<F>, slot_root: HashOut<F>, ctr: usize, depth: usize, mask_bits: Vec<bool>) -> Vec<bool> {
    let ctr_field = F::from_canonical_u64(ctr as u64);
    let mut ctr_as_digest = HashOut::<F>::ZERO;
    ctr_as_digest.elements[0] = ctr_field;
    let mut hash_inputs = Vec::new();
    hash_inputs.extend_from_slice(&entropy);
    hash_inputs.extend_from_slice(&slot_root.elements);
    hash_inputs.extend_from_slice(&ctr_as_digest.elements);
    let hash_output = hash_n_with_padding::<F,D,HF>(&hash_inputs);
    let cell_index_bytes = hash_output.elements[0].to_canonical_u64();

    let cell_index_bits = low_bits(cell_index_bytes as usize, depth);

    let mut masked_cell_index_bits = vec![];

    for i in 0..depth{
        masked_cell_index_bits.push(cell_index_bits[i] && mask_bits[i]);
    }

    masked_cell_index_bits
}

/// Converts a vector of bits (LSB first) into an index (usize).
pub fn bits_le_padded_to_usize(bits: &[bool]) -> usize {
    bits.iter().enumerate().fold(0usize, |acc, (i, &bit)| {
        if bit {
            acc | (1 << i)
        } else {
            acc
        }
    })
}

/// computes the `last_index` (the binary decomposition of `inp-1`) and the `mask_bits`
pub fn ceiling_log2(
    inp: usize,
    n: usize,
) -> (Vec<bool>, Vec<bool>) {
    // Handle the case when inp is 0
    let last_index = if inp == 0 { panic!("input to ceiling_log2 is 0") } else { inp - 1 };
    let last_bits = usize_to_bits_le(last_index, n);

    // Initialize aux, all false
    let mut aux = vec![false; n+1];
    aux[n] = true; // aux[n] = 1

    // Initialize mask vector
    let mut mask = vec![false; n+1];

    // Compute aux and mask bits
    for i in (0..n).rev() {
        aux[i] = aux[i + 1] && !last_bits[i];
        mask[i] = !aux[i];
    }

    (last_bits, mask)
}
