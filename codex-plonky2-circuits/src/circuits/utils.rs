


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