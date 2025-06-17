use plonky2::hash::hash_types::{HashOutTarget, NUM_HASH_OUT_ELTS, RichField};
use plonky2::hash::hashing::PlonkyPermutation;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::config::AlgebraicHasher;
use plonky2_field::extension::Extendable;
use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2;
use crate::error::CircuitError;
use crate::Result;

/// hash n targets (field elements) into hash digest / HashOutTarget (4 Goldilocks field elements)
/// this function uses the 10* padding
pub fn hash_n_with_padding<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    H: AlgebraicHasher<F>
>(
    builder: &mut CircuitBuilder<F, D>,
    inputs: Vec<Target>,
) -> Result<HashOutTarget> {
    Ok(
        HashOutTarget::from_vec(
            hash_n_to_m_with_padding::<F,D,H>(builder, inputs, NUM_HASH_OUT_ELTS)?
        )
    )
}

pub fn hash_n_to_m_with_padding<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    H: AlgebraicHasher<F>
>(
    builder: &mut CircuitBuilder<F, D>,
    inputs: Vec<Target>,
    num_outputs: usize,
) -> Result<Vec<Target>> {
    let rate = H::AlgebraicPermutation::RATE;
    let width = H::AlgebraicPermutation::WIDTH; // rate + capacity
    let zero = builder.zero();
    let one = builder.one();
    let mut state = H::AlgebraicPermutation::new(core::iter::repeat(zero).take(width));

    // Set the domain separator at index 8
    let dom_sep_value = rate as u64 + 256 * 12 + 65536 * 63;
    let dom_sep = builder.constant(F::from_canonical_u64(dom_sep_value));
    state.set_elt(dom_sep, 8);

    let n = inputs.len();
    let num_chunks = (n + rate) / rate; // 10* padding
    let mut input_iter = inputs.iter();

    // Process the first (num_chunks - 1) chunks
    for _ in 0..(num_chunks - 1) {
        let mut chunk = Vec::with_capacity(rate);
        for _ in 0..rate {
            if let Some(&input) = input_iter.next() {
                chunk.push(input);
            } else {
                // should not happen here
                return Err(CircuitError::InsufficientInputs(rate,chunk.len()));
            }
        }
        // Add the chunk to the state
        for j in 0..rate {
            state.set_elt(builder.add(state.as_ref()[j], chunk[j]), j);
        }
        // Apply permutation
        state = builder.permute::<H>(state);
    }

    // Process the last chunk with 10* padding
    let rem = num_chunks * rate - n; // 0 < rem <= rate
    let ofs = rate - rem; // Offset where padding starts

    let mut last_chunk = Vec::with_capacity(rate);
    for _ in 0..ofs {
        if let Some(&input) = input_iter.next() {
            last_chunk.push(input);
        } else {
            last_chunk.push(zero); // Pad zeros if no more inputs
        }
    }

    // Add the '1' padding bit
    last_chunk.push(one);

    // Pad zeros to reach the full rate
    while last_chunk.len() < rate {
        last_chunk.push(zero);
    }

    // Add the last chunk to the state
    for j in 0..rate {
        state.set_elt(builder.add(state.as_ref()[j], last_chunk[j]), j);
    }
    // Apply permutation
    state = builder.permute::<H>(state);

    // Squeeze until we have the desired number of outputs
    let mut outputs = Vec::with_capacity(num_outputs);
    loop {
        for &s in state.squeeze() {
            outputs.push(s);
            if outputs.len() == num_outputs {
                return Ok(outputs);
            }
        }
        state = builder.permute::<H>(state);
    }
}

/// hash n targets (field elements) into hash digest / HashOutTarget (4 Goldilocks field elements)
/// this function uses doesn't pad and expects input to be divisible by rate
/// rate is fixed at 8 for now.
pub fn hash_n_no_padding<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    H: AlgebraicHasher<F>
>(
    builder: &mut CircuitBuilder<F, D>,
    inputs: Vec<Target>,
) -> Result<HashOutTarget> {
    Ok(
        HashOutTarget::from_vec(
            hash_n_to_m_no_padding::<F, D, H>(builder, inputs, NUM_HASH_OUT_ELTS)?
        )
    )
}

pub fn hash_n_to_m_no_padding<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    H: AlgebraicHasher<F>
>(
    builder: &mut CircuitBuilder<F, D>,
    inputs: Vec<Target>,
    num_outputs: usize,
) -> Result<Vec<Target>> {
    let rate = H::AlgebraicPermutation::RATE;
    let width = H::AlgebraicPermutation::WIDTH; // rate + capacity
    let zero = builder.zero();
    let mut state = H::AlgebraicPermutation::new(core::iter::repeat(zero).take(width));

    // Set the domain separator at index 8
    let dom_sep_value = rate as u64 + 256 * 12 + 65536 * 8;
    let dom_sep = builder.constant(F::from_canonical_u64(dom_sep_value));
    state.set_elt(dom_sep, 8);

    let n = inputs.len();
    if n % rate != 0 {
        return Err(CircuitError::SpongeInputLengthMismatch(n, rate));
    }
    let num_chunks = n / rate; // 10* padding
    let mut input_iter = inputs.iter();

    // Process all chunks
    for _ in 0..num_chunks {
        let mut chunk = Vec::with_capacity(rate);
        for _ in 0..rate {
            if let Some(&input) = input_iter.next() {
                chunk.push(input);
            } else {
                // should not happen here
                return Err(CircuitError::InsufficientInputs(rate,chunk.len()));
            }
        }
        // Add the chunk to the state
        for j in 0..rate {
            state.set_elt(builder.add(state.as_ref()[j], chunk[j]), j);
        }
        // Apply permutation
        state = builder.permute::<H>(state);
    }
    // Squeeze until we have the desired number of outputs
    let mut outputs = Vec::with_capacity(num_outputs);
    loop {
        for &s in state.squeeze() {
            outputs.push(s);
            if outputs.len() == num_outputs {
                return Ok(outputs);
            }
        }
        state = builder.permute::<H>(state);
    }
}