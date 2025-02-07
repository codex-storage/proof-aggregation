use plonky2::hash::hash_types::{ HashOutTarget, RichField};
use plonky2::hash::hashing::PlonkyPermutation;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::config::AlgebraicHasher;
use plonky2_field::types::HasExtension;
use crate::circuits::params::NUM_HASH_OUT_ELTS;

/// Compression function which takes two 256 bit inputs (HashOutTarget) and key Target
/// and returns a 256 bit output (HashOutTarget /  4 Targets).
pub fn key_compress_circuit<
    F: RichField + HasExtension<D>,
    const D: usize,
    H: AlgebraicHasher<F, NUM_HASH_OUT_ELTS>,
>(
    builder: &mut CircuitBuilder<F, D, NUM_HASH_OUT_ELTS>,
    x: HashOutTarget<NUM_HASH_OUT_ELTS>,
    y: HashOutTarget<NUM_HASH_OUT_ELTS>,
    key: Target,
) -> HashOutTarget<NUM_HASH_OUT_ELTS> {
    let zero = builder.zero();
    let mut state = H::AlgebraicPermutation::new(core::iter::repeat(zero));

    state.set_from_slice(&x.elements, 0);
    state.set_from_slice(&y.elements, NUM_HASH_OUT_ELTS);
    state.set_elt(key, NUM_HASH_OUT_ELTS*2);

    state = builder.permute::<H>(state);

    HashOutTarget {
        elements: state.squeeze()[..NUM_HASH_OUT_ELTS].try_into().unwrap(),
    }
}

