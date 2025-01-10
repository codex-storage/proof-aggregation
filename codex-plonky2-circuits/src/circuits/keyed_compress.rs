use plonky2::hash::hash_types::{ HashOutTarget, RichField, NUM_HASH_OUT_ELTS};
use plonky2::hash::hashing::PlonkyPermutation;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::config::AlgebraicHasher;
use plonky2_field::extension::Extendable;
use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2;

/// Compression function which takes two 256 bit inputs (HashOutTarget) and key Target
/// and returns a 256 bit output (HashOutTarget /  4 Targets).
pub fn key_compress_circuit<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    H: AlgebraicHasher<F>,
>(
    builder: &mut CircuitBuilder<F, D>,
    x: HashOutTarget,
    y: HashOutTarget,
    key: Target,
) -> HashOutTarget {
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

