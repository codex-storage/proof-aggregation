use plonky2::hash::hash_types::{HashOut, HashOutTarget, RichField, NUM_HASH_OUT_ELTS};
use plonky2::hash::hashing::PlonkyPermutation;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::config::{AlgebraicHasher, Hasher};
use plonky2_field::extension::Extendable;
use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2;

/// Compression function which takes two 256 bit inputs (HashOut) and u64 key (which is converted to field element in the function)
/// and returns a 256 bit output (HashOut).
pub fn key_compress<F: RichField, H:Hasher<F> >(x: HashOut<F>, y: HashOut<F>, key: u64) -> HashOut<F> {

    debug_assert_eq!(x.elements.len(), NUM_HASH_OUT_ELTS);
    debug_assert_eq!(y.elements.len(), NUM_HASH_OUT_ELTS);

    let key_field = F::from_canonical_u64(key);

    let mut perm = H::Permutation::new(core::iter::repeat(F::ZERO));
    perm.set_from_slice(&x.elements, 0);
    perm.set_from_slice(&y.elements, NUM_HASH_OUT_ELTS);
    perm.set_elt(key_field,NUM_HASH_OUT_ELTS*2);

    perm.permute();

    HashOut {
        elements: perm.squeeze()[..NUM_HASH_OUT_ELTS].try_into().unwrap(),
    }
}

/// same as above but in-circuit
pub fn key_compress_circuit<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    H: AlgebraicHasher<F>,
>(
    builder: &mut CircuitBuilder<F, D>,
    x: Vec<Target>,
    y: Vec<Target>,
    key: Target,
) -> HashOutTarget {
    let zero = builder.zero();
    let mut state = H::AlgebraicPermutation::new(core::iter::repeat(zero));

    state.set_from_slice(&x, 0);
    state.set_from_slice(&y, NUM_HASH_OUT_ELTS);
    state.set_elt(key, NUM_HASH_OUT_ELTS*2);

    state = builder.permute::<H>(state);

    HashOutTarget {
        elements: state.squeeze()[..NUM_HASH_OUT_ELTS].try_into().unwrap(),
    }
}



