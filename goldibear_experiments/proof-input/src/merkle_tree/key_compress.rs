use plonky2::hash::hash_types::{HashOut, RichField};
use plonky2::hash::hashing::PlonkyPermutation;
use plonky2::plonk::config::Hasher;
use codex_plonky2_circuits::circuits::params::NUM_HASH_OUT_ELTS;
use plonky2_field::types::HasExtension;

/// Compression function which takes two 256 bit inputs (HashOut) and u64 key (which is converted to field element in the function)
/// and returns a 256 bit output (HashOut /  4 Goldilocks field elems).
pub fn key_compress<
    F: RichField + HasExtension<D>,
    const D: usize,
    H:Hasher<F>
>(x: HashOut<F, NUM_HASH_OUT_ELTS>, y: HashOut<F, NUM_HASH_OUT_ELTS>, key: u64) -> HashOut<F, NUM_HASH_OUT_ELTS> {

    let key_field = F::from_canonical_u64(key);

    let mut perm = H::Permutation::new(core::iter::repeat(F::zero()));
    perm.set_from_slice(&x.elements, 0);
    perm.set_from_slice(&y.elements, NUM_HASH_OUT_ELTS);
    perm.set_elt(key_field,NUM_HASH_OUT_ELTS*2);

    perm.permute();

    HashOut {
        elements: perm.squeeze()[..NUM_HASH_OUT_ELTS].try_into().unwrap(),
    }
}