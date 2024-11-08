use plonky2::hash::hash_types::{HashOut, HashOutTarget, NUM_HASH_OUT_ELTS, RichField};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_data::{CircuitData, VerifierCircuitData};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig, Hasher};
use plonky2::plonk::proof::{Proof, ProofWithPublicInputs};
use plonky2_field::extension::Extendable;
use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2;
use crate::circuits::params::HF;
use anyhow::Result;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::plonk::circuit_builder::CircuitBuilder;

// --------- helper functions ---------

/// Converts an index to a vector of bits (LSB first) with padding.
pub fn usize_to_bits_le_padded(index: usize, bit_length: usize) -> Vec<bool> {
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

/// assign a vec of bool values to a vec of BoolTargets
pub fn assign_bool_targets<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
>(
    pw: &mut PartialWitness<F>,
    bool_targets: &Vec<BoolTarget>,
    bools: Vec<bool>,
){
    for (i, bit) in bools.iter().enumerate() {
        pw.set_bool_target(bool_targets[i], *bit);
    }
}

/// assign a vec of field elems to hash out target elements
pub fn assign_hash_out_targets<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
>(
    pw: &mut PartialWitness<F>,
    hash_out_elements_targets: &[Target],
    hash_out_elements: &[F],
){
    for j in 0..NUM_HASH_OUT_ELTS {
        pw.set_target(hash_out_elements_targets[j], hash_out_elements[j]);
    }
}

/// helper fn to multiply a HashOutTarget by a Target
pub fn mul_hash_out_target<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
>(builder: &mut CircuitBuilder<F, D>, t: &Target, hash_target: &mut HashOutTarget) -> HashOutTarget {
    let mut mul_elements = vec![];
    for i in 0..NUM_HASH_OUT_ELTS {
        mul_elements.push(builder.mul(hash_target.elements[i], *t));
    }
    HashOutTarget::from_vec(mul_elements)
}

/// helper fn to add AND assign a HashOutTarget (hot) to a mutable HashOutTarget (mut_hot)
pub fn add_assign_hash_out_target<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
>(builder: &mut CircuitBuilder<F, D>, mut_hot: &mut HashOutTarget, hot: &HashOutTarget) {
    for i in 0..NUM_HASH_OUT_ELTS {
        mut_hot.elements[i] = (builder.add(mut_hot.elements[i], hot.elements[i]));
    }
}