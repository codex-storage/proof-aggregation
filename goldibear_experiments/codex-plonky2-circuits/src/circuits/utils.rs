use std::{fs, io};
use std::path::Path;
use itertools::Itertools;
use plonky2::hash::hash_types::{HashOut, HashOutTarget, RichField};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2_field::types::HasExtension;
use crate::Result;
use crate::error::CircuitError;
use crate::circuits::params::NUM_HASH_OUT_ELTS;

// --------- helper functions ---------

/// computes the `last_index` (the binary decomposition of `inp-1`) and the `mask_bits`
pub fn ceiling_log2<
    F: RichField + HasExtension<D>,
    const D: usize,
>(
    builder: &mut CircuitBuilder<F, D, NUM_HASH_OUT_ELTS>,
    inp: Target,
    n: usize,
) -> (Vec<BoolTarget>, Vec<BoolTarget>){
    let one = builder.one();
    let zero = builder.zero();
    let last_index = builder.sub(inp, one.clone());
    let last_bits = builder.split_le(last_index,n);

    let mut aux: Vec<BoolTarget> = vec![BoolTarget::new_unsafe(zero.clone()); n + 1];
    aux[n] = BoolTarget::new_unsafe(one.clone());
    let mut mask: Vec<BoolTarget> = vec![BoolTarget::new_unsafe(zero.clone()); n + 1];
    for i in (0..n).rev(){
        let diff = builder.sub(one.clone(), last_bits[i].target);
        let aux_i = builder.mul( aux[i+1].target, diff);
        aux[i] = BoolTarget::new_unsafe(aux_i);
        mask[i] = BoolTarget::new_unsafe(builder.sub(one.clone(), aux[i].target));
    }

    (last_bits, mask)
}

/// assign a vec of bool values to a vec of BoolTargets
pub fn assign_bool_targets<
    F: RichField + HasExtension<D>,
    const D: usize,
>(
    pw: &mut PartialWitness<F>,
    bool_targets: &Vec<BoolTarget>,
    bools: Vec<bool>,
) -> Result<()>{
    if bools.len() > bool_targets.len() {
        return Err(CircuitError::AssignmentLengthMismatch (
                bool_targets.len(),
                bools.len(),
            )
        );
    }
    for (i, bit) in bools.iter().enumerate() {
        pw.set_bool_target(bool_targets[i], *bit);
    }
    Ok(())
}

/// assign a vec of field elems to hash out target elements
/// TODO: change to HashOut
pub fn assign_hash_out_targets<
    F: RichField + HasExtension<D>,
    const D: usize,
>(
    pw: &mut PartialWitness<F>,
    hash_out_elements_targets: &HashOutTarget<NUM_HASH_OUT_ELTS>,
    hash_out_elements: &HashOut<F, NUM_HASH_OUT_ELTS>,
) -> Result<()>{

    // Assign each field element to its corresponding target
    for (j, (&target, &element)) in hash_out_elements_targets.elements.iter().zip(hash_out_elements.elements.iter()).enumerate() {
        pw.set_target(target, element)
    }

    Ok(())
}

/// helper fn to multiply a HashOutTarget by a Target
pub fn mul_hash_out_target<
    F: RichField + HasExtension<D>,
    const D: usize,
>(builder: &mut CircuitBuilder<F, D, NUM_HASH_OUT_ELTS>, t: &Target, hash_target: &mut HashOutTarget<NUM_HASH_OUT_ELTS>) -> HashOutTarget<NUM_HASH_OUT_ELTS> {
    let mut mul_elements = vec![];
    for i in 0..NUM_HASH_OUT_ELTS {
        mul_elements.push(builder.mul(hash_target.elements[i], *t));
    }
    HashOutTarget::from_vec(mul_elements)
}

/// helper fn to add AND assign a HashOutTarget (hot) to a mutable HashOutTarget (mut_hot)
pub fn add_assign_hash_out_target<
    F: RichField + HasExtension<D>,
    const D: usize,
>(builder: &mut CircuitBuilder<F, D, NUM_HASH_OUT_ELTS>, mut_hot: &mut HashOutTarget<NUM_HASH_OUT_ELTS>, hot: &HashOutTarget<NUM_HASH_OUT_ELTS>) {
    for i in 0..NUM_HASH_OUT_ELTS {
        mut_hot.elements[i] = builder.add(mut_hot.elements[i], hot.elements[i]);
    }
}

/// Reads the contents of the specified file and returns them as a vector of bytes using `std::fs::read`.
pub fn read_bytes_from_file<P: AsRef<Path>>(path: P) -> io::Result<Vec<u8>> {
    fs::read(path)
}

/// select hash helper method
/// Computes `if b { h0 } else { h1 }`.
pub fn select_hash<
    F: RichField + HasExtension<D>,
    const D: usize,
>(
    builder: &mut CircuitBuilder<F, D, NUM_HASH_OUT_ELTS>,
    b: BoolTarget,
    h0: HashOutTarget<NUM_HASH_OUT_ELTS>,
    h1: HashOutTarget<NUM_HASH_OUT_ELTS>,
) -> HashOutTarget<NUM_HASH_OUT_ELTS> {
    HashOutTarget {
        elements: core::array::from_fn(|i| builder.select(b, h0.elements[i], h1.elements[i])),
    }
}

/// Converts a Vec<T> into a fixed-size array [T; N], returning an error if the lengths don't match.
pub fn vec_to_array<const N: usize, T>(vec: Vec<T>) -> Result<[T; N]> {
    vec.try_into().map_err(|v: Vec<T>| CircuitError::ArrayLengthMismatchError(format!(
        "Expected exactly {} elements, got {}",
        N,
        v.len()
    )))
}

/// Computes `if b { v0 } else { v1 }`.
pub fn select_vec<
    F: RichField + HasExtension<D>,
    const D: usize,
>(builder: &mut CircuitBuilder<F, D, NUM_HASH_OUT_ELTS>, b: BoolTarget, v0: &[Target], v1: &[Target]) -> Vec<Target> {
    v0.iter()
        .zip_eq(v1)
        .map(|(t0, t1)| builder.select(b, *t0, *t1))
        .collect()
}
