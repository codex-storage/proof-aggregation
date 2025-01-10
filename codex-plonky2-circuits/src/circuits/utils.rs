use std::{fs, io};
use std::path::Path;
use plonky2::hash::hash_types::{HashOut, HashOutTarget, NUM_HASH_OUT_ELTS, RichField};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2_field::extension::Extendable;
use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use crate::Result;
use crate::error::CircuitError;

// --------- helper functions ---------

/// computes the `last_index` (the binary decomposition of `inp-1`) and the `mask_bits`
pub fn ceiling_log2<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
>(
    builder: &mut CircuitBuilder::<F, D>,
    inp: Target,
    n: usize,
)-> (Vec<BoolTarget>, Vec<BoolTarget>){
    let one = builder.one();
    let zero = builder.zero();
    let last_index = builder.sub(inp, one.clone());
    let last_bits = builder.split_le(last_index,n);

    let mut aux: Vec<BoolTarget> = vec![BoolTarget::new_unsafe(zero.clone()); n + 1];
    aux[n] = BoolTarget::new_unsafe(one.clone());
    let mut mask: Vec<BoolTarget> = vec![BoolTarget::new_unsafe(zero.clone()); n + 1];
    for i in (0..n).rev(){
        let diff = (builder.sub(one.clone(), last_bits[i].target));
        let aux_i = builder.mul( aux[i+1].target, diff);
        aux[i] = BoolTarget::new_unsafe(aux_i);
        mask[i] = BoolTarget::new_unsafe(builder.sub(one.clone(), aux[i].target));
    }

    (last_bits, mask)
}

/// assign a vec of bool values to a vec of BoolTargets
pub fn assign_bool_targets<
    F: RichField + Extendable<D> + Poseidon2,
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
        pw.set_bool_target(bool_targets[i], *bit)
            .map_err(|e|
                CircuitError::ArrayBoolTargetAssignmentError(i, e.to_string()),
            )?;
    }
    Ok(())
}

/// assign a vec of field elems to hash out target elements
/// TODO: change to HashOut
pub fn assign_hash_out_targets<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
>(
    pw: &mut PartialWitness<F>,
    hash_out_elements_targets: &HashOutTarget,
    hash_out_elements: &HashOut<F>,
) -> Result<()>{

    // Assign each field element to its corresponding target
    for (j, (&target, &element)) in hash_out_elements_targets.elements.iter().zip(hash_out_elements.elements.iter()).enumerate() {
        pw.set_target(target, element).map_err(|e| {
            CircuitError::ArrayTargetAssignmentError(j, e.to_string())
        })?;
    }

    Ok(())
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

/// Reads the contents of the specified file and returns them as a vector of bytes using `std::fs::read`.
pub fn read_bytes_from_file<P: AsRef<Path>>(path: P) -> io::Result<Vec<u8>> {
    fs::read(path)
}

/// select hash helper method
/// Computes `if b { h0 } else { h1 }`.
pub fn select_hash<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
    b: BoolTarget,
    h0: HashOutTarget,
    h1: HashOutTarget,
) -> HashOutTarget {
    HashOutTarget {
        elements: core::array::from_fn(|i| builder.select(b, h0.elements[i], h1.elements[i])),
    }
}