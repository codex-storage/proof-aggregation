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
/// calculate the sampled cell index from entropy, slot root, and counter
pub(crate) fn calculate_cell_index_bits<F: RichField>(entropy: &Vec<F>, slot_root: HashOut<F>, ctr: usize, depth: usize) -> Vec<bool> {
    let ctr_field = F::from_canonical_u64(ctr as u64);
    let mut ctr_as_digest = HashOut::<F>::ZERO;
    ctr_as_digest.elements[0] = ctr_field;
    let mut hash_inputs = Vec::new();
    hash_inputs.extend_from_slice(&entropy);
    hash_inputs.extend_from_slice(&slot_root.elements);
    hash_inputs.extend_from_slice(&ctr_as_digest.elements);
    let hash_output = HF::hash_no_pad(&hash_inputs);
    let cell_index_bytes = hash_output.elements[0].to_canonical_u64();

    let cell_index_bits = usize_to_bits_le_padded(cell_index_bytes as usize, depth);
    cell_index_bits
}

pub(crate) fn take_n_bits_from_bytes(bytes: &[u8], n: usize) -> Vec<bool> {
    bytes.iter()
        .flat_map(|byte| (0..8u8).map(move |i| (byte >> i) & 1 == 1))
        .take(n)
        .collect()
}

/// Converts a vector of bits (LSB first) into an index (usize).
pub(crate) fn bits_le_padded_to_usize(bits: &[bool]) -> usize {
    bits.iter().enumerate().fold(0usize, |acc, (i, &bit)| {
        if bit {
            acc | (1 << i)
        } else {
            acc
        }
    })
}

/// prove given the circuit data and partial witness
pub fn prove<
    F: RichField + Extendable<D> + Poseidon2,
    C: GenericConfig<D, F = F>,
    const D: usize,
    H: Hasher<F> + AlgebraicHasher<F>,
>(
    data: CircuitData<F, C, D>,
    pw: PartialWitness<F>
) -> Result<ProofWithPublicInputs<F, C, D>>{
    let proof = data.prove(pw);
    return proof
}

/// verify given verifier data, public input, and proof
pub fn verify<
    F: RichField + Extendable<D> + Poseidon2,
    C: GenericConfig<D, F = F>,
    const D: usize,
    H: Hasher<F> + AlgebraicHasher<F>,
>(
    verifier_data: &VerifierCircuitData<F, C, D>,
    public_inputs: Vec<F>,
    proof: Proof<F, C, D>
)-> Result<()> {
    verifier_data.verify(ProofWithPublicInputs {
        proof,
        public_inputs,
    })
}

/// assign a vec of bool values to a vec of BoolTargets
pub(crate) fn assign_bool_targets<
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
pub(crate) fn assign_hash_out_targets<
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
pub(crate) fn mul_hash_out_target<
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
pub(crate) fn add_assign_hash_out_target<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
>(builder: &mut CircuitBuilder<F, D>, mut_hot: &mut HashOutTarget, hot: &HashOutTarget) {
    for i in 0..NUM_HASH_OUT_ELTS {
        mut_hot.elements[i] = (builder.add(mut_hot.elements[i], hot.elements[i]));
    }
}