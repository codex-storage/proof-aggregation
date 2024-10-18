use plonky2::hash::hash_types::{HashOut, RichField};
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::circuit_data::{CircuitData, VerifierCircuitData};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig, GenericHashOut, Hasher};
use plonky2::plonk::proof::{Proof, ProofWithPublicInputs};
use plonky2_field::extension::Extendable;
use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2;
use crate::circuits::params::{HF, MAX_DEPTH};
use anyhow::Result;

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

pub(crate) fn calculate_cell_index_bits<F: RichField>(p0: usize, p1: HashOut<F>, p2: usize) -> Vec<bool> {
    let p0_field = F::from_canonical_u64(p0 as u64);
    let p2_field = F::from_canonical_u64(p2 as u64);
    let mut inputs = Vec::new();
    inputs.extend_from_slice(&p1.elements);
    inputs.push(p0_field);
    inputs.push(p2_field);
    let p_hash = HF::hash_no_pad(&inputs);
    let p_bytes = p_hash.to_bytes();

    let p_bits = take_n_bits_from_bytes(&p_bytes, MAX_DEPTH);
    p_bits
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