use plonky2::hash::hash_types::{HashOut, RichField};
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::circuit_data::{CircuitData, VerifierCircuitData};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig, Hasher};
use plonky2::plonk::proof::{Proof, ProofWithPublicInputs};
use plonky2_field::extension::Extendable;
use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2;
use codex_plonky2_circuits::circuits::params::HF;
use anyhow::Result;
use plonky2::hash::hashing::PlonkyPermutation;
use crate::sponge::hash_n_with_padding;

// --------- helper functions ---------

/// Converts an index to a vector of bits (LSB first) no padding.
pub(crate) fn usize_to_bits_le(index: usize, bit_length: usize) -> Vec<bool> {
    // Assert that the index can fit within the given bit length.
    assert!(
        index < (1 << bit_length),
        "Index ({}) does not fit in {} bits",
        index,
        bit_length
    );

    let mut bits = Vec::with_capacity(bit_length);
    for i in 0..bit_length {
        bits.push(((index >> i) & 1) == 1);
    }

    // No padding
    bits
}

/// returns the first bit_length bits of index
pub(crate) fn low_bits(index: usize, bit_length: usize) -> Vec<bool> {

    let mut bits = Vec::with_capacity(bit_length);

    for i in 0..bit_length {
        // get the i-th bit and push its bool value
        bits.push(((index >> i) & 1) == 1);
    }

    bits
}

/// calculate the sampled cell index from entropy, slot root, and counter
/// this is the non-circuit version for testing
pub(crate) fn calculate_cell_index_bits<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize
>(entropy: &Vec<F>, slot_root: HashOut<F>, ctr: usize, depth: usize, mask_bits: Vec<bool>) -> Vec<bool> {
    let ctr_field = F::from_canonical_u64(ctr as u64);
    let mut ctr_as_digest = HashOut::<F>::ZERO;
    ctr_as_digest.elements[0] = ctr_field;
    let mut hash_inputs = Vec::new();
    hash_inputs.extend_from_slice(&entropy);
    hash_inputs.extend_from_slice(&slot_root.elements);
    hash_inputs.extend_from_slice(&ctr_as_digest.elements);
    let hash_output = hash_n_with_padding::<F,D,HF>(&hash_inputs);
    let cell_index_bytes = hash_output.elements[0].to_canonical_u64();

    let cell_index_bits = low_bits(cell_index_bytes as usize, depth);

    let mut masked_cell_index_bits = vec![];

    for i in 0..depth{
        masked_cell_index_bits.push(cell_index_bits[i] && mask_bits[i]);
    }

    masked_cell_index_bits
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