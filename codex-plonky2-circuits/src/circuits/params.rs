// global params for the circuits

use plonky2::hash::poseidon::PoseidonHash;
use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2Hash;

// hash function used. this is hackish way of doing it because
// H::Hash is not consistent with HashOut<F> and causing a lot of headache
// will look into this later.
pub type HF = PoseidonHash;

// params used for the circuits
// should be defined prior to building the circuit
#[derive(Clone, Debug)]
pub struct CircuitParams{
    pub max_depth: usize,
    pub max_log2_n_slots: usize,
    pub block_tree_depth: usize,
    pub n_field_elems_per_cell: usize,
    pub n_samples: usize,
}

