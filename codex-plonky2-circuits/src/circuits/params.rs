// global params for the circuits
// only change params here

use plonky2::hash::poseidon::PoseidonHash;

// constants and types used throughout the circuit
pub const N_FIELD_ELEMS_PER_CELL: usize = 4;
pub const BOT_DEPTH: usize = 5; // block depth - depth of the block merkle tree
pub const MAX_DEPTH: usize = 16; // depth of big tree (slot tree depth + block tree depth)
pub const N_CELLS_IN_BLOCKS: usize = 1<<BOT_DEPTH; //2^BOT_DEPTH
pub const N_BLOCKS: usize = 1<<(MAX_DEPTH - BOT_DEPTH); // 2^(MAX_DEPTH - BOT_DEPTH)
pub const N_CELLS: usize = N_CELLS_IN_BLOCKS * N_BLOCKS;

pub const DATASET_DEPTH: usize = 2;
pub const N_SAMPLES: usize = 5;

// hash function used. this is hackish way of doing it because
// H::Hash is not consistent with HashOut<F> and causing a lot of headache
// will look into this later.
pub type HF = PoseidonHash;