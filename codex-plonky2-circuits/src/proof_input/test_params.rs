// config for generating input for proof circuit

use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

// fake input params

// types
pub const D: usize = 2;
pub type C = PoseidonGoldilocksConfig;
pub type F = <C as GenericConfig<D>>::F; // this is the goldilocks field
pub type H = PoseidonHash;


// hardcoded params for generating proof input
pub const MAX_DEPTH: usize = 8; // depth of big tree (slot tree depth, includes block tree depth)
pub const MAX_SLOTS: usize = 256; // maximum number of slots
pub const CELL_SIZE: usize = 2048; // cell size in bytes
pub const BLOCK_SIZE: usize = 65536; // block size in bytes
pub const N_SAMPLES: usize = 5; // number of samples to prove

pub const ENTROPY: usize = 1234567; // external randomness
pub const SEED: usize = 12345; // seed for creating fake data TODO: not used now

pub const N_SLOTS: usize = 8; // number of slots in the dataset
pub const TESTING_SLOT_INDEX: usize = 2; //the index of the slot to be sampled
pub const N_CELLS: usize = 512; // number of cells in each slot

// computed constants
pub const GOLDILOCKS_F_SIZE: usize = 64;
pub const N_FIELD_ELEMS_PER_CELL: usize = CELL_SIZE * 8 / GOLDILOCKS_F_SIZE;
pub const BOT_DEPTH: usize = (BLOCK_SIZE/CELL_SIZE).ilog2() as usize; // block tree depth

pub const N_CELLS_IN_BLOCKS: usize = 1<< BOT_DEPTH; //2^BOT_DEPTH
pub const N_BLOCKS: usize = 1<<(MAX_DEPTH - BOT_DEPTH); // 2^(MAX_DEPTH - BOT_DEPTH)

pub const DATASET_DEPTH: usize = MAX_SLOTS.ilog2() as usize;

// TODO: load params