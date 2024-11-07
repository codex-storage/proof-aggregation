// config for generating input for proof circuit

use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use std::env;
use anyhow::{Result, Context};

// fake input params

// types
pub const D: usize = 2;
pub type C = PoseidonGoldilocksConfig;
pub type F = <C as GenericConfig<D>>::F; // this is the goldilocks field
pub type H = PoseidonHash;


// hardcoded params for generating proof input
pub const MAX_DEPTH: usize = 32; // depth of big tree (slot tree depth, includes block tree depth)
pub const MAX_SLOTS: usize = 256; // maximum number of slots
pub const CELL_SIZE: usize = 2048; // cell size in bytes
pub const BLOCK_SIZE: usize = 65536; // block size in bytes
pub const N_SAMPLES: usize = 5; // number of samples to prove

pub const ENTROPY: usize = 1234567; // external randomness
pub const SEED: usize = 12345; // seed for creating fake data TODO: not used now

pub const N_SLOTS: usize = 16; // number of slots in the dataset
pub const TESTING_SLOT_INDEX: usize = 2; // the index of the slot to be sampled
pub const N_CELLS: usize = 512; // number of cells in each slot

/// Params struct
#[derive(Clone)]
pub struct Params {
    pub max_depth: usize,
    pub max_slots: usize,
    pub cell_size: usize,
    pub block_size: usize,
    pub n_samples: usize,
    pub entropy: usize,
    pub seed: usize,
    pub n_slots: usize,
    pub testing_slot_index: usize,
    pub n_cells: usize,
}

/// Implement the Default trait for Params using the hardcoded constants
impl Default for Params {
    fn default() -> Self {
        Params {
            max_depth: MAX_DEPTH,
            max_slots: MAX_SLOTS,
            cell_size: CELL_SIZE,
            block_size: BLOCK_SIZE,
            n_samples: N_SAMPLES,
            entropy: ENTROPY,
            seed: SEED,
            n_slots: N_SLOTS,
            testing_slot_index: TESTING_SLOT_INDEX,
            n_cells: N_CELLS,
        }
    }
}

/// Implement a new function to create Params with custom values
impl Params {
    pub fn new(
        max_depth: usize,
        max_slots: usize,
        cell_size: usize,
        block_size: usize,
        n_samples: usize,
        entropy: usize,
        seed: usize,
        n_slots: usize,
        testing_slot_index: usize,
        n_cells: usize,
    ) -> Self {
        Params {
            max_depth,
            max_slots,
            cell_size,
            block_size,
            n_samples,
            entropy,
            seed,
            n_slots,
            testing_slot_index,
            n_cells,
        }
    }
    // GOLDILOCKS_F_SIZE
    pub fn goldilocks_f_size(&self) -> usize {
        64
    }

    // N_FIELD_ELEMS_PER_CELL
    pub fn n_field_elems_per_cell(&self) -> usize {
        self.cell_size * 8 / self.goldilocks_f_size()
    }

    // BOT_DEPTH
    pub fn bot_depth(&self) -> usize {
        (self.block_size / self.cell_size).trailing_zeros() as usize
    }

    // N_CELLS_IN_BLOCKS
    pub fn n_cells_in_blocks(&self) -> usize {
        1 << self.bot_depth()
    }

    // N_BLOCKS
    pub fn n_blocks(&self) -> usize {
        1 << (self.max_depth - self.bot_depth())
    }

    // Depth of test input
    pub fn depth_test(&self) -> usize {
        self.n_cells.trailing_zeros() as usize
    }

    // N_BLOCKS for the test input
    pub fn n_blocks_test(&self) -> usize {
        1 << (self.depth_test() - self.bot_depth())
    }

    // DATASET_DEPTH
    pub fn dataset_depth(&self) -> usize {
        self.max_slots.trailing_zeros() as usize
    }

    // DATASET_DEPTH for test
    pub fn dataset_depth_test(&self) -> usize {
        self.n_slots.trailing_zeros() as usize
    }

    // n_cells_per_slot (2^max_depth)
    pub fn n_cells_per_slot(&self) -> usize {
        1 << self.max_depth
    }

    // n_slots_per_dataset (2^dataset_depth)
    pub fn n_slots_per_dataset(&self) -> usize {
        1 << self.dataset_depth()
    }

}


// computed constants
pub const GOLDILOCKS_F_SIZE: usize = 64;
pub const N_FIELD_ELEMS_PER_CELL: usize = CELL_SIZE * 8 / GOLDILOCKS_F_SIZE;
pub const BOT_DEPTH: usize = (BLOCK_SIZE/CELL_SIZE).ilog2() as usize; // block tree depth

pub const N_CELLS_IN_BLOCKS: usize = 1<< BOT_DEPTH; //2^BOT_DEPTH
pub const N_BLOCKS: usize = 1<<(MAX_DEPTH - BOT_DEPTH); // 2^(MAX_DEPTH - BOT_DEPTH)

pub const DATASET_DEPTH: usize = MAX_SLOTS.ilog2() as usize;

// load params

impl Params {
    pub fn from_env() -> Result<Self> {
        let max_depth = env::var("MAXDEPTH")
            .context("MAXDEPTH not set")?
            .parse::<usize>()
            .context("Invalid MAXDEPTH")?;

        let max_slots = env::var("MAXSLOTS")
            .context("MAXSLOTS not set")?
            .parse::<usize>()
            .context("Invalid MAXSLOTS")?;

        let cell_size = env::var("CELLSIZE")
            .context("CELLSIZE not set")?
            .parse::<usize>()
            .context("Invalid CELLSIZE")?;

        let block_size = env::var("BLOCKSIZE")
            .context("BLOCKSIZE not set")?
            .parse::<usize>()
            .context("Invalid BLOCKSIZE")?;

        let n_samples = env::var("NSAMPLES")
            .context("NSAMPLES not set")?
            .parse::<usize>()
            .context("Invalid NSAMPLES")?;

        let entropy = env::var("ENTROPY")
            .context("ENTROPY not set")?
            .parse::<usize>()
            .context("Invalid ENTROPY")?;

        let seed = env::var("SEED")
            .context("SEED not set")?
            .parse::<usize>()
            .context("Invalid SEED")?;

        let n_slots = env::var("NSLOTS")
            .context("NSLOTS not set")?
            .parse::<usize>()
            .context("Invalid NSLOTS")?;

        let testing_slot_index = env::var("SLOTINDEX")
            .context("SLOTINDEX not set")?
            .parse::<usize>()
            .context("Invalid SLOTINDEX")?;

        let n_cells = env::var("NCELLS")
            .context("NCELLS not set")?
            .parse::<usize>()
            .context("Invalid NCELLS")?;

        Ok(Params {
            max_depth,
            max_slots,
            cell_size,
            block_size,
            n_samples,
            entropy,
            seed,
            n_slots,
            testing_slot_index,
            n_cells,
        })
    }
}