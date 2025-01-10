// params for generating input for proof circuit

use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use std::env;
use anyhow::{Result, Context};
use codex_plonky2_circuits::circuits::params::CircuitParams;
use plonky2_field::goldilocks_field::GoldilocksField;
use plonky2_poseidon2::config::Poseidon2GoldilocksConfig;

// test types
pub const D: usize = 2;
pub type C = PoseidonGoldilocksConfig;
pub type F = <C as GenericConfig<D>>::F; // this is the goldilocks field
pub type HF = PoseidonHash;
// pub type HP = <PoseidonHash as plonky2::plonk::config::Hasher<F>>::Permutation;

// hardcoded default params for generating proof input
const DEFAULT_MAX_DEPTH: usize = 32; // depth of big tree (slot tree depth, includes block tree depth)
const DEFAULT_MAX_SLOTS: usize = 256; // maximum number of slots
const DEFAULT_CELL_SIZE: usize = 2048; // cell size in bytes
const DEFAULT_BLOCK_SIZE: usize = 65536; // block size in bytes
const DEFAULT_N_SAMPLES: usize = 5; // number of samples to prove

const DEFAULT_ENTROPY: usize = 1234567; // external randomness
const DEFAULT_SEED: usize = 12345; // seed for creating fake data TODO: not used now

const DEFAULT_N_SLOTS: usize = 11; // number of slots in the dataset
const DEFAULT_SLOT_INDEX: usize = 3; // the index of the slot to be sampled
const DEFAULT_N_CELLS: usize = 512; // number of cells in each slot

/// Params struct
#[derive(Clone)]
pub struct Params {
    pub circuit_params: CircuitParams,
    pub test: TestParams,
}

/// test params
#[derive(Clone)]
pub struct TestParams{
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
impl Default for TestParams {
    fn default() -> Self {
        TestParams {
            max_depth: DEFAULT_MAX_DEPTH,
            max_slots: DEFAULT_MAX_SLOTS,
            cell_size: DEFAULT_CELL_SIZE,
            block_size: DEFAULT_BLOCK_SIZE,
            n_samples: DEFAULT_N_SAMPLES,
            entropy: DEFAULT_ENTROPY,
            seed: DEFAULT_SEED,
            n_slots: DEFAULT_N_SLOTS,
            testing_slot_index: DEFAULT_SLOT_INDEX,
            n_cells: DEFAULT_N_CELLS,
        }
    }
}

/// Implement a new function to create Params with custom values
impl TestParams {
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
        TestParams {
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
        (self.cell_size + 62) / 62 * 8
    }

    // BOT_DEPTH
    pub fn bot_depth(&self) -> usize {
        log2(self.block_size / self.cell_size)
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
    pub fn dataset_max_depth(&self) -> usize {
        ceiling_log2(self.max_slots)
    }

    // DATASET_DEPTH for test
    pub fn dataset_depth_test(&self) -> usize {
        ceiling_log2(self.n_slots)
    }

}

pub fn log2(x: usize) -> usize {
    assert!(x.is_power_of_two(), "Input must be a power of 2.");
    x.trailing_zeros() as usize
}

pub fn ceiling_log2(x: usize) -> usize {
    if x <= 1 {
        return 0;
    }
    usize::BITS as usize - x.saturating_sub(1).leading_zeros() as usize
}

/// load test params from env
impl TestParams {
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

        Ok(TestParams {
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

/// load params from env
impl Params {
    pub fn from_env() -> Result<Self> {
        let test_params = TestParams::from_env()?;
        let circuit_params = CircuitParams{
            max_depth: test_params.max_depth,
            max_log2_n_slots: test_params.dataset_max_depth(),
            block_tree_depth: test_params.bot_depth(),
            n_field_elems_per_cell: test_params.n_field_elems_per_cell(),
            n_samples:test_params.n_samples,
        };

        Ok(Params{
            circuit_params,
            test: test_params,
        })
    }
}