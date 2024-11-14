// global params for the circuits

use anyhow::{Result, Context};
use std::env;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2Hash;

// hash function used. this is hackish way of doing it because
// H::Hash is not consistent with HashOut<F> and causing a lot of headache
// will look into this later.
pub type HF = Poseidon2Hash;

/// params used for the circuits
/// should be defined prior to building the circuit
#[derive(Clone, Debug)]
pub struct CircuitParams{
    pub max_depth: usize,
    pub max_log2_n_slots: usize,
    pub block_tree_depth: usize,
    pub n_field_elems_per_cell: usize,
    pub n_samples: usize,
}

// hardcoded default constants
const DEFAULT_MAX_DEPTH:usize = 32;
const DEFAULT_MAX_LOG2_N_SLOTS:usize = 8;
const DEFAULT_BLOCK_TREE_DEPTH:usize = 5;
const DEFAULT_N_FIELD_ELEMS_PER_CELL:usize = 272;
const DEFAULT_N_SAMPLES:usize = 5;

/// Implement the Default trait for Params using the hardcoded constants
impl Default for CircuitParams {
    fn default() -> Self {
        Self{
            max_depth: DEFAULT_MAX_DEPTH,
            max_log2_n_slots: DEFAULT_MAX_LOG2_N_SLOTS,
            block_tree_depth: DEFAULT_BLOCK_TREE_DEPTH,
            n_field_elems_per_cell: DEFAULT_N_FIELD_ELEMS_PER_CELL,
            n_samples: DEFAULT_N_SAMPLES,
        }
    }
}

impl CircuitParams {
    /// Creates a new `CircuitParams` struct from environment.
    ///
    /// - `MAX_DEPTH`:The maximum slot depth
    /// - `MAX_LOG2_N_SLOTS`:The maximum log2 number of slots
    /// - `BLOCK_TREE_DEPTH`:The block tree depth
    /// - `N_FIELD_ELEMS_PER_CELL`: The number of field elements per cell
    /// - `N_SAMPLES`: number of samples
    ///
    /// Returns an error if any environment variable is missing or fails to parse.
    pub fn from_env() -> Result<Self> {
        let MAX_DEPTH = env::var("MAX_DEPTH")
            .context("MAX_DEPTH is not set")?
            .parse::<usize>()
            .context("MAX_DEPTH must be a valid usize")?;

        let MAX_LOG2_N_SLOTS = env::var("MAX_LOG2_N_SLOTS")
            .context("MAX_LOG2_N_SLOTS is not set")?
            .parse::<usize>()
            .context("MAX_LOG2_N_SLOTS must be a valid usize")?;

        let block_tree_depth = env::var("BLOCK_TREE_DEPTH")
            .context("BLOCK_TREE_DEPTH is not set")?
            .parse::<usize>()
            .context("BLOCK_TREE_DEPTH must be a valid usize")?;

        let n_field_elems_per_cell = env::var("N_FIELD_ELEMS_PER_CELL")
            .context("N_FIELD_ELEMS_PER_CELL is not set")?
            .parse::<usize>()
            .context("N_FIELD_ELEMS_PER_CELL must be a valid usize")?;

        let n_samples = env::var("N_SAMPLES")
            .context("N_SAMPLES is not set")?
            .parse::<usize>()
            .context("N_SAMPLES must be a valid usize")?;

        Ok(CircuitParams {
            max_depth: MAX_DEPTH,
            max_log2_n_slots: MAX_LOG2_N_SLOTS,
            block_tree_depth,
            n_field_elems_per_cell,
            n_samples,
        })
    }
}
