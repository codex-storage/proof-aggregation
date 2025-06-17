// global params for the circuits

use anyhow::{Result, Context};
use std::env;

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
        let max_depth = env::var("MAX_DEPTH")
            .context("MAX_DEPTH is not set")?
            .parse::<usize>()
            .context("MAX_DEPTH must be a valid usize")?;

        let max_log2_n_slots = env::var("MAX_LOG2_N_SLOTS")
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
            max_depth,
            max_log2_n_slots,
            block_tree_depth,
            n_field_elems_per_cell,
            n_samples,
        })
    }
}
