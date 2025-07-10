use std::time::Instant;
use anyhow::Result;
use codex_plonky2_circuits::circuit_trait::Plonky2Circuit;
use codex_plonky2_circuits::circuits::sample_cells::SampleCircuit;
use codex_plonky2_circuits::serialization::export_circuit_data;
use proof_input::params::Params;
use crate::params::{D, C, F, H};
use crate::file_paths::SAMPLING_CIRC_BASE_PATH;

pub fn run() -> Result<()> {
    // Load the parameters from environment variables
    let params = Params::from_env()?;

    // Create the circuit
    let circuit_params = params.circuit_params;
    let circ = SampleCircuit::<F,D,H>::new(circuit_params);
    let start_time = Instant::now();
    let (targets, data) = circ.build_with_standard_config()?;
    println!("Build time: {:?}", start_time.elapsed());
    println!("Circuit size (degree bits): {:?}", data.common.degree_bits());

    // export the circuit data
    export_circuit_data::<F,C,D, _>(data, &targets, SAMPLING_CIRC_BASE_PATH)?;
    println!("all data written to {}", SAMPLING_CIRC_BASE_PATH);

    Ok(())
}
