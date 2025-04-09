use std::time::Instant;
use anyhow::Result;
use codex_plonky2_circuits::circuit_helper::Plonky2Circuit;
use codex_plonky2_circuits::circuits::sample_cells::SampleCircuit;
use proof_input::serialization::json::export_circuit_data;
use proof_input::params::Params;
use proof_input::params::{D, C, F,HF};
use proof_input::serialization::file_paths::{PROVER_CIRC_DATA_JSON, TARGETS_JSON, VERIFIER_CIRC_DATA_JSON};

fn main() -> Result<()> {
    // Load the parameters from environment variables
    let params = Params::from_env()?;

    // Create the circuit
    let circuit_params = params.circuit_params;
    let circ = SampleCircuit::<F,D,HF>::new(circuit_params);
    let start_time = Instant::now();
    let (targets, data) = circ.build_with_standard_config()?;
    println!("Build time: {:?}", start_time.elapsed());
    println!("Circuit size (degree bits): {:?}", data.common.degree_bits());

    // export the circuit data
    export_circuit_data::<F,C,D>(data, &targets)?;
    println!("Prover Data written to {}", PROVER_CIRC_DATA_JSON);
    println!("Verifier Data written to {}", VERIFIER_CIRC_DATA_JSON);
    println!("Targets written to {}", TARGETS_JSON);

    Ok(())
}
