use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::GenericConfig;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use anyhow::Result;
use std::time::Instant;
use codex_plonky2_circuits::circuits::sample_cells::SampleCircuit;
use proof_input::params::Params;
use proof_input::params::{D, C, F};

fn main() -> Result<()> {
    // Load the parameters from environment variables
    let params = Params::from_env()?;

    // Create the circuit
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let circuit_params = params.circuit_params;
    let circ = SampleCircuit::new(circuit_params);
    let mut targets = circ.sample_slot_circuit(&mut builder);

    // Build the circuit
    let build_time = Instant::now();
    let data = builder.build::<C>();
    println!("Build time: {:?}", build_time.elapsed());
    println!("Circuit size (degree bits): {:?}", data.common.degree_bits());

    Ok(())
}
