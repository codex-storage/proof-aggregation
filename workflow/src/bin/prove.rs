use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::GenericConfig;
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use anyhow::Result;
use std::time::Instant;

use proof_input::serialization::circuit_input::import_circ_input_from_json;
use codex_plonky2_circuits::circuits::sample_cells::{SampleCircuit, SampleCircuitInput};
use codex_plonky2_circuits::circuits::params::CircuitParams;
use proof_input::params::{D, C, F};

fn main() -> Result<()> {
    // Load the parameters from environment variables
    let circuit_params = CircuitParams::from_env()?;

    // Read the witness from input.json
    let circ_input: SampleCircuitInput<F, D> = import_circ_input_from_json("input.json")?;
    println!("Witness imported from input.json");

    // Create the circuit
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let circ = SampleCircuit::new(circuit_params);
    let mut targets = circ.sample_slot_circuit_with_public_input(&mut builder)?;

    // Create a PartialWitness and assign
    let mut pw = PartialWitness::new();
    circ.sample_slot_assign_witness(&mut pw, &targets, &circ_input);

    // Build the circuit
    let build_time = Instant::now();
    let data = builder.build::<C>();
    println!("Build time: {:?}", build_time.elapsed());
    println!("Circuit size (degree bits): {:?}", data.common.degree_bits());

    // Prove the circuit with the assigned witness
    let start_time = Instant::now();
    let proof_with_pis = data.prove(pw)?;
    println!("Proving time: {:?}", start_time.elapsed());

    //TODO: write proof to json file

    Ok(())
}
