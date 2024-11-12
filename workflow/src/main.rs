use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::GenericConfig;
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use anyhow::Result;
use std::time::Instant;

use proof_input::json::import_witness_from_json;
use codex_plonky2_circuits::circuits::sample_cells::{SampleCircuit, SampleCircuitInput};
use codex_plonky2_circuits::circuits::params::CircuitParams;
use proof_input::params::Params;
use proof_input::params::{D, C, F};

fn main() -> Result<()> {
    // Load the parameters from environment variables
    let params = Params::from_env()?;

    // Read the witness from input.json
    let witness: SampleCircuitInput<F, D> = import_witness_from_json("input.json")?;
    println!("Witness imported from input.json");

    // Create the circuit
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    let circuit_params = CircuitParams {
        max_depth: params.max_depth,
        max_log2_n_slots: params.dataset_depth(),
        block_tree_depth: params.bot_depth(),
        n_field_elems_per_cell: params.n_field_elems_per_cell(),
        n_samples: params.n_samples,
    };
    let circ = SampleCircuit::new(circuit_params);
    let mut targets = circ.sample_slot_circuit(&mut builder);

    // Create a PartialWitness and assign
    let mut pw = PartialWitness::new();

    circ.sample_slot_assign_witness(&mut pw, &mut targets, witness);

    // Build the circuit
    let build_time = Instant::now();
    let data = builder.build::<C>();
    println!("Build time: {:?}", build_time.elapsed());
    println!("Circuit size (degree bits): {:?}", data.common.degree_bits());

    // Prove the circuit with the assigned witness
    let start_time = Instant::now();
    let proof_with_pis = data.prove(pw)?;
    println!("Proving time: {:?}", start_time.elapsed());

    // Verify the proof
    let verifier_data = data.verifier_data();
    let ver_time = Instant::now();
    verifier_data.verify(proof_with_pis)?;
    println!("verification time: {:?}", ver_time.elapsed());
    println!("Proof verification succeeded.");

    Ok(())
}