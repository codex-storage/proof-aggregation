use anyhow::Result;
use std::time::Instant;
use codex_plonky2_circuits::circuit_helper::Plonky2Circuit;
use proof_input::serialization::circuit_input::import_circ_input_from_json;
use codex_plonky2_circuits::circuits::sample_cells::{SampleCircuit, SampleCircuitInput, SampleTargets};
use codex_plonky2_circuits::circuits::params::CircuitParams;
use proof_input::params::{D, C, F, HF};
use proof_input::serialization::file_paths::{CIRC_INPUT_JSON, PROVER_CIRC_DATA_JSON, TARGETS_JSON, TREE_PROOF_JSON};
use proof_input::serialization::json::{export_proof_with_pi, import_prover_circuit_data, import_targets};

fn main() -> Result<()> {
    // Load the parameters from environment variables
    let circuit_params = CircuitParams::from_env()?;

    // Read the witness from input.json
    let circ_input: SampleCircuitInput<F, D> = import_circ_input_from_json()?;
    println!("Witness imported from: {}", CIRC_INPUT_JSON);

    // read the targets
    let circ_targets: SampleTargets = import_targets()?;
    println!("circuit targets imported from: {}", TARGETS_JSON);

    // read the circuit data
    let prover_data = import_prover_circuit_data::<F,C,D>()?;
    println!("Prover circuit data imported from: {}", PROVER_CIRC_DATA_JSON);
    println!("Circuit size (degree bits): {:?}", prover_data.common.degree_bits());

    // Prove the circuit with the assigned witness
    let circ = SampleCircuit::<F,D,HF>::new(circuit_params);
    let start_time = Instant::now();
    let proof_with_pis = circ.prove(&circ_targets, &circ_input, &prover_data)?;
    println!("Proving time: {:?}", start_time.elapsed());

    //export the proof to json file
    export_proof_with_pi(&proof_with_pis)?;
    println!("Tree proof written to: {}", TREE_PROOF_JSON);

    Ok(())
}
