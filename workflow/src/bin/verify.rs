use std::time::Instant;
use plonky2::plonk::config::GenericConfig;
use anyhow::Result;
use codex_plonky2_circuits::circuits::params::CircuitParams;
use proof_input::params::{D, C, F};
use proof_input::serialization::file_paths::{PROOF_JSON, VERIFIER_CIRC_DATA_JSON};
use proof_input::serialization::json::{import_proof_with_pi, import_verifier_circuit_data};

fn main() -> Result<()> {
    // Load the parameters from environment variables
    let circuit_params = CircuitParams::from_env()?;

    // read the circuit data
    let verifier_data = import_verifier_circuit_data::<F,C,D>()?;
    println!("Verifier circuit data imported from: {}", VERIFIER_CIRC_DATA_JSON);

    // Read the proof
    let proof_with_pi = import_proof_with_pi::<F,C,D>()?;
    println!("Proof with public input imported from: {}", PROOF_JSON);

    // verify the proof
    let start_time = Instant::now();
    assert!(verifier_data.verify(proof_with_pi).is_ok(), "proof is NOT VALID");
    println!("Verifying time: {:?}", start_time.elapsed());

    Ok(())
}
