use std::time::Instant;
use anyhow::Result;
use plonky2::plonk::config::GenericConfig;
use serde::Serialize;
use proof_input::params::{D, F};
use codex_plonky2_circuits::serialization::{import_proof_with_pi, import_verifier_circuit_data};

pub fn run<
    // F: RichField + Extendable<D> + Poseidon2 + Serialize,
    C: GenericConfig<D, F = F> + Serialize,
>(circuit_path: &str) -> Result<()> {

    // read the circuit data
    let verifier_data = import_verifier_circuit_data::<F,C,D,_>(circuit_path)?;
    println!("Verifier circuit data imported from: {}", circuit_path);

    // Read the proof
    let proof_with_pi = import_proof_with_pi::<F,C,D,_>(circuit_path)?;
    println!("Proof with public input imported from: {}", circuit_path);

    // verify the proof
    let start_time = Instant::now();
    assert!(verifier_data.verify(proof_with_pi).is_ok(), "proof is NOT VALID");
    println!("Verifying time: {:?}", start_time.elapsed());

    Ok(())
}
