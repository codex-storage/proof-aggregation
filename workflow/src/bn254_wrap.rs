use std::time::Instant;
use anyhow::Result;
use codex_plonky2_circuits::bn254_wrapper::config::PoseidonBN254GoldilocksConfig;
use codex_plonky2_circuits::bn254_wrapper::wrap::{WrapCircuit, WrapInput, WrappedOutput};
use codex_plonky2_circuits::circuit_trait::Plonky2Circuit;
use codex_plonky2_circuits::serialization::{export_verifier_circuit_data, import_proof_with_pi, import_verifier_circuit_data};
use crate::params::{D, C, F};
use crate::file_paths::WRAP_CIRC_BASE_PATH;

type OuterParameters = PoseidonBN254GoldilocksConfig;

pub fn run(circuit_path: &str) -> Result<()> {

    // Read the proof
    let proof_with_pi = import_proof_with_pi::<F,C,D,_>(&circuit_path)?;
    println!("Proof with public input imported from: {}", &circuit_path);

    // read the circuit data
    let verifier_data = import_verifier_circuit_data::<F,C,D,_>(&circuit_path)?;
    println!("Verifier circuit data imported from: {}", &circuit_path);

    let wrapper = WrapCircuit::<F,D,C,OuterParameters>::new(verifier_data);
    let (targ, data) = wrapper.build_with_standard_config().unwrap();
    println!(
        "wrapper circuit degree: {}",
        data.common.degree_bits()
    );
    let verifier_data = data.verifier_data();
    let prover_data = data.prover_data();
    let wrap_input = WrapInput{
        inner_proof: proof_with_pi,
    };
    let start_time = Instant::now();
    let proof = wrapper.prove(&targ, &wrap_input,&prover_data).unwrap();
    println!("Wrap time: {:?}", start_time.elapsed());

    let wrap_circ = WrappedOutput::<F, OuterParameters,D>{
        proof,
        common_data: verifier_data.common.clone(),
        verifier_data: verifier_data.verifier_only.clone(),
    };

    // export the circuit data
    export_verifier_circuit_data::<F,OuterParameters,D, _>(verifier_data, WRAP_CIRC_BASE_PATH)?;
    println!("all data written to {}", WRAP_CIRC_BASE_PATH);

    wrap_circ.save(WRAP_CIRC_BASE_PATH).unwrap();
    println!("Saved wrapped circuit");

    Ok(())
}
