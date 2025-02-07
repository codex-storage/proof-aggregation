// tests for simple recursion approaches

use std::time::Instant;
use plonky2::plonk::circuit_data::{CircuitData};
use crate::gen_input::{build_circuit, prove_circuit};
use codex_plonky2_circuits::recursion::simple::simple_tree_recursion::aggregate_sampling_proofs_tree;
use crate::params::{C, D, F,HF};

// Test simple tree recursion
#[test]
fn test_simple_tree_recursion() -> anyhow::Result<()> {
    // number of samples in each proof
    let n_samples = 5;
    // number of inner proofs:
    let n_inner = 4;
    let mut data: Option<CircuitData<F, C, D>> = None;

    // get proofs
    let mut proofs_with_pi = vec![];
    for i in 0..n_inner{
        // build the circuit
        let (data_i, pw) = build_circuit(n_samples, i)?;
        proofs_with_pi.push(prove_circuit(&data_i, &pw)?);
        data = Some(data_i);
    }

    let data = data.unwrap();
    println!("inner circuit size = {:?}", data.common.degree_bits());
    // serialization
    // let gate_serializer = DefaultGateSerializer;
    // let generator_serializer =DefaultGeneratorSerializer::<C, D>::default();
    // let data_bytes = data.to_bytes(&gate_serializer, &generator_serializer).unwrap();
    // println!("inner proof circuit data size = {} bytes", data_bytes.len());
    // let file_path = "inner_circ_data.bin";
    // // Write data to the file
    // write_bytes_to_file(data_bytes, file_path).unwrap();
    // println!("Data written to {}", file_path);

    let start_time = Instant::now();
    let (proof, vd_agg) = aggregate_sampling_proofs_tree::<F,D,C,HF>(&proofs_with_pi, data.verifier_data())?;
    println!("prove_time = {:?}", start_time.elapsed());
    println!("num of public inputs = {}", proof.public_inputs.len());
    println!("agg pub input = {:?}", proof.public_inputs);
    println!("outer circuit size = {:?}", vd_agg.common.degree_bits());

    // serialization
    // // let gate_serializer = DefaultGateSerializer;
    // // let generator_serializer =DefaultGeneratorSerializer::<C, D>::default();
    // let outer_data_bytes = vd_agg.to_bytes(&gate_serializer, &generator_serializer).unwrap();
    // println!("outer proof circuit data size = {} bytes", outer_data_bytes.len());
    // let file_path = "outer_circ_data.bin";
    // // Write data to the file
    // write_bytes_to_file(outer_data_bytes, file_path).unwrap();
    // println!("Data written to {}", file_path);

    // Verify the proof
    let verifier_data = vd_agg;//.verifier_data();
    assert!(
        verifier_data.verify(proof).is_ok(),
        "Merkle proof verification failed"
    );

    Ok(())
}
