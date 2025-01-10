// tests for simple recursion approaches

use std::time::Instant;
use plonky2::hash::hash_types::HashOut;
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2_field::types::Field;
use codex_plonky2_circuits::recursion::circuits::sampling_inner_circuit::SamplingRecursion;
use codex_plonky2_circuits::recursion::simple::simple_recursion::{aggregate_sampling_proofs, SimpleRecursionCircuit, SimpleRecursionInput};
use codex_plonky2_circuits::recursion::simple::simple_tree_recursion::aggregate_sampling_proofs_tree;
use plonky2_poseidon2::serialization::{DefaultGateSerializer, DefaultGeneratorSerializer};
use crate::gen_input::{build_circuit, prove_circuit};
use crate::json::write_bytes_to_file;
use crate::params::{C, D, F};

// Test simple recursion
#[test]
fn test_simple_recursion() -> anyhow::Result<()> {
    // number of samples in each proof
    let n_samples = 10;
    // number of inner proofs:
    let n_inner = 4;

    let mut data: Option<CircuitData<F, C, D>> = None;

    // get proofs
    let mut proofs_with_pi = vec![];
    for i in 0..n_inner{
        // build the circuit
        let (data_i, pw) = build_circuit(n_samples, i)?;
        // prove
        proofs_with_pi.push(prove_circuit(&data_i, &pw)?);
        data = Some(data_i);

    }

    println!("num of public inputs inner proof = {}", proofs_with_pi[0].public_inputs.len());

    // Create the circuit
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    // Create a PartialWitness
    let mut pw_agg = PartialWitness::new();
    // aggregate proofs
    aggregate_sampling_proofs(&proofs_with_pi, &data.unwrap().verifier_data(), &mut builder, &mut pw_agg)?;

    let data_agg = builder.build::<C>();

    // Prove the circuit with the assigned witness
    let start_time = Instant::now();
    let proof_with_pis_agg = data_agg.prove(pw_agg)?;
    println!("prove_time = {:?}", start_time.elapsed());

    println!("num of public inputs = {}", proof_with_pis_agg.public_inputs.len());

    // Verify the proof
    let verifier_data = data_agg.verifier_data();
    assert!(
        verifier_data.verify(proof_with_pis_agg).is_ok(),
        "Merkle proof verification failed"
    );

    Ok(())
}

// Test simple tree recursion
#[test]
fn test_simple_tree_recursion() -> anyhow::Result<()> {
    // number of samples in each proof
    let n_samples = 10;
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
    let (proof, vd_agg) = aggregate_sampling_proofs_tree(&proofs_with_pi, data)?;
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
    let verifier_data = vd_agg.verifier_data();
    assert!(
        verifier_data.verify(proof).is_ok(),
        "Merkle proof verification failed"
    );

    Ok(())
}

// test another approach of the simple recursion
#[test]
pub fn test_simple_recursion_approach2()-> anyhow::Result<()>{
    // number of samples in each proof
    let n_samples = 5;
    // number of inner proofs:
    const n_inner: usize = 4;
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

    // careful here, the sampling recursion is the default so proofs should be for circuit
    // with default params
    let sampling_inner_circ = SamplingRecursion::default();
    let rec_circuit = SimpleRecursionCircuit::<_,n_inner>::new(sampling_inner_circ);

    // Create the circuit
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    // Create a PartialWitness
    let mut pw = PartialWitness::new();

    let targets = rec_circuit.build_circuit(&mut builder)?;

    let start = Instant::now();
    let agg_data = builder.build::<C>();
    println!("build time = {:?}", start.elapsed());
    println!("circuit size = {:?}", data.common.degree_bits());

    let mut default_entropy = HashOut::ZERO;
    default_entropy.elements[0] = F::from_canonical_u64(1234567);

    let w = SimpleRecursionInput{
        proofs: proofs_with_pi,
        verifier_data: data.verifier_data(),
        entropy: default_entropy,
    };

    rec_circuit.assign_witness(&mut pw,&targets,w)?;

    let start = Instant::now();
    let proof = agg_data.prove(pw)?;
    println!("prove time = {:?}", start.elapsed());

    // Verify the proof
    let verifier_data = agg_data.verifier_data();
    assert!(
        verifier_data.verify(proof).is_ok(),
        "Merkle proof verification failed"
    );

    Ok(())
}