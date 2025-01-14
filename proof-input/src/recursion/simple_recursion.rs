// tests for simple recursion approaches

use std::time::Instant;
use plonky2::hash::hash_types::{HashOut, NUM_HASH_OUT_ELTS};
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::AlgebraicHasher;
use plonky2_field::types::Field;
use codex_plonky2_circuits::recursion::circuits::sampling_inner_circuit::SamplingRecursion;
use codex_plonky2_circuits::recursion::simple::simple_recursion::{SimpleRecursionCircuit, SimpleRecursionInput};
use codex_plonky2_circuits::recursion::simple::simple_recursion_hashed_pi::{SimpleRecursionCircuitHashedPI, SimpleRecursionInputHashedPI};
use crate::gen_input::{build_circuit, prove_circuit};
use crate::params::{C, D, F, HF, Params};


// test the simple recursion approach
#[test]
pub fn test_simple_recursion()-> anyhow::Result<()>{
    // number of samples in each proof
    let n_samples = 5;
    // number of inner proofs:
    const N_INNER: usize = 4;
    let mut data: Option<CircuitData<F, C, D>> = None;

    // get proofs
    let mut proofs_with_pi = vec![];
    for i in 0..N_INNER {
        // build the circuit
        let (data_i, pw) = build_circuit(n_samples, i)?;
        proofs_with_pi.push(prove_circuit(&data_i, &pw)?);
        data = Some(data_i);
    }
    let data = data.unwrap();
    println!("inner circuit size = {:?}", data.common.degree_bits());

    // careful here, the sampling recursion is the default so proofs should be for circuit
    // with default params
    let sampling_inner_circ = SamplingRecursion::<F,D,HF,C>::new(Params::default().circuit_params);
    let rec_circuit = SimpleRecursionCircuit::<F,D, _, N_INNER, C>::new(sampling_inner_circ);

    // Create the circuit
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    // Create a PartialWitness
    let mut pw = PartialWitness::new();

    let targets = rec_circuit.build_circuit(&mut builder)?;

    let start = Instant::now();
    let agg_data = builder.build::<C>();
    println!("build time = {:?}", start.elapsed());
    println!("agg circuit size = {:?}", agg_data.common.degree_bits());

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
    println!("public input count = {:?}", proof.public_inputs.len());

    // Verify the proof
    let verifier_data = agg_data.verifier_data();
    assert!(
        verifier_data.verify(proof).is_ok(),
        "proof verification failed"
    );

    Ok(())
}

// test the simple recursion approach with hashed public input
#[test]
pub fn test_simple_recursion_with_hashed_pi()-> anyhow::Result<()>{
    // number of samples in each proof
    let n_samples = 5;
    // number of inner proofs:
    const N_INNER: usize = 4;
    let mut data: Option<CircuitData<F, C, D>> = None;

    // get proofs
    let mut proofs_with_pi = vec![];
    for i in 0..N_INNER {
        // build the circuit
        let (data_i, pw) = build_circuit(n_samples, i)?;
        proofs_with_pi.push(prove_circuit(&data_i, &pw)?);
        data = Some(data_i);
    }
    let data = data.unwrap();
    println!("inner circuit size = {:?}", data.common.degree_bits());

    // careful here, the sampling recursion is the default so proofs should be for circuit
    // with default params
    let sampling_inner_circ = SamplingRecursion::<F,D,HF,C>::new(Params::default().circuit_params);
    let rec_circuit = SimpleRecursionCircuitHashedPI::<F,D, _, N_INNER, C>::new(sampling_inner_circ);

    // Create the circuit
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    // Create a PartialWitness
    let mut pw = PartialWitness::new();

    let targets = rec_circuit.build_circuit::<HF>(&mut builder)?;

    let start = Instant::now();
    let agg_data = builder.build::<C>();
    println!("build time = {:?}", start.elapsed());
    println!("agg circuit size = {:?}", agg_data.common.degree_bits());

    let mut default_entropy = HashOut::ZERO;
    default_entropy.elements[0] = F::from_canonical_u64(1234567);

    let w = SimpleRecursionInputHashedPI{
        proofs: proofs_with_pi.clone(),
        verifier_data: data.verifier_data(),
    };

    rec_circuit.assign_witness(&mut pw,&targets,w)?;

    let start = Instant::now();
    let proof = agg_data.prove(pw)?;
    println!("prove time = {:?}", start.elapsed());
    println!("public input count = {:?}", proof.public_inputs.len());

    // Verify the proof
    let verifier_data = agg_data.verifier_data();
    assert!(
        verifier_data.verify(proof.clone()).is_ok(),
        "proof verification failed"
    );

    let inner_pi: Vec<F> = proofs_with_pi.iter()
        .flat_map(|p| p.public_inputs.iter())
        .cloned()
        .collect();

    assert!(
        check_agg_proof_hash::<HF>(inner_pi, proof.public_inputs),
        "public input verification failed"
    );

    Ok(())
}

pub fn check_agg_proof_hash<H: AlgebraicHasher<F>>(inner_pi: Vec<F>, agg_pi: Vec<F>) -> bool{

    if agg_pi.len() != NUM_HASH_OUT_ELTS {
        return false;
    }
    let expected = H::hash_no_pad(&inner_pi);

    expected == HashOut::from_vec(agg_pi)
}