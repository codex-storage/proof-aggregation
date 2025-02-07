use anyhow::Result;
use criterion::{criterion_group, criterion_main, Criterion};
use plonky2::hash::hash_types::HashOut;
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig};
use plonky2::plonk::config::GenericConfig;
use plonky2_field::types::Field;
use codex_plonky2_circuits::recursion::circuits::sampling_inner_circuit::SamplingRecursion;
use codex_plonky2_circuits::recursion::simple::simple_recursion::{SimpleRecursionCircuit, SimpleRecursionInput};
use proof_input::params::{D, C, F, HF, Params};
use proof_input::gen_input::{build_circuit, prove_circuit};

/// Benchmark for building, proving, and verifying the Plonky2 recursion circuit.
/// Simple recursion approach - verify N proofs in-circuit
fn bench_simple_recursion<const N_INNER: usize>(c: &mut Criterion) -> Result<()>{
    let mut group = c.benchmark_group(format!("Simple Recursion Benchmark for N ={}", N_INNER));

    // number of samples in each proof
    let n_samples = 10;
    // params
    let mut circ_params = Params::default().circuit_params;
    circ_params.n_samples = n_samples;

    let (data, pw) = build_circuit(n_samples, 3)?;
    let proof = prove_circuit(&data, &pw)?;

    // get proofs
    let mut proofs_with_pi =  (0..N_INNER).map(|i| proof.clone()).collect::<Vec<_>>();

    println!("inner circuit size = {:?}", data.common.degree_bits());

    // careful here, the sampling recursion is the default so proofs should be for circuit
    // with default params
    let sampling_inner_circ = SamplingRecursion::<F,D,HF,C>::new(circ_params);
    let rec_circuit = SimpleRecursionCircuit::<F,D, _, N_INNER, C>::new(sampling_inner_circ);

    group.bench_function("Build Circuit", |b| {
        b.iter(|| {
            // Create the circuit
            let local_config = CircuitConfig::standard_recursion_config();
            let mut local_builder = CircuitBuilder::<F, D>::new(local_config);
            // aggregate proofs
            let _loc_targets = rec_circuit.build_circuit(&mut local_builder).unwrap();
            let _agg_data = local_builder.build::<C>();
        })
    });


    // Create the circuit
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    // Create a PartialWitness
    let mut pw = PartialWitness::new();

    let targets = rec_circuit.build_circuit(&mut builder)?;
    let agg_data = builder.build::<C>();

    println!("agg circuit size = {:?}", agg_data.common.degree_bits());

    let mut default_entropy = HashOut::ZERO;
    default_entropy.elements[0] = F::from_canonical_u64(1234567);

    let w = SimpleRecursionInput{
        proofs: proofs_with_pi,
        verifier_data: data.verifier_data(),
        entropy: default_entropy,
    };

    rec_circuit.assign_witness(&mut pw,&targets,w)?;

    group.bench_function("Prove Circuit", |b| {
        b.iter(|| {
            let local_pw = pw.clone();
            agg_data.prove(local_pw).expect("Failed to prove circuit")
        })
    });

    let proof = agg_data.prove(pw)?;
    println!("Proof size: {} bytes", proof.to_bytes().len());
    println!("public input count = {:?}", proof.public_inputs.len());

    // Verify the proof
    let verifier_data = agg_data.verifier_data();
    group.bench_function("Verify Proof", |b| {
        b.iter(|| {
            verifier_data.clone().verify(proof.clone()).expect("Failed to verify proof");
        })
    });

    assert!(
        verifier_data.verify(proof).is_ok(),
        "proof verification failed"
    );

    group.finish();
    Ok(())
}

fn bench_multiple_n(c: &mut Criterion){
    bench_simple_recursion::<32>(c);
    bench_simple_recursion::<64>(c);
    bench_simple_recursion::<128>(c);
}

/// Criterion benchmark group
criterion_group!{
    name = recursion;
    config = Criterion::default().sample_size(10);
    targets = bench_multiple_n
}
criterion_main!(recursion);
