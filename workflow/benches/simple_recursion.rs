use anyhow::Result;
use criterion::{criterion_group, criterion_main, Criterion};
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::GenericConfig;
use codex_plonky2_circuits::recursion::simple_recursion::aggregate_sampling_proofs;
use proof_input::params::{D, C, F, Params, TestParams};
use proof_input::gen_input::{build_circuit, prove_circuit};

/// Benchmark for building, proving, and verifying the Plonky2 recursion circuit.
/// Simple recursion approach - verify N proofs in-circuit
fn bench_recursion(c: &mut Criterion) {
    // num of inner proofs
    let num_of_inner_proofs = 4;
    // number of samples in each proof
    let n_samples = 10;

    let mut data: Option<CircuitData<F, C, D>> = None;

    // get proofs
    let mut proofs_with_pi = vec![];
    for i in 0..num_of_inner_proofs{
        // build the circuit
        let (data_i, pw) = build_circuit(n_samples, 3).unwrap();
        proofs_with_pi.push(prove_circuit(&data_i, &pw).unwrap());
        data = Some(data_i);
    }

    // Create the circuit
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    // Create a PartialWitness
    let mut pw_agg = PartialWitness::new();
    // aggregate proofs
    let data = data.unwrap();
    let vd = data.verifier_data();
    aggregate_sampling_proofs(&proofs_with_pi.clone(), &vd, &mut builder, &mut pw_agg);

    let mut group = c.benchmark_group("bench recursion");

    group.bench_function("Build Circuit", |b| {
        b.iter(|| {
            // Create the circuit
            let local_config = CircuitConfig::standard_recursion_config();
            let mut local_builder = CircuitBuilder::<F, D>::new(local_config);
            // Create a PartialWitness
            let mut local_pw_agg = PartialWitness::new();
            // aggregate proofs
            aggregate_sampling_proofs(&proofs_with_pi.clone(), &vd, &mut local_builder, &mut local_pw_agg);
            let _data = local_builder.build::<C>();
        })
    });

    let agg_data = builder.build::<C>();
    println!("Circuit size (degree bits): {:?}", agg_data.common.degree_bits());
    println!("Number of gates used: {}", agg_data.common.gates.len());

    group.bench_function("Prove Circuit", |b| {
        b.iter(|| {
            let local_pw = pw_agg.clone();
            agg_data.prove(local_pw).expect("Failed to prove circuit")
        })
    });

    let agg_proof_with_pis = agg_data.prove(pw_agg.clone()).expect("Failed to prove circuit");
    let agg_verifier_data = agg_data.verifier_data();

    println!("Proof size: {} bytes", agg_proof_with_pis.to_bytes().len());

    group.bench_function("Verify Proof", |b| {
        b.iter(|| {
            agg_verifier_data.verify(agg_proof_with_pis.clone()).expect("Failed to verify proof");
        })
    });

    group.finish();
}

/// Criterion benchmark group
criterion_group!{
    name = recursion;
    config = Criterion::default().sample_size(10);
    targets = bench_recursion
}
criterion_main!(recursion);
