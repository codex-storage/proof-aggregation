use anyhow::Result;
use criterion::{criterion_group, criterion_main, Criterion};
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::GenericConfig;

use codex_plonky2_circuits::circuits::sample_cells::SampleCircuit;
use codex_plonky2_circuits::circuits::params::CircuitParams;
use proof_input::gen_input::gen_testing_circuit_input;
use proof_input::params::{D, C, F, Params, TestParams};

/// Benchmark for building, proving, and verifying the Plonky2 circuit.
fn bench_prove_verify(c: &mut Criterion) {
    // get default parameters
    let mut test_params = TestParams::default();
    test_params.n_samples = 100;

    let mut circuit_params = CircuitParams::default();
    circuit_params.n_samples = 100;

    // gen the circuit input
    let circ_input = gen_testing_circuit_input::<F,D>(&test_params);

    // Create the circuit configuration
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Initialize the SampleCircuit with the parameters
    let circ = SampleCircuit::new(circuit_params.clone());
    let mut targets = circ.sample_slot_circuit_with_public_input(&mut builder);

    // Create a PartialWitness and assign the circuit input
    let mut pw = PartialWitness::new();
    circ.sample_slot_assign_witness(&mut pw, &mut targets, circ_input.clone());

    // Benchmark Group: Separate benchmarks for building, proving, and verifying
    let mut group = c.benchmark_group("Prove and Verify");

    // Benchmark the Circuit Building Phase
    group.bench_function("Build Circuit", |b| {
        b.iter(|| {
            let config = CircuitConfig::standard_recursion_config();
            let mut local_builder = CircuitBuilder::<F, D>::new(config);
            let local_circ = SampleCircuit::new(circuit_params.clone());
            let mut local_targets = local_circ.sample_slot_circuit_with_public_input(&mut local_builder);
            let mut local_pw = PartialWitness::new();
            local_circ.sample_slot_assign_witness(&mut local_pw, &mut local_targets, circ_input.clone());
            let _data = local_builder.build::<C>();
        })
    });

    // Build the circuit once for proving and verifying benchmarks
    let build_start = std::time::Instant::now();
    let data = builder.build::<C>();
    let build_duration = build_start.elapsed();
    println!("Build time: {:?}", build_duration);
    println!("Circuit size (degree bits): {:?}", data.common.degree_bits());

    let num_constr: usize = data.common
        .gates
        .iter()
        .map(|gate| gate.0.num_constraints())
        .sum();

    println!("Number of constraints: {}", num_constr);
    println!("Number of gates used: {}", data.common.gates.len());

    // Benchmark the Proving Phase
    group.bench_function("Prove Circuit", |b| {
        b.iter(|| {
            let local_pw = pw.clone();
            data.prove(local_pw).expect("Failed to prove circuit")
        })
    });

    // Generate the proof once for verification benchmarking
    let prove_start = std::time::Instant::now();
    let proof_with_pis = data.prove(pw.clone()).expect("Failed to prove circuit");
    let prove_duration = prove_start.elapsed();
    println!("prove time: {:?}", prove_duration);
    let verifier_data = data.verifier_data();

    println!("Proof size: {} bytes", proof_with_pis.to_bytes().len());

    // Benchmark the Verifying Phase
    group.bench_function("Verify Proof", |b| {
        b.iter(|| {
            verifier_data.verify(proof_with_pis.clone()).expect("Failed to verify proof");
        })
    });

    group.finish();
}

/// Criterion benchmark group
criterion_group!{
    name = prove_verify_benches;
    config = Criterion::default().sample_size(10);
    targets = bench_prove_verify
}
criterion_main!(prove_verify_benches);
