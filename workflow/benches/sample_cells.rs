use anyhow::Result;
use criterion::{criterion_group, criterion_main, Criterion};
use plonky2::plonk::circuit_data::{CircuitData, VerifierCircuitData};
use codex_plonky2_circuits::circuit_trait::Plonky2Circuit;

use codex_plonky2_circuits::circuits::sample_cells::SampleCircuit;
use proof_input::gen_input::gen_testing_circuit_input;
use proof_input::params::{D, C, F, HF, Params};

/// Benchmark for building, proving, and verifying the Plonky2 circuit.
fn bench_prove_verify<const N: usize>(c: &mut Criterion) -> Result<()>{

    // get default parameters
    let mut params = Params::default();
    params.set_n_samples(N);

    let test_params = params.input_params;
    let circuit_params = params.circuit_params;

    #[cfg(feature = "parallel")]
    println!("Parallel feature is ENABLED");

    // gen the circuit input
    let circ_input = gen_testing_circuit_input::<F,D>(&test_params);

    // Initialize the SampleCircuit with the parameters
    let circ = SampleCircuit::<F,D,HF>::new(circuit_params.clone());
    let (targets, data) = circ.build_with_standard_config()?;
    let verifier_data:VerifierCircuitData<F,C,D> = data.verifier_data();
    let prover_data = data.prover_data();

    // Benchmark Group: Separate benchmarks for building, proving, and verifying
    let mut group = c.benchmark_group(format!("Sampling Circuit Benchmark for N= {} Samples", N));

    // Benchmark the Circuit Building Phase
    group.bench_function("Build Circuit", |b| {
        b.iter(|| {
            let _: (_, CircuitData<F, C, D>) = circ.build_with_standard_config().unwrap();
        })
    });

    // circuit size
    println!("Circuit size (degree bits): {:?}", prover_data.common.degree_bits());

    group.bench_function("Prove Circuit", |b| {
        b.iter(|| {
            let _ = circ.prove(&targets, &circ_input, &prover_data);
        })
    });

    // Generate the proof once for verification benchmarking
    let proof_with_pis = circ.prove(&targets, &circ_input, &prover_data)?;
    println!("Proof size: {} bytes", proof_with_pis.to_bytes().len());

    // Benchmark the Verifying Phase
    group.bench_function("Verify Proof", |b| {
        b.iter(|| {
            verifier_data.verify(proof_with_pis.clone()).expect("Failed to verify proof");
        })
    });

    group.finish();
    Ok(())
}

fn bench_sampling(c: &mut Criterion){
    bench_prove_verify::<10>(c).expect("bench failed");
    bench_prove_verify::<50>(c).expect("bench failed");
    bench_prove_verify::<100>(c).expect("bench failed");
}

/// Criterion benchmark group
criterion_group!{
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_sampling
}
criterion_main!(benches);
