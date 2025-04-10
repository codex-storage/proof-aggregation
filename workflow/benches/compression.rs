use anyhow::{anyhow, Result};
use criterion::{criterion_group, criterion_main, Criterion};
use plonky2::gates::noop::NoopGate;
use plonky2::hash::hash_types::HashOut;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, VerifierCircuitData};
use codex_plonky2_circuits::circuit_helper::Plonky2Circuit;

use codex_plonky2_circuits::recursion::uniform::compress::{CompressionCircuit, CompressionInput};
use codex_plonky2_circuits::recursion::uniform::tree::get_hash_of_verifier_data;
use proof_input::params::{D, C, F, HF};

/// Benchmark for building, proving, and verifying the Plonky2 circuit.
fn bench_compression_runtime(c: &mut Criterion, circuit_size: usize) -> Result<()>{

    #[cfg(feature = "parallel")]
    println!("Parallel feature is ENABLED");

    // Create the circuit configuration
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    let num_dummy_gates = match circuit_size {
        0 => return Err(anyhow!("size must be at least 1")),
        1 => 0,
        2 => 1,
        n => (1 << (n - 1)) + 1,
    };

    for _ in 0..num_dummy_gates {
        builder.add_gate(NoopGate, vec![]);
    }

    // 2 virtual hashes (8 field elems) as public input - same as in the recursion tree
    let mut pi = vec![];
    for _i in 0..2{
        pi.push(builder.add_virtual_hash_public_input());
    }

    let inner_data = builder.build::<C>();
    println!("inner circuit size = {:?}", inner_data.common.degree_bits());

    let inner_verifier_data: VerifierCircuitData<F,C,D> = inner_data.verifier_data();
    // prove with dummy public input
    let mut pw = PartialWitness::<F>::new();
    pw.set_hash_target(pi[0], HashOut::<F>::ZERO)?;
    pw.set_hash_target(pi[1], get_hash_of_verifier_data::<F,D,C,HF>(&inner_verifier_data))?;
    let inner_proof = inner_data.prove(pw)?;

    // Compression circuit
    let compression_circ = CompressionCircuit::<F,D,C,HF>::new(inner_data.common.clone(), inner_data.verifier_only.clone());
    let (compression_targets, compression_circ_data) = compression_circ.build_with_standard_config()?;

    // Benchmark Group
    let mut group = c.benchmark_group(format!("Compression Circuit Benchmark for inner-proof size = {}", circuit_size));

    // Benchmark the Circuit Building Phase
    group.bench_function("Build Circuit", |b| {
        b.iter(|| {
            let _compression_targets = compression_circ.build_with_standard_config();
        })
    });

    // Build the circuit once for proving and verifying benchmarks
    println!("compress circuit size = {:?}", compression_circ_data.common.degree_bits());

    let compression_input = CompressionInput{
        inner_proof,
    };

    let verifier_data: VerifierCircuitData<F,C,D> = compression_circ_data.verifier_data();
    let prover_data = compression_circ_data.prover_data();

    group.bench_function("Prove Circuit", |b| {
        b.iter( ||
            {
                let _ = compression_circ.prove(&compression_targets, &compression_input, &prover_data);
            })
    });

    let proof = compression_circ.prove(&compression_targets, &compression_input, &prover_data)?;
    println!("Proof size: {} bytes", proof.to_bytes().len());

    // Benchmark the Verifying Phase
    group.bench_function("Verify Proof", |b| {
        b.iter(|| {
            verifier_data.verify(proof.clone()).expect("Failed to verify proof");
        })
    });

    group.finish();
    Ok(())
}

fn bench_compression(c: &mut Criterion){
    bench_compression_runtime(c, 13).expect("bench failed");
    bench_compression_runtime(c, 14).expect("bench failed");
}

/// Criterion benchmark group
criterion_group!{
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_compression
}
criterion_main!(benches);
