use anyhow::{anyhow, Result};
use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use plonky2::gates::noop::NoopGate;
use plonky2::hash::hash_types::HashOut;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::GenericConfig;

use codex_plonky2_circuits::recursion::uniform::compress::CompressionCircuit;
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
    for i in 0..2{
        pi.push(builder.add_virtual_hash_public_input());
    }

    let inner_data = builder.build::<C>();
    println!("inner circuit size = {:?}", inner_data.common.degree_bits());

    // prove with dummy public input
    let mut pw = PartialWitness::<F>::new();
    pw.set_hash_target(pi[0], HashOut::<F>::ZERO)?;
    pw.set_hash_target(pi[1], HashOut::<F>::ZERO)?;
    let inner_proof = inner_data.prove(pw)?;

    // Compression circuit
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let compression_circ = CompressionCircuit::<F,D,C,HF>::new(inner_data.common.clone());
    let compression_targets = compression_circ.build(&mut builder)?;

    // Benchmark Group
    let mut group = c.benchmark_group(format!("Compression Circuit Benchmark for inner-proof size = {}", circuit_size));

    // Benchmark the Circuit Building Phase
    group.bench_function("Build Circuit", |b| {
        b.iter(|| {
            let config = CircuitConfig::standard_recursion_config();
            let mut local_builder = CircuitBuilder::<F, D>::new(config);
            let _compression_targets = compression_circ.build(&mut local_builder);
            let _data = local_builder.build::<C>();
        })
    });

    // Build the circuit once for proving and verifying benchmarks
    let compression_circ_data = builder.build::<C>();
    println!("compress circuit size = {:?}", compression_circ_data.common.degree_bits());

    let mut pw = PartialWitness::<F>::new();
    compression_circ.assign_targets(&mut pw, &compression_targets, inner_proof, &inner_data.verifier_only)?;

    group.bench_function("Prove Circuit", |b| {
        b.iter_batched(
            || pw.clone(),
            |local_pw| compression_circ_data.prove(local_pw).expect("Failed to prove circuit"),
            BatchSize::SmallInput,
        )
    });

    let proof = compression_circ_data.prove(pw)?;
    println!("Proof size: {} bytes", proof.to_bytes().len());

    let verifier_data = compression_circ_data.verifier_data();

    // Benchmark the Verifying Phase
    group.bench_function("Verify Proof", |b| {
        b.iter(|| {
            verifier_data.verify(proof.clone()).expect("Failed to verify proof");
        })
    });

    group.finish();
    Ok(())
}

fn bench_compression(c: &mut Criterion) -> Result<()>{
    bench_compression_runtime(c, 13)?;
    bench_compression_runtime(c, 14)?;
    Ok(())
}

/// Criterion benchmark group
criterion_group!{
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_compression
}
criterion_main!(benches);
