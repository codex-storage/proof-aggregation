use anyhow::anyhow;
use criterion::{Criterion, criterion_group, criterion_main};
use plonky2::plonk::config::GenericConfig;
use plonky2::plonk::proof::ProofWithPublicInputs;
use codex_plonky2_circuits::recursion::circuits::sampling_inner_circuit::SamplingRecursion;
use codex_plonky2_circuits::recursion::tree_recursion::{NodeCircuit, TreeRecursion};
use codex_plonky2_circuits::params::{C, D, F};
use proof_input::gen_input::get_m_default_circ_input;


/// Benchmark for building, proving, and verifying the approach1 Plonky2 tree recursion circuit.
fn bench_tree_recursion<const M: usize, const N: usize>(c: &mut Criterion) {

    let mut group = c.benchmark_group("bench tree recursion - approach 1");

    let inner_sampling_circuit = SamplingRecursion::default();

    let node_circ = NodeCircuit::<_,M,N>::new(inner_sampling_circuit);
    let mut tree_circ = TreeRecursion::new(node_circ);
    let circ_input = get_m_default_circ_input::<M>();

    // Building Phase
    group.bench_function("build", |b| {
        b.iter(|| {
            tree_circ.build();
        })
    });

    let mut proof: Option<ProofWithPublicInputs<F, C, D>> = None;

    // prove Phase
    group.bench_function("prove with leaf only", |b| {
        b.iter(|| {
            proof = Some(tree_circ.prove(&circ_input,None, true).unwrap());
        })
    });

    // Verifying Phase for proof with leaf
    group.bench_function("Verify proof with only leaf", |b| {
        b.iter(|| {
            tree_circ.verify_proof(proof.clone().unwrap()).expect("Failed to verify proof");
        })
    });

    // make N node proofs
    let node_proofs: [ProofWithPublicInputs<F, C, D>; N] = (0..N)
        .map(|_| {
            proof.clone().unwrap()
        })
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| anyhow!("Expected exactly M inner circuits")).unwrap();

    // prove Phase for node leaf and node proofs
    group.bench_function("prove with leaf and node", |b| {
        b.iter(|| {
            proof = Some(tree_circ.prove(&circ_input,Some(node_proofs.clone()), true).unwrap());
        })
    });

    // Verifying Phase for node leaf and node proofs
    group.bench_function("Verify Proof with leaf and node proofs", |b| {
        b.iter(|| {
            tree_circ.verify_proof(proof.clone().unwrap()).expect("Failed to verify proof");
        })
    });

    // print circuit size
    let tree_common_data = tree_circ.node_circ.cyclic_circuit_data.unwrap().common;
    println!("Circuit size (degree bits): {:?}", tree_common_data.degree_bits() );

    group.finish();
}

fn bench_tree_recursion_approach1(c: &mut Criterion){
    const M: usize = 1;
    const N: usize = 2;
    bench_tree_recursion::<M,N>(c);
}

/// Criterion benchmark group
criterion_group!{
    name = recursion;
    config = Criterion::default().sample_size(10);
    targets = bench_tree_recursion_approach1
}
criterion_main!(recursion);
