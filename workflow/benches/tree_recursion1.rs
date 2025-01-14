use anyhow::{anyhow, Result};
use criterion::{Criterion, criterion_group, criterion_main};
use plonky2::plonk::config::GenericConfig;
use plonky2::plonk::proof::ProofWithPublicInputs;
use codex_plonky2_circuits::recursion::circuits::sampling_inner_circuit::SamplingRecursion;
use codex_plonky2_circuits::recursion::tree1::{tree_circuit::TreeRecursion};
use proof_input::params::{C, D, F, HF, Params};
use proof_input::gen_input::{get_m_circ_input};


/// Benchmark for building, proving, and verifying the approach1 Plonky2 tree recursion circuit.
fn bench_node_recursion<const M: usize, const N: usize>(c: &mut Criterion) -> Result<()>{

    let mut group = c.benchmark_group("Tree Recursion - Approach 1 Benchmark");

    // number of samples in each proof
    let n_samples = 5;
    // params
    let mut circ_params = Params::default().circuit_params;
    circ_params.n_samples = n_samples;
    let mut input_params = Params::default().input_params;
    input_params.n_samples = n_samples;

    let inner_sampling_circuit = SamplingRecursion::<F,D,HF,C>::new(circ_params);

    let circ_input = get_m_circ_input::<M>(input_params);

    // Building Phase
    group.bench_function("build", |b| {
        b.iter(|| {
            let _tree_circ = TreeRecursion::<F,D,_,M,N,C>::build::<HF>(inner_sampling_circuit.clone());
        })
    });

    let mut tree_circ = TreeRecursion::<F,D,_,M,N,C>::build::<HF>(inner_sampling_circuit)?;
    println!("tree circuit size = {:?}", tree_circ.node_circ.cyclic_circuit_data.common.degree_bits());

    // prove Phase
    group.bench_function("prove with leaf only", |b| {
        b.iter(|| {
            let _proof = tree_circ.prove(&circ_input,None, true);
        })
    });

    let proof = tree_circ.prove(&circ_input,None, true)?;
    println!("Proof size: {} bytes", proof.to_bytes().len());
    println!("num of pi = {}", proof.public_inputs.len());

    // make N node proofs
    let node_proofs: [ProofWithPublicInputs<F, C, D>; N] = (0..N)
        .map(|_| {
            proof.clone()
        })
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| anyhow!("Expected exactly M inner circuits")).unwrap();

    // prove Phase for node leaf and node proofs
    group.bench_function("prove with leaf and node", |b| {
        b.iter(|| {
            let _proof = tree_circ.prove(&circ_input,Some(node_proofs.clone()), true);
        })
    });

    // Verifying Phase for node leaf and node proofs
    group.bench_function("Verify Proof with leaf and node proofs", |b| {
        b.iter(|| {
            tree_circ.verify_proof(proof.clone()).expect("Failed to verify proof");
        })
    });

    assert!(
        tree_circ.verify_proof(proof).is_ok(),
        "proof verification failed"
    );

    group.finish();
    Ok(())
}

fn bench_tree_recursion(c: &mut Criterion) -> Result<()>{
    let mut group = c.benchmark_group("bench tree recursion - approach 1");

    const M: usize = 1;
    const N: usize = 2;
    const DEPTH: usize = 3;

    const TOTAL_INPUT: usize = (N.pow(DEPTH as u32) - 1) / (N - 1);

    // number of samples in each proof
    let n_samples = 5;
    // params
    let mut circ_params = Params::default().circuit_params;
    circ_params.n_samples = n_samples;
    let mut input_params = Params::default().input_params;
    input_params.n_samples = n_samples;

    let inner_sampling_circuit = SamplingRecursion::<F,D,HF,C>::new(circ_params);

    let circ_input = get_m_circ_input::<TOTAL_INPUT>(input_params).to_vec();

    // Building Phase
    group.bench_function("build", |b| {
        b.iter(|| {
            let _tree_circ = TreeRecursion::<F,D,_,M,N,C>::build::<HF>(inner_sampling_circuit.clone()).unwrap();
        })
    });

    let mut tree_circ = TreeRecursion::<F,D,_,M,N,C>::build::<HF>(inner_sampling_circuit)?;
    println!("tree circuit size = {:?}", tree_circ.node_circ.cyclic_circuit_data.common.degree_bits());

    // prove Phase
    group.bench_function("prove tree", |b| {
        b.iter(|| {
            let _proof = tree_circ.prove_tree(circ_input.clone(),DEPTH).unwrap();
        })
    });

    let proof = tree_circ.prove_tree(circ_input,DEPTH)?;
    println!("Proof size: {} bytes", proof.to_bytes().len());
    println!("num of pi = {}", proof.public_inputs.len());

    // Verifying Phase for node leaf and node proofs
    group.bench_function("Verify final proof", |b| {
        b.iter(|| {
            tree_circ.verify_proof(proof.clone()).expect("Failed to verify proof");
        })
    });

    assert!(
        tree_circ.verify_proof(proof).is_ok(),
        "proof verification failed"
    );

    group.finish();
    Ok(())
}

fn bench_tree_recursion_approach1(c: &mut Criterion){
    const M: usize = 1;
    const N: usize = 2;
    bench_node_recursion::<M,N>(c);
    bench_tree_recursion(c);
}


/// Criterion benchmark group
criterion_group!{
    name = recursion;
    config = Criterion::default().sample_size(10);
    targets = bench_tree_recursion_approach1
}
criterion_main!(recursion);
