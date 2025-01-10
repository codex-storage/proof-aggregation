use criterion::{Criterion, criterion_group, criterion_main};
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, VerifierCircuitData};
use plonky2::plonk::config::GenericConfig;
use plonky2::plonk::proof::ProofWithPublicInputs;
use codex_plonky2_circuits::circuits::params::CircuitParams;
use codex_plonky2_circuits::circuits::sample_cells::{SampleCircuit, SampleCircuitInput};
use codex_plonky2_circuits::recursion::leaf_circuit::{LeafCircuit, LeafInput};
use codex_plonky2_circuits::recursion::circuits::sampling_inner_circuit::SamplingRecursion;
use codex_plonky2_circuits::recursion::tree_recursion2::{NodeCircuit, TreeRecursion};
use codex_plonky2_circuits::params::{C, D, F};
use proof_input::gen_input::gen_testing_circuit_input;
use proof_input::params::TestParams;


/// Benchmark for building, proving, and verifying the Plonky2 tree recursion circuit.
fn bench_tree_recursion<const N: usize>(c: &mut Criterion){

    let mut group = c.benchmark_group("bench tree recursion - approach 2");

    //------------ sampling inner circuit ----------------------
    // Circuit that does the sampling - default input
    let config = CircuitConfig::standard_recursion_config();
    let mut sampling_builder = CircuitBuilder::<F, D>::new(config);
    let mut params = TestParams::default();
    let one_circ_input = gen_testing_circuit_input::<F,D>(&params);
    let samp_circ = SampleCircuit::<F,D>::new(CircuitParams::default());
    let inner_tar = samp_circ.sample_slot_circuit_with_public_input(&mut sampling_builder);
    // get generate a sampling proof
    let mut pw = PartialWitness::<F>::new();
    samp_circ.sample_slot_assign_witness(&mut pw,&inner_tar,&one_circ_input);
    let inner_data = sampling_builder.build::<C>();
    let inner_proof = inner_data.prove(pw.clone()).unwrap();

    // Building Phase
    group.bench_function("build inner circuit", |b| {
        b.iter(|| {
            let config = CircuitConfig::standard_recursion_config();
            let mut sampling_builder = CircuitBuilder::<F, D>::new(config);
            let _inner_tar = samp_circ.sample_slot_circuit_with_public_input(&mut sampling_builder);
            sampling_builder.build::<C>();
        })
    });

    // Proving Phase
    group.bench_function("prove inner circuit", |b| {
        b.iter(|| {
            let _inner_proof = inner_data.prove(pw.clone());
        })
    });

    println!("inner circuit - Circuit size (degree bits): {:?}", inner_data.common.degree_bits() );
    println!("inner proof - num of public input = {}", inner_proof.public_inputs.len());

    // ------------------- leaf --------------------
    // leaf circuit that verifies the sampling proof
    let inner_circ = SamplingRecursion::default();
    let leaf_circuit = LeafCircuit::new(inner_circ);

    let leaf_in = LeafInput{
        inner_proof,
        verifier_data: inner_data.verifier_data(),
    };
    let config = CircuitConfig::standard_recursion_config();
    let mut leaf_builder = CircuitBuilder::<F, D>::new(config);
    let leaf_targets = leaf_circuit.build(&mut leaf_builder).unwrap();
    let leaf_circ_data =  leaf_builder.build::<C>();

    // Building Phase
    group.bench_function("build leaf circuit", |b| {
        b.iter(|| {
            let config = CircuitConfig::standard_recursion_config();
            let mut leaf_builder = CircuitBuilder::<F, D>::new(config);
            let _leaf_targets = leaf_circuit.build(&mut leaf_builder).unwrap();
            let _leaf_circ_data =  leaf_builder.build::<C>();
        })
    });

    let mut pw = PartialWitness::<F>::new();
    leaf_circuit.assign_targets(&mut pw, &leaf_targets, &leaf_in);
    let leaf_proof = leaf_circ_data.prove(pw.clone()).unwrap();

    // Proving Phase
    group.bench_function("prove leaf circuit", |b| {
        b.iter(|| {
            let _leaf_proof = leaf_circ_data.prove(pw.clone());
        })
    });

    println!("leaf circuit - Circuit size (degree bits): {:?}", leaf_circ_data.common.degree_bits() );
    println!("leaf proof - num of public input = {}", leaf_proof.public_inputs.len());

    // ------------- Node/tree circuit ------------------
    // node circuit that verifies leafs or itself

    let mut tree  = TreeRecursion::<N>::build().unwrap();

    // Building phase
    group.bench_function("build tree circuit", |b| {
        b.iter(|| {
            let _tree  = TreeRecursion::<N>::build();
        })
    });


    let leaf_proofs: Vec<ProofWithPublicInputs<F, C, D>> = (0..N)
        .map(|_| {
            leaf_proof.clone()
        })
        .collect::<Vec<_>>();

    let tree_root_proof = tree.prove_tree(leaf_proofs.clone()).unwrap();

    // Proving Phase
    group.bench_function("prove tree circuit", |b| {
        b.iter(|| {
            let _tree_root_proof = tree.prove_tree(leaf_proofs.clone());
        })
    });

    println!("tree circuit - Circuit size (degree bits): {:?}", tree.node.node_data.node_circuit_data.common.degree_bits());
    println!("tree circuit - num of public input = {}", tree_root_proof.public_inputs.len());

    assert!(
        tree.verify_proof(tree_root_proof.clone()).is_ok(),
        "proof verification failed"
    );

    // Verifying Phase
    group.bench_function("verify tree circuit", |b| {
        b.iter(|| {
            tree.verify_proof(tree_root_proof.clone()).expect("verify fail");
        })
    });


    group.finish();
}

fn bench_tree_recursion_approach2(c: &mut Criterion){
    const N: usize = 2;
    bench_tree_recursion::<N>(c);
}

/// Criterion benchmark group
criterion_group!{
    name = recursion;
    config = Criterion::default().sample_size(10);
    targets = bench_tree_recursion_approach2
}
criterion_main!(recursion);
