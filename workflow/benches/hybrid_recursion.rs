use criterion::{Criterion, criterion_group, criterion_main};
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig};
use plonky2::plonk::config::GenericConfig;
use plonky2::plonk::proof::ProofWithPublicInputs;
use codex_plonky2_circuits::circuits::sample_cells::{SampleCircuit};
use codex_plonky2_circuits::recursion::circuits::leaf_circuit::LeafCircuit;
use codex_plonky2_circuits::recursion::circuits::sampling_inner_circuit::SamplingRecursion;
use codex_plonky2_circuits::recursion::hybrid::tree_circuit::HybridTreeRecursion;
use proof_input::params::{C, D, F,HF};
use proof_input::gen_input::gen_testing_circuit_input;
use proof_input::params::Params;

/// Benchmark for building, proving, and verifying the Plonky2 tree recursion circuit.
fn bench_hybrid_recursion<const N: usize, const M: usize, const K: usize>(c: &mut Criterion) -> anyhow::Result<()>{

    let mut group = c.benchmark_group(format!("Tree Recursion - Approach 2 Benchmark for N={}",K));

    //------------ sampling inner circuit ----------------------
    // Circuit that does the sampling - default input
    let config = CircuitConfig::standard_recursion_config();
    let mut sampling_builder = CircuitBuilder::<F, D>::new(config);
    let mut params = Params::default();
    let one_circ_input = gen_testing_circuit_input::<F,D>(&params.input_params);
    let samp_circ = SampleCircuit::<F,D,HF>::new(params.circuit_params);
    let inner_tar = samp_circ.sample_slot_circuit_with_public_input(&mut sampling_builder)?;
    // get generate a sampling proof
    let mut pw = PartialWitness::<F>::new();
    samp_circ.sample_slot_assign_witness(&mut pw,&inner_tar,&one_circ_input);
    let inner_data = sampling_builder.build::<C>();
    let inner_proof = inner_data.prove(pw.clone())?;

    // ------------------- leaf --------------------
    let inner_circ = SamplingRecursion::<F,D,HF,C>::new(Params::default().circuit_params);
    let leaf_circuit = LeafCircuit::<F,D,_,M>::new(inner_circ);


    // ------------- Node/tree circuit ------------------
    // node circuit that verifies leafs or itself

    let mut tree = HybridTreeRecursion::<F,D,_,N,M>::new(leaf_circuit);

    // prepare input
    let input_proofs: Vec<ProofWithPublicInputs<F, C, D>> = (0..K)
        .map(|_| {
            inner_proof.clone()
        })
        .collect::<Vec<_>>();

    // Building phase
    group.bench_function("prove tree", |b| {
        b.iter(|| {
            let _ = tree.prove_tree::<C,HF>(&input_proofs, inner_data.verifier_data());

        })
    });

    let (tree_root_proof, verifier_data) = tree.prove_tree::<C,HF>(&input_proofs, inner_data.verifier_data())?;

    println!("tree circuit - num of public input = {}", tree_root_proof.public_inputs.len());
    println!("Proof size: {} bytes", tree_root_proof.to_bytes().len());

    // Verifying Phase
    group.bench_function("verify tree circuit", |b| {
        b.iter(|| {
            verifier_data.verify(tree_root_proof.clone()).expect("verify fail");
        })
    });


    group.finish();
    Ok(())
}

fn bench_tree_recursion_approach2(c: &mut Criterion){
    const N: usize = 2; // number of child nodes - binary here
    const M: usize = 64; // number of proofs aggregated in leaves
    const K: usize = 128; // number of proofs to be aggregated in the tree
    bench_hybrid_recursion::<N,8,128>(c);
    bench_hybrid_recursion::<N,4,128>(c);
    // bench_hybrid_recursion::<N,M,K>(c);
}

/// Criterion benchmark group
criterion_group!{
    name = recursion;
    config = Criterion::default().sample_size(10);
    targets = bench_tree_recursion_approach2
}
criterion_main!(recursion);
