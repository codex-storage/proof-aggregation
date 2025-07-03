use criterion::{Criterion, criterion_group, criterion_main};
use plonky2::plonk::proof::ProofWithPublicInputs;
use codex_plonky2_circuits::circuit_trait::Plonky2Circuit;
use codex_plonky2_circuits::circuits::sample_cells::{SampleCircuit};
use codex_plonky2_circuits::recursion::uniform::tree::TreeRecursion;
use proof_input::params::{C, D, F,HF};
use proof_input::gen_input::gen_testing_circuit_input;
use proof_input::params::Params;

/// Benchmark for building, proving, and verifying the Plonky2 tree recursion circuit.
fn bench_uniform_recursion<const K: usize,const N: usize,const M: usize,>(c: &mut Criterion) -> anyhow::Result<()>{

    let mut group = c.benchmark_group(format!("Uniform Tree Recursion Benchmark for aggregating {} proofs with params: N={}, M={}",K,N,M));

    //------------ sampling inner circuit ----------------------
    // Circuit that does the sampling - 100 samples
    let mut params = Params::default();
    params.set_n_samples(100);
    let one_circ_input = gen_testing_circuit_input::<F,D>(&params.input_params);
    let samp_circ = SampleCircuit::<F,D,HF>::new(params.circuit_params);
    let (inner_tar, inner_data) = samp_circ.build_with_standard_config()?;
    // get generate a sampling proof
    let inner_verifier_data = inner_data.verifier_data();
    let inner_prover_data = inner_data.prover_data();
    let inner_proof = samp_circ.prove(&inner_tar, &one_circ_input, &inner_prover_data)?;
    // clone the proof to get K proofs
    let proofs: Vec<ProofWithPublicInputs<F, C, D>> = (0..K).map(|_i| inner_proof.clone()).collect();

    // ------------------- tree --------------------

    let mut tree : Option<TreeRecursion<F, D, C, HF, N, M>> = None;

    // Building phase
    group.bench_function("build tree", |b| {
        b.iter(|| {
            tree = Some(TreeRecursion::<F,D,C,HF, N, M>::build_with_standard_config(inner_verifier_data.common.clone(), inner_verifier_data.verifier_only.clone()).unwrap());
        })
    });

    let mut tree = tree.unwrap();

    let mut proof: Option<ProofWithPublicInputs<F, C, D>>  = None;

    // Proving Phase
    group.bench_function("prove tree", |b| {
        b.iter(|| {
            proof = Some(tree.prove_tree(&proofs).unwrap());
        })
    });

    let proof = proof.unwrap();

    let inner_pi: Vec<Vec<F>> = proofs.iter().map(|p| p.public_inputs.clone()).collect();

    // Verifying Phase
    group.bench_function("verify root proof", |b| {
        b.iter(|| {
            tree.verify_proof_and_public_input(proof.clone(),inner_pi.clone(), false)
        })
    });

    group.finish();
    Ok(())
}

fn bench_uniform_tree_recursion(c: &mut Criterion){
    // const K: usize = 4; // number of inner proofs to aggregate
    const N: usize = 1; // number of inner proofs in the leaf
    const M: usize = 2; // number of leaf proofs in the node
    bench_uniform_recursion::<2, N, M>(c).expect("bench failed");
    bench_uniform_recursion::<4, N, M>(c).expect("bench failed");
    bench_uniform_recursion::<8, N, M>(c).expect("bench failed");
    bench_uniform_recursion::<16, N, M>(c).expect("bench failed");
    bench_uniform_recursion::<32, N, M>(c).expect("bench failed");
    bench_uniform_recursion::<64, N, M>(c).expect("bench failed");
    bench_uniform_recursion::<128, N, M>(c).expect("bench failed");
    bench_uniform_recursion::<256, N, M>(c).expect("bench failed");
}

/// Criterion benchmark group
criterion_group!{
    name = recursion;
    config = Criterion::default().sample_size(10);
    targets = bench_uniform_tree_recursion
}
criterion_main!(recursion);
