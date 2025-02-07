use criterion::{Criterion, criterion_group, criterion_main};
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig};
use plonky2::plonk::config::GenericConfig;
use plonky2::plonk::proof::ProofWithPublicInputs;
use codex_plonky2_circuits::circuits::sample_cells::{SampleCircuit};
use codex_plonky2_circuits::recursion::uniform::tree::TreeRecursion;
use proof_input::params::{C, D, F,HF};
use proof_input::gen_input::gen_testing_circuit_input;
use proof_input::params::Params;

/// Benchmark for building, proving, and verifying the Plonky2 tree recursion circuit.
fn bench_uniform_recursion<const N: usize,>(c: &mut Criterion) -> anyhow::Result<()>{

    let mut group = c.benchmark_group(format!("Uniform Tree Recursion Benchmark for N={}",N));

    //------------ sampling inner circuit ----------------------
    // Circuit that does the sampling - 100 samples
    let config = CircuitConfig::standard_recursion_config();
    let mut sampling_builder = CircuitBuilder::<F, D>::new(config);
    let mut params = Params::default();
    params.input_params.n_samples = 100;
    params.circuit_params.n_samples = 100;
    let one_circ_input = gen_testing_circuit_input::<F,D>(&params.input_params);
    let samp_circ = SampleCircuit::<F,D,HF>::new(params.circuit_params);
    let inner_tar = samp_circ.sample_slot_circuit_with_public_input(&mut sampling_builder)?;
    // get generate a sampling proof
    let mut pw = PartialWitness::<F>::new();
    samp_circ.sample_slot_assign_witness(&mut pw,&inner_tar,&one_circ_input)?;
    let inner_data = sampling_builder.build::<C>();
    let inner_proof = inner_data.prove(pw.clone())?;

    let proofs: Vec<ProofWithPublicInputs<F, C, D>> = (0..N).map(|i| inner_proof.clone()).collect();

    // ------------------- tree --------------------

    let mut tree : Option<TreeRecursion<F, D, C, HF>> = None;

    // Building phase
    group.bench_function("build tree", |b| {
        b.iter(|| {
            tree = Some(TreeRecursion::<F,D,C,HF>::build(inner_data.common.clone()).unwrap());
        })
    });

    let mut tree = tree.unwrap();

    let mut proof: Option<ProofWithPublicInputs<F, C, D>>  = None;

    // Proving Phase
    group.bench_function("prove tree", |b| {
        b.iter(|| {
            proof = Some(tree.prove_tree(&proofs, &inner_data.verifier_only).unwrap());
        })
    });

    let proof = proof.unwrap();

    // Verifying Phase
    // group.bench_function("verify tree circuit", |b| {
    //     b.iter(|| {
    //         verifier_data.verify(proof.clone()).expect("verify fail");
    //     })
    // });

    group.finish();
    Ok(())
}

fn bench_uniform_tree_recursion(c: &mut Criterion){
    const N: usize = 2; // number of child nodes - binary here
    bench_uniform_recursion::<2>(c).expect("bench failed");
    bench_uniform_recursion::<4>(c).expect("bench failed");
    bench_uniform_recursion::<8>(c).expect("bench failed");
    bench_uniform_recursion::<16>(c).expect("bench failed");
    bench_uniform_recursion::<32>(c).expect("bench failed");
    bench_uniform_recursion::<64>(c).expect("bench failed");
    bench_uniform_recursion::<128>(c).expect("bench failed");
    bench_uniform_recursion::<256>(c).expect("bench failed");
}

/// Criterion benchmark group
criterion_group!{
    name = recursion;
    config = Criterion::default().sample_size(10);
    targets = bench_uniform_tree_recursion
}
criterion_main!(recursion);
