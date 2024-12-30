use criterion::{Criterion, criterion_group, criterion_main};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, VerifierCircuitData};
use plonky2::plonk::config::GenericConfig;
use plonky2::plonk::proof::ProofWithPublicInputs;
use codex_plonky2_circuits::circuits::sample_cells::SampleCircuitInput;
use codex_plonky2_circuits::recursion::sampling_inner_circuit::SamplingRecursion;
use codex_plonky2_circuits::recursion::tree_recursion::{NodeCircuit, TreeRecursion};
use proof_input::params::{C, D, F, TestParams};
use proof_input::gen_input::gen_testing_circuit_input;

fn get_m_default_circ_input<const M: usize>() -> [SampleCircuitInput<codex_plonky2_circuits::recursion::params::F,D>; M]{
    let mut params = TestParams::default();
    params.n_samples = 10;
    let one_circ_input = gen_testing_circuit_input::<codex_plonky2_circuits::recursion::params::F,D>(&params);
    let circ_input: [SampleCircuitInput<codex_plonky2_circuits::recursion::params::F,D>; M] = (0..M)
        .map(|_| one_circ_input.clone())
        .collect::<Vec<_>>()
        .try_into().unwrap();
    circ_input
}

/// Benchmark for building, proving, and verifying the Plonky2 tree recursion circuit.
fn bench_tree_recursion(c: &mut Criterion) {

    const M: usize = 1;
    const N: usize = 2;

    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<codex_plonky2_circuits::recursion::params::F, D>::new(config);

    // Circuit that does the sampling
    let inner_sampling_circuit = SamplingRecursion::default();

    let mut cyclic_circ = NodeCircuit::<_,M,N>::new(inner_sampling_circuit);
    let mut tree_circ = TreeRecursion::new(cyclic_circ);
    let circ_input = get_m_default_circ_input::<M>();

    // // get proofs
    // let mut proofs_with_pi = vec![];
    // for i in 0..num_of_inner_proofs{
    //     proofs_with_pi.push(prove_circuit(&data, &pw).unwrap());
    // }
    // let vd = data.verifier_data();

    let mut group = c.benchmark_group("bench simple tree recursion");
    let mut agg_proof_with_pis: Option<ProofWithPublicInputs<F, C, D>> = None;
    let mut agg_vd: Option<VerifierCircuitData<F, C, D>> = None;

    // Benchmark the Circuit Building Phase
    group.bench_function("build", |b| {
        b.iter(|| {
            let mut cyclic_circ = NodeCircuit::<_,M,N>::new(inner_sampling_circuit.clone());
            let mut tree_circ = TreeRecursion::new(cyclic_circ);
            tree_circ.build();
        })
    });

    // let proof = agg_proof_with_pis.unwrap();
    // println!("Proof size: {} bytes", proof.to_bytes().len());

    let mut proof: Option<ProofWithPublicInputs<F, C, D>> = None;

    // Benchmark the Circuit prove Phase
    group.bench_function("prove", |b| {
        b.iter(|| {
            proof = Some(tree_circ.prove(&circ_input,None, true).unwrap());
        })
    });

    // let proof = tree_circ.prove(&circ_input,None, true)?;

    // Benchmark the Verifying Phase
    let loc_vd = agg_vd.unwrap();
    group.bench_function("Verify Proof", |b| {
        b.iter(|| {
            tree_circ.verify_proof(proof.unwrap()).expect("Failed to verify proof");
        })
    });

    group.finish();
}

/// Criterion benchmark group
criterion_group!{
    name = recursion;
    config = Criterion::default().sample_size(3);
    targets = bench_tree_recursion
}
criterion_main!(recursion);
