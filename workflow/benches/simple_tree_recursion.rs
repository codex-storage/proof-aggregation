use criterion::{Criterion, criterion_group, criterion_main};
use plonky2::plonk::circuit_data::VerifierCircuitData;
use plonky2::plonk::config::GenericConfig;
use plonky2::plonk::proof::ProofWithPublicInputs;
use codex_plonky2_circuits::recursion::simple::simple_tree_recursion::aggregate_sampling_proofs_tree;
use proof_input::params::{C, D, F, HF, Params};
use proof_input::gen_input::{build_circuit, prove_circuit};

/// Benchmark for building, proving, and verifying the Plonky2 recursion circuit.
fn bench_tree_recursion<const N_INNER:usize>(c: &mut Criterion) -> anyhow::Result<()>{

    let mut group = c.benchmark_group(format!("Simple Tree Recursion Benchmark for N={}",N_INNER));

    // number of samples in each proof
    let n_samples = 10;
    // params
    let mut circ_params = Params::default().circuit_params;
    circ_params.n_samples = n_samples;
    // number of inner proofs:
    // const N_INNER: usize = 4;
    // let mut data: Option<CircuitData<F, C, D>> = None;

    let (data, pw) = build_circuit(n_samples, 3)?;
    let proof = prove_circuit(&data, &pw)?;

    // get proofs
    let proofs_with_pi =  (0..N_INNER).map(|i| proof.clone()).collect::<Vec<_>>();

    println!("inner circuit size = {:?}", data.common.degree_bits());


    let mut agg_proof_with_pis: Option<ProofWithPublicInputs<F, C, D>> = None;
    let mut agg_vd: Option<VerifierCircuitData<F, C, D>> = None;

    // Benchmark the Circuit Building Phase
    group.bench_function("build & prove Circuit", |b| {
        b.iter(|| {
            let (proof, vd_agg) = aggregate_sampling_proofs_tree::<F,D,C,HF>(&proofs_with_pi, data.verifier_data()).unwrap();
            agg_proof_with_pis = Some(proof);
            agg_vd = Some(vd_agg);
        })
    });

    let proof = agg_proof_with_pis.unwrap();
    println!("Proof size: {} bytes", proof.to_bytes().len());

    // Benchmark the Verifying Phase
    let loc_vd = agg_vd.unwrap();
    group.bench_function("Verify Proof", |b| {
        b.iter(|| {
            loc_vd.clone().verify(proof.clone()).expect("Failed to verify proof");
        })
    });

    group.finish();
    Ok(())
}

fn bench_multiple_n(c: &mut Criterion){
    bench_tree_recursion::<4>(c);
    bench_tree_recursion::<8>(c);
    bench_tree_recursion::<16>(c);
}

/// Criterion benchmark group
criterion_group!{
    name = recursion;
    config = Criterion::default().sample_size(10);
    targets = bench_multiple_n
}
criterion_main!(recursion);
