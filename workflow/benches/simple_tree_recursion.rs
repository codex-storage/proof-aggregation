use criterion::{Criterion, criterion_group, criterion_main};
use plonky2::plonk::circuit_data::VerifierCircuitData;
use plonky2::plonk::config::GenericConfig;
use plonky2::plonk::proof::ProofWithPublicInputs;
use codex_plonky2_circuits::recursion::simple_tree_recursion::aggregate_sampling_proofs_tree2;
use proof_input::params::{C, D, F};
use proof_input::gen_input::{build_circuit, prove_circuit};

/// Benchmark for building, proving, and verifying the Plonky2 recursion circuit.
fn bench_tree_recursion(c: &mut Criterion) {
    // num of inner proofs
    let num_of_inner_proofs = 4;
    // number of samples in each proof
    let n_samples = 10;

    let (data, pw) = build_circuit(n_samples, 3).unwrap();

    // get proofs
    let mut proofs_with_pi = vec![];
    for i in 0..num_of_inner_proofs{
        proofs_with_pi.push(prove_circuit(&data, &pw).unwrap());
    }
    let vd = data.verifier_data();

    let mut group = c.benchmark_group("bench simple tree recursion");
    let mut agg_proof_with_pis: Option<ProofWithPublicInputs<F, C, D>> = None;
    let mut agg_vd: Option<VerifierCircuitData<F, C, D>> = None;

    // Benchmark the Circuit Building Phase
    group.bench_function("build & prove Circuit", |b| {
        b.iter(|| {
            let (agg_p, agg_d) = aggregate_sampling_proofs_tree2(&proofs_with_pi, vd.clone()).unwrap();
            agg_proof_with_pis = Some(agg_p);
            agg_vd = Some(agg_d);
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
}

/// Criterion benchmark group
criterion_group!{
    name = recursion;
    config = Criterion::default().sample_size(10);
    targets = bench_tree_recursion
}
criterion_main!(recursion);
