use criterion::{Criterion, criterion_group, criterion_main};
use plonky2::plonk::config::GenericConfig;
use codex_plonky2_circuits::recursion::circuits::sampling_inner_circuit::SamplingRecursion;
use codex_plonky2_circuits::recursion::cyclic::CyclicCircuit;
use proof_input::params::{C, D, F,HF};
use proof_input::gen_input::gen_testing_circuit_input;
use proof_input::params::Params;


/// Benchmark for building, proving, and verifying the Plonky2 tree recursion circuit.
fn bench_cyclic_recursion<const N: usize>(c: &mut Criterion) -> anyhow::Result<()>{

    let mut group = c.benchmark_group(format!("Cyclic Recursion Benchmark for N={}",N));

    // number of samples in each proof
    let n_samples = 10;

    let mut params = Params::default();
    let mut input_params = params.input_params;
    input_params.n_samples = n_samples;
    let mut circuit_params = params.circuit_params;
    circuit_params.n_samples = n_samples;
    let inner_sampling_circuit = SamplingRecursion::<F,D,HF,C>::new(circuit_params);
    let mut circ_inputs = vec![];
    for _i in 0..N {
        circ_inputs.push(gen_testing_circuit_input::<F, D>(&input_params));
    }

    let mut cyclic_circ = CyclicCircuit::<F,D,_,C>::build_circuit::<HF>(inner_sampling_circuit.clone())?;

    // Building Phase
    group.bench_function("build cyclic circuit", |b| {
        b.iter(|| {
            let _cyclic_circ = CyclicCircuit::<F,D,_,C>::build_circuit::<HF>(inner_sampling_circuit.clone());

        })
    });
    println!("cyclic circuit size = {:?}", cyclic_circ.cyclic_circuit_data.common.degree_bits());

    let proof = cyclic_circ.prove_n_layers(circ_inputs.clone())?;

    // Proving Phase
    group.bench_function("prove cyclic circuit", |b| {
        b.iter(|| {
            let _proof = cyclic_circ.prove_n_layers(circ_inputs.clone());
        })
    });
    println!("Proof size: {} bytes", proof.to_bytes().len());
    println!("num of pi = {}", proof.public_inputs.len());

    // Verifying Phase
    group.bench_function("verify cyclic circuit proof", |b| {
        b.iter(|| {
            cyclic_circ.verify_latest_proof();
        })
    });

    assert!(
        cyclic_circ.verify_latest_proof().is_ok(),
        "proof verification failed"
    );

    group.finish();
    Ok(())
}

fn bench_recursion(c: &mut Criterion){
    const N: usize = 2; //  number of proofs to be aggregated
    bench_cyclic_recursion::<4>(c);
    bench_cyclic_recursion::<8>(c);
    bench_cyclic_recursion::<16>(c);
}

/// Criterion benchmark group
criterion_group!{
    name = recursion;
    config = Criterion::default().sample_size(10);
    targets = bench_recursion
}
criterion_main!(recursion);
