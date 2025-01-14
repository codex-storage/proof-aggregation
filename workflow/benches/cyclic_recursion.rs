use criterion::{Criterion, criterion_group, criterion_main};
use plonky2::plonk::config::GenericConfig;
use codex_plonky2_circuits::recursion::circuits::sampling_inner_circuit::SamplingRecursion;
use codex_plonky2_circuits::recursion::cyclic::CyclicCircuit;
use proof_input::params::{C, D, F,HF};
use proof_input::gen_input::gen_testing_circuit_input;
use proof_input::params::Params;


/// Benchmark for building, proving, and verifying the Plonky2 tree recursion circuit.
fn bench_cyclic_recursion<const N: usize>(c: &mut Criterion) -> anyhow::Result<()>{

    let mut group = c.benchmark_group("Cyclic Recursion Benchmark");

    let mut params = Params::default();
    let inner_sampling_circuit = SamplingRecursion::<F,D,HF,C>::new(params.circuit_params);
    let mut circ_inputs = vec![];
    for _i in 0..N {
        circ_inputs.push(gen_testing_circuit_input::<F, D>(&params.input_params));
    }

    let mut cyclic_circ = CyclicCircuit::<F,D,_,C>::build_circuit::<HF>(inner_sampling_circuit.clone())?;

    // Building Phase
    group.bench_function("build cyclic circuit", |b| {
        b.iter(|| {
            let _cyclic_circ = CyclicCircuit::<F,D,_,C>::build_circuit::<HF>(inner_sampling_circuit.clone());

        })
    });

    let proof = cyclic_circ.prove_n_layers(circ_inputs.clone())?;

    // Proving Phase
    group.bench_function("prove cyclic circuit", |b| {
        b.iter(|| {
            let _proof = cyclic_circ.prove_n_layers(circ_inputs.clone());
        })
    });

    println!("num of pi = {}", proof.public_inputs.len());
    println!("pub input: {:?}", proof.public_inputs);

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
    bench_cyclic_recursion::<N>(c);
}

/// Criterion benchmark group
criterion_group!{
    name = recursion;
    config = Criterion::default().sample_size(10);
    targets = bench_recursion
}
criterion_main!(recursion);
