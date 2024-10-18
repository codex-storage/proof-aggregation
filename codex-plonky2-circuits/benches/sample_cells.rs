use criterion::{criterion_group, criterion_main, Criterion};
use anyhow::Result;
use std::time::{Duration, Instant};
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig, Hasher, PoseidonGoldilocksConfig};
use plonky2::iop::witness::PartialWitness;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use codex_plonky2_circuits::circuits::params::TESTING_SLOT_INDEX;
use codex_plonky2_circuits::circuits::sample_cells::DatasetTreeCircuit;

macro_rules! pretty_print {
    ($($arg:tt)*) => {
        print!("\x1b[0;36mINFO ===========>\x1b[0m ");
        println!($($arg)*);
    }
}

// Hash function used
type HF = PoseidonHash;

fn prepare_data<
    F: RichField + Extendable<D> + Poseidon2,
    C: GenericConfig<D, F = F>,
    const D: usize,
    H: Hasher<F> + AlgebraicHasher<F>,
>() -> Result<(
    DatasetTreeCircuit<F, C, D, H>,
    usize,
    usize,
)> {
    // Initialize the dataset tree with testing data
    let mut dataset_t = DatasetTreeCircuit::<F,C,D,H>::new_for_testing();

    let slot_index = TESTING_SLOT_INDEX;
    let entropy = 123;

    Ok((dataset_t, slot_index, entropy))
}

fn build_circuit<
    F: RichField + Extendable<D> + Poseidon2,
    C: GenericConfig<D, F = F>,
    const D: usize,
    H: Hasher<F> + AlgebraicHasher<F>,
>(
    dataset_tree: &mut DatasetTreeCircuit<F, C, D, H>,
    slot_index: usize,
    entropy: usize,
    // proofs: &[MerkleProof<F, H>],
) -> Result<(CircuitData<F, C, D>, PartialWitness<F>)>
{
    // Create the circuit
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    let mut targets = dataset_tree.sample_slot_circuit(&mut builder);

    // Create a PartialWitness
    let mut pw = PartialWitness::new();
    dataset_tree.sample_slot_assign_witness(&mut pw, &mut targets,slot_index,entropy);

    // Build the circuit
    let data = builder.build::<C>();

    Ok((data, pw))
}

fn sampling_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("Sampling Benchmark");

    // Circuit parameters
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    type H = PoseidonHash;

    // Prepare the data that will be used in all steps
    let (mut dataset_tree, slot_index, entropy) = prepare_data::<F, C, D, H>().unwrap();

    // Benchmark the circuit building
    group.bench_function("Single Cell Proof Build", |b| {
        b.iter(|| {
            build_circuit::<F, C, D, H>(&mut dataset_tree, slot_index, entropy).unwrap();
        })
    });

    // Build the circuit
    let (data, pw) = build_circuit::<F, C, D, H>(&mut dataset_tree, slot_index, entropy).unwrap();

    pretty_print!(
        "Circuit size: 2^{} gates",
        data.common.degree_bits()
    );

    let start_time = Instant::now();
    let proof_with_pis = data.prove(pw.clone()).unwrap();
    println!("prove_time = {:?}", start_time.elapsed());

    // Benchmark the proving time
    group.bench_function("Single Cell Proof Prove", |b| {
        b.iter(|| {
            let _proof_with_pis = data.prove(pw.clone()).unwrap();
        })
    });

    // Generate the proof
    let proof_with_pis = data.prove(pw.clone()).unwrap();
    let verifier_data = data.verifier_data();

    pretty_print!("Proof size: {} bytes", proof_with_pis.to_bytes().len());

    // Benchmark the verification time
    group.bench_function("Single Cell Proof Verify", |b| {
        b.iter(|| {
            verifier_data.verify(proof_with_pis.clone()).unwrap();
        })
    });

    group.finish();
}

criterion_group!(name = benches;
    config = Criterion::default().sample_size(10);
    targets = sampling_benchmark);
criterion_main!(benches);
