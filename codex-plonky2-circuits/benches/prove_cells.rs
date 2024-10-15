use criterion::{criterion_group, criterion_main, Criterion};
use anyhow::Result;
use std::time::{Duration, Instant};

use codex_plonky2_circuits::{
    merkle_tree::merkle_safe::MerkleProof,
    circuits::safe_tree_circuit::MerkleTreeCircuit,
};
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig, Hasher, PoseidonGoldilocksConfig};
use plonky2::iop::witness::PartialWitness;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2;
use std::marker::PhantomData;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use codex_plonky2_circuits::circuits::prove_single_cell::SlotTree;

macro_rules! pretty_print {
    ($($arg:tt)*) => {
        print!("\x1b[0;36mINFO ===========>\x1b[0m ");
        println!($($arg)*);
    }
}

// Hash function used
type HF = PoseidonHash;

fn prepare_data<F, H>(N: usize) -> Result<(
    SlotTree<F, H>,
    Vec<usize>,
    Vec<MerkleProof<F, H>>,
)>
where
    F: RichField + Extendable<2> + Poseidon2,
    H: Hasher<F> + AlgebraicHasher<F> + Hasher<F>,
{
    // Initialize the slot tree with default data
    let slot_tree = SlotTree::<F, H>::default();

    // Select N leaf indices to prove
    let leaf_indices: Vec<usize> = (0..N).collect();

    // Get the Merkle proofs for the selected leaves
    let proofs: Vec<_> = leaf_indices
        .iter()
        .map(|&leaf_index| slot_tree.get_proof(leaf_index))
        .collect();

    Ok((slot_tree, leaf_indices, proofs))
}

fn build_circuit<F, C, const D: usize, H>(
    slot_tree: &SlotTree<F, H>,
    leaf_indices: &[usize],
    proofs: &[MerkleProof<F, H>],
) -> Result<(CircuitData<F, C, D>, PartialWitness<F>)>
where
    F: RichField + Extendable<D> + Poseidon2,
    C: GenericConfig<D, F = F>,
    H: Hasher<F> + AlgebraicHasher<F> + Hasher<F>,
{
    // Create the circuit
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Create a PartialWitness
    let mut pw = PartialWitness::new();

    // Initialize the circuit instance
    let mut circuit_instance = MerkleTreeCircuit::<F, C, D, H> {
        tree: slot_tree.tree.clone(),
        _phantom: PhantomData,
    };

    // For each proof, create targets, add constraints, and assign witnesses
    for (i, &leaf_index) in leaf_indices.iter().enumerate() {
        // Build the circuit for each proof
        let mut targets = circuit_instance.prove_single_cell2(&mut builder);

        // Assign witnesses for each proof
        circuit_instance.single_cell_assign_witness(
            &mut pw,
            &mut targets,
            leaf_index,
            &slot_tree.cell_data[leaf_index],
            proofs[i].clone(),
        )?;
    }

    // Build the circuit
    let data = builder.build::<C>();

    Ok((data, pw))
}

fn single_cell_proof_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("Single Cell Proof Benchmark");

    // Circuit parameters
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    type H = PoseidonHash;

    // Prepare the data that will be used in all steps
    let N = 5; // Number of leaves to prove
    let (slot_tree, leaf_indices, proofs) = prepare_data::<F, H>(N).unwrap();

    // Benchmark the circuit building
    group.bench_function("Single Cell Proof Build", |b| {
        b.iter(|| {
            build_circuit::<F, C, D, H>(&slot_tree, &leaf_indices, &proofs).unwrap();
        })
    });

    // Build the circuit
    let (data, pw) = build_circuit::<F, C, D, H>(&slot_tree, &leaf_indices, &proofs).unwrap();

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
    targets = single_cell_proof_benchmark);
criterion_main!(benches);
