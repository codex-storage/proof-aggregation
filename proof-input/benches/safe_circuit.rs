use criterion::{criterion_group, criterion_main, Criterion};
use anyhow::Result;

use codex_plonky2_circuits::{merkle_tree::merkle_safe::MerkleTree, circuits::merkle_circuit::MerkleTreeCircuit};
use plonky2::field::types::Field;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig, Hasher, PoseidonGoldilocksConfig};
use plonky2::iop::witness::PartialWitness;
use plonky2::hash::hash_types::HashOut;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2;
use std::marker::PhantomData;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use codex_plonky2_circuits::merkle_tree::merkle_safe::MerkleProof;

macro_rules! pretty_print {
    ($($arg:tt)*) => {
        print!("\x1b[0;36mINFO ===========>\x1b[0m ");
        println!($($arg)*);
    }
}

fn prepare_data<F, H>(N: usize) -> Result<(
    MerkleTree<F, H>,
    Vec<HashOut<F>>,
    Vec<usize>,
    Vec<MerkleProof<F, H>>,
    HashOut<F>,
)>
    where
        F: RichField + Extendable<2> + Poseidon2,
        H: Hasher<F> + AlgebraicHasher<F> + Hasher<F>,
{
    // Total number of leaves in the Merkle tree
    let nleaves = 1u64 << 16;

    // Generate leaf data
    let data = (0..nleaves)
        .map(|i| F::from_canonical_u64(i as u64))
        .collect::<Vec<_>>();

    // Hash the data to obtain leaf hashes
    let leaves: Vec<HashOut<F>> = data
        .iter()
        .map(|&element| {
            PoseidonHash::hash_no_pad(&[element])
        })
        .collect();

    let zero_hash = HashOut {
        elements: [F::ZERO; 4],
    };
    let tree = MerkleTree::<F, H>::new(&leaves, zero_hash)?;

    // Select N leaf indices to prove
    let leaf_indices: Vec<usize> = (0..N).collect();

    // Get the Merkle proofs for the selected leaves
    let proofs: Vec<_> = leaf_indices
        .iter()
        .map(|&leaf_index| tree.get_proof(leaf_index))
        .collect::<Result<Vec<_>, _>>()?;

    // Expected Merkle root
    let expected_root = tree.root()?;

    Ok((tree, leaves, leaf_indices, proofs, expected_root))
}

fn build_circuit<F, C, const D: usize, H>(
    tree: &MerkleTree<F, H>,
    leaf_indices: &[usize],
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
        tree: tree.clone(),
        _phantom: PhantomData,
    };

    // For each proof, create targets, add constraints, and assign witnesses
    for &leaf_index in leaf_indices.iter() {
        // Build the circuit for each proof
        let (mut targets, _root) = circuit_instance.build_circuit(&mut builder);

        // Assign witnesses for each proof
        circuit_instance.assign_witness(&mut pw, &mut targets, leaf_index)?;
    }

    // Build the circuit
    let data = builder.build::<C>();

    Ok((data, pw))
}

fn merkle_proof_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("Merkle Proof Benchmark");

    // Circuit parameters
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    type H = PoseidonHash;

    // Prepare the data that will be used in all steps
    let N = 5; // Number of leaves to prove
    let (tree, _leaves, leaf_indices, _proofs, _expected_root) = prepare_data::<F, H>(N).unwrap();

    // Benchmark the circuit building
    group.bench_function("Merkle Proof Build", |b| {
        b.iter(|| {
            build_circuit::<F, C, D, H>(&tree, &leaf_indices).unwrap();
        })
    });

    // Build the circuit once to get the data for the proving and verifying steps
    let (data, pw) = build_circuit::<F, C, D, H>(&tree, &leaf_indices).unwrap();

    pretty_print!(
        "circuit size: 2^{} gates",
        data.common.degree_bits()
    );

    // Benchmark the proving time
    group.bench_function("Merkle Proof Prove", |b| {
        b.iter(|| {
            let _proof_with_pis = data.prove(pw.clone()).unwrap();
        })
    });

    // Generate the proof once for verification
    let proof_with_pis = data.prove(pw.clone()).unwrap();
    let verifier_data = data.verifier_data();

    pretty_print!("proof size: {}", proof_with_pis.to_bytes().len());

    // Benchmark the verification time
    group.bench_function("Merkle Proof Verify", |b| {
        b.iter(|| {
            verifier_data.verify(proof_with_pis.clone()).unwrap();
        })
    });

    group.finish();
}

// criterion_group!(benches, merkle_proof_benchmark);
criterion_group!(name = benches;
    config = Criterion::default().sample_size(10);
    targets = merkle_proof_benchmark);
criterion_main!(benches);
