use criterion::{criterion_group, criterion_main, Criterion};
use anyhow::Result;

use codex_plonky2_circuits::{merkle_tree::merkle_safe::MerkleTree, circuits::merkle_circuit::MerkleTreeCircuit};
use plonky2::field::types::Field;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig, Hasher, PoseidonGoldilocksConfig};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::hash::hash_types::{HashOut, NUM_HASH_OUT_ELTS};
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2_poseidon2::poseidon2_hash::poseidon2::{Poseidon2, Poseidon2Hash};
use std::marker::PhantomData;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use codex_plonky2_circuits::merkle_tree::merkle_safe::MerkleProof;
use plonky2_field::goldilocks_field::GoldilocksField;
use proof_input::tests::merkle_circuit;
use proof_input::tests::merkle_circuit::{assign_witness, MerkleTreeCircuitInput};
use proof_input::utils::usize_to_bits_le;

macro_rules! pretty_print {
    ($($arg:tt)*) => {
        print!("\x1b[0;36mINFO ===========>\x1b[0m ");
        println!($($arg)*);
    }
}

fn prepare_data<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    C: GenericConfig<D, F = F>,
    H: Hasher<F> + AlgebraicHasher<F>,
>(N: usize, max_depth: usize) -> Result<(
    Vec<MerkleTreeCircuitInput<F, D>>,
    HashOut<F>,
)> {
    // Generate random leaf data
    let nleaves = 16; // Number of leaves
    let data = (0..nleaves)
        .map(|i| F::from_canonical_u64(i))
        .collect::<Vec<_>>();
    // Hash the data to obtain leaf hashes
    let leaves: Vec<HashOut<F>> = data
        .iter()
        .map(|&element| {
            // Hash each field element to get the leaf hash
            PoseidonHash::hash_no_pad(&[element])
        })
        .collect();

    //initialize the Merkle tree
    let zero_hash = HashOut {
        elements: [F::ZERO; 4],
    };
    let tree = MerkleTree::<F, D>::new(&leaves, zero_hash)?;

    // Select N leaf indices to prove
    let leaf_indices: Vec<usize> = (0..N).collect();

    // Get the Merkle proofs for the selected leaves
    let proofs: Vec<_> = leaf_indices
        .iter()
        .map(|&leaf_index| tree.get_proof(leaf_index))
        .collect::<Result<Vec<_>, _>>()?;

    let mut circ_inputs = vec![];

    for i in 0..N{
        let path_bits = usize_to_bits_le(leaf_indices[i], max_depth);
        let last_index = (nleaves - 1) as usize;
        let last_bits = usize_to_bits_le(last_index, max_depth);
        let mask_bits = usize_to_bits_le(last_index, max_depth+1);

        // circuit input
        let circuit_input = MerkleTreeCircuitInput::<F, D>{
            leaf: tree.layers[0][leaf_indices[i]],
            path_bits,
            last_bits,
            mask_bits,
            merkle_path: proofs[i].path.clone(),
        };

        circ_inputs.push(circuit_input);
    }

    // Expected Merkle root
    let expected_root = tree.root()?;

    Ok((circ_inputs, expected_root))
}

fn build_circuit<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    C: GenericConfig<D, F = F>,
    H: Hasher<F> + AlgebraicHasher<F>,
>(
    circ_inputs: Vec<MerkleTreeCircuitInput<F, D>>,
    expected_root: HashOut<F>,
    max_depth: usize,
) -> Result<(CircuitData<F, C, D>, PartialWitness<F>)>
{
    // Create the circuit
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Create a PartialWitness
    let mut pw = PartialWitness::new();

    for i in 0..circ_inputs.len() {
        let (mut targets, reconstructed_root_target) = merkle_circuit::build_circuit(&mut builder, max_depth);

        // expected Merkle root
        let expected_root_target = builder.add_virtual_hash();

        // check equality with expected root
        for i in 0..NUM_HASH_OUT_ELTS {
            builder.connect(expected_root_target.elements[i], reconstructed_root_target.elements[i]);
        }

        //assign input
        assign_witness(&mut pw, &mut targets, circ_inputs[i].clone())?;
        pw.set_hash_target(expected_root_target, expected_root);
    }

    // Build the circuit
    let data = builder.build::<C>();

    Ok((data, pw))
}

fn merkle_proof_benchmark<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    C: GenericConfig<D, F = F>,
    H: Hasher<F> + AlgebraicHasher<F>,
>(c: &mut Criterion) {
    let mut group = c.benchmark_group("Merkle Proof Benchmark");

    // Prepare the data that will be used in all steps
    let N = 5; // Number of leaves to prove
    let max_depth = 4;
    let (circ_input, expected_root) = prepare_data::<F, D,C,H>(N, max_depth).unwrap();

    // Benchmark the circuit building
    group.bench_function("Merkle Proof Build", |b| {
        b.iter(|| {
            build_circuit::<F, D, C, H>(circ_input.clone(), expected_root.clone(), max_depth).unwrap();
        })
    });

    // Build the circuit once to get the data for the proving and verifying steps
    let (data, pw) = build_circuit::<F, D, C, H>(circ_input.clone(), expected_root.clone(), max_depth).unwrap();

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

fn run_bench(c: &mut Criterion){
    // Circuit types
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    type H = Poseidon2Hash;

    merkle_proof_benchmark::<F,D,C,H>(c);
}

// criterion_group!(benches, merkle_proof_benchmark);
criterion_group!(name = benches;
    config = Criterion::default().sample_size(10);
    targets = run_bench);
criterion_main!(benches);
