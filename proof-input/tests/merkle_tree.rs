use plonky2::hash::hash_types::{HashOut, RichField};
use plonky2_field::extension::Extendable;
use plonky2_field::goldilocks_field::GoldilocksField;
use plonky2_poseidon2::config::Poseidon2GoldilocksConfig;
use plonky2_poseidon2::Poseidon2;
use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2Hash;
use proof_input::input_generator::utils::usize_to_bits_le;


// types used in all tests
type F = GoldilocksField;
type H = Poseidon2Hash;
const D: usize = 2;
type C = Poseidon2GoldilocksConfig;

struct TestCase {
    n: usize,
    digest: [u64; 4],
}

const TEST_CASES: [TestCase; 3] = [
    TestCase { n: 1, digest: [0x232f21acc9d346d8, 0x2eba96d3a73822c1, 0x4163308f6d0eff64, 0x5190c2b759734aff] },
    TestCase { n: 2, digest: [0x999dde2cb60b5bdb, 0xacb725a87250a306, 0x8eeb00a6fc173443, 0x5f510b7eeece33bb] },
    TestCase { n: 3, digest: [0x00b72dc0a592b9c0, 0x68575842dd1c6e27, 0x871d5146985881d6, 0xc945d7f3d5fdde00] },
    // TestCase { n: 5, digest: [0x76c082d76254d6a4, 0x50090b2fa457d882, 0x1e24539e510441c8, 0x98f629df254418c7] },
    // TestCase { n: 8, digest: [0xea2ef6bfa2bde2ea, 0x566ad81f99d5e1e1, 0x0ce590217c9eb98d, 0x1937f1549f3a04db] },
    // TestCase { n: 15, digest: [0x92e26850cb3f3778, 0x4b5b473a56ced536, 0xb34e984a4bba48a6, 0x3366506bd7e6d209] },
    // TestCase { n: 29, digest: [0xd41a5bad429a66bf, 0x197f114359cf8763, 0x98c38dd9887fb7d7, 0x385b9895a84cb0e1] },
    // TestCase { n: 42, digest: [0xa1797f85ba1a05a2, 0x222ab8d64fe238e3, 0xbf1258219cc2ca7c, 0x4a479264e7558d52] },
    // TestCase { n: 56, digest: [0xe30e74aa1f13ae26, 0x773a2c60942c399b, 0x14b3ab953e4ac2a5, 0x2df6035c61fd9e50] },
    // TestCase { n: 78, digest: [0xc9ac91157af04bcd, 0x5b1567f3801f3abd, 0x7d97183e3ef64d5f, 0xf9fe83f25515919f] },
    // TestCase { n: 99, digest: [0x2160a76f4328b3ec, 0x84497fc521e445f2, 0x3e0b60acf5e6a06e, 0x24f2c09bdb0434e4] },
    // TestCase { n: 123, digest: [0xed4b1d62013d3755, 0x184c408cef01edbe, 0x4cdcb65b877e72a7, 0xbdbef5049bd15ac9] },
    // TestCase { n: 150, digest: [0xeace58c60055d3f2, 0x5a8ccfc77b037ef1, 0xd996c1669a9fed21, 0x78ccf90f1acdc643] },
];

fn digest_seq<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
>(n: usize) -> Vec<HashOut<F>> {
    (0..n)
        .map(|i| HashOut {
            elements: [
                F::from_canonical_u64((i + 1) as u64),
                F::ZERO,
                F::ZERO,
                F::ZERO,
            ],
        })
        .collect()
}

/// Compute the minimal tree depth for n leaves.
fn compute_max_depth(n: usize) -> usize {
    let mut depth = 0;
    while (1 << depth) < n {
        depth += 1;
    }
    if depth == 0 {
        1
    } else {
        depth
    }
}

/// tests for the merkle tree - non circuit tests
#[cfg(test)]
mod merkle_tree_tests {
    use super::*;
    use plonky2::hash::hash_types::HashOut;
    use proof_input::merkle_tree::merkle_safe::{KEY_BOTTOM_LAYER, KEY_NONE, KEY_ODD, KEY_ODD_AND_BOTTOM_LAYER, MerkleProof, MerkleTree};
    use plonky2::field::types::Field;
    use proof_input::hash::key_compress::key_compress;
    use plonky2::plonk::config::Hasher;
    use plonky2::field::goldilocks_field::GoldilocksField;
    use proof_input::merkle_tree::merkle_safe::zero;

    fn compress(
        x: HashOut<F>,
        y: HashOut<F>,
        key: u64,
    ) -> HashOut<F> {
        key_compress::<F,D,H>(x,y,key)
    }

    fn make_tree(
        data: &[F],
    ) -> anyhow::Result<MerkleTree<F, D, H>> {
        // Hash the data to obtain leaf hashes
        let leaves: Vec<HashOut<GoldilocksField>> = data
            .iter()
            .map(|&element| {
                // Hash each field element to get the leaf hash
                H::hash_no_pad(&[element])
            })
            .collect();

        MerkleTree::<F, D, H>::new(&leaves)
    }

    #[test]
    fn single_proof_test() -> anyhow::Result<()> {
        let data = (1u64..=8)
            .map(|i| F::from_canonical_u64(i))
            .collect::<Vec<_>>();

        // Hash the data to obtain leaf hashes
        let leaves: Vec<HashOut<F>> = data
            .iter()
            .map(|&element| {
                // Hash each field element to get the leaf hash
                H::hash_no_pad(&[element])
            })
            .collect();

        // Build the Merkle tree
        let tree = MerkleTree::<F, D, H>::new(&leaves)?;

        // Get the root
        let root = tree.root()?;

        // Get a proof for the first leaf
        let proof = tree.get_proof(0)?;

        // Verify the proof
        let is_valid = proof.verify(leaves[0], root)?;
        assert!(is_valid, "Merkle proof verification failed");

        Ok(())
    }

    #[test]
    fn test_correctness_even_bottom_layer() -> anyhow::Result<()> {
        // Data for the test (field elements)
        let data = (1u64..=8)
            .map(|i| F::from_canonical_u64(i))
            .collect::<Vec<_>>();

        // Hash the data to get leaf hashes
        let leaf_hashes: Vec<HashOut<F>> = data
            .iter()
            .map(|&element| H::hash_no_pad(&[element]))
            .collect();

        let expected_root =
            compress(
                compress(
                    compress(
                        leaf_hashes[0],
                        leaf_hashes[1],
                        KEY_BOTTOM_LAYER,
                    ),
                    compress(
                        leaf_hashes[2],
                        leaf_hashes[3],
                        KEY_BOTTOM_LAYER,
                    ),
                    KEY_NONE,
                ),
                compress(
                    compress(
                        leaf_hashes[4],
                        leaf_hashes[5],
                        KEY_BOTTOM_LAYER,
                    ),
                    compress(
                        leaf_hashes[6],
                        leaf_hashes[7],
                        KEY_BOTTOM_LAYER,
                    ),
                    KEY_NONE,
                ),
                KEY_NONE,
            );

        // Build the tree
        let tree = make_tree(&data)?;

        // Get the computed root
        let computed_root = tree.root()?;

        // Check that the computed root matches the expected root
        assert_eq!(computed_root, expected_root);

        Ok(())
    }

    #[test]
    fn test_correctness_odd_bottom_layer() -> anyhow::Result<()> {
        // Data for the test (field elements)
        let data = (1u64..=7)
            .map(|i| F::from_canonical_u64(i))
            .collect::<Vec<_>>();

        // Hash the data to get leaf hashes
        let leaf_hashes: Vec<HashOut<F>> = data
            .iter()
            .map(|&element| H::hash_no_pad(&[element]))
            .collect();

        let expected_root =
            compress(
                compress(
                    compress(
                        leaf_hashes[0],
                        leaf_hashes[1],
                        KEY_BOTTOM_LAYER,
                    ),
                    compress(
                        leaf_hashes[2],
                        leaf_hashes[3],
                        KEY_BOTTOM_LAYER,
                    ),
                    KEY_NONE,
                ),
                compress(
                    compress(
                        leaf_hashes[4],
                        leaf_hashes[5],
                        KEY_BOTTOM_LAYER,
                    ),
                    compress(
                        leaf_hashes[6],
                        zero::<F,D>(),
                        KEY_ODD_AND_BOTTOM_LAYER,
                    ),
                    KEY_NONE,
                ),
                KEY_NONE,
            );

        // Build the tree
        let tree = make_tree(&data)?;

        // Get the computed root
        let computed_root = tree.root()?;

        // Check that the computed root matches the expected root
        assert_eq!(computed_root, expected_root);

        Ok(())
    }

    #[test]
    fn test_correctness_even_bottom_odd_upper_layers() -> anyhow::Result<()> {
        // Data for the test (field elements)
        let data = (1u64..=10)
            .map(|i| F::from_canonical_u64(i))
            .collect::<Vec<_>>();

        // Hash the data to get leaf hashes
        let leaf_hashes: Vec<HashOut<F>> = data
            .iter()
            .map(|&element| H::hash_no_pad(&[element]))
            .collect();

        let expected_root = compress(
            compress(
                compress(
                    compress(
                        leaf_hashes[0],
                        leaf_hashes[1],
                        KEY_BOTTOM_LAYER,
                    ),
                    compress(
                        leaf_hashes[2],
                        leaf_hashes[3],
                        KEY_BOTTOM_LAYER,
                    ),
                    KEY_NONE,
                ),
                compress(
                    compress(
                        leaf_hashes[4],
                        leaf_hashes[5],
                        KEY_BOTTOM_LAYER,
                    ),
                    compress(
                        leaf_hashes[6],
                        leaf_hashes[7],
                        KEY_BOTTOM_LAYER,
                    ),
                    KEY_NONE,
                ),
                KEY_NONE,
            ),
            compress(
                compress(
                    compress(
                        leaf_hashes[8],
                        leaf_hashes[9],
                        KEY_BOTTOM_LAYER,
                    ),
                    zero::<F,D>(),
                    KEY_ODD,
                ),
                zero::<F,D>(),
                KEY_ODD,
            ),
            KEY_NONE,
        );

        // Build the tree
        let tree = make_tree(&data)?;

        // Get the computed root
        let computed_root = tree.root()?;

        // Check that the computed root matches the expected root
        assert_eq!(computed_root, expected_root);

        Ok(())
    }

    #[test]
    fn test_merkle_tree_proofs() -> anyhow::Result<()> {
        // Data for the test (field elements)
        let data = (1u64..=10)
            .map(|i| F::from_canonical_u64(i))
            .collect::<Vec<_>>();

        // Hash the data to get leaf hashes
        let leaf_hashes: Vec<HashOut<F>> = data
            .iter()
            .map(|&element| H::hash_no_pad(&[element]))
            .collect();

        // Build the tree
        let tree = MerkleTree::<F, D, H>::new(&leaf_hashes)?;

        // Get the root
        let expected_root = tree.root()?;

        // Verify proofs for all leaves
        for (i, &leaf_hash) in leaf_hashes.iter().enumerate() {
            let proof = tree.get_proof(i)?;
            let is_valid = proof.verify(leaf_hash, expected_root)?;
            assert!(is_valid, "Proof verification failed for leaf {}", i);
        }

        Ok(())
    }

    #[test]
    fn test_merkle_tree_roots() -> anyhow::Result<()> {
        for test_case in TEST_CASES.iter() {
            let n = test_case.n;
            let expected_digest = test_case.digest;

            // Generate the inputs
            let inputs = digest_seq::<F,D>(n);

            // Build the Merkle tree
            let tree = MerkleTree::<F, D, H>::new(&inputs)?;

            // Get the computed root
            let proof = tree.get_proof(0)?;
            let leaf = inputs[0];
            let computed_root = tree.root()?;

            let reconstructed_root = proof.reconstruct_root(leaf.clone())?;

            let max_depth = compute_max_depth(n);
            let path_bits = usize_to_bits_le(0, max_depth);
            let last_index = n - 1;
            let last_bits = usize_to_bits_le(last_index, max_depth);
            let mask_bits = usize_to_bits_le(last_index, max_depth + 1);

            let reconstructed_root2 = MerkleProof::<F, D, H>::reconstruct_root2(leaf, path_bits.clone(), last_bits.clone(), proof.path.clone(), mask_bits.clone(), max_depth).unwrap();


            // Construct the expected root hash
            let expected_root = HashOut {
                elements: [
                    F::from_canonical_u64(expected_digest[0]),
                    F::from_canonical_u64(expected_digest[1]),
                    F::from_canonical_u64(expected_digest[2]),
                    F::from_canonical_u64(expected_digest[3]),
                ],
            };

            // Compare computed root to expected digest
            assert_eq!(
                computed_root, expected_root,
                "Mismatch at n = {}",
                n
            );

            assert_eq!(
                reconstructed_root, expected_root,
                "Mismatch at n = {}",
                n
            );

            assert_eq!(
                reconstructed_root2, expected_root,
                "Mismatch at n = {}",
                n
            );
        }

        Ok(())
    }

}


/// tests for the merkle circuit
#[cfg(test)]
mod merkle_circuit_tests {
    use super::*;
    use plonky2::hash::hash_types::{HashOut, NUM_HASH_OUT_ELTS};
    use proof_input::merkle_tree::merkle_safe::{MerkleProof, MerkleTree};
    use plonky2::field::goldilocks_field::GoldilocksField;
    use plonky2::field::types::Field;
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::Hasher;
    use proof_input::merkle_tree::merkle_circuit::{assign_witness, build_circuit, MerkleTreeCircuitInput};

    /// Build the Merkle circuit, assign the given leaf, proof, and root, and verify.
    fn verify_circuit(
        leaf: HashOut<F>,
        proof: MerkleProof<F, D, H>,
        root: HashOut<F>,
        index: usize,
        n: usize,
    ) -> anyhow::Result<()> {
        let max_depth = compute_max_depth(n);
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let (mut targets, reconstructed_root) = build_circuit::<F, D, H>(&mut builder, max_depth);

        // connect expected root to reconstructed root, in-circuit equality check
        let expected_root = builder.add_virtual_hash();
        for i in 0..NUM_HASH_OUT_ELTS {
            builder.connect(expected_root.elements[i], reconstructed_root.elements[i]);
        }

        let path_bits = usize_to_bits_le(index, max_depth);
        let last_index = n - 1;
        let last_bits = usize_to_bits_le(last_index, max_depth);
        let mask_bits = usize_to_bits_le(last_index, max_depth + 1);

        let circuit_input = MerkleTreeCircuitInput::<F, D> {
            leaf,
            path_bits,
            last_bits,
            mask_bits,
            merkle_path: proof.path.clone(),
        };

        let mut pw = PartialWitness::new();
        assign_witness(&mut pw, &mut targets, circuit_input)?;
        pw.set_hash_target(expected_root, root)?;

        let data = builder.build::<C>();
        let proof_with_pis = data.prove(pw)?;
        let verifier_data = data.verifier_data();
        assert!(
            verifier_data.verify(proof_with_pis).is_ok(),
            "Circuit verification failed (n={}, index={})",
            n,
            index
        );
        Ok(())
    }

    #[test]
    fn test_merkle_tree_circuit() -> anyhow::Result<()> {
        // Generate random leaf data
        let n_leaves = 16; // Number of leaves
        let _max_depth = 4;
        let data = (0..n_leaves)
            .map(|i| GoldilocksField::from_canonical_u64(i))
            .collect::<Vec<_>>();
        // Hash the data to obtain leaf hashes
        let leaves: Vec<HashOut<GoldilocksField>> = data
            .iter()
            .map(|&element| {
                // Hash each field element to get the leaf hash
                H::hash_no_pad(&[element])
            })
            .collect();

        //initialize the Merkle tree
        let tree = MerkleTree::<F, D, H>::new(&leaves)?;

        // select leaf index to prove
        let leaf_index: usize = 8;
        let leaf = tree.layers[0][leaf_index];

        // get the Merkle proof for the selected leaf
        let proof = tree.get_proof(leaf_index)?;
        // sanity check:
        let check = proof.verify(leaf.clone(),tree.root().unwrap()).unwrap();
        assert_eq!(check, true);

        verify_circuit(leaf, proof, tree.root()?, leaf_index, n_leaves as usize)?;

        Ok(())
    }

    #[test]
    fn test_mt_roots_in_circuit() -> anyhow::Result<()> {
        for test_case in TEST_CASES.iter() {
            let n = test_case.n;
            let inputs = digest_seq::<F, D>(n);
            let tree = MerkleTree::<F, D, H>::new(&inputs)?;
            let expected_digest = test_case.digest;

            // Construct the expected root hash
            let expected_root = HashOut {
                elements: [
                    F::from_canonical_u64(expected_digest[0]),
                    F::from_canonical_u64(expected_digest[1]),
                    F::from_canonical_u64(expected_digest[2]),
                    F::from_canonical_u64(expected_digest[3]),
                ],
            };
            let proof = tree.get_proof(0)?;
            verify_circuit(
                tree.layers[0][0],
                proof,
                expected_root,
                0,
                n,
            )?;
        }

        Ok(())
    }

    #[test]
    fn test_singleton_merkle_circuit() -> anyhow::Result<()> {
        // Single field element test
        let data_elem = GoldilocksField::from_canonical_u64(42);
        let leaf_hash: HashOut<F> = H::hash_no_pad(&[data_elem]);
        // Build Merkle tree on singleton leaf
        let tree = MerkleTree::<F, D, H>::new(&[leaf_hash.clone()])?;
        let root = tree.root()?;
        let proof = tree.get_proof(0)?;
        assert!(proof.verify(leaf_hash.clone(), root).is_ok());

        // build and verify singleton case
        verify_circuit(
            leaf_hash.clone(),
            proof,
            root,
            0,
            1,
        )?;

        Ok(())
    }
}
