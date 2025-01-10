use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::{HashOut, RichField};
use plonky2_field::extension::Extendable;
use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2;

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

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use crate::merkle_tree::merkle_safe::{MerkleProof, MerkleTree};
    use plonky2::field::goldilocks_field::GoldilocksField;
    use plonky2::field::types::Field;
    use plonky2::hash::hash_types::HashOut;
    use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2;

    type F = GoldilocksField;
    const D: usize = 2;

    struct TestCase {
        n: usize,
        digest: [u64; 4],
    }

    #[test]
    fn test_merkle_roots() -> Result<()> {
        let zero = HashOut {
            elements: [F::ZERO; 4],
        };

        let test_cases: Vec<TestCase> = vec![
            TestCase { n: 1, digest: [0x232f21acc9d346d8, 0x2eba96d3a73822c1, 0x4163308f6d0eff64, 0x5190c2b759734aff] },
            TestCase { n: 2, digest: [0x999dde2cb60b5bdb, 0xacb725a87250a306, 0x8eeb00a6fc173443, 0x5f510b7eeece33bb] },
            TestCase { n: 3, digest: [0x00b72dc0a592b9c0, 0x68575842dd1c6e27, 0x871d5146985881d6, 0xc945d7f3d5fdde00] },
        ];

        for test_case in test_cases {
            let n = test_case.n;
            let expected_digest = test_case.digest;

            // Generate the inputs
            let inputs = digest_seq::<F,D>(n);

            // Build the Merkle tree
            let tree = MerkleTree::<F, D>::new(&inputs, zero.clone())?;

            // Get the computed root
            let computed_root = tree.root()?;

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
        }

        Ok(())
    }

    #[test]
    fn test_merkle_proof_with_given_leaf_and_root() -> Result<()> {
        // Parse the root
        let root_elements = vec![
            "14459953088494886308",
            "12400665201701660877",
            "8918969394875474575",
            "3734475392324688728",
        ];
        let root = HashOut {
            elements: root_elements
                .iter()
                .map(|s| {
                    let num = s.parse::<u64>().unwrap();
                    F::from_canonical_u64(num)
                })
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        };

        // Parse the leaf
        let leaf_elements = vec![
            "6216356142838248961",
            "7651361162368135479",
            "8250178335123580371",
            "3813462866599431579",
        ];
        let leaf = HashOut {
            elements: leaf_elements
                .iter()
                .map(|s| {
                    let num = s.parse::<u64>().unwrap();
                    F::from_canonical_u64(num)
                })
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        };

        // Parse the proof
        let proof_strings = vec![
            "1345604040032513712",
            "7222769029677219453",
            "4856886058017005512",
            "17218820401481758629",
            "6741690371018853470",
            "10000950172891759230",
            "1256624250298316158",
            "14572953286928282395",
            "11250861626949238654",
            "2066450512590186880",
            "4406339264013603126",
            "6649535526486987988",
            "14920223145083393283",
            "18017129979212138612",
            "1235310154294028825",
            "16382646529383194172",
        ];

        let proof_numbers: Vec<u64> = proof_strings
            .iter()
            .map(|s| s.parse::<u64>().unwrap())
            .collect();

        let proof_elements: Vec<F> = proof_numbers
            .iter()
            .map(|&num| F::from_canonical_u64(num))
            .collect();

        let path_hashes: Vec<HashOut<F>> = proof_elements
            .chunks(4)
            .map(|chunk| HashOut {
                elements: chunk.try_into().unwrap(),
            })
            .collect();

        let num_indices = 1 << path_hashes.len();
        let mut found = false;

        for index in 0..num_indices {
            let proof = MerkleProof::<F,D> {
                index,
                path: path_hashes.clone(),
                nleaves: num_indices,
                zero: HashOut {
                    elements: [F::ZERO; 4],
                },
            };

            // Reconstruct the root
            let reconstructed_root = proof.reconstruct_root(leaf.clone())?;

            // Compare with the given root
            if reconstructed_root == root {
                println!("Proof is valid for index {}", index);
                found = true;
                break;
            }
        }

        assert!(found, "No valid proof found for the given leaf and root");

        Ok(())
    }
}
