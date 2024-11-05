// Implementation of "safe" merkle tree
// consistent with the one in codex:
// https://github.com/codex-storage/nim-codex/blob/master/codex/merkletree/merkletree.nim

use std::marker::PhantomData;
use anyhow::{ensure, Result};
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::hash::hash_types::{HashOut, RichField};
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::config::Hasher;
use std::ops::Shr;
use plonky2_field::types::Field;
use crate::circuits::keyed_compress::key_compress;
use crate::circuits::params::HF;

// Constants for the keys used in compression
pub const KEY_NONE: u64 = 0x0;
pub const KEY_BOTTOM_LAYER: u64 = 0x1;
pub const KEY_ODD: u64 = 0x2;
pub const KEY_ODD_AND_BOTTOM_LAYER: u64 = 0x3;

/// Merkle tree struct, containing the layers, compression function, and zero hash.
#[derive(Clone)]
pub struct MerkleTree<F: RichField> {
    pub layers: Vec<Vec<HashOut<F>>>,
    pub zero: HashOut<F>,
}

impl<F: RichField> MerkleTree<F> {
    /// Constructs a new Merkle tree from the given leaves.
    pub fn new(
        leaves: &[HashOut<F>],
        zero: HashOut<F>,
    ) -> Result<Self> {
        let layers = merkle_tree_worker::<F>(leaves, zero, true)?;
        Ok(Self {
            layers,
            zero,
        })
    }

    /// Returns the depth of the Merkle tree.
    pub fn depth(&self) -> usize {
        self.layers.len() - 1
    }

    /// Returns the number of leaves in the Merkle tree.
    pub fn leaves_count(&self) -> usize {
        self.layers[0].len()
    }

    /// Returns the root hash of the Merkle tree.
    pub fn root(&self) -> Result<HashOut<F>> {
        let last_layer = self.layers.last().ok_or_else(|| anyhow::anyhow!("Empty tree"))?;
        ensure!(last_layer.len() == 1, "Invalid Merkle tree");
        Ok(last_layer[0])
    }

    /// Generates a Merkle proof for a given leaf index.
    pub fn get_proof(&self, index: usize) -> Result<MerkleProof<F>> {
        let depth = self.depth();
        let nleaves = self.leaves_count();

        ensure!(index < nleaves, "Index out of bounds");

        let mut path = Vec::with_capacity(depth);
        let mut k = index;
        let mut m = nleaves;

        for i in 0..depth {
            let j = k ^ 1;
            let sibling = if j < m {
                self.layers[i][j]
            } else {
                self.zero
            };
            path.push(sibling);
            k = k >> 1;
            m = (m + 1) >> 1;
        }

        Ok(MerkleProof {
            index,
            path,
            nleaves,
            zero: self.zero,
        })
    }
}

/// Build the Merkle tree layers.
fn merkle_tree_worker<F: RichField>(
    xs: &[HashOut<F>],
    zero: HashOut<F>,
    is_bottom_layer: bool,
) -> Result<Vec<Vec<HashOut<F>>>> {
    let m = xs.len();
    if !is_bottom_layer && m == 1 {
        return Ok(vec![xs.to_vec()]);
    }

    let halfn = m / 2;
    let n = 2 * halfn;
    let is_odd = n != m;

    let mut ys = Vec::with_capacity(halfn + if is_odd { 1 } else { 0 });

    for i in 0..halfn {
        let key = if is_bottom_layer { KEY_BOTTOM_LAYER } else { KEY_NONE };
        let h = key_compress::<F, HF>(xs[2 * i], xs[2 * i + 1], key);
        ys.push(h);
    }

    if is_odd {
        let key = if is_bottom_layer {
            KEY_ODD_AND_BOTTOM_LAYER
        } else {
            KEY_ODD
        };
        let h = key_compress::<F, HF>(xs[n], zero, key);
        ys.push(h);
    }

    let mut layers = vec![xs.to_vec()];
    let mut upper_layers = merkle_tree_worker::<F>(&ys, zero, false)?;
    layers.append(&mut upper_layers);

    Ok(layers)
}

/// Merkle proof struct, containing the index, path, and other necessary data.
#[derive(Clone)]
pub struct MerkleProof<F: RichField> {
    pub index: usize,       // Index of the leaf
    pub path: Vec<HashOut<F>>, // Sibling hashes from the leaf to the root
    pub nleaves: usize,     // Total number of leaves
    pub zero: HashOut<F>,
}

impl<F: RichField> MerkleProof<F> {
    /// Reconstructs the root hash from the proof and the given leaf.
    pub fn reconstruct_root(&self, leaf: HashOut<F>) -> Result<HashOut<F>> {
        let mut m = self.nleaves;
        let mut j = self.index;
        let mut h = leaf;
        let mut bottom_flag = KEY_BOTTOM_LAYER;

        for p in &self.path {
            let odd_index = (j & 1) != 0;
            if odd_index {
                // The index of the child is odd
                h = key_compress::<F,HF>(*p, h, bottom_flag);
            } else {
                if j == m - 1 {
                    // Single child -> so odd node
                    h = key_compress::<F,HF>(h, *p, bottom_flag + 2);
                } else {
                    // Even node
                    h = key_compress::<F,HF>(h, *p, bottom_flag);
                }
            }
            bottom_flag = KEY_NONE;
            j = j.shr(1);
            m = (m + 1).shr(1);
        }

        Ok(h)
    }

    /// reconstruct the root using path_bits and last_bits in similar way as the circuit
    /// this is used for testing - sanity check
    pub fn reconstruct_root2(leaf: HashOut<F>, path_bits: Vec<bool>, last_bits:Vec<bool>,  path: Vec<HashOut<F>>) -> Result<HashOut<F>> {
        let is_last = compute_is_last(path_bits.clone(),last_bits);

        let mut h = leaf;
        let mut i = 0;

        for p in &path {
            let bottom = if(i==0){
                KEY_BOTTOM_LAYER
            }else{
                KEY_NONE
            };

            let odd = (is_last[i] as usize) * (1-(path_bits[i] as usize));

            let key = bottom + (2 * (odd as u64));
            let odd_index = path_bits[i];
            if odd_index {
                h = key_compress::<F,HF>(*p, h, key);
            } else {
                h = key_compress::<F,HF>(h, *p, key);
            }
            i += 1;
        }

        Ok(h)
    }

    /// Verifies the proof against a given root and leaf.
    pub fn verify(&self, leaf: HashOut<F>, root: HashOut<F>) -> Result<bool> {
        let reconstructed_root = self.reconstruct_root(leaf)?;
        Ok(reconstructed_root == root)
    }
}

///helper function to compute is_last
fn compute_is_last(path_bits: Vec<bool>, last_bits: Vec<bool>) -> Vec<bool> {
    let max_depth = path_bits.len();

    // Initialize isLast vector
    let mut is_last = vec![false; max_depth + 1];
    is_last[max_depth] = true; // Set isLast[max_depth] to 1 (true)

    // Iterate over eq and isLast in reverse order
    for i in (0..max_depth).rev() {
        let eq_out = path_bits[i] == last_bits[i]; // eq[i].out
        is_last[i] = is_last[i + 1] && eq_out; // isLast[i] = isLast[i+1] * eq[i].out
    }

    is_last
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::field::types::Field;
    use crate::circuits::keyed_compress::key_compress;

    // types used in all tests
    type F = GoldilocksField;
    type H = PoseidonHash;

    fn compress(
        x: HashOut<F>,
        y: HashOut<F>,
        key: u64,
    ) -> HashOut<F> {
        key_compress::<F,HF>(x,y,key)
    }

    fn make_tree(
        data: &[F],
        zero: HashOut<F>,
    ) -> Result<MerkleTree<F>> {
        // Hash the data to obtain leaf hashes
        let leaves: Vec<HashOut<GoldilocksField>> = data
            .iter()
            .map(|&element| {
                // Hash each field element to get the leaf hash
                H::hash_no_pad(&[element])
            })
            .collect();

        MerkleTree::<F>::new(&leaves, zero)
    }

    #[test]
    fn single_proof_test() -> Result<()> {
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

        let zero = HashOut {
            elements: [F::ZERO; 4],
        };

        // Build the Merkle tree
        let tree = MerkleTree::<F>::new(&leaves, zero)?;

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
    fn test_correctness_even_bottom_layer() -> Result<()> {
        // Data for the test (field elements)
        let data = (1u64..=8)
            .map(|i| F::from_canonical_u64(i))
            .collect::<Vec<_>>();

        // Hash the data to get leaf hashes
        let leaf_hashes: Vec<HashOut<F>> = data
            .iter()
            .map(|&element| H::hash_no_pad(&[element]))
            .collect();

        // zero hash
        let zero = HashOut {
            elements: [F::ZERO; 4],
        };

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
        let tree = make_tree(&data, zero)?;

        // Get the computed root
        let computed_root = tree.root()?;

        // Check that the computed root matches the expected root
        assert_eq!(computed_root, expected_root);

        Ok(())
    }

    #[test]
    fn test_correctness_odd_bottom_layer() -> Result<()> {
        // Data for the test (field elements)
        let data = (1u64..=7)
            .map(|i| F::from_canonical_u64(i))
            .collect::<Vec<_>>();

        // Hash the data to get leaf hashes
        let leaf_hashes: Vec<HashOut<F>> = data
            .iter()
            .map(|&element| H::hash_no_pad(&[element]))
            .collect();

        // zero hash
        let zero = HashOut {
            elements: [F::ZERO; 4],
        };

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
                        zero,
                        KEY_ODD_AND_BOTTOM_LAYER,
                    ),
                    KEY_NONE,
                ),
                KEY_NONE,
            );

        // Build the tree
        let tree = make_tree(&data, zero)?;

        // Get the computed root
        let computed_root = tree.root()?;

        // Check that the computed root matches the expected root
        assert_eq!(computed_root, expected_root);

        Ok(())
    }

    #[test]
    fn test_correctness_even_bottom_odd_upper_layers() -> Result<()> {
        // Data for the test (field elements)
        let data = (1u64..=10)
            .map(|i| F::from_canonical_u64(i))
            .collect::<Vec<_>>();

        // Hash the data to get leaf hashes
        let leaf_hashes: Vec<HashOut<F>> = data
            .iter()
            .map(|&element| H::hash_no_pad(&[element]))
            .collect();

        // zero hash
        let zero = HashOut {
            elements: [F::ZERO; 4],
        };

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
                    zero,
                    KEY_ODD,
                ),
                zero,
                KEY_ODD,
            ),
            KEY_NONE,
        );

        // Build the tree
        let tree = make_tree(&data, zero)?;

        // Get the computed root
        let computed_root = tree.root()?;

        // Check that the computed root matches the expected root
        assert_eq!(computed_root, expected_root);

        Ok(())
    }

    #[test]
    fn test_proofs() -> Result<()> {
        // Data for the test (field elements)
        let data = (1u64..=10)
            .map(|i| F::from_canonical_u64(i))
            .collect::<Vec<_>>();

        // Hash the data to get leaf hashes
        let leaf_hashes: Vec<HashOut<F>> = data
            .iter()
            .map(|&element| H::hash_no_pad(&[element]))
            .collect();

        // zero hash
        let zero = HashOut {
            elements: [F::ZERO; 4],
        };

        // Build the tree
        let tree = MerkleTree::<F>::new(&leaf_hashes, zero)?;

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
}