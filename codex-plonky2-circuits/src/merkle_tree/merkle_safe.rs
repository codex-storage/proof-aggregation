// Implementation of "safe" merkle tree
// consistent with the one in codex:
// https://github.com/codex-storage/nim-codex/blob/master/codex/merkletree/merkletree.nim

use anyhow::{ensure, Result};
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::hash::hash_types::{HashOut, HashOutTarget, RichField};
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::config::Hasher;
use std::ops::Shr;
use plonky2_field::types::Field;

// Constants for the keys used in compression
pub const KEY_NONE: u64 = 0x0;
pub const KEY_BOTTOM_LAYER: u64 = 0x1;
pub const KEY_ODD: u64 = 0x2;
pub const KEY_ODD_AND_BOTTOM_LAYER: u64 = 0x3;

/// Trait for a hash function that supports keyed compression.
pub trait KeyedHasher<F: RichField>: Hasher<F> {
    fn compress(x: Self::Hash, y: Self::Hash, key: u64) -> Self::Hash;
}

impl KeyedHasher<GoldilocksField> for PoseidonHash {
    fn compress(x: Self::Hash, y: Self::Hash, key: u64) -> Self::Hash {
        let key_field = GoldilocksField::from_canonical_u64(key);
        let mut inputs = Vec::new();
        inputs.extend_from_slice(&x.elements);
        inputs.extend_from_slice(&y.elements);
        inputs.push(key_field);
        PoseidonHash::hash_no_pad(&inputs) // TODO: double-check this function
    }
}

/// Merkle tree struct, containing the layers, compression function, and zero hash.
#[derive(Clone)]
pub struct MerkleTree<F: RichField, H: KeyedHasher<F>> {
    pub layers: Vec<Vec<H::Hash>>,
    pub compress: fn(H::Hash, H::Hash, u64) -> H::Hash,
    pub zero: H::Hash,
}

impl<F: RichField, H: KeyedHasher<F>> MerkleTree<F, H> {
    /// Constructs a new Merkle tree from the given leaves.
    pub fn new(
        leaves: &[H::Hash],
        zero: H::Hash,
        compress: fn(H::Hash, H::Hash, u64) -> H::Hash,
    ) -> Result<Self> {
        let layers = merkle_tree_worker::<F,H>(leaves, zero, compress, true)?;
        Ok(Self {
            layers,
            compress,
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
    pub fn root(&self) -> Result<H::Hash> {
        let last_layer = self.layers.last().ok_or_else(|| anyhow::anyhow!("Empty tree"))?;
        ensure!(last_layer.len() == 1, "Invalid Merkle tree");
        Ok(last_layer[0])
    }

    /// Generates a Merkle proof for a given leaf index.
    pub fn get_proof(&self, index: usize) -> Result<MerkleProof<F, H>> {
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
            compress: self.compress,
            zero: self.zero,
        })
    }
}

/// Build the Merkle tree layers.
fn merkle_tree_worker<F: RichField, H: KeyedHasher<F>>(
    xs: &[H::Hash],
    zero: H::Hash,
    compress: fn(H::Hash, H::Hash, u64) -> H::Hash,
    is_bottom_layer: bool,
) -> Result<Vec<Vec<H::Hash>>> {
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
        let h = compress(xs[2 * i], xs[2 * i + 1], key);
        ys.push(h);
    }

    if is_odd {
        let key = if is_bottom_layer {
            KEY_ODD_AND_BOTTOM_LAYER
        } else {
            KEY_ODD
        };
        let h = compress(xs[n], zero, key);
        ys.push(h);
    }

    let mut layers = vec![xs.to_vec()];
    let mut upper_layers = merkle_tree_worker::<F,H>(&ys, zero, compress, false)?;
    layers.append(&mut upper_layers);

    Ok(layers)
}

/// Merkle proof struct, containing the index, path, and other necessary data.
#[derive(Clone)]
pub struct MerkleProof<F: RichField, H: KeyedHasher<F>> {
    pub index: usize,       // Index of the leaf
    pub path: Vec<H::Hash>, // Sibling hashes from the leaf to the root
    pub nleaves: usize,     // Total number of leaves
    pub compress: fn(H::Hash, H::Hash, u64) -> H::Hash, // compression function - TODO: make it generic instead
    pub zero: H::Hash,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MerkleProofTarget {
    /// The Merkle digest of each sibling subtree, staying from the bottommost layer.
    pub path: Vec<HashOutTarget>,
}

impl<F: RichField, H: KeyedHasher<F>> MerkleProof<F, H> {
    /// Reconstructs the root hash from the proof and the given leaf.
    pub fn reconstruct_root(&self, leaf: H::Hash) -> Result<H::Hash> {
        let mut m = self.nleaves;
        let mut j = self.index;
        let mut h = leaf;
        let mut bottom_flag = KEY_BOTTOM_LAYER;

        for p in &self.path {
            let odd_index = (j & 1) != 0;
            if odd_index {
                // The index of the child is odd
                h = (self.compress)(*p, h, bottom_flag);
            } else {
                if j == m - 1 {
                    // Single child -> so odd node
                    h = (self.compress)(h, *p, bottom_flag + 2);
                } else {
                    // Even node
                    h = (self.compress)(h, *p, bottom_flag);
                }
            }
            bottom_flag = KEY_NONE;
            j = j.shr(1);
            m = (m + 1).shr(1);
        }

        Ok(h)
    }

    /// Verifies the proof against a given root and leaf.
    pub fn verify(&self, leaf: H::Hash, root: H::Hash) -> Result<bool> {
        let reconstructed_root = self.reconstruct_root(leaf)?;
        Ok(reconstructed_root == root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::field::types::Field;

    // Constants for the keys used in compression
    // const KEY_NONE: u64 = 0x0;
    // const KEY_BOTTOM_LAYER: u64 = 0x1;
    // const KEY_ODD: u64 = 0x2;
    // const KEY_ODD_AND_BOTTOM_LAYER: u64 = 0x3;

    fn compress(
        x: HashOut<GoldilocksField>,
        y: HashOut<GoldilocksField>,
        key: u64,
    ) -> HashOut<GoldilocksField> {
        let key_field = GoldilocksField::from_canonical_u64(key);
        let mut inputs = Vec::new();
        inputs.extend_from_slice(&x.elements);
        inputs.extend_from_slice(&y.elements);
        inputs.push(key_field);
        PoseidonHash::hash_no_pad(&inputs)
    }

    fn make_tree(
        data: &[GoldilocksField],
        zero: HashOut<GoldilocksField>,
    ) -> Result<MerkleTree<GoldilocksField, PoseidonHash>> {
        let compress_fn = PoseidonHash::compress;

        // Hash the data to obtain leaf hashes
        let leaves: Vec<HashOut<GoldilocksField>> = data
            .iter()
            .map(|&element| {
                // Hash each field element to get the leaf hash
                PoseidonHash::hash_no_pad(&[element])
            })
            .collect();

        MerkleTree::<GoldilocksField, PoseidonHash>::new(&leaves, zero, compress_fn)
    }

    #[test]
    fn single_proof_test() -> Result<()> {
        let data = (1u64..=8)
            .map(|i| GoldilocksField::from_canonical_u64(i))
            .collect::<Vec<_>>();

        // Hash the data to obtain leaf hashes
        let leaves: Vec<HashOut<GoldilocksField>> = data
            .iter()
            .map(|&element| {
                // Hash each field element to get the leaf hash
                PoseidonHash::hash_no_pad(&[element])
            })
            .collect();

        let zero = HashOut {
            elements: [GoldilocksField::ZERO; 4],
        };

        let compress_fn = PoseidonHash::compress;

        // Build the Merkle tree
        let tree = MerkleTree::<GoldilocksField, PoseidonHash>::new(&leaves, zero, compress_fn)?;

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
            .map(|i| GoldilocksField::from_canonical_u64(i))
            .collect::<Vec<_>>();

        // Hash the data to get leaf hashes
        let leaf_hashes: Vec<HashOut<GoldilocksField>> = data
            .iter()
            .map(|&element| PoseidonHash::hash_no_pad(&[element]))
            .collect();

        // zero hash
        let zero = HashOut {
            elements: [GoldilocksField::ZERO; 4],
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
            .map(|i| GoldilocksField::from_canonical_u64(i))
            .collect::<Vec<_>>();

        // Hash the data to get leaf hashes
        let leaf_hashes: Vec<HashOut<GoldilocksField>> = data
            .iter()
            .map(|&element| PoseidonHash::hash_no_pad(&[element]))
            .collect();

        // zero hash
        let zero = HashOut {
            elements: [GoldilocksField::ZERO; 4],
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
            .map(|i| GoldilocksField::from_canonical_u64(i))
            .collect::<Vec<_>>();

        // Hash the data to get leaf hashes
        let leaf_hashes: Vec<HashOut<GoldilocksField>> = data
            .iter()
            .map(|&element| PoseidonHash::hash_no_pad(&[element]))
            .collect();

        // zero hash
        let zero = HashOut {
            elements: [GoldilocksField::ZERO; 4],
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
            .map(|i| GoldilocksField::from_canonical_u64(i))
            .collect::<Vec<_>>();

        // Hash the data to get leaf hashes
        let leaf_hashes: Vec<HashOut<GoldilocksField>> = data
            .iter()
            .map(|&element| PoseidonHash::hash_no_pad(&[element]))
            .collect();

        // zero hash
        let zero = HashOut {
            elements: [GoldilocksField::ZERO; 4],
        };

        let compress_fn = PoseidonHash::compress;

        // Build the tree
        let tree = MerkleTree::<GoldilocksField, PoseidonHash>::new(&leaf_hashes, zero, compress_fn)?;

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