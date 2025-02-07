// Implementation of "safe" merkle tree
// consistent with the one in codex:
// https://github.com/codex-storage/nim-codex/blob/master/codex/merkletree/merkletree.nim

use anyhow::{ensure, Result};
// use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::hash::hash_types::{HashOut, RichField};
// use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::config::Hasher;
use std::ops::Shr;
use plonky2_field::types::{ HasExtension};
use crate::merkle_tree::key_compress::key_compress;
use crate::params::HF;
use codex_plonky2_circuits::circuits::params::NUM_HASH_OUT_ELTS;

// Constants for the keys used in compression
pub const KEY_NONE: u64 = 0x0;
pub const KEY_BOTTOM_LAYER: u64 = 0x1;
pub const KEY_ODD: u64 = 0x2;
pub const KEY_ODD_AND_BOTTOM_LAYER: u64 = 0x3;

/// Merkle tree struct, containing the layers, compression function, and zero hash.
#[derive(Clone)]
pub struct MerkleTree<
    F: RichField + HasExtension<D>,
    const D: usize,
> {
    pub layers: Vec<Vec<HashOut<F, NUM_HASH_OUT_ELTS>>>,
    pub zero: HashOut<F, NUM_HASH_OUT_ELTS>,
}

impl<
    F: RichField + HasExtension<D>,
    const D: usize,
> MerkleTree<F, D> {
    /// Constructs a new Merkle tree from the given leaves.
    pub fn new(
        leaves: &[HashOut<F, NUM_HASH_OUT_ELTS>],
        zero: HashOut<F, NUM_HASH_OUT_ELTS>,
    ) -> Result<Self> {
        let layers = merkle_tree_worker::<F, D>(leaves, zero, true)?;
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
    pub fn root(&self) -> Result<HashOut<F, NUM_HASH_OUT_ELTS>> {
        let last_layer = self.layers.last().ok_or_else(|| anyhow::anyhow!("Empty tree"))?;
        ensure!(last_layer.len() == 1, "Invalid Merkle tree");
        Ok(last_layer[0])
    }

    /// Generates a Merkle proof for a given leaf index.
    pub fn get_proof(&self, index: usize) -> Result<MerkleProof<F, D>> {
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
fn merkle_tree_worker<
    F: RichField + HasExtension<D>,
    const D: usize,
>(
    xs: &[HashOut<F, NUM_HASH_OUT_ELTS>],
    zero: HashOut<F, NUM_HASH_OUT_ELTS>,
    is_bottom_layer: bool,
) -> Result<Vec<Vec<HashOut<F, NUM_HASH_OUT_ELTS>>>> {
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
        let h = key_compress::<F, D, HF>(xs[2 * i], xs[2 * i + 1], key);
        ys.push(h);
    }

    if is_odd {
        let key = if is_bottom_layer {
            KEY_ODD_AND_BOTTOM_LAYER
        } else {
            KEY_ODD
        };
        let h = key_compress::<F, D, HF>(xs[n], zero, key);
        ys.push(h);
    }

    let mut layers = vec![xs.to_vec()];
    let mut upper_layers = merkle_tree_worker::<F, D>(&ys, zero, false)?;
    layers.append(&mut upper_layers);

    Ok(layers)
}

/// Merkle proof struct, containing the index, path, and other necessary data.
#[derive(Clone)]
pub struct MerkleProof<
    F: RichField + HasExtension<D>,
    const D: usize,
> {
    pub index: usize,       // Index of the leaf
    pub path: Vec<HashOut<F, NUM_HASH_OUT_ELTS>>, // Sibling hashes from the leaf to the root
    pub nleaves: usize,     // Total number of leaves
    pub zero: HashOut<F, NUM_HASH_OUT_ELTS>,
}

impl<
    F: RichField + HasExtension<D>,
    const D: usize,
> MerkleProof<F, D> {
    /// Reconstructs the root hash from the proof and the given leaf.
    pub fn reconstruct_root(&self, leaf: HashOut<F, NUM_HASH_OUT_ELTS>) -> Result<HashOut<F, NUM_HASH_OUT_ELTS>> {
        let mut m = self.nleaves;
        let mut j = self.index;
        let mut h = leaf;
        let mut bottom_flag = KEY_BOTTOM_LAYER;

        for p in &self.path {
            let odd_index = (j & 1) != 0;
            if odd_index {
                // The index of the child is odd
                h = key_compress::<F, D, HF>(*p, h, bottom_flag);
            } else {
                if j == m - 1 {
                    // Single child -> so odd node
                    h = key_compress::<F, D, HF>(h, *p, bottom_flag + 2);
                } else {
                    // Even node
                    h = key_compress::<F, D, HF>(h, *p, bottom_flag);
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
    pub fn reconstruct_root2(leaf: HashOut<F, NUM_HASH_OUT_ELTS>, path_bits: Vec<bool>, last_bits:Vec<bool>, path: Vec<HashOut<F, NUM_HASH_OUT_ELTS>>, mask_bits:Vec<bool>, depth: usize) -> Result<HashOut<F, NUM_HASH_OUT_ELTS>> {
        let is_last = compute_is_last(path_bits.clone(),last_bits);

        let mut h = vec![];
        h.push(leaf);
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
                h.push(key_compress::<F, D, HF>(*p, h[i], key));
            } else {
                h.push(key_compress::<F,D,HF>(h[i], *p, key));
            }
            i += 1;
        }

        let mut reconstructed_root = HashOut::<F, NUM_HASH_OUT_ELTS>::zero();
        for k in 0..depth{
            let diff = (mask_bits[k] as u64) - (mask_bits[k+1] as u64);
            let mul_res: Vec<F> = h[k+1].elements.iter().map(|e| e.mul(F::from_canonical_u64(diff))).collect();
            reconstructed_root = HashOut::<F, NUM_HASH_OUT_ELTS>::from_vec(
                mul_res.iter().zip(reconstructed_root.elements).map(|(e1,e2)| e1.add(e2)).collect()
            );
        }

        Ok(reconstructed_root)
    }

    /// Verifies the proof against a given root and leaf.
    pub fn verify(&self, leaf: HashOut<F, NUM_HASH_OUT_ELTS>, root: HashOut<F, NUM_HASH_OUT_ELTS>) -> Result<bool> {
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
