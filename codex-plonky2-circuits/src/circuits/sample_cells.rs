// Sample cells
// consistent with:
// https://github.com/codex-storage/codex-storage-proofs-circuits/blob/master/circuit/codex/sample_cells.circom
// circuit consists of:
// - reconstruct the dataset merkle root using the slot root as leaf
// - samples multiple cells by calling the sample_cells

use anyhow::Result;
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::{HashOut, RichField};
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::{PartialWitness, WitnessWrite, Witness};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig, Hasher, GenericHashOut};
use std::marker::PhantomData;
use itertools::Itertools;

use crate::merkle_tree::merkle_safe::MerkleTree;
use plonky2::hash::poseidon::PoseidonHash;

use plonky2::hash::hash_types::{HashOutTarget, NUM_HASH_OUT_ELTS};
use crate::merkle_tree::merkle_safe::{MerkleProof, MerkleProofTarget};
use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2;

use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::plonk::config::PoseidonGoldilocksConfig;

use plonky2::hash::hashing::PlonkyPermutation;
use crate::circuits::prove_single_cell::{MAX_DEPTH, SlotTree};
use crate::circuits::safe_tree_circuit::{MerkleTreeCircuit, MerkleTreeTargets};

// constatnts and types
const DATASET_DEPTH: usize = 8;
const N_SAMPLES: usize = 5;

type HF = PoseidonHash;

// ------ Dataset Tree --------
///dataset tree containing all slot trees
#[derive(Clone)]
pub struct DatasetTree<F: RichField, H: Hasher<F>> {
    pub tree: MerkleTree<F,H>, // dataset tree
    pub slot_trees: Vec<SlotTree<F,H>>, // vec of slot trees
}

/// Dataset Merkle proof struct, containing the dataset proof and N_SAMPLES proofs.
#[derive(Clone)]
pub struct DatasetMerkleProof<F: RichField, H: Hasher<F>> {
    pub slot_index: usize,
    pub entropy: usize,
    pub dataset_proof: MerkleProof<F,H>,       // proof for dataset level tree
    pub slot_proofs: Vec<MerkleProof<F,H>>, // proofs for sampled slot, contains N_SAMPLES proofs
}

impl<F: RichField, H: Hasher<F>> Default for DatasetTree<F,H> {
    /// dataset tree with fake data, for testing only
    fn default() -> Self {
        let mut slot_trees = vec![];
        let n_slots = 1<<DATASET_DEPTH;
        for i in 0..n_slots {
            slot_trees.push(SlotTree::<F,H>::default());
        }
        // get the roots or slot trees
        let slot_roots = slot_trees.iter()
            .map(|t| {
                t.tree.root().unwrap()
            })
            .collect::<Vec<_>>();
        // zero hash
        let zero = HashOut {
            elements: [F::ZERO; 4],
        };
        let dataset_tree = MerkleTree::<F, H>::new(&slot_roots, zero).unwrap();
        Self{
            tree: dataset_tree,
            slot_trees,
        }
    }
}


impl<F: RichField, H: Hasher<F>> DatasetTree<F, H> {
    /// same as default but with supplied slot trees
    pub fn new(slot_trees: Vec<SlotTree<F,H>>) -> Self{
        // get the roots or slot trees
        let slot_roots = slot_trees.iter()
            .map(|t| {
                t.tree.root().unwrap()
            })
            .collect::<Vec<_>>();
        // zero hash
        let zero = HashOut {
            elements: [F::ZERO; 4],
        };
        let dataset_tree = MerkleTree::<F, H>::new(&slot_roots, zero).unwrap();
        Self{
            tree: dataset_tree,
            slot_trees,
        }
    }

    /// generates a dataset level proof for given slot index
    /// just a regular merkle tree proof
    pub fn get_proof(&self, index: usize) -> MerkleProof<F, H> {
        let dataset_proof = self.tree.get_proof(index).unwrap();
        dataset_proof
    }

    /// generates a proof for given slot index
    /// also takes entropy so it can use it sample the slot
    pub fn sample_slot(&self, index: usize, entropy: usize) -> DatasetMerkleProof<F, H> {
        let dataset_proof = self.get_proof(index);
        let slot = &self.slot_trees[index];
        let slot_root = slot.tree.root().unwrap();
        let mut slot_proofs = vec![];
        // get the index for cell from H(slot_root|counter|entropy)
        for i in 0..N_SAMPLES {
            let cell_index_bits = calculate_cell_index_bits(entropy, slot_root, i);
            let cell_index = bits_le_padded_to_usize(&cell_index_bits);
            slot_proofs.push(slot.get_proof(cell_index));
        }

        DatasetMerkleProof{
            slot_index: index,
            entropy,
            dataset_proof,
            slot_proofs,
        }
    }

    // verify the sampling - non-circuit version
    pub fn verify_sampling(&self, proof: DatasetMerkleProof<F,H>) -> Result<bool>{
        let slot = &self.slot_trees[proof.slot_index];
        let slot_root = slot.tree.root().unwrap();
        // check dataset level proof
        let d_res = proof.dataset_proof.verify(slot_root,self.tree.root().unwrap());
        if(d_res.unwrap() == false){
            return Ok(false);
        }
        // sanity check
        assert_eq!(N_SAMPLES, proof.slot_proofs.len());
        // get the index for cell from H(slot_root|counter|entropy)
        for i in 0..N_SAMPLES {
            let cell_index_bits = calculate_cell_index_bits(proof.entropy, slot_root, i);
            let cell_index = bits_le_padded_to_usize(&cell_index_bits);
            //check the cell_index is the same as one in the proof
            assert_eq!(cell_index, proof.slot_proofs[i].index);
            let s_res = slot.verify_cell_proof(proof.slot_proofs[i].clone(),slot_root);
            if(s_res.unwrap() == false){
                return Ok(false);
            }
        }
        Ok(true)
    }
}

// --------- helper functions --------------
fn calculate_cell_index_bits<F: RichField>(p0: usize, p1: HashOut<F>, p2: usize) -> Vec<bool> {
    let p0_field = F::from_canonical_u64(p0 as u64);
    let p2_field = F::from_canonical_u64(p2 as u64);
    let mut inputs = Vec::new();
    inputs.extend_from_slice(&p1.elements);
    inputs.push(p0_field);
    inputs.push(p2_field);
    let p_hash = HF::hash_no_pad(&inputs);
    let p_bytes = p_hash.to_bytes();

    let p_bits = take_n_bits_from_bytes(&p_bytes, MAX_DEPTH);
    p_bits
}
fn take_n_bits_from_bytes(bytes: &[u8], n: usize) -> Vec<bool> {
    bytes.iter()
        .flat_map(|byte| (0..8u8).map(move |i| (byte >> i) & 1 == 1))
        .take(n)
        .collect()
}
/// Converts a vector of bits (LSB first) into an index (usize).
fn bits_le_padded_to_usize(bits: &[bool]) -> usize {
    bits.iter().enumerate().fold(0usize, |acc, (i, &bit)| {
        if bit {
            acc | (1 << i)
        } else {
            acc
        }
    })
}
