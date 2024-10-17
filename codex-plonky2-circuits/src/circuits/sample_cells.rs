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
use crate::circuits::prove_single_cell::{SingleCellTargets, SlotTreeCircuit};
use crate::circuits::params::{MAX_DEPTH, BOT_DEPTH, N_FIELD_ELEMS_PER_CELL, N_CELLS_IN_BLOCKS, N_BLOCKS, N_CELLS, HF, DATASET_DEPTH, N_SAMPLES};

use crate::circuits::safe_tree_circuit::{MerkleTreeCircuit, MerkleTreeTargets};
use crate::circuits::utils::{bits_le_padded_to_usize, calculate_cell_index_bits};

// ------ Dataset Tree --------
///dataset tree containing all slot trees
#[derive(Clone)]
pub struct DatasetTreeCircuit<
    F: RichField + Extendable<D> + Poseidon2,
    C: GenericConfig<D, F = F>,
    const D: usize,
    H: Hasher<F> + AlgebraicHasher<F>,
> {
    pub tree: MerkleTreeCircuit<F, C, D, H>, // dataset tree
    pub slot_trees: Vec<SlotTreeCircuit<F,C,D,H>>, // vec of slot trees
}

/// Dataset Merkle proof struct, containing the dataset proof and N_SAMPLES proofs.
#[derive(Clone)]
pub struct DatasetMerkleProof<F: RichField, H: Hasher<F>> {
    pub slot_index: usize,
    pub entropy: usize,
    pub dataset_proof: MerkleProof<F,H>,       // proof for dataset level tree
    pub slot_proofs: Vec<MerkleProof<F,H>>, // proofs for sampled slot, contains N_SAMPLES proofs
}

impl<
    F: RichField + Extendable<D> + Poseidon2,
    C: GenericConfig<D, F = F>,
    const D: usize,
    H: Hasher<F> + AlgebraicHasher<F>,
> Default for DatasetTreeCircuit<F,C,D,H> {
    /// dataset tree with fake data, for testing only
    fn default() -> Self {
        let mut slot_trees = vec![];
        let n_slots = 1<<DATASET_DEPTH;
        for i in 0..n_slots {
            slot_trees.push(SlotTreeCircuit::<F,C,D,H>::default());
        }
        // get the roots or slot trees
        let slot_roots = slot_trees.iter()
            .map(|t| {
                t.tree.tree.root().unwrap()
            })
            .collect::<Vec<_>>();
        // zero hash
        let zero = HashOut {
            elements: [F::ZERO; 4],
        };
        let dataset_tree = MerkleTree::<F, H>::new(&slot_roots, zero).unwrap();
        Self{
            tree: MerkleTreeCircuit::<F,C,D,H>{ tree:dataset_tree, _phantom:Default::default()},
            slot_trees,
        }
    }
}


impl<
    F: RichField + Extendable<D> + Poseidon2,
    C: GenericConfig<D, F = F>,
    const D: usize,
    H: Hasher<F> + AlgebraicHasher<F>,
> DatasetTreeCircuit<F,C,D,H> {
    /// same as default but with supplied slot trees
    pub fn new(slot_trees: Vec<SlotTreeCircuit<F,C,D,H>>) -> Self{
        // get the roots or slot trees
        let slot_roots = slot_trees.iter()
            .map(|t| {
                t.tree.tree.root().unwrap()
            })
            .collect::<Vec<_>>();
        // zero hash
        let zero = HashOut {
            elements: [F::ZERO; 4],
        };
        let dataset_tree = MerkleTree::<F, H>::new(&slot_roots, zero).unwrap();
        Self{
            tree: MerkleTreeCircuit::<F,C,D,H>{ tree:dataset_tree, _phantom:Default::default()},
            slot_trees,
        }
    }

    /// generates a dataset level proof for given slot index
    /// just a regular merkle tree proof
    pub fn get_proof(&self, index: usize) -> MerkleProof<F, H> {
        let dataset_proof = self.tree.tree.get_proof(index).unwrap();
        dataset_proof
    }

    /// generates a proof for given slot index
    /// also takes entropy so it can use it sample the slot
    pub fn sample_slot(&self, index: usize, entropy: usize) -> DatasetMerkleProof<F, H> {
        let dataset_proof = self.tree.tree.get_proof(index).unwrap();
        let slot = &self.slot_trees[index];
        let slot_root = slot.tree.tree.root().unwrap();
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
        let slot_root = slot.tree.tree.root().unwrap();
        // check dataset level proof
        let d_res = proof.dataset_proof.verify(slot_root,self.tree.tree.root().unwrap());
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

//------- single cell struct ------

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DatasetTargets<
    F: RichField + Extendable<D> + Poseidon2,
    C: GenericConfig<D, F = F>,
    const D: usize,
    H: Hasher<F> + AlgebraicHasher<F>,
> {
    // pub expected_dataset_root_target: HashOutTarget,
    // pub slot_index: Target,
    // pub entropy_target: Target,
    // pub slot_root: HashOutTarget,
    pub slot_proofs: Vec<SingleCellTargets<F, C, D, H>>,


    // pub proof_target: MerkleProofTarget,
    // pub leaf_target: Vec<Target>,
    // pub path_bits: Vec<BoolTarget>,
    // pub last_bits: Vec<BoolTarget>,
    _phantom: PhantomData<(C,H)>,
}

//------- circuit impl --------
impl<
    F: RichField + Extendable<D> + Poseidon2,
    C: GenericConfig<D, F=F>,
    const D: usize,
    H: Hasher<F> + AlgebraicHasher<F> + Hasher<F>,
> DatasetTreeCircuit<F, C, D, H> {

    // the in-circuit sampling of a slot in a dataset
    pub fn sample_slot_circuit(
        &mut self,
        builder: &mut CircuitBuilder::<F, D>,
    )-> DatasetTargets<F,C,D,H>{

        // Create virtual targets
        // let slot_root = builder.add_virtual_hash();
        let mut slot_proofs =vec![];
        for i in 0..N_SAMPLES{
            let proof_i = SlotTreeCircuit::<F,C,D,H>::prove_single_cell(builder);
            slot_proofs.push(proof_i);
        }

        DatasetTargets::<F,C,D,H>{
            // expected_dataset_root_target: HashOutTarget {},
            // slot_index: Default::default(),
            // entropy_target: Default::default(),
            // slot_root: HashOutTarget {},
            slot_proofs,
            _phantom: Default::default(),
        }
    }

    // assign the witnesses to the target
    // takes the dataset tree, slot index, and entropy
    pub fn sample_slot_assign_witness(
        &mut self,
        pw: &mut PartialWitness<F>,
        targets: DatasetTargets<F,C,D,H>,
        dataset_tree: DatasetTreeCircuit<F,C,D,H>,
        slot_index:usize,
        entropy:usize,
    ){


    }

}

#[cfg(test)]
mod tests {
    use std::time::Instant;
    use super::*;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use plonky2::iop::witness::PartialWitness;

    //types for tests
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    type H = PoseidonHash;

    #[test]
    fn test_sample_cells() {
        let dataset_t = DatasetTreeCircuit::<F,C,D,H>::default();
        let slot_index = 2;
        let entropy = 123;
        let proof = dataset_t.sample_slot(slot_index,entropy);
        let res = dataset_t.verify_sampling(proof).unwrap();
        assert_eq!(res, true);
    }
}