// Sample cells
// consistent with:
// https://github.com/codex-storage/codex-storage-proofs-circuits/blob/master/circuit/codex/sample_cells.circom
// circuit consists of:
// - reconstruct the dataset merkle root using the slot root as leaf
// - samples multiple cells by calling the sample_cells

use anyhow::Result;
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::{HashOut, HashOutTarget, NUM_HASH_OUT_ELTS, RichField};
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::{PartialWitness, WitnessWrite, Witness};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig, Hasher, GenericHashOut};
use std::marker::PhantomData;
use itertools::Itertools;

use crate::merkle_tree::merkle_safe::MerkleTree;
use plonky2::hash::poseidon::PoseidonHash;

use crate::merkle_tree::merkle_safe::{MerkleProof, MerkleProofTarget};
use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2;

use plonky2::plonk::config::PoseidonGoldilocksConfig;

use plonky2::hash::hashing::PlonkyPermutation;
use crate::circuits::prove_single_cell::{SingleCellTargets, SlotTreeCircuit};
use crate::circuits::params::{BOT_DEPTH, DATASET_DEPTH, MAX_DEPTH, N_FIELD_ELEMS_PER_CELL, N_SAMPLES, TESTING_SLOT_INDEX};

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
    /// dataset tree with fake data, for testing only
    /// create data for only the TESTING_SLOT_INDEX in params file
    pub fn new_for_testing() -> Self {
        let mut slot_trees = vec![];
        let n_slots = 1<<DATASET_DEPTH;
        // zero hash
        let zero = HashOut {
            elements: [F::ZERO; 4],
        };
        let zero_slot = SlotTreeCircuit::<F,C,D,H>{
            tree: MerkleTreeCircuit {
                tree: MerkleTree::<F,H>::new(&[zero.clone()], zero.clone()).unwrap(),
                _phantom: Default::default(),
            },
            block_trees: vec![],
            cell_data: vec![],
        };
        for i in 0..n_slots {
            if(i == TESTING_SLOT_INDEX) {
                slot_trees.push(SlotTreeCircuit::<F, C, D, H>::new_for_testing());
            }else{
                slot_trees.push(zero_slot.clone());
            }

        }
        // get the roots or slot trees
        let slot_roots = slot_trees.iter()
            .map(|t| {
                t.tree.tree.root().unwrap()
            })
            .collect::<Vec<_>>();
        let dataset_tree = MerkleTree::<F, H>::new(&slot_roots, zero).unwrap();
        Self{
            tree: MerkleTreeCircuit::<F,C,D,H>{ tree:dataset_tree, _phantom:Default::default()},
            slot_trees,
        }
    }

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

#[derive(Clone)]
pub struct DatasetTargets<
    F: RichField + Extendable<D> + Poseidon2,
    C: GenericConfig<D, F = F>,
    const D: usize,
    H: Hasher<F> + AlgebraicHasher<F>,
> {
    pub dataset_proof: MerkleProofTarget, // proof that slot_root in dataset tree
    pub dataset_root: HashOutTarget,

    pub cell_data: Vec<Vec<Target>>,
    pub entropy: HashOutTarget,
    pub slot_index: Target,
    pub slot_root: HashOutTarget,
    pub slot_proofs: Vec<MerkleProofTarget>,

    _phantom: PhantomData<(C,H)>,
}

//------- circuit impl --------
impl<
    F: RichField + Extendable<D> + Poseidon2,
    C: GenericConfig<D, F=F>,
    const D: usize,
    H: Hasher<F> + AlgebraicHasher<F> + Hasher<F>,
> DatasetTreeCircuit<F, C, D, H> {

    // in-circuit sampling
    // TODO: make it more modular
    pub fn sample_slot_circuit(
        &mut self,
        builder: &mut CircuitBuilder::<F, D>,
    )-> DatasetTargets<F,C,D,H>{

        // constants
        let zero = builder.zero();
        let one = builder.one();
        let two = builder.two();

        // ***** prove slot root is in dataset tree *********

        // Retrieve dataset tree depth
        let d_depth = DATASET_DEPTH;

        // Create virtual target for slot root and index
        let slot_root = builder.add_virtual_hash();
        let slot_index = builder.add_virtual_target();

        // dataset path bits (binary decomposition of leaf_index)
        let d_path_bits = builder.split_le(slot_index,d_depth);

        // dataset last bits (binary decomposition of last_index = nleaves - 1)
        let depth_target = builder.constant(F::from_canonical_u64(d_depth as u64));
        let mut d_last_index = builder.exp(two,depth_target,d_depth);
        d_last_index = builder.sub(d_last_index, one);
        let d_last_bits = builder.split_le(d_last_index,d_depth);

        // dataset Merkle path (sibling hashes from leaf to root)
        let d_merkle_path = MerkleProofTarget {
            path: (0..d_depth).map(|_| builder.add_virtual_hash()).collect(),
        };

        // create MerkleTreeTargets struct
        let mut d_targets = MerkleTreeTargets {
            leaf: slot_root,
            path_bits: d_path_bits,
            last_bits: d_last_bits,
            merkle_path: d_merkle_path,
            _phantom: PhantomData,
        };

        // dataset reconstructed root
        let d_reconstructed_root =
            MerkleTreeCircuit::<F,C,D,H>::reconstruct_merkle_root_circuit(builder, &mut d_targets);

        // expected Merkle root
        let d_expected_root = builder.add_virtual_hash();

        // check equality with expected root
        for i in 0..NUM_HASH_OUT_ELTS {
            builder.connect(d_expected_root.elements[i], d_reconstructed_root.elements[i]);
        }

        //*********** do the sampling ************

        let mut data_targets =vec![];
        let mut slot_sample_proofs = vec![];
        let entropy_target = builder.add_virtual_hash();

        //TODO: this can probably be optimized by supplying nCellsPerSlot as input to the circuit
        let b_depth_target = builder.constant(F::from_canonical_u64(BOT_DEPTH as u64));
        let mut b_last_index = builder.exp(two,b_depth_target,BOT_DEPTH);
        b_last_index = builder.sub(b_last_index, one);
        let b_last_bits = builder.split_le(b_last_index,BOT_DEPTH);

        let s_depth_target = builder.constant(F::from_canonical_u64(MAX_DEPTH as u64));
        let mut s_last_index = builder.exp(two,s_depth_target,MAX_DEPTH);
        s_last_index = builder.sub(s_last_index, one);
        let s_last_bits = builder.split_le(s_last_index,MAX_DEPTH);

        for i in 0..N_SAMPLES{
            // cell data targets
            let mut data_i = (0..N_FIELD_ELEMS_PER_CELL).map(|_| builder.add_virtual_target()).collect::<Vec<_>>();

            let mut perm_inputs:Vec<Target>= Vec::new();
            perm_inputs.extend_from_slice(&data_i);
            let data_i_hash = builder.hash_n_to_hash_no_pad::<H>(perm_inputs);
            // counter constant
            let ctr_target = builder.constant(F::from_canonical_u64(i as u64));
            let mut ctr = builder.add_virtual_hash();
            for i in 0..ctr.elements.len() {
                if(i==0){
                    ctr.elements[i] = ctr_target;
                }else{
                    ctr.elements[i] = zero.clone();
                }
            }
            // paths
            let mut b_path_bits = Self::calculate_cell_index_bits(builder, &entropy_target, &d_targets.leaf, &ctr);
            let mut s_path_bits = b_path_bits.split_off(BOT_DEPTH);

            let mut b_merkle_path = MerkleProofTarget {
                path: (0..BOT_DEPTH).map(|_| builder.add_virtual_hash()).collect(),
            };

            let mut s_merkle_path = MerkleProofTarget {
                path: (0..(MAX_DEPTH - BOT_DEPTH)).map(|_| builder.add_virtual_hash()).collect(),
            };

            let mut block_targets = MerkleTreeTargets {
                leaf: data_i_hash,
                path_bits:b_path_bits,
                last_bits: b_last_bits.clone(),
                merkle_path: b_merkle_path,
                _phantom: PhantomData,
            };

            // reconstruct block root
            let b_root = MerkleTreeCircuit::<F,C,D,H>::reconstruct_merkle_root_circuit(builder, &mut block_targets);

            let mut slot_targets = MerkleTreeTargets {
                leaf: b_root,
                path_bits:s_path_bits,
                last_bits:s_last_bits.clone(),
                merkle_path:s_merkle_path,
                _phantom: PhantomData,
            };

            // reconstruct slot root with block root as leaf
            let slot_reconstructed_root = MerkleTreeCircuit::<F,C,D,H>::reconstruct_merkle_root_circuit(builder, &mut slot_targets);

            // check equality with expected root
            for i in 0..NUM_HASH_OUT_ELTS {
                builder.connect( d_targets.leaf.elements[i], slot_reconstructed_root.elements[i]);
            }

            // combine block and slot path to get the full path so we can assign it later.
            let mut slot_sample_proof_target = MerkleProofTarget{
                path: block_targets.merkle_path.path,
            };
            slot_sample_proof_target.path.extend_from_slice(&slot_targets.merkle_path.path);

            data_targets.push(data_i);
            slot_sample_proofs.push(slot_sample_proof_target);

        }

        DatasetTargets::<F,C,D,H>{
            dataset_proof: d_targets.merkle_path,
            dataset_root: d_expected_root,
            cell_data: data_targets,
            entropy: entropy_target,
            slot_index,
            slot_root: d_targets.leaf,
            slot_proofs: slot_sample_proofs,
            _phantom: Default::default(),
        }
    }

    pub fn calculate_cell_index_bits(builder: &mut CircuitBuilder::<F, D>, entropy: &HashOutTarget, slot_root: &HashOutTarget, ctr: &HashOutTarget) -> Vec<BoolTarget> {
        let mut hash_inputs:Vec<Target>= Vec::new();
        hash_inputs.extend_from_slice(&entropy.elements);
        hash_inputs.extend_from_slice(&slot_root.elements);
        hash_inputs.extend_from_slice(&ctr.elements);
        let hash_out = builder.hash_n_to_hash_no_pad::<H>(hash_inputs);
        let cell_index_bits =  builder.low_bits(hash_out.elements[0], MAX_DEPTH, 64);

        cell_index_bits
    }

    pub fn sample_slot_assign_witness(
        &mut self,
        pw: &mut PartialWitness<F>,
        targets: &mut DatasetTargets<F,C,D,H>,
        slot_index:usize,
        entropy:usize,
    ){
        // dataset proof
        let d_proof = self.tree.tree.get_proof(slot_index).unwrap();

        // assign dataset proof
        for (i, sibling_hash) in d_proof.path.iter().enumerate() {
            // TODO: fix this HashOutTarget later
            let sibling_hash_out = sibling_hash.to_vec();
            for j in 0..sibling_hash_out.len() {
                pw.set_target(targets.dataset_proof.path[i].elements[j], sibling_hash_out[j]);
            }
        }
        // assign slot index
        pw.set_target(targets.slot_index, F::from_canonical_u64(slot_index as u64));

        // assign the expected Merkle root of dataset to the target
        let expected_root = self.tree.tree.root().unwrap();
        let expected_root_hash_out = expected_root.to_vec();
        for j in 0..expected_root_hash_out.len() {
            pw.set_target(targets.dataset_root.elements[j], expected_root_hash_out[j]);
        }

        // the sampled slot
        let slot = &self.slot_trees[slot_index];
        let slot_root = slot.tree.tree.root().unwrap();
        pw.set_hash_target(targets.slot_root, slot_root);

        // assign entropy
        for (i, element) in targets.entropy.elements.iter().enumerate() {
            if(i==0) {
                pw.set_target(*element, F::from_canonical_u64(entropy as u64));
            }else {
                pw.set_target(*element, F::from_canonical_u64(0));
            }
        }
        // pw.set_target(targets.entropy, F::from_canonical_u64(entropy as u64));

        // do the sample N times
        for i in 0..N_SAMPLES {
            let cell_index_bits = calculate_cell_index_bits(entropy,slot_root,i);
            let cell_index = bits_le_padded_to_usize(&cell_index_bits);
            // assign cell data
            let leaf = &slot.cell_data[cell_index];
            for j in 0..leaf.len(){
                pw.set_target(targets.cell_data[i][j], leaf[j]);
            }
            // assign proof for that cell
            let cell_proof = slot.get_proof(cell_index);
            for (k, sibling_hash) in cell_proof.path.iter().enumerate() {
                let sibling_hash_out = sibling_hash.to_vec();
                for j in 0..sibling_hash_out.len() {
                    pw.set_target(targets.slot_proofs[i].path[k].elements[j], sibling_hash_out[j]);
                }
            }
        }

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

    // sample cells with full set of fake data
    // this test takes too long, see next test
    #[test]
    fn test_sample_cells_circuit() -> Result<()> {

        let mut dataset_t = DatasetTreeCircuit::<F,C,D,H>::default();

        let slot_index = 2;
        let entropy = 123;

        // sanity check
        let proof = dataset_t.sample_slot(slot_index,entropy);
        let slot_root = dataset_t.slot_trees[slot_index].tree.tree.root().unwrap();
        let res = dataset_t.verify_sampling(proof).unwrap();
        assert_eq!(res, true);

        // create the circuit
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let mut targets = dataset_t.sample_slot_circuit(&mut builder);

        // create a PartialWitness and assign
        let mut pw = PartialWitness::new();
        dataset_t.sample_slot_assign_witness(&mut pw, &mut targets,slot_index,entropy);

        // build the circuit
        let data = builder.build::<C>();
        println!("circuit size = {:?}", data.common.degree_bits());

        // Prove the circuit with the assigned witness
        let start_time = Instant::now();
        let proof_with_pis = data.prove(pw)?;
        println!("prove_time = {:?}", start_time.elapsed());

        // verify the proof
        let verifier_data = data.verifier_data();
        assert!(
            verifier_data.verify(proof_with_pis).is_ok(),
            "Merkle proof verification failed"
        );

        Ok(())
    }

    // same as above but with fake data for the specific slot to be sampled
    #[test]
    fn test_sample_cells_circuit_from_selected_slot() -> Result<()> {

        let mut dataset_t = DatasetTreeCircuit::<F,C,D,H>::new_for_testing();

        let slot_index = TESTING_SLOT_INDEX;
        let entropy = 123;

        // sanity check
        let proof = dataset_t.sample_slot(slot_index,entropy);
        let slot_root = dataset_t.slot_trees[slot_index].tree.tree.root().unwrap();
        let res = dataset_t.verify_sampling(proof).unwrap();
        assert_eq!(res, true);

        // create the circuit
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let mut targets = dataset_t.sample_slot_circuit(&mut builder);

        // create a PartialWitness and assign
        let mut pw = PartialWitness::new();
        dataset_t.sample_slot_assign_witness(&mut pw, &mut targets,slot_index,entropy);

        // build the circuit
        let data = builder.build::<C>();
        println!("circuit size = {:?}", data.common.degree_bits());

        // Prove the circuit with the assigned witness
        let start_time = Instant::now();
        let proof_with_pis = data.prove(pw)?;
        println!("prove_time = {:?}", start_time.elapsed());

        // verify the proof
        let verifier_data = data.verifier_data();
        assert!(
            verifier_data.verify(proof_with_pis).is_ok(),
            "Merkle proof verification failed"
        );

        Ok(())
    }
}