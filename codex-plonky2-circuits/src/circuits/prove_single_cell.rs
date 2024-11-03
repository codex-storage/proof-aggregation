// prove single cell
// consistent with:
// https://github.com/codex-storage/codex-storage-proofs-circuits/blob/master/circuit/codex/single_cell.circom
// circuit consists of:
// - reconstruct the block merkle root
// - use merkle root as leaf and reconstruct slot root
// - check equality with given slot root

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

use plonky2::plonk::config::PoseidonGoldilocksConfig;

use plonky2::hash::hashing::PlonkyPermutation;
use crate::circuits::safe_tree_circuit::{MerkleTreeCircuit, MerkleTreeTargets};
use crate::circuits::utils::usize_to_bits_le_padded;
use crate::circuits::params::{MAX_DEPTH, BOT_DEPTH, N_FIELD_ELEMS_PER_CELL, N_CELLS_IN_BLOCKS, N_BLOCKS, N_CELLS, HF};

// ------ Slot Tree --------

#[derive(Clone)]
pub struct SlotTreeCircuit<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
> {
    pub tree: MerkleTreeCircuit<F,D>, // slot tree
    pub block_trees: Vec<MerkleTreeCircuit<F,D>>, // vec of block trees
    pub cell_data: Vec<Vec<F>>, // cell data as field elements
}

impl<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
> Default for SlotTreeCircuit<F,D>{
    /// slot tree with fake data, for testing only
    fn default() -> Self {
        // generate fake cell data
        let mut cell_data = (0..N_CELLS)
            .map(|i|{
                (0..N_FIELD_ELEMS_PER_CELL)
                    .map(|j| F::from_canonical_u64((j+i) as u64))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        // hash it
        let leaves: Vec<HashOut<F>> = cell_data
            .iter()
            .map(|element| {
                HF::hash_no_pad(&element)
            })
            .collect();
        // zero hash
        let zero = HashOut {
            elements: [F::ZERO; 4],
        };
        // create block tree
        let block_trees = (0..N_BLOCKS)
            .map(|i| {
                let start = i * N_CELLS_IN_BLOCKS;
                let end = (i + 1) * N_CELLS_IN_BLOCKS;
                let b_tree = Self::get_block_tree(&leaves[start..end].to_vec()); // use helper function
                MerkleTreeCircuit::<F,D>{ tree:b_tree}
            })
            .collect::<Vec<_>>();
        // get the roots or block trees
        let block_roots = block_trees.iter()
            .map(|t| {
                t.tree.root().unwrap()
            })
            .collect::<Vec<_>>();
        // create slot tree
        let slot_tree = MerkleTree::<F>::new(&block_roots, zero).unwrap();

        Self{
            tree: MerkleTreeCircuit::<F,D>{ tree:slot_tree},
            block_trees,
            cell_data,
        }
    }
}

impl<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
> SlotTreeCircuit<F,D> {

    /// Slot tree with fake data, for testing only
    pub fn new_for_testing() -> Self {
        // Generate fake cell data for one block
        let cell_data_block = (0..N_CELLS_IN_BLOCKS)
            .map(|i| {
                (0..N_FIELD_ELEMS_PER_CELL)
                    .map(|j| F::from_canonical_u64((j + i) as u64))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        // Hash the cell data block to create leaves for one block
        let leaves_block: Vec<HashOut<F>> = cell_data_block
            .iter()
            .map(|element| {
                HF::hash_no_pad(&element)
            })
            .collect();

        // Zero hash
        let zero = HashOut {
            elements: [F::ZERO; 4],
        };

        // Create a block tree from the leaves of one block
        let b_tree = Self::get_block_tree(&leaves_block);

        // Create a block tree circuit
        let block_tree_circuit = MerkleTreeCircuit::<F, D> {
            tree: b_tree,
            // _phantom: Default::default(),
        };

        // Now replicate this block tree for all N_BLOCKS blocks
        let block_trees = vec![block_tree_circuit.clone(); N_BLOCKS];

        // Get the roots of block trees
        let block_roots = block_trees
            .iter()
            .map(|t| t.tree.root().unwrap())
            .collect::<Vec<_>>();

        // Create the slot tree from block roots
        let slot_tree = MerkleTree::<F>::new(&block_roots, zero).unwrap();

        // Create the full cell data and cell hash by repeating the block data
        let cell_data = vec![cell_data_block.clone(); N_BLOCKS].concat();

        // Return the constructed Self
        Self {
            tree: MerkleTreeCircuit::<F, D> {
                tree: slot_tree,
            },
            block_trees,
            cell_data,
        }
    }


    /// same as default but with supplied cell data
    pub fn new(cell_data: Vec<Vec<F>>) -> Self{
        let leaves: Vec<HashOut<F>> = cell_data
            .iter()
            .map(|element| {
                HF::hash_no_pad(element)
            })
            .collect();
        let zero = HashOut {
            elements: [F::ZERO; 4],
        };
        let block_trees = (0..N_BLOCKS as usize)
            .map(|i| {
                let start = i * N_CELLS_IN_BLOCKS;
                let end = (i + 1) * N_CELLS_IN_BLOCKS;
                let b_tree = Self::get_block_tree(&leaves[start..end].to_vec());
                MerkleTreeCircuit::<F,D>{ tree:b_tree}
            })
            .collect::<Vec<_>>();
        let block_roots = block_trees.iter()
            .map(|t| {
                t.tree.root().unwrap()
            })
            .collect::<Vec<_>>();
        let slot_tree = MerkleTree::<F>::new(&block_roots, zero).unwrap();
        Self{
            tree: MerkleTreeCircuit::<F,D>{ tree:slot_tree},
            block_trees,
            cell_data,
        }
    }

    /// generates a proof for given leaf index
    /// the path in the proof is a combined block and slot path to make up the full path
    pub fn get_proof(&self, index: usize) -> MerkleProof<F> {
        let block_index = index/ N_CELLS_IN_BLOCKS;
        let leaf_index = index % N_CELLS_IN_BLOCKS;
        let block_proof = self.block_trees[block_index].tree.get_proof(leaf_index).unwrap();
        let slot_proof = self.tree.tree.get_proof(block_index).unwrap();

        // Combine the paths from the block and slot proofs
        let mut combined_path = block_proof.path.clone();
        combined_path.extend(slot_proof.path.clone());

        MerkleProof::<F> {
            index: index,
            path: combined_path,
            nleaves: self.cell_data.len(),
            zero: block_proof.zero.clone(),
        }

    }

    /// verify the given proof for slot tree, checks equality with given root
    pub fn verify_cell_proof(&self, proof: MerkleProof<F>, root: HashOut<F>) -> Result<bool>{
        let mut block_path_bits = usize_to_bits_le_padded(proof.index, MAX_DEPTH);
        let last_index = N_CELLS - 1;
        let mut block_last_bits = usize_to_bits_le_padded(last_index, MAX_DEPTH);

        let split_point = BOT_DEPTH;

        let slot_last_bits = block_last_bits.split_off(split_point);
        let slot_path_bits = block_path_bits.split_off(split_point);

        let leaf_hash = HF::hash_no_pad(&self.cell_data[proof.index]);

        let mut block_path = proof.path;
        let slot_path = block_path.split_off(split_point);

        let block_res = MerkleProof::<F>::reconstruct_root2(leaf_hash,block_path_bits.clone(),block_last_bits.clone(),block_path);
        let reconstructed_root = MerkleProof::<F>::reconstruct_root2(block_res.unwrap(),slot_path_bits,slot_last_bits,slot_path);

        Ok(reconstructed_root.unwrap() == root)
    }

    fn get_block_tree(leaves: &Vec<HashOut<F>>) -> MerkleTree<F> {
        let zero = HashOut {
            elements: [F::ZERO; 4],
        };
        // Build the Merkle tree
        let block_tree = MerkleTree::<F>::new(leaves, zero).unwrap();
        block_tree
    }
}

//------- single cell struct ------
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SingleCellTargets{
    pub expected_slot_root_target: HashOutTarget,
    pub proof_target: MerkleProofTarget,
    pub leaf_target: Vec<Target>,
    pub path_bits: Vec<BoolTarget>,
    pub last_bits: Vec<BoolTarget>,
}

//------- circuit impl --------

impl<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
> SlotTreeCircuit<F, D> {

    pub fn prove_single_cell(
        builder: &mut CircuitBuilder::<F, D>
    ) -> SingleCellTargets {

        // Retrieve tree depth
        let depth = MAX_DEPTH;

        // Create virtual targets
        let mut leaf = (0..N_FIELD_ELEMS_PER_CELL).map(|_| builder.add_virtual_target()).collect::<Vec<_>>();

        let mut perm_inputs:Vec<Target>= Vec::new();
        perm_inputs.extend_from_slice(&leaf);
        let leaf_hash = builder.hash_n_to_hash_no_pad::<HF>(perm_inputs);

        // path bits (binary decomposition of leaf_index)
        let mut block_path_bits = (0..BOT_DEPTH).map(|_| builder.add_virtual_bool_target_safe()).collect::<Vec<_>>();
        let mut slot_path_bits = (0..(depth - BOT_DEPTH)).map(|_| builder.add_virtual_bool_target_safe()).collect::<Vec<_>>();

        // last bits (binary decomposition of last_index = nleaves - 1)
        let block_last_bits = (0..BOT_DEPTH).map(|_| builder.add_virtual_bool_target_safe()).collect::<Vec<_>>();
        let slot_last_bits = (0..(depth-BOT_DEPTH)).map(|_| builder.add_virtual_bool_target_safe()).collect::<Vec<_>>();

        // Merkle path (sibling hashes from leaf to root)
        let mut block_merkle_path = MerkleProofTarget {
            path: (0..BOT_DEPTH).map(|_| builder.add_virtual_hash()).collect(),
        };
        let mut slot_merkle_path = MerkleProofTarget {
            path: (0..(depth - BOT_DEPTH)).map(|_| builder.add_virtual_hash()).collect(),
        };

        // expected Merkle root
        let slot_expected_root = builder.add_virtual_hash();

        let mut block_targets = MerkleTreeTargets {
            leaf: leaf_hash,
            path_bits:block_path_bits,
            last_bits: block_last_bits,
            merkle_path: block_merkle_path,
        };

        // reconstruct block root
        let block_root = MerkleTreeCircuit::<F,D>::reconstruct_merkle_root_circuit(builder, &mut block_targets);

        // create MerkleTreeTargets struct
        let mut slot_targets = MerkleTreeTargets {
            leaf: block_root,
            path_bits:slot_path_bits,
            last_bits:slot_last_bits,
            merkle_path:slot_merkle_path,
        };

        // reconstruct slot root with block root as leaf
        let slot_root = MerkleTreeCircuit::<F,D>::reconstruct_merkle_root_circuit(builder, &mut slot_targets);

        // check equality with expected root
        for i in 0..NUM_HASH_OUT_ELTS {
            builder.connect(slot_expected_root.elements[i], slot_root.elements[i]);
        }

        let mut proof_target = MerkleProofTarget{
            path: block_targets.merkle_path.path,
        };
        proof_target.path.extend_from_slice(&slot_targets.merkle_path.path);

        let mut path_bits = block_targets.path_bits;
        path_bits.extend_from_slice(&slot_targets.path_bits);

        let mut last_bits = block_targets.last_bits;
        last_bits.extend_from_slice(&slot_targets.last_bits);

        let mut cell_targets = SingleCellTargets {
            expected_slot_root_target: slot_expected_root,
            proof_target,
            leaf_target: leaf,
            path_bits,
            last_bits,
        };

        // Return MerkleTreeTargets
        cell_targets
    }

    /// assign the witness values in the circuit targets
    /// this takes leaf_index, leaf, and proof (generated from slot_tree)
    /// and fills all required circuit targets(circuit inputs)
    pub fn single_cell_assign_witness(
        &self,
        pw: &mut PartialWitness<F>,
        targets: &mut SingleCellTargets,
        leaf_index: usize,
        leaf: &Vec<F>,
        proof: MerkleProof<F>,
    )-> Result<()> {

        // Assign the leaf to the leaf target
        for i in 0..targets.leaf_target.len(){
            pw.set_target(targets.leaf_target[i], leaf[i]);
        }

        // Convert `leaf_index` to binary bits and assign as path_bits
        let path_bits = usize_to_bits_le_padded(leaf_index, MAX_DEPTH);
        for (i, bit) in path_bits.iter().enumerate() {
            pw.set_bool_target(targets.path_bits[i], *bit);
        }

        // get `last_index` (nleaves - 1) in binary bits and assign
        let last_index = N_CELLS - 1;
        let last_bits = usize_to_bits_le_padded(last_index, MAX_DEPTH);
        for (i, bit) in last_bits.iter().enumerate() {
            pw.set_bool_target(targets.last_bits[i], *bit);
        }

        // assign the Merkle path (sibling hashes) to the targets
        for (i, sibling_hash) in proof.path.iter().enumerate() {
            // This is a bit hacky because it should be HashOutTarget, but it is H:Hash
            // pw.set_hash_target(targets.merkle_path.path[i],sibling_hash);
            // TODO: fix this HashOutTarget later
            let sibling_hash_out = sibling_hash.to_vec();
            for j in 0..sibling_hash_out.len() {
                pw.set_target(targets.proof_target.path[i].elements[j], sibling_hash_out[j]);
            }
        }

        // assign the expected Merkle root to the target
        let expected_root = self.tree.tree.root()?;
        // TODO: fix this HashOutTarget later same issue as above
        let expected_root_hash_out = expected_root.to_vec();
        for j in 0..expected_root_hash_out.len() {
            pw.set_target(targets.expected_slot_root_target.elements[j], expected_root_hash_out[j]);
        }

        Ok(())
    }

    fn hash_leaf(builder: &mut CircuitBuilder<F, D >, leaf: &mut Vec<Target>){
        builder.hash_n_to_hash_no_pad::<HF>(leaf.to_owned());
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
    fn test_prove_single_cell(){
        let slot_t = SlotTreeCircuit::<F,D>::default();
        let index = 8;
        let proof = slot_t.get_proof(index);
        let res = slot_t.verify_cell_proof(proof,slot_t.tree.tree.root().unwrap()).unwrap();
        assert_eq!(res, true);
    }

    #[test]
    fn test_cell_build_circuit() -> Result<()> {

        let slot_t = SlotTreeCircuit::<F,D>::default();

        // select leaf index to prove
        let leaf_index: usize = 8;

        let proof = slot_t.get_proof(leaf_index);
        // get the expected Merkle root
        let expected_root = slot_t.tree.tree.root().unwrap();
        let res = slot_t.verify_cell_proof(proof.clone(),expected_root).unwrap();
        assert_eq!(res, true);

        // create the circuit
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let mut targets = SlotTreeCircuit::<F,D>::prove_single_cell(&mut builder);

        // create a PartialWitness and assign
        let mut pw = PartialWitness::new();
        slot_t.single_cell_assign_witness(&mut pw, &mut targets, leaf_index, &slot_t.cell_data[leaf_index], proof)?;

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

