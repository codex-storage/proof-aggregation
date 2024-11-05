use anyhow::Result;
use plonky2::hash::hash_types::{HashOut, RichField};
use plonky2::plonk::config::{GenericConfig, Hasher};
use plonky2_field::extension::Extendable;
use plonky2_field::types::Field;
use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2;
use crate::circuits::params::HF;
use crate::proof_input::test_params::{BOT_DEPTH, DATASET_DEPTH, MAX_DEPTH, N_BLOCKS, N_CELLS, N_CELLS_IN_BLOCKS, N_FIELD_ELEMS_PER_CELL, N_SAMPLES, TESTING_SLOT_INDEX};
use crate::circuits::utils::{bits_le_padded_to_usize, calculate_cell_index_bits, usize_to_bits_le_padded};
use crate::merkle_tree::merkle_safe::{MerkleProof, MerkleTree};

#[derive(Clone)]
pub struct SlotTree<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
> {
    pub tree: MerkleTree<F>, // slot tree
    pub block_trees: Vec<MerkleTree<F>>, // vec of block trees
    pub cell_data: Vec<Cell<F,D>>, // cell data as field elements
}

#[derive(Clone)]
pub struct Cell<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
> {
    pub data: Vec<F>, // cell data as field elements
}

impl<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
> Default for Cell<F, D> {
    /// default cell with random data
    fn default() -> Self {
        let data = (0..N_FIELD_ELEMS_PER_CELL)
            .map(|j| F::rand())
            .collect::<Vec<_>>();
        Self{
            data,
        }
    }
}

impl<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
> Default for SlotTree<F, D> {
    /// slot tree with fake data, for testing only
    fn default() -> Self {
        // generate fake cell data
        let mut cell_data = (0..N_CELLS)
            .map(|i|{
                Cell::<F,D>::default()
            })
            .collect::<Vec<_>>();
        Self::new(cell_data)
    }
}

impl<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
> SlotTree<F, D> {
    /// Slot tree with fake data, for testing only
    pub fn new_for_testing(cells: Vec<Cell<F, D>>) -> Self {
        // Hash the cell data block to create leaves for one block
        let leaves_block: Vec<HashOut<F>> = cells
            .iter()
            .map(|element| {
                HF::hash_no_pad(&element.data)
            })
            .collect();

        // Zero hash
        let zero = HashOut {
            elements: [F::ZERO; 4],
        };

        // Create a block tree from the leaves of one block
        let b_tree = Self::get_block_tree(&leaves_block);

        // Now replicate this block tree for all N_BLOCKS blocks
        let block_trees = vec![b_tree; N_BLOCKS];

        // Get the roots of block trees
        let block_roots = block_trees
            .iter()
            .map(|t| t.root().unwrap())
            .collect::<Vec<_>>();

        // Create the slot tree from block roots
        let slot_tree = MerkleTree::<F>::new(&block_roots, zero).unwrap();

        // Create the full cell data and cell hash by repeating the block data
        let cell_data = vec![cells.clone(); N_BLOCKS].concat();

        // Return the constructed Self
        Self {
            tree: slot_tree,
            block_trees,
            cell_data,
        }
    }
    /// same as default but with supplied cell data
    pub fn new(cells: Vec<Cell<F, D>>) -> Self {
        let leaves: Vec<HashOut<F>> = cells
            .iter()
            .map(|element| {
                HF::hash_no_pad(&element.data)
            })
            .collect();
        let zero = HashOut {
            elements: [F::ZERO; 4],
        };
        let block_trees = (0..N_BLOCKS as usize)
            .map(|i| {
                let start = i * N_CELLS_IN_BLOCKS;
                let end = (i + 1) * N_CELLS_IN_BLOCKS;
                Self::get_block_tree(&leaves[start..end].to_vec())
                // MerkleTree::<F> { tree: b_tree }
            })
            .collect::<Vec<_>>();
        let block_roots = block_trees.iter()
            .map(|t| {
                t.root().unwrap()
            })
            .collect::<Vec<_>>();
        let slot_tree = MerkleTree::<F>::new(&block_roots, zero).unwrap();
        Self {
            tree: slot_tree,
            block_trees,
            cell_data: cells,
        }
    }

    /// generates a proof for given leaf index
    /// the path in the proof is a combined block and slot path to make up the full path
    pub fn get_proof(&self, index: usize) -> MerkleProof<F> {
        let block_index = index / N_CELLS_IN_BLOCKS;
        let leaf_index = index % N_CELLS_IN_BLOCKS;
        let block_proof = self.block_trees[block_index].get_proof(leaf_index).unwrap();
        let slot_proof = self.tree.get_proof(block_index).unwrap();

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
    pub fn verify_cell_proof(&self, proof: MerkleProof<F>, root: HashOut<F>) -> anyhow::Result<bool> {
        let mut block_path_bits = usize_to_bits_le_padded(proof.index, MAX_DEPTH);
        let last_index = N_CELLS - 1;
        let mut block_last_bits = usize_to_bits_le_padded(last_index, MAX_DEPTH);

        let split_point = BOT_DEPTH;

        let slot_last_bits = block_last_bits.split_off(split_point);
        let slot_path_bits = block_path_bits.split_off(split_point);

        let leaf_hash = HF::hash_no_pad(&self.cell_data[proof.index].data);

        let mut block_path = proof.path;
        let slot_path = block_path.split_off(split_point);

        let block_res = MerkleProof::<F>::reconstruct_root2(leaf_hash, block_path_bits.clone(), block_last_bits.clone(), block_path);
        let reconstructed_root = MerkleProof::<F>::reconstruct_root2(block_res.unwrap(), slot_path_bits, slot_last_bits, slot_path);

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

// ------ Dataset Tree --------
///dataset tree containing all slot trees
#[derive(Clone)]
pub struct DatasetTree<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
> {
    pub tree: MerkleTree<F>, // dataset tree
    pub slot_trees: Vec<SlotTree<F, D>>, // vec of slot trees
}

/// Dataset Merkle proof struct, containing the dataset proof and N_SAMPLES proofs.
#[derive(Clone)]
pub struct DatasetProof<F: RichField> {
    pub slot_index: F,
    pub entropy: HashOut<F>,
    pub dataset_proof: MerkleProof<F>,       // proof for dataset level tree
    pub slot_proofs: Vec<MerkleProof<F>>, // proofs for sampled slot, contains N_SAMPLES proofs
    pub cell_data: Vec<Vec<F>>,
}

impl<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
> Default for DatasetTree<F, D> {
    /// dataset tree with fake data, for testing only
    fn default() -> Self {
        let mut slot_trees = vec![];
        let n_slots = 1 << DATASET_DEPTH;
        for i in 0..n_slots {
            slot_trees.push(SlotTree::<F, D>::default());
        }
        Self::new(slot_trees)
    }
}

impl<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
> DatasetTree<F, D> {
    /// dataset tree with fake data, for testing only
    /// create data for only the TESTING_SLOT_INDEX in params file
    pub fn new_for_testing() -> Self {
        let mut slot_trees = vec![];
        let n_slots = 1 << DATASET_DEPTH;
        // zero hash
        let zero = HashOut {
            elements: [F::ZERO; 4],
        };
        let zero_slot = SlotTree::<F, D> {
            tree: MerkleTree::<F>::new(&[zero.clone()], zero.clone()).unwrap(),
            block_trees: vec![],
            cell_data: vec![],
        };
        for i in 0..n_slots {
            if (i == TESTING_SLOT_INDEX) {
                slot_trees.push(SlotTree::<F, D>::default());
            } else {
                slot_trees.push(zero_slot.clone());
            }
        }
        // get the roots or slot trees
        let slot_roots = slot_trees.iter()
            .map(|t| {
                t.tree.root().unwrap()
            })
            .collect::<Vec<_>>();
        let dataset_tree = MerkleTree::<F>::new(&slot_roots, zero).unwrap();
        Self {
            tree: dataset_tree,
            slot_trees,
        }
    }

    /// same as default but with supplied slot trees
    pub fn new(slot_trees: Vec<SlotTree<F, D>>) -> Self {
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
        let dataset_tree = MerkleTree::<F>::new(&slot_roots, zero).unwrap();
        Self {
            tree: dataset_tree,
            slot_trees,
        }
    }

    /// generates a dataset level proof for given slot index
    /// just a regular merkle tree proof
    pub fn get_proof(&self, index: usize) -> MerkleProof<F> {
        let dataset_proof = self.tree.get_proof(index).unwrap();
        dataset_proof
    }

    /// generates a proof for given slot index
    /// also takes entropy so it can use it sample the slot
    pub fn sample_slot(&self, index: usize, entropy: usize) -> DatasetProof<F> {
        let dataset_proof = self.tree.get_proof(index).unwrap();
        let slot = &self.slot_trees[index];
        let slot_root = slot.tree.root().unwrap();
        let mut slot_proofs = vec![];
        let mut cell_data = vec![];
        let entropy_field = F::from_canonical_u64(entropy as u64);
        let mut entropy_as_digest = HashOut::<F>::ZERO;
        entropy_as_digest.elements[0] = entropy_field;
        // get the index for cell from H(slot_root|counter|entropy)
        for i in 0..N_SAMPLES {
            let cell_index_bits = calculate_cell_index_bits(&entropy_as_digest.elements.to_vec(), slot_root, i+1, MAX_DEPTH);
            let cell_index = bits_le_padded_to_usize(&cell_index_bits);
            let s_proof = slot.get_proof(cell_index);
            slot_proofs.push(s_proof);
            cell_data.push(slot.cell_data[cell_index].data.clone());
        }

        DatasetProof {
            slot_index: F::from_canonical_u64(index as u64),
            entropy: entropy_as_digest,
            dataset_proof,
            slot_proofs,
            cell_data,
        }
    }

    // verify the sampling - non-circuit version
    pub fn verify_sampling(&self, proof: DatasetProof<F>) -> bool {
        let slot = &self.slot_trees[proof.slot_index.to_canonical_u64() as usize];
        let slot_root = slot.tree.root().unwrap();
        // check dataset level proof
        let d_res = proof.dataset_proof.verify(slot_root, self.tree.root().unwrap());
        if (d_res.unwrap() == false) {
            return false;
        }
        // sanity check
        assert_eq!(N_SAMPLES, proof.slot_proofs.len());
        // get the index for cell from H(slot_root|counter|entropy)
        for i in 0..N_SAMPLES {
            // let entropy_field = F::from_canonical_u64(proof.entropy as u64);
            // let mut entropy_as_digest = HashOut::<F>::ZERO;
            // entropy_as_digest.elements[0] = entropy_field;
            let cell_index_bits = calculate_cell_index_bits(&proof.entropy.elements.to_vec(), slot_root, i+1, MAX_DEPTH);
            let cell_index = bits_le_padded_to_usize(&cell_index_bits);
            //check the cell_index is the same as one in the proof
            assert_eq!(cell_index, proof.slot_proofs[i].index);
            let s_res = slot.verify_cell_proof(proof.slot_proofs[i].clone(), slot_root);
            if (s_res.unwrap() == false) {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;
    use super::*;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::GenericConfig;
    use plonky2::iop::witness::PartialWitness;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use crate::circuits::sample_cells::{CircuitParams, DatasetTreeCircuit, SampleCircuitInput};
    use crate::proof_input::test_params::{D, C, F, H, N_SLOTS};

    #[test]
    fn test_sample_cells() {
        let dataset_t = DatasetTree::<F, D>::new_for_testing();
        let slot_index = 2;
        let entropy = 2;
        let proof = dataset_t.sample_slot(slot_index,entropy);
        let res = dataset_t.verify_sampling(proof);
        assert_eq!(res, true);
    }

    #[test]
    fn test_sample_cells_circuit_from_selected_slot() -> anyhow::Result<()> {

        let mut dataset_t = DatasetTree::<F, D>::new_for_testing();

        let slot_index = TESTING_SLOT_INDEX;
        let entropy = 123;

        // sanity check
        let proof = dataset_t.sample_slot(slot_index,entropy);
        let slot_root = dataset_t.slot_trees[slot_index].tree.root().unwrap();
        let res = dataset_t.verify_sampling(proof.clone());
        assert_eq!(res, true);

        // create the circuit
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let circuit_params = CircuitParams{
            max_depth: MAX_DEPTH,
            max_log2_n_slots: DATASET_DEPTH,
            block_tree_depth: BOT_DEPTH,
            n_field_elems_per_cell: N_FIELD_ELEMS_PER_CELL,
            n_samples: N_SAMPLES,
        };
        let circ = DatasetTreeCircuit::new(circuit_params);
        let mut targets = circ.sample_slot_circuit(&mut builder);

        // create a PartialWitness and assign
        let mut pw = PartialWitness::new();

        let mut slot_paths = vec![];
        for i in 0..N_SAMPLES{
            let path = proof.slot_proofs[i].path.clone();
            slot_paths.push(path);
            //TODO: need to be padded
        }

        let witness = SampleCircuitInput::<F,D>{
            entropy: proof.entropy.elements.clone().to_vec(),
            dataset_root: dataset_t.tree.root().unwrap(),
            slot_index: proof.slot_index.clone(),
            slot_root,
            n_cells_per_slot: F::from_canonical_u64((2_u32.pow(MAX_DEPTH as u32)) as u64),
            n_slots_per_dataset: F::from_canonical_u64((2_u32.pow(DATASET_DEPTH as u32)) as u64),
            slot_proof: proof.dataset_proof.path.clone(),
            cell_data: proof.cell_data.clone(),
            merkle_paths: slot_paths,
        };

        println!("dataset ={:?}",dataset_t.slot_trees[0].tree.layers);

        circ.sample_slot_assign_witness(&mut pw, &mut targets,witness);

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