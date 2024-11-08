use plonky2::hash::hash_types::{HashOut, RichField};
use plonky2::plonk::config::{GenericConfig, Hasher};
use plonky2_field::extension::Extendable;
use plonky2_field::types::Field;
use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2;
use codex_plonky2_circuits::circuits::params::{CircuitParams, HF};
use crate::params::Params;
use crate::utils::{bits_le_padded_to_usize, calculate_cell_index_bits, usize_to_bits_le_padded};
use codex_plonky2_circuits::merkle_tree::merkle_safe::{MerkleProof, MerkleTree};
use codex_plonky2_circuits::circuits::sample_cells::{Cell, MerklePath, SampleCircuit, SampleCircuitInput};
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use crate::sponge::hash_n_with_padding;

/// generates input witness (SampleCircuitInput) from fake data
/// which can be later stored into json see json.rs
pub fn gen_witness<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
>(params: &Params) -> SampleCircuitInput<F,D>{
    let dataset_t = DatasetTree::<F, D>::new_for_testing(&params);

    let slot_index = params.testing_slot_index; // samples the specified slot
    let entropy = params.entropy; // Use the entropy from Params

    let proof = dataset_t.sample_slot(slot_index, entropy);
    let slot_root = dataset_t.slot_trees[slot_index].tree.root().unwrap();

    let mut slot_paths = vec![];
    for i in 0..params.n_samples {
        let path = proof.slot_proofs[i].path.clone();
        let mp = MerklePath::<F,D>{
            path,
        };
        slot_paths.push(mp);
    }

    SampleCircuitInput::<F, D> {
        entropy: proof.entropy.elements.clone().to_vec(),
        dataset_root: dataset_t.tree.root().unwrap(),
        slot_index: proof.slot_index.clone(),
        slot_root,
        n_cells_per_slot: F::from_canonical_usize(params.n_cells),
        n_slots_per_dataset: F::from_canonical_usize(params.n_slots),
        slot_proof: proof.dataset_proof.path.clone(),
        cell_data: proof.cell_data.clone(),
        merkle_paths: slot_paths,
    }
}

/// verifies the witness.
/// this is non circuit version for sanity check
pub fn verify_witness<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
>(witness: SampleCircuitInput<F,D>, params: &Params) -> bool{
    let slot_index = witness.slot_index.to_canonical_u64();
    let slot_root = witness.slot_root.clone();
    // check dataset level proof
    let slot_proof = witness.slot_proof.clone();
    let dataset_path_bits = usize_to_bits_le_padded(slot_index as usize, params.dataset_depth());
    let last_index = params.n_slots - 1;
    let dataset_last_bits = usize_to_bits_le_padded(last_index, params.dataset_depth());
    let dataset_mask_bits = usize_to_bits_le_padded(last_index, params.dataset_depth()+1);
    let reconstructed_slot_root = MerkleProof::<F,D>::reconstruct_root2(
        slot_root,
        dataset_path_bits,
        dataset_last_bits,
        slot_proof,
        dataset_mask_bits,
        params.max_slots.trailing_zeros() as usize,
    ).unwrap();
    // assert reconstructed equals dataset root
    assert_eq!(reconstructed_slot_root, witness.dataset_root.clone());

    // check each sampled cell

    // get the index for cell from H(slot_root|counter|entropy)
    let mask_bits = usize_to_bits_le_padded(params.n_cells -1, params.max_depth);
    for i in 0..params.n_samples {
        let cell_index_bits = calculate_cell_index_bits(
            &witness.entropy,
            slot_root,
            i + 1,
            params.max_depth,
            mask_bits.clone(),
        );
        let cell_index = bits_le_padded_to_usize(&cell_index_bits);

        let s_res = verify_cell_proof(&witness, &params, cell_index, i);
        if s_res.unwrap() == false {
            println!("call {} is false", i);
            return false;
        }
    }
    true
}

/// Verify the given proof for slot tree, checks equality with the given root
pub fn verify_cell_proof<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
>(witness: &SampleCircuitInput<F,D>, params: &Params, cell_index: usize, ctr: usize) -> anyhow::Result<bool> {
    let mut block_path_bits = usize_to_bits_le_padded(cell_index, params.max_depth);
    let last_index = params.n_cells - 1;
    let mut block_last_bits = usize_to_bits_le_padded(last_index, params.max_depth);

    let split_point = params.bot_depth();

    let slot_last_bits = block_last_bits.split_off(split_point);
    let slot_path_bits = block_path_bits.split_off(split_point);

    // pub type HP = <PoseidonHash as Hasher<F>>::Permutation;
    let leaf_hash = hash_n_with_padding::<F,D,HF>(&witness.cell_data[ctr].data);
    // HF::hash_no_pad()

    let mut block_path = witness.merkle_paths[ctr].path.clone();
    let slot_path = block_path.split_off(split_point);

    let mask_bits = usize_to_bits_le_padded(last_index, params.max_depth+1);

    let block_res = MerkleProof::<F,D>::reconstruct_root2(
        leaf_hash,
        block_path_bits.clone(),
        block_last_bits.clone(),
        block_path,
        mask_bits.clone(),
        params.bot_depth(),
    );
    let reconstructed_root = MerkleProof::<F,D>::reconstruct_root2(
        block_res.unwrap(),
        slot_path_bits,
        slot_last_bits,
        slot_path,
        mask_bits.clone(),
        params.max_depth - params.bot_depth(),
    );

    Ok(reconstructed_root.unwrap() == witness.slot_root)
}


/// Create a new cell with random data, using the parameters from `Params`
pub fn new_random_cell<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
>(params: &Params) -> Cell<F,D> {
    let data = (0..params.n_field_elems_per_cell())
        .map(|_| F::rand())
        .collect::<Vec<_>>();
    Cell::<F,D> {
        data,
    }
}

#[derive(Clone)]
pub struct SlotTree<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
> {
    pub tree: MerkleTree<F, D>,         // slot tree
    pub block_trees: Vec<MerkleTree<F,D>>, // vec of block trees
    pub cell_data: Vec<Cell<F, D>>,  // cell data as field elements
    pub params: Params,              // parameters
}

impl<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
> SlotTree<F, D> {
    /// Create a slot tree with fake data, for testing only
    pub fn new_default(params: &Params) -> Self {
        // generate fake cell data
        let cell_data = (0..params.n_cells)
            .map(|_| new_random_cell(params))
            .collect::<Vec<_>>();
        Self::new(cell_data, params.clone())
    }

    /// Create a new slot tree with the supplied cell data and parameters
    pub fn new(cells: Vec<Cell<F, D>>, params: Params) -> Self {
        let leaves: Vec<HashOut<F>> = cells
            .iter()
            .map(|element| hash_n_with_padding::<F,D,HF>(&element.data))
            .collect();
        let zero = HashOut {
            elements: [F::ZERO; 4],
        };
        let n_blocks = params.n_blocks_test();
        let n_cells_in_blocks = params.n_cells_in_blocks();

        let block_trees = (0..n_blocks)
            .map(|i| {
                let start = i * n_cells_in_blocks;
                let end = (i + 1) * n_cells_in_blocks;
                Self::get_block_tree(&leaves[start..end].to_vec())
            })
            .collect::<Vec<_>>();
        let block_roots = block_trees
            .iter()
            .map(|t| t.root().unwrap())
            .collect::<Vec<_>>();
        let slot_tree = MerkleTree::<F,D>::new(&block_roots, zero).unwrap();
        Self {
            tree: slot_tree,
            block_trees,
            cell_data: cells,
            params,
        }
    }

    /// Generates a proof for the given leaf index
    /// The path in the proof is a combined block and slot path to make up the full path
    pub fn get_proof(&self, index: usize) -> MerkleProof<F,D> {
        let block_index = index / self.params.n_cells_in_blocks();
        let leaf_index = index % self.params.n_cells_in_blocks();
        let block_proof = self.block_trees[block_index].get_proof(leaf_index).unwrap();
        let slot_proof = self.tree.get_proof(block_index).unwrap();

        // Combine the paths from the block and slot proofs
        let mut combined_path = block_proof.path.clone();
        combined_path.extend(slot_proof.path.clone());

        MerkleProof::<F,D> {
            index,
            path: combined_path,
            nleaves: self.cell_data.len(),
            zero: block_proof.zero.clone(),
        }
    }

    fn get_block_tree(leaves: &Vec<HashOut<F>>) -> MerkleTree<F,D> {
        let zero = HashOut {
            elements: [F::ZERO; 4],
        };
        // Build the Merkle tree
        let block_tree = MerkleTree::<F,D>::new(leaves, zero).unwrap();
        block_tree
    }
}

// ------ Dataset Tree --------
/// Dataset tree containing all slot trees
#[derive(Clone)]
pub struct DatasetTree<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
> {
    pub tree: MerkleTree<F,D>,          // dataset tree
    pub slot_trees: Vec<SlotTree<F, D>>, // vec of slot trees
    pub params: Params,               // parameters
}

/// Dataset Merkle proof struct, containing the dataset proof and sampled proofs.
#[derive(Clone)]
pub struct DatasetProof<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
> {
    pub slot_index: F,
    pub entropy: HashOut<F>,
    pub dataset_proof: MerkleProof<F,D>,    // proof for dataset level tree
    pub slot_proofs: Vec<MerkleProof<F,D>>, // proofs for sampled slot
    pub cell_data: Vec<Cell<F,D>>,
}

impl<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
> DatasetTree<F, D> {
    /// Dataset tree with fake data, for testing only
    pub fn new_default(params: &Params) -> Self {
        let mut slot_trees = vec![];
        let n_slots = 1 << params.dataset_depth_test();
        for _ in 0..n_slots {
            slot_trees.push(SlotTree::<F, D>::new_default(params));
        }
        Self::new(slot_trees, params.clone())
    }

    /// Create data for only the specified slot index in params
    pub fn new_for_testing(params: &Params) -> Self {
        let mut slot_trees = vec![];
        // let n_slots = 1 << params.dataset_depth();
        let n_slots = params.n_slots;
        // zero hash
        let zero = HashOut {
            elements: [F::ZERO; 4],
        };
        let zero_slot = SlotTree::<F, D> {
            tree: MerkleTree::<F,D>::new(&[zero.clone()], zero.clone()).unwrap(),
            block_trees: vec![],
            cell_data: vec![],
            params: params.clone(),
        };
        for i in 0..n_slots {
            if i == params.testing_slot_index {
                slot_trees.push(SlotTree::<F, D>::new_default(params));
            } else {
                slot_trees.push(zero_slot.clone());
            }
        }
        // get the roots of slot trees
        let slot_roots = slot_trees
            .iter()
            .map(|t| t.tree.root().unwrap())
            .collect::<Vec<_>>();
        let dataset_tree = MerkleTree::<F,D>::new(&slot_roots, zero).unwrap();
        Self {
            tree: dataset_tree,
            slot_trees,
            params: params.clone(),
        }
    }

    /// Same as default but with supplied slot trees
    pub fn new(slot_trees: Vec<SlotTree<F, D>>, params: Params) -> Self {
        // get the roots of slot trees
        let slot_roots = slot_trees
            .iter()
            .map(|t| t.tree.root().unwrap())
            .collect::<Vec<_>>();
        // zero hash
        let zero = HashOut {
            elements: [F::ZERO; 4],
        };
        let dataset_tree = MerkleTree::<F,D>::new(&slot_roots, zero).unwrap();
        Self {
            tree: dataset_tree,
            slot_trees,
            params,
        }
    }

    /// Generates a proof for the given slot index
    /// Also takes entropy so it can use it to sample the slot
    /// note: proofs are padded based on the params in self
    pub fn sample_slot(&self, index: usize, entropy: usize) -> DatasetProof<F,D> {
        let mut dataset_proof = self.tree.get_proof(index).unwrap();
        Self::pad_proof(&mut dataset_proof, self.params.dataset_depth());

        let slot = &self.slot_trees[index];
        let slot_root = slot.tree.root().unwrap();
        let mut slot_proofs = vec![];
        let mut cell_data = vec![];
        let entropy_field = F::from_canonical_u64(entropy as u64);
        let mut entropy_as_digest = HashOut::<F>::ZERO;
        entropy_as_digest.elements[0] = entropy_field;

        // get the index for cell from H(slot_root|counter|entropy)
        let mask_bits = usize_to_bits_le_padded(self.params.n_cells-1, self.params.max_depth+1);
        for i in 0..self.params.n_samples {
            let cell_index_bits = calculate_cell_index_bits(
                &entropy_as_digest.elements.to_vec(),
                slot_root,
                i + 1,
                self.params.max_depth,
                mask_bits.clone()
            );
            let cell_index = bits_le_padded_to_usize(&cell_index_bits);
            let mut s_proof = slot.get_proof(cell_index);
            Self::pad_proof(&mut s_proof, self.params.max_depth);
            slot_proofs.push(s_proof);
            let data_i = slot.cell_data[cell_index].data.clone();
            let cell_i = Cell::<F,D>{
                data: data_i
            };
            cell_data.push(cell_i);
        }

        DatasetProof {
            slot_index: F::from_canonical_u64(index as u64),
            entropy: entropy_as_digest,
            dataset_proof,
            slot_proofs,
            cell_data,
        }
    }
    /// pad the proof with 0s until max_depth
    pub fn pad_proof(merkle_proof: &mut MerkleProof<F,D>, max_depth: usize){
        for i in merkle_proof.path.len()..max_depth{
            merkle_proof.path.push(HashOut::<F>::ZERO);
        }
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
    use codex_plonky2_circuits::circuits::params::CircuitParams;
    use codex_plonky2_circuits::circuits::sample_cells::{MerklePath, SampleCircuit, SampleCircuitInput};
    use crate::params::{C, D, F};

    // Test sample cells (non-circuit)
    #[test]
    fn test_gen_verify_proof(){
        let params = Params::default();
        let w = gen_witness::<F,D>(&params);
        assert!(verify_witness::<F,D>(w,&params));
    }

    // Test sample cells in-circuit for a selected slot
    #[test]
    fn test_proof_in_circuit() -> anyhow::Result<()> {
        // get witness
        let params = Params::default();
        let witness = gen_witness::<F,D>(&params);

        // Create the circuit
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let circuit_params = CircuitParams {
            max_depth: params.max_depth,
            max_log2_n_slots: params.dataset_depth(),
            block_tree_depth: params.bot_depth(),
            n_field_elems_per_cell: params.n_field_elems_per_cell(),
            n_samples: params.n_samples,
        };

        // build the circuit
        let circ = SampleCircuit::new(circuit_params.clone());
        let mut targets = circ.sample_slot_circuit(&mut builder);

        // Create a PartialWitness and assign
        let mut pw = PartialWitness::new();

        // assign a witness
        circ.sample_slot_assign_witness(&mut pw, &mut targets, witness);

        // Build the circuit
        let data = builder.build::<C>();
        println!("circuit size = {:?}", data.common.degree_bits());

        // Prove the circuit with the assigned witness
        let start_time = Instant::now();
        let proof_with_pis = data.prove(pw)?;
        println!("prove_time = {:?}", start_time.elapsed());

        // Verify the proof
        let verifier_data = data.verifier_data();
        assert!(
            verifier_data.verify(proof_with_pis).is_ok(),
            "Merkle proof verification failed"
        );

        Ok(())
    }
}
