// Data structure used to generate the proof input

use plonky2::hash::hash_types::{HashOut, RichField};
use plonky2_field::extension::Extendable;
use codex_plonky2_circuits::circuits::sample_cells::Cell;
use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2;
use crate::merkle_tree::merkle_safe::{MerkleProof, MerkleTree};
use crate::params::{InputParams, HF};
use crate::sponge::hash_bytes_no_padding;
use crate::utils::{bits_le_padded_to_usize, calculate_cell_index_bits, usize_to_bits_le};

// ----------------- slot tree -----------------
#[derive(Clone)]
pub struct SlotTree<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
> {
    pub tree: MerkleTree<F, D>,         // slot tree
    pub block_trees: Vec<MerkleTree<F,D>>, // vec of block trees
    pub cell_data: Vec<Cell<F, D>>,  // cell data as field elements
    pub params: InputParams,              // parameters
}

impl<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
> SlotTree<F, D> {
    /// Create a slot tree with fake data, for testing only
    pub fn new_default(params: &InputParams) -> Self {
        // generate fake cell data
        let cell_data = (0..params.n_cells)
            .map(|_| new_random_cell(params))
            .collect::<Vec<_>>();
        Self::new(cell_data, params.clone())
    }

    /// Create a new slot tree with the supplied cell data and parameters
    pub fn new(cells: Vec<Cell<F, D>>, params: InputParams) -> Self {
        let leaves: Vec<HashOut<F>> = cells
            .iter()
            .map(|element| hash_bytes_no_padding::<F,D,HF>(&element.data))
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

// -------------- Dataset Tree -------------
/// Dataset tree containing all slot trees
#[derive(Clone)]
pub struct DatasetTree<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
> {
    pub tree: MerkleTree<F,D>,          // dataset tree
    pub slot_trees: Vec<SlotTree<F, D>>, // vec of slot trees
    pub params: InputParams,               // parameters
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
    pub fn new_default(params: &InputParams) -> Self {
        let mut slot_trees = vec![];
        let n_slots = 1 << params.dataset_depth_test();
        for _ in 0..n_slots {
            slot_trees.push(SlotTree::<F, D>::new_default(params));
        }
        Self::new(slot_trees, params.clone())
    }

    /// Create data for only the specified slot index in params
    pub fn new_for_testing(params: &InputParams) -> Self {
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
    pub fn new(slot_trees: Vec<SlotTree<F, D>>, params: InputParams) -> Self {
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
        Self::pad_proof(&mut dataset_proof, self.params.dataset_max_depth());

        let slot = &self.slot_trees[index];
        let slot_root = slot.tree.root().unwrap();
        let mut slot_proofs = vec![];
        let mut cell_data = vec![];
        let entropy_field = F::from_canonical_u64(entropy as u64);
        let mut entropy_as_digest = HashOut::<F>::ZERO;
        entropy_as_digest.elements[0] = entropy_field;

        // get the index for cell from H(slot_root|counter|entropy)
        let mask_bits = usize_to_bits_le(self.params.n_cells-1, self.params.max_depth+1);
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
        for _i in merkle_proof.path.len()..max_depth{
            merkle_proof.path.push(HashOut::<F>::ZERO);
        }
    }
}

// ------------ helper functions -------------

/// Create a new cell with random data, using the parameters from `Params`
pub fn new_random_cell<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
>(params: &InputParams) -> Cell<F,D> {
    let data = (0..params.n_field_elems_per_cell())
        .map(|_| F::rand())
        .collect::<Vec<_>>();
    Cell::<F,D> {
        data,
    }
}
