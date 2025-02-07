// Sample cells
// consistent with:
// https://github.com/codex-storage/codex-storage-proofs-circuits/blob/master/circuit/codex/sample_cells.circom
// circuit consists of:
// - reconstruct the dataset merkle root using the slot root as leaf
// - samples multiple cells by calling the sample_cells

use std::marker::PhantomData;

use plonky2::{
    hash::{
        hash_types::{HashOut, HashOutTarget, RichField},
        hashing::PlonkyPermutation,
    },
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2::plonk::config::AlgebraicHasher;
use plonky2_field::types::HasExtension;

use crate::{
    circuits::{
    merkle_circuit::{MerkleProofTarget, MerkleTreeCircuit, MerkleTreeTargets},
    params::{CircuitParams, NUM_HASH_OUT_ELTS},
    sponge::{hash_n_no_padding, hash_n_with_padding},
    utils::{assign_hash_out_targets, ceiling_log2},
    },
    Result,
    error::CircuitError,
};

/// circuit for sampling a slot in a dataset merkle tree
#[derive(Clone, Debug)]
pub struct SampleCircuit<
    F: RichField + HasExtension<D>,
    const D: usize,
    H: AlgebraicHasher<F, NUM_HASH_OUT_ELTS>,
> {
    params: CircuitParams,
    phantom_data: PhantomData<(F,H)>,
}

impl<
    F: RichField + HasExtension<D>,
    const D: usize,
    H: AlgebraicHasher<F, NUM_HASH_OUT_ELTS>,
> SampleCircuit<F, D, H> {
    pub fn new(params: CircuitParams) -> Self{
        Self{
            params,
            phantom_data: Default::default(),
        }
    }
}

/// struct of input to the circuit as targets
/// used to build the circuit and can be assigned after building
#[derive(Clone, Debug)]
pub struct SampleTargets {

    pub entropy: HashOutTarget<NUM_HASH_OUT_ELTS>, // public input
    pub dataset_root: HashOutTarget<NUM_HASH_OUT_ELTS>, // public input
    pub slot_index: Target, // public input

    pub slot_root: HashOutTarget<NUM_HASH_OUT_ELTS>,
    pub n_cells_per_slot: Target,
    pub n_slots_per_dataset: Target,

    pub slot_proof: MerkleProofTarget,

    pub cell_data: Vec<CellTarget>,
    pub merkle_paths: Vec<MerkleProofTarget>,
}

/// circuit input as field elements
#[derive(Clone, Debug, PartialEq)]
pub struct SampleCircuitInput<
    F: RichField + HasExtension<D>,
    const D: usize,
>{
    pub entropy: HashOut<F, NUM_HASH_OUT_ELTS>, // public input
    pub dataset_root: HashOut<F, NUM_HASH_OUT_ELTS>, // public input
    pub slot_index: F, // public input

    pub slot_root: HashOut<F, NUM_HASH_OUT_ELTS>,
    pub n_cells_per_slot: F,
    pub n_slots_per_dataset: F,

    pub slot_proof: Vec<HashOut<F, NUM_HASH_OUT_ELTS>>,

    pub cell_data: Vec<Cell<F,D>>,
    pub merkle_paths: Vec<MerklePath<F,D>>,

}

/// merkle path from leaf to root as vec of HashOut (4 Goldilocks field elems)
#[derive(Clone, Debug, PartialEq)]
pub struct MerklePath<
    F: RichField + HasExtension<D>,
    const D: usize,
> {
    pub path: Vec<HashOut<F, NUM_HASH_OUT_ELTS>>
}

/// a vec of cell targets
#[derive(Clone, Debug, PartialEq)]
pub struct CellTarget {
    pub data: Vec<Target>
}

/// cell data as field elements
#[derive(Clone, Debug, PartialEq)]
pub struct Cell<
    F: RichField + HasExtension<D>,
    const D: usize,
> {
    pub data: Vec<F>,
}

//------- circuit impl --------
impl<
    F: RichField + HasExtension<D>,
    const D: usize,
    H: AlgebraicHasher<F, NUM_HASH_OUT_ELTS>,
> SampleCircuit<F, D, H> {

    /// samples and registers the public input
    pub fn sample_slot_circuit_with_public_input(
        &self,
        builder: &mut CircuitBuilder<F, D, NUM_HASH_OUT_ELTS>,
    ) -> Result<SampleTargets> {
        let targets = self.sample_slot_circuit(builder)?;
        let mut pub_targets = vec![];
        pub_targets.push(targets.slot_index);
        pub_targets.extend_from_slice(&targets.dataset_root.elements);
        pub_targets.extend_from_slice(&targets.entropy.elements);
        builder.register_public_inputs(&pub_targets);
        Ok(targets)
    }

    /// in-circuit sampling
    /// WARNING: no public input are registered when calling this function
    pub fn sample_slot_circuit(
        &self,
        builder: &mut CircuitBuilder::<F, D, NUM_HASH_OUT_ELTS>,
    ) -> Result<SampleTargets> {
        // circuit params
        let CircuitParams {
            max_depth,
            max_log2_n_slots,
            block_tree_depth,
            n_field_elems_per_cell,
            n_samples,
        } = self.params;

        // constants
        let zero = builder.zero();
        let one = builder.one();

        // ***** prove slot root is in dataset tree *********

        // Create virtual target for slot root and index
        let slot_root = builder.add_virtual_hash();
        let slot_index = builder.add_virtual_target();// public input
        // let slot_index = builder.add_virtual_public_input();// public input

        // dataset path bits (binary decomposition of leaf_index)
        let d_path_bits = builder.split_le(slot_index,max_log2_n_slots);

        // create virtual target for n_slots_per_dataset
        let n_slots_per_dataset = builder.add_virtual_target();

        // dataset last bits and mask bits
        let (d_last_bits, d_mask_bits) =
            ceiling_log2(builder, n_slots_per_dataset, max_log2_n_slots);

        // dataset Merkle path (sibling hashes from leaf to root)
        let d_merkle_path = MerkleProofTarget {
            path: (0..max_log2_n_slots).map(|_| builder.add_virtual_hash()).collect(),
        };

        // create MerkleTreeTargets struct
        let mut d_targets = MerkleTreeTargets{
            leaf: slot_root,
            path_bits: d_path_bits,
            last_bits: d_last_bits,
            mask_bits: d_mask_bits,
            merkle_path: d_merkle_path,
        };

        // dataset reconstructed root
        let d_reconstructed_root =
            MerkleTreeCircuit::<F,D, H>::reconstruct_merkle_root_circuit_with_mask(builder, &mut d_targets, max_log2_n_slots)?;

        // expected Merkle root
        let d_expected_root = builder.add_virtual_hash(); // public input
        // let d_expected_root = builder.add_virtual_hash_public_input(); // public input

        // check equality with expected root
        for i in 0..NUM_HASH_OUT_ELTS {
            builder.connect(d_expected_root.elements[i], d_reconstructed_root.elements[i]);
        }

        //*********** do the sampling ************

        let mut data_targets =vec![];
        let mut slot_sample_proofs = vec![];
        let entropy_target = builder.add_virtual_hash(); // public input
        // let entropy_target = builder.add_virtual_hash_public_input(); // public input

        // virtual target for n_cells_per_slot
        let n_cells_per_slot = builder.add_virtual_target();

        // calculate last index = n_cells_per_slot-1
        let slot_last_index = builder.sub(n_cells_per_slot, one);

        // create the mask bits
        // TODO: re-use this for block and slot trees
        let mask_bits = builder.split_le(slot_last_index,max_depth);

        // last and mask bits for block tree
        let mut b_last_bits = builder.split_le(slot_last_index,max_depth);
        let mut b_mask_bits = builder.split_le(slot_last_index,max_depth);

        // last and mask bits for the slot tree
        let mut s_last_bits = b_last_bits.split_off(block_tree_depth);
        let mut s_mask_bits = b_mask_bits.split_off(block_tree_depth);

        // pad mask bits with 0
        b_mask_bits.push(BoolTarget::new_unsafe(zero.clone()));
        s_mask_bits.push(BoolTarget::new_unsafe(zero.clone()));

        for i in 0..n_samples{
            // cell data targets
            let mut data_i = (0..n_field_elems_per_cell).map(|_| builder.add_virtual_target()).collect::<Vec<_>>();
            // hash the cell data
            let mut hash_inputs:Vec<Target>= Vec::new();
            hash_inputs.extend_from_slice(&data_i);
            // let data_i_hash = builder.hash_n_to_hash_no_pad::<HF>(hash_inputs);
            let data_i_hash = hash_n_no_padding::<F,D,H>(builder, hash_inputs)?;
            // make the counter into hash digest
            let ctr_target = builder.constant(F::from_canonical_u64((i+1) as u64));
            let mut ctr = builder.add_virtual_hash();
            for i in 0..ctr.elements.len() {
                if i==0 {
                    ctr.elements[i] = ctr_target;
                }else{
                    ctr.elements[i] = zero.clone();
                }
            }
            // paths for block and slot
            let mut b_path_bits = self.calculate_cell_index_bits(builder, &entropy_target, &d_targets.leaf, &ctr, mask_bits.clone())?;
            let mut s_path_bits = b_path_bits.split_off(block_tree_depth);

            let mut b_merkle_path = MerkleProofTarget {
                path: (0..block_tree_depth).map(|_| builder.add_virtual_hash()).collect(),
            };

            let mut s_merkle_path = MerkleProofTarget {
                path: (0..(max_depth - block_tree_depth)).map(|_| builder.add_virtual_hash()).collect(),
            };

            let mut block_targets = MerkleTreeTargets {
                leaf: data_i_hash,
                path_bits:b_path_bits,
                last_bits: b_last_bits.clone(),
                mask_bits: b_mask_bits.clone(),
                merkle_path: b_merkle_path,
            };

            // reconstruct block root
            let b_root = MerkleTreeCircuit::<F,D,H>::reconstruct_merkle_root_circuit_with_mask(builder, &mut block_targets, block_tree_depth)?;

            let mut slot_targets = MerkleTreeTargets {
                leaf: b_root,
                path_bits:s_path_bits,
                last_bits:s_last_bits.clone(),
                mask_bits:s_mask_bits.clone(),
                merkle_path:s_merkle_path,
            };

            // reconstruct slot root with block root as leaf
            let slot_reconstructed_root = MerkleTreeCircuit::<F,D,H>::reconstruct_merkle_root_circuit_with_mask(builder, &mut slot_targets, max_depth-block_tree_depth)?;

            // check equality with expected root
            for i in 0..NUM_HASH_OUT_ELTS {
                builder.connect( d_targets.leaf.elements[i], slot_reconstructed_root.elements[i]);
            }

            // combine block and slot path to get the full path so we can assign it later.
            let mut slot_sample_proof_target = MerkleProofTarget{
                path: block_targets.merkle_path.path,
            };
            slot_sample_proof_target.path.extend_from_slice(&slot_targets.merkle_path.path);

            let cell_i = CellTarget{
                data: data_i
            };
            data_targets.push(cell_i);
            slot_sample_proofs.push(slot_sample_proof_target);

        }

        let st = SampleTargets {
            entropy: entropy_target,
            dataset_root: d_expected_root,
            slot_index,
            slot_root: d_targets.leaf,
            n_cells_per_slot,
            n_slots_per_dataset,
            slot_proof: d_targets.merkle_path,
            cell_data: data_targets,
            merkle_paths: slot_sample_proofs,
        };

        Ok(st)
    }

    /// calculate the cell index = H( entropy | slotRoot | counter ) `mod` nCells
    pub fn calculate_cell_index_bits(&self, builder: &mut CircuitBuilder<F, D, NUM_HASH_OUT_ELTS>, entropy: &HashOutTarget<NUM_HASH_OUT_ELTS>, slot_root: &HashOutTarget<NUM_HASH_OUT_ELTS>, ctr: &HashOutTarget<NUM_HASH_OUT_ELTS>, mask_bits: Vec<BoolTarget>) -> Result<Vec<BoolTarget>> {
        let mut hash_inputs:Vec<Target>= Vec::new();
        hash_inputs.extend_from_slice(&entropy.elements);
        hash_inputs.extend_from_slice(&slot_root.elements);
        hash_inputs.extend_from_slice(&ctr.elements);

        let hash_out = hash_n_with_padding::<F,D,H>(builder, hash_inputs)?;
        let cell_index_bits =  builder.low_bits(hash_out.elements[0], self.params.max_depth, true);

        let mut masked_cell_index_bits = vec![];

        // extract the lowest 32 bits using the bit mask
        for i in 0..self.params.max_depth{
            masked_cell_index_bits.push(BoolTarget::new_unsafe(builder.mul(mask_bits[i].target, cell_index_bits[i].target)));
        }

        Ok(masked_cell_index_bits)
    }

    /// helper method to assign the targets in the circuit to actual field elems
    pub fn sample_slot_assign_witness(
        &self,
        pw: &mut PartialWitness<F>,
        targets: &SampleTargets,
        witnesses: &SampleCircuitInput<F, D>,
    ) -> Result<()>{
        // circuit params
        let CircuitParams {
            max_depth,
            n_field_elems_per_cell,
            n_samples,
            ..
        } = self.params;

        // assign n_cells_per_slot
        pw.set_target(targets.n_cells_per_slot, witnesses.n_cells_per_slot)
            ;

        // assign n_slots_per_dataset
        pw.set_target(targets.n_slots_per_dataset, witnesses.n_slots_per_dataset)
            ;

        // assign dataset proof
        for (i, sibling_hash) in witnesses.slot_proof.iter().enumerate() {
            pw.set_hash_target(targets.slot_proof.path[i], *sibling_hash)
                ;
        }
        // assign slot index
        pw.set_target(targets.slot_index, witnesses.slot_index)
            ;

        // assign the expected Merkle root of dataset to the target
        pw.set_hash_target(targets.dataset_root, witnesses.dataset_root)
            ;

        // assign the sampled slot
        pw.set_hash_target(targets.slot_root, witnesses.slot_root)
            ;

        // assign entropy
        assign_hash_out_targets(pw, &targets.entropy, &witnesses.entropy)?;

        // do the sample N times
        for i in 0..n_samples {
            // assign cell data
            let leaf = witnesses.cell_data[i].data.clone();
            for j in 0..n_field_elems_per_cell{
                pw.set_target(targets.cell_data[i].data[j], leaf[j])
                    ;
            }
            // assign proof for that cell
            let cell_proof = witnesses.merkle_paths[i].path.clone();
            for k in 0..max_depth {
                pw.set_hash_target(targets.merkle_paths[i].path[k], cell_proof[k])
                    ;
            }
        }

        Ok(())
    }

}
