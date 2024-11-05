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
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig, Hasher, GenericHashOut};
use std::marker::PhantomData;
use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2;
use plonky2::hash::hashing::PlonkyPermutation;
use crate::circuits::params::HF;

use crate::circuits::merkle_circuit::{MerkleTreeCircuit, MerkleTreeTargets, MerkleProofTarget};
use crate::circuits::utils::{assign_hash_out_targets, bits_le_padded_to_usize, calculate_cell_index_bits};

// ------ Dataset Tree --------
///dataset tree containing all slot trees
#[derive(Clone)]
pub struct DatasetTreeCircuit<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
> {
    params: CircuitParams,
    phantom_data: PhantomData<F>,
}

impl<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
> DatasetTreeCircuit<F, D> {
    pub fn new(params: CircuitParams) -> Self{
        Self{
            params,
            phantom_data: Default::default(),
        }
    }
}

// params used for the circuits
// should be defined prior to building the circuit
#[derive(Clone)]
pub struct CircuitParams{
    pub max_depth: usize,
    pub max_log2_n_slots: usize,
    pub block_tree_depth: usize,
    pub n_field_elems_per_cell: usize,
    pub n_samples: usize,
}

#[derive(Clone)]
pub struct SampleTargets {

    pub entropy: HashOutTarget,
    pub dataset_root: HashOutTarget,
    pub slot_index: Target,

    pub slot_root: HashOutTarget,
    pub n_cells_per_slot: Target,
    pub n_slots_per_dataset: Target,

    pub slot_proof: MerkleProofTarget, // proof that slot_root in dataset tree

    pub cell_data: Vec<Vec<Target>>,
    pub merkle_paths: Vec<MerkleProofTarget>,
}

#[derive(Clone)]
pub struct SampleCircuitInput<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
>{
    pub entropy: Vec<F>,
    pub dataset_root: HashOut<F>,
    pub slot_index: F,

    pub slot_root: HashOut<F>,
    pub n_cells_per_slot: F,
    pub n_slots_per_dataset: F,

    pub slot_proof: Vec<HashOut<F>>, // proof that slot_root in dataset tree

    pub cell_data: Vec<Vec<F>>,
    pub merkle_paths: Vec<Vec<HashOut<F>>>,

}

#[derive(Clone)]
pub struct MerklePath<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
> {
    path: Vec<HashOut<F>>
}

#[derive(Clone)]
pub struct CellTarget {
    pub data: Vec<Target>
}

//------- circuit impl --------
impl<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
> DatasetTreeCircuit<F, D> {

    // in-circuit sampling
    // TODO: make it more modular
    pub fn sample_slot_circuit(
        &self,
        builder: &mut CircuitBuilder::<F, D>,
    )-> SampleTargets {
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
        let two = builder.two();

        // ***** prove slot root is in dataset tree *********

        // Create virtual target for slot root and index
        let slot_root = builder.add_virtual_hash();
        let slot_index = builder.add_virtual_target();

        // dataset path bits (binary decomposition of leaf_index)
        let d_path_bits = builder.split_le(slot_index,max_log2_n_slots);

        // create virtual target for n_slots_per_dataset
        let n_slots_per_dataset = builder.add_virtual_target();

        // dataset last bits (binary decomposition of last_index = nleaves - 1)
        let dataset_last_index = builder.sub(n_slots_per_dataset, one);
        let d_last_bits = builder.split_le(dataset_last_index,max_log2_n_slots);
        let d_mask_bits = builder.split_le(dataset_last_index,max_log2_n_slots+1);

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
            MerkleTreeCircuit::<F,D>::reconstruct_merkle_root_circuit_with_mask(builder, &mut d_targets, max_log2_n_slots);

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

        // virtual target for n_cells_per_slot
        let n_cells_per_slot = builder.add_virtual_target();

        let slot_last_index = builder.sub(n_cells_per_slot, one);
        let mut b_last_bits = builder.split_le(slot_last_index,max_depth);
        let mut b_mask_bits = builder.split_le(slot_last_index,max_depth);


        let mut s_last_bits = b_last_bits.split_off(block_tree_depth);
        let mut s_mask_bits = b_mask_bits.split_off(block_tree_depth);

        b_mask_bits.push(BoolTarget::new_unsafe(zero.clone()));
        s_mask_bits.push(BoolTarget::new_unsafe(zero.clone()));

        for i in 0..n_samples{
            // cell data targets
            let mut data_i = (0..n_field_elems_per_cell).map(|_| builder.add_virtual_target()).collect::<Vec<_>>();

            let mut hash_inputs:Vec<Target>= Vec::new();
            hash_inputs.extend_from_slice(&data_i);
            let data_i_hash = builder.hash_n_to_hash_no_pad::<HF>(hash_inputs);
            // counter constant
            let ctr_target = builder.constant(F::from_canonical_u64((i+1) as u64));
            let mut ctr = builder.add_virtual_hash();
            for i in 0..ctr.elements.len() {
                if(i==0){
                    ctr.elements[i] = ctr_target;
                }else{
                    ctr.elements[i] = zero.clone();
                }
            }
            // paths
            let mut b_path_bits = self.calculate_cell_index_bits(builder, &entropy_target, &d_targets.leaf, &ctr);
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
            let b_root = MerkleTreeCircuit::<F,D>::reconstruct_merkle_root_circuit_with_mask(builder, &mut block_targets, block_tree_depth);

            let mut slot_targets = MerkleTreeTargets {
                leaf: b_root,
                path_bits:s_path_bits,
                last_bits:s_last_bits.clone(),
                mask_bits:s_mask_bits.clone(),
                merkle_path:s_merkle_path,
            };

            // reconstruct slot root with block root as leaf
            let slot_reconstructed_root = MerkleTreeCircuit::<F,D>::reconstruct_merkle_root_circuit_with_mask(builder, &mut slot_targets, max_depth-block_tree_depth);

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

        SampleTargets {
            entropy: entropy_target,
            dataset_root: d_expected_root,
            slot_index,
            slot_root: d_targets.leaf,
            n_cells_per_slot,
            n_slots_per_dataset,
            slot_proof: d_targets.merkle_path,
            cell_data: data_targets,
            merkle_paths: slot_sample_proofs,
        }
    }

    pub fn calculate_cell_index_bits(&self, builder: &mut CircuitBuilder::<F, D>, entropy: &HashOutTarget, slot_root: &HashOutTarget, ctr: &HashOutTarget) -> Vec<BoolTarget> {
        let mut hash_inputs:Vec<Target>= Vec::new();
        hash_inputs.extend_from_slice(&entropy.elements);
        hash_inputs.extend_from_slice(&slot_root.elements);
        hash_inputs.extend_from_slice(&ctr.elements);
        let hash_out = builder.hash_n_to_hash_no_pad::<HF>(hash_inputs);
        let cell_index_bits =  builder.low_bits(hash_out.elements[0], self.params.max_depth, 64);

        cell_index_bits
    }

    pub fn sample_slot_assign_witness(
        &self,
        pw: &mut PartialWitness<F>,
        targets: &mut SampleTargets,
        witnesses: SampleCircuitInput<F, D>,
    ){
        // circuit params
        let CircuitParams {
            max_depth,
            max_log2_n_slots,
            block_tree_depth,
            n_field_elems_per_cell,
            n_samples,
        } = self.params;

        // assign n_cells_per_slot
        pw.set_target(targets.n_cells_per_slot, witnesses.n_cells_per_slot);

        // assign n_slots_per_dataset
        pw.set_target(targets.n_slots_per_dataset, witnesses.n_slots_per_dataset);

        // assign dataset proof
        for (i, sibling_hash) in witnesses.slot_proof.iter().enumerate() {
            pw.set_hash_target(targets.slot_proof.path[i], *sibling_hash);
        }
        // assign slot index
        pw.set_target(targets.slot_index, witnesses.slot_index);

        // assign the expected Merkle root of dataset to the target
        pw.set_hash_target(targets.dataset_root, witnesses.dataset_root);

        // assign the sampled slot
        pw.set_hash_target(targets.slot_root, witnesses.slot_root);

        // assign entropy
        assign_hash_out_targets(pw, &targets.entropy.elements, &witnesses.entropy);

        // do the sample N times
        for i in 0..n_samples {
            let cell_index_bits = calculate_cell_index_bits(&witnesses.entropy,witnesses.slot_root,i+1,max_depth);
            let cell_index = bits_le_padded_to_usize(&cell_index_bits);
            // assign cell data
            let leaf = witnesses.cell_data[i].clone();
            for j in 0..n_field_elems_per_cell{
                pw.set_target(targets.cell_data[i][j], leaf[j]);
            }

            // assign proof for that cell
            let cell_proof = witnesses.merkle_paths[i].clone();
            for k in 0..max_depth {
                pw.set_hash_target(targets.merkle_paths[i].path[k], cell_proof[k])
            }
        }

    }

}
