use plonky2::hash::hash_types::RichField;
use plonky2::plonk::config::{GenericConfig, Hasher};
use crate::params::{Params,InputParams};
use crate::utils::{bits_le_padded_to_usize, calculate_cell_index_bits, ceiling_log2, usize_to_bits_le};
use crate::merkle_tree::merkle_safe::MerkleProof;
use codex_plonky2_circuits::circuits::sample_cells::{MerklePath, SampleCircuit, SampleCircuitInput, SampleTargets};
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::proof::ProofWithPublicInputs;
use codex_plonky2_circuits::circuits::params::CircuitParams;
use plonky2_field::types::HasExtension;
use crate::data_structs::DatasetTree;
use crate::sponge::hash_bytes_no_padding;
use crate::params::{C, D, F, HF};
use codex_plonky2_circuits::circuits::params::NUM_HASH_OUT_ELTS;

/// generates circuit input (SampleCircuitInput) from fake data for testing
/// which can be later stored into json see json.rs
pub fn gen_testing_circuit_input<
    F: RichField + HasExtension<D>,
    const D: usize,
>(params: &InputParams) -> SampleCircuitInput<F,D>{
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
        entropy: proof.entropy,
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

/// verifies the given circuit input.
/// this is non circuit version for sanity check
pub fn verify_circuit_input<
    F: RichField + HasExtension<D>,
    const D: usize,
>(circ_input: SampleCircuitInput<F,D>, params: &InputParams) -> bool{
    let slot_index = circ_input.slot_index.as_canonical_u64();
    let slot_root = circ_input.slot_root.clone();
    // check dataset level proof
    let slot_proof = circ_input.slot_proof.clone();
    let dataset_path_bits = usize_to_bits_le(slot_index as usize, params.dataset_max_depth());
    let (dataset_last_bits, dataset_mask_bits) = ceiling_log2(params.n_slots, params.dataset_max_depth());
    let reconstructed_slot_root = MerkleProof::<F,D>::reconstruct_root2(
        slot_root,
        dataset_path_bits,
        dataset_last_bits,
        slot_proof,
        dataset_mask_bits,
        params.max_slots.trailing_zeros() as usize,
    ).unwrap();
    // assert reconstructed equals dataset root
    assert_eq!(reconstructed_slot_root, circ_input.dataset_root.clone());

    // check each sampled cell
    // get the index for cell from H(slot_root|counter|entropy)
    let mask_bits = usize_to_bits_le(params.n_cells -1, params.max_depth);
    for i in 0..params.n_samples {
        let cell_index_bits = calculate_cell_index_bits(
            &circ_input.entropy.elements.to_vec(),
            slot_root,
            i + 1,
            params.max_depth,
            mask_bits.clone(),
        );

        let cell_index = bits_le_padded_to_usize(&cell_index_bits);

        let s_res = verify_cell_proof(&circ_input, &params, cell_index, i);
        if s_res.unwrap() == false {
            println!("call {} is false", i);
            return false;
        }
    }
    true
}

/// Verify the given proof for slot tree, checks equality with the given root
pub fn verify_cell_proof<
    F: RichField + HasExtension<D>,
    const D: usize,
>(circ_input: &SampleCircuitInput<F,D>, params: &InputParams, cell_index: usize, ctr: usize) -> anyhow::Result<bool> {
    let mut block_path_bits = usize_to_bits_le(cell_index, params.max_depth);
    let last_index = params.n_cells - 1;
    let mut block_last_bits = usize_to_bits_le(last_index, params.max_depth);

    let split_point = params.bot_depth();

    let slot_last_bits = block_last_bits.split_off(split_point);
    let slot_path_bits = block_path_bits.split_off(split_point);

    // pub type HP = <PoseidonHash as Hasher<F>>::Permutation;
    let leaf_hash = hash_bytes_no_padding::<F,D,HF>(&circ_input.cell_data[ctr].data);

    let mut block_path = circ_input.merkle_paths[ctr].path.clone();
    let slot_path = block_path.split_off(split_point);

    let mut block_mask_bits = usize_to_bits_le(last_index, params.max_depth+1);
    let mut slot_mask_bits = block_mask_bits.split_off(split_point);

    block_mask_bits.push(false);
    slot_mask_bits.push(false);

    let block_res = MerkleProof::<F,D>::reconstruct_root2(
        leaf_hash,
        block_path_bits.clone(),
        block_last_bits.clone(),
        block_path,
        block_mask_bits,
        params.bot_depth(),
    );
    let reconstructed_root = MerkleProof::<F,D>::reconstruct_root2(
        block_res.unwrap(),
        slot_path_bits,
        slot_last_bits,
        slot_path,
        slot_mask_bits,
        params.max_depth - params.bot_depth(),
    );

    Ok(reconstructed_root.unwrap() == circ_input.slot_root)
}


/// returns exactly M default circuit input
pub fn get_m_default_circ_input<const M: usize>() -> [SampleCircuitInput<F,D>; M]{
    let params = Params::default().input_params;
    // let one_circ_input = gen_testing_circuit_input::<F,D>(&params);
    // let circ_input: [SampleCircuitInput<F,D>; M] = (0..M)
    //     .map(|_| one_circ_input.clone())
    //     .collect::<Vec<_>>()
    //     .try_into().unwrap();
    // circ_input
    get_m_circ_input::<M>(params)
}

/// returns exactly M default circuit input
pub fn get_m_circ_input<const M: usize>(params: InputParams) -> [SampleCircuitInput<F,D>; M]{
    // let params = Params::default().input_params;
    let one_circ_input = gen_testing_circuit_input::<F,D>(&params);
    let circ_input: [SampleCircuitInput<F,D>; M] = (0..M)
        .map(|_| one_circ_input.clone())
        .collect::<Vec<_>>()
        .try_into().unwrap();
    circ_input
}

#[cfg(test)]
mod tests {
    use std::time::Instant;
    use super::*;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::iop::witness::PartialWitness;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use codex_plonky2_circuits::circuits::params::CircuitParams;
    use codex_plonky2_circuits::circuits::sample_cells::SampleCircuit;
    // use crate::params::{C, D, F};

    // Test sample cells (non-circuit)
    #[test]
    fn test_gen_verify_proof(){
        let params = Params::default().input_params;
        let w = gen_testing_circuit_input::<F,D>(&params);
        assert!(verify_circuit_input::<F,D>(w, &params));
    }

    // Test sample cells in-circuit for a selected slot
    #[test]
    fn test_proof_in_circuit() -> anyhow::Result<()> {
        // get input
        let mut params = Params::default();
        let mut input_params = params.input_params;
        input_params.n_samples = 10;
        let circ_input = gen_testing_circuit_input::<F,D>(&input_params);

        // Create the circuit
        let config = CircuitConfig::standard_recursion_config_gl();
        let mut builder = CircuitBuilder::<F, D, NUM_HASH_OUT_ELTS>::new(config);

        let mut circuit_params = params.circuit_params;
        circuit_params.n_samples = 10;

        // build the circuit
        let circ = SampleCircuit::<F,D,HF>::new(circuit_params.clone());
        let mut targets = circ.sample_slot_circuit_with_public_input(&mut builder)?;

        // Create a PartialWitness and assign
        let mut pw = PartialWitness::new();

        // assign a witness
        circ.sample_slot_assign_witness(&mut pw, &targets, &circ_input)?;

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
