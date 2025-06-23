use std::marker::PhantomData;
use std::path::Path;
use plonky2::hash::hash_types::RichField;
use plonky2_field::extension::Extendable;
use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2;
use crate::params::{Params,InputParams};
use crate::utils::{bits_le_padded_to_usize, calculate_cell_index_bits, ceiling_log2, usize_to_bits_le};
use crate::merkle_tree::merkle_safe::MerkleProof;
use codex_plonky2_circuits::circuits::sample_cells::{MerklePath, SampleCircuitInput};
use plonky2::plonk::config::AlgebraicHasher;
use crate::data_structs::DatasetTree;
use crate::serialization::circuit_input::export_circ_input_to_json;
use crate::sponge::hash_bytes_no_padding;

/// Input Generator to generates circuit input (SampleCircuitInput)
/// which can be later stored into json see json.rs
/// For now it generates input from fake data for testing
pub struct InputGenerator<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    H: AlgebraicHasher<F>,
>{
    pub input_params: InputParams,
    phantom_data: PhantomData<(F,H)>
}

impl<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    H: AlgebraicHasher<F>,
> InputGenerator<F, D, H> {

    pub fn new(input_params: InputParams) -> Self{
        Self{
            input_params,
            phantom_data: PhantomData::default(),
        }
    }

    pub fn default() -> Self{
        Self{
            input_params: Params::default().input_params,
            phantom_data: PhantomData::default(),
        }
    }

    /// Generate circuit input and export to JSON
    pub fn generate_and_export_circ_input_to_json<
        P: AsRef<Path>,
    >(
        &self,
        base_path: P,
    ) -> anyhow::Result<()> {
        let circ_input = self.gen_testing_circuit_input();
        export_circ_input_to_json(circ_input, base_path)?;

        Ok(())
    }

    /// returns exactly M default circuit input of all same circuit input
    pub fn get_m_testing_circ_input<const M: usize>(&self) -> [SampleCircuitInput<F,D>; M]{
        let one_circ_input = self.gen_testing_circuit_input();
        let circ_input: [SampleCircuitInput<F,D>; M] = (0..M)
            .map(|_| one_circ_input.clone())
            .collect::<Vec<_>>()
            .try_into().unwrap();
        circ_input
    }

    /// returns exactly M default circuit input of different circuit input
    pub fn get_m_unique_testing_circ_input<const M: usize>(&self) -> [SampleCircuitInput<F,D>; M]{
        todo!()
    }

    /// generates circuit input (SampleCircuitInput) from fake data for testing
    pub fn gen_testing_circuit_input(&self) -> SampleCircuitInput<F,D>{
        let params = &self.input_params;
        let dataset_t = DatasetTree::<F, D, H>::new_for_testing(params);

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
    >(&self, circ_input: SampleCircuitInput<F,D>) -> bool{
        let params = self.input_params.clone();
        let slot_index = circ_input.slot_index.to_canonical_u64();
        let slot_root = circ_input.slot_root.clone();
        // check dataset level proof
        let slot_proof = circ_input.slot_proof.clone();
        let dataset_path_bits = usize_to_bits_le(slot_index as usize, params.dataset_max_depth());
        let (dataset_last_bits, dataset_mask_bits) = ceiling_log2(params.n_slots, params.dataset_max_depth());
        let reconstructed_slot_root = MerkleProof::<F,D,H>::reconstruct_root2(
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

            let s_res = self.verify_cell_proof(&circ_input, cell_index, i);
            if s_res.unwrap() == false {
                println!("call {} is false", i);
                return false;
            }
        }
        true
    }

    /// Verify the given proof for slot tree, checks equality with the given root
    fn verify_cell_proof<
    >(&self, circ_input: &SampleCircuitInput<F,D>, cell_index: usize, ctr: usize) -> anyhow::Result<bool> {
        let params = self.input_params.clone();
        let mut block_path_bits = usize_to_bits_le(cell_index, params.max_depth);
        let last_index = params.n_cells - 1;
        let mut block_last_bits = usize_to_bits_le(last_index, params.max_depth);

        let split_point = params.bot_depth();

        let slot_last_bits = block_last_bits.split_off(split_point);
        let slot_path_bits = block_path_bits.split_off(split_point);

        // pub type HP = <PoseidonHash as Hasher<F>>::Permutation;
        let leaf_hash = hash_bytes_no_padding::<F,D,H>(&circ_input.cell_data[ctr].data);

        let mut block_path = circ_input.merkle_paths[ctr].path.clone();
        let slot_path = block_path.split_off(split_point);

        let mut block_mask_bits = usize_to_bits_le(last_index, params.max_depth+1);
        let mut slot_mask_bits = block_mask_bits.split_off(split_point);

        block_mask_bits.push(false);
        slot_mask_bits.push(false);

        let block_res = MerkleProof::<F,D,H>::reconstruct_root2(
            leaf_hash,
            block_path_bits.clone(),
            block_last_bits.clone(),
            block_path,
            block_mask_bits,
            params.bot_depth(),
        );
        let reconstructed_root = MerkleProof::<F,D,H>::reconstruct_root2(
            block_res.unwrap(),
            slot_path_bits,
            slot_last_bits,
            slot_path,
            slot_mask_bits,
            params.max_depth - params.bot_depth(),
        );

        Ok(reconstructed_root.unwrap() == circ_input.slot_root)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;
    use plonky2::hash::poseidon::PoseidonHash;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;
    use plonky2::plonk::proof::ProofWithPublicInputs;
    use plonky2_field::goldilocks_field::GoldilocksField;
    use super::*;
    use codex_plonky2_circuits::circuit_helper::Plonky2Circuit;
    use codex_plonky2_circuits::circuits::sample_cells::SampleCircuit;

    // types used in all tests
    type F = GoldilocksField;
    const D: usize = 2;
    type H = PoseidonHash;
    type C = PoseidonGoldilocksConfig;

    // Test sample cells (non-circuit)
    #[test]
    fn test_gen_verify_proof(){
        let input_gen = InputGenerator::<F,D,H>::default();
        let w = input_gen.gen_testing_circuit_input();
        assert!(input_gen.verify_circuit_input(w));
    }

    // Test sample cells in-circuit for a selected slot
    #[test]
    fn test_proof_in_circuit() -> anyhow::Result<()> {
        // get input
        let mut params = Params::default();
        params.set_n_samples(10);
        let input_params = params.input_params;
        let circuit_params = params.circuit_params;
        let input_gen = InputGenerator::<F,D,H>::new(input_params);
        let circ_input = input_gen.gen_testing_circuit_input();

        // build the circuit
        let circ = SampleCircuit::<F,D,H>::new(circuit_params.clone());
        let (targets, data) = circ.build_with_standard_config()?;
        println!("circuit size = {:?}", data.common.degree_bits());

        // separate the prover and verifier
        let verifier_data = data.verifier_data();
        let prover_data = data.prover_data();

        // Prove the circuit using the circuit input
        let start_time = Instant::now();
        let proof_with_pis: ProofWithPublicInputs<F, C, D> = circ.prove(&targets, &circ_input, &prover_data)?;
        println!("prove_time = {:?}", start_time.elapsed());

        // Verify the proof
        assert!(
            verifier_data.verify(proof_with_pis).is_ok(),
            "Merkle proof verification failed"
        );

        Ok(())
    }

}
