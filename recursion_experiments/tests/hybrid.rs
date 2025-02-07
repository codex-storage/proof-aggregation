// some tests for approach 2 of the tree recursion

#[cfg(test)]
mod tests {
    use std::time::Instant;
    use plonky2::iop::witness::PartialWitness;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{GenericConfig, Hasher};
    use plonky2::plonk::proof::{ProofWithPublicInputs};
    use codex_plonky2_circuits::circuits::sample_cells::SampleCircuit;
    use crate::params::{F, D, C, HF};
    use codex_plonky2_circuits::recursion::circuits::sampling_inner_circuit::SamplingRecursion;
    use codex_plonky2_circuits::recursion::circuits::inner_circuit::InnerCircuit;
    use codex_plonky2_circuits::recursion::circuits::leaf_circuit::{LeafCircuit};
    // use plonky2_poseidon2::poseidon2_hash::poseidon2::{Poseidon2, Poseidon2Hash};
    use crate::gen_input::gen_testing_circuit_input;
    use crate::params::Params;
    use codex_plonky2_circuits::recursion::hybrid::tree_circuit::HybridTreeRecursion;


    #[test]
    fn test_hybrid_recursion() -> anyhow::Result<()> {
        const N: usize = 2; // binary tree
        const M: usize = 1; // number of proofs in leaves
        const K: usize = 8;

        let config = CircuitConfig::standard_recursion_config();
        let mut sampling_builder = CircuitBuilder::<F, D>::new(config);

        //------------ sampling inner circuit ----------------------
        // Circuit that does the sampling - default input
        let mut params = Params::default();
        let one_circ_input = gen_testing_circuit_input::<F,D>(&params.input_params);
        let samp_circ = SampleCircuit::<F,D,HF>::new(params.circuit_params);
        let inner_tar = samp_circ.sample_slot_circuit_with_public_input(&mut sampling_builder)?;
        // get generate a sampling proof
        let mut pw = PartialWitness::<F>::new();
        samp_circ.sample_slot_assign_witness(&mut pw,&inner_tar,&one_circ_input)?;
        let inner_data = sampling_builder.build::<C>();
        println!("sampling circuit degree bits = {:?}", inner_data.common.degree_bits());
        let inner_proof = inner_data.prove(pw)?;

        // ------------------- leaf --------------------
        // leaf circuit that verifies the sampling proof
        let inner_circ = SamplingRecursion::<F,D,HF,C>::new(Params::default().circuit_params);
        let leaf_circuit = LeafCircuit::<F,D,_,M>::new(inner_circ);

        // ------------- tree circuit ------------------

        let mut tree = HybridTreeRecursion::<F,D,_,N,M>::new(leaf_circuit);

        // prepare input
        let input_proofs: Vec<ProofWithPublicInputs<F, C, D>> = (0..K)
            .map(|_| {
                inner_proof.clone()
            })
            .collect::<Vec<_>>();

        // prove tree

        let s = Instant::now();
        let (tree_root_proof, verifier_data) = tree.prove_tree::<C,HF>(&input_proofs, inner_data.verifier_data())?;
        println!("prove = {:?}", s.elapsed());
        println!("num of pi = {}", tree_root_proof.public_inputs.len());
        let s = Instant::now();
        assert!(
            verifier_data.verify(tree_root_proof.clone()).is_ok(),
            "proof verification failed"
        );

        assert_eq!(
            tree_root_proof.public_inputs[0..4].to_vec(),
            get_expected_tree_root_pi_hash::<M, N>(input_proofs),
            "Public input of tree_root_proof does not match the expected root hash"
        );
        println!("verify = {:?}", s.elapsed());

        Ok(())
    }

    // ------------ Public Input Verification ------------
    /// Recompute the expected root public input hash outside the circuit
    fn get_expected_tree_root_pi_hash<const M: usize, const N:usize>(input_proofs: Vec<ProofWithPublicInputs<F, C, D>>) -> Vec<F>{
        // Compute the leaf hashes

        let mut current_hashes = vec![];
        for chunk in input_proofs.chunks(M){
            let chunk_f: Vec<F> = chunk.iter()
                .flat_map(|p| p.public_inputs.iter().cloned())
                .collect();

            let hash = HF::hash_no_pad(&chunk_f);
            current_hashes.push(hash);
        }

        // compute parent hashes until one root hash remains
        while current_hashes.len() > 1 {
            let mut next_level_hashes = Vec::new();

            for chunk in current_hashes.chunks(N) {
                // Ensure each chunk has exactly N elements
                assert!(
                    chunk.len() == N,
                    "Number of proofs is not divisible by N"
                );

                // collect field elements
                let chunk_f: Vec<F> = chunk.iter()
                    .flat_map(|h| h.elements.iter().cloned())
                    .collect();

                // Compute Poseidon2 hash of the concatenated chunk
                let hash = HF::hash_no_pad(&chunk_f);
                next_level_hashes.push(hash);
            }

            current_hashes = next_level_hashes;
        }

        //the expected root hash
        current_hashes[0].elements.to_vec()
    }
}