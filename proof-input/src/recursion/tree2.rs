// some tests for approach 2 of the tree recursion

#[cfg(test)]
mod tests {
    use std::time::Instant;
    use plonky2::hash::hash_types::HashOut;
    use plonky2::iop::witness::PartialWitness;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{GenericConfig, Hasher};
    use plonky2::plonk::proof::{ProofWithPublicInputs};
    use codex_plonky2_circuits::circuits::sample_cells::SampleCircuit;
    use crate::params::{F, D, C, HF};
    use codex_plonky2_circuits::recursion::circuits::sampling_inner_circuit::SamplingRecursion;
    use codex_plonky2_circuits::recursion::circuits::inner_circuit::InnerCircuit;
    use codex_plonky2_circuits::recursion::circuits::leaf_circuit::{LeafCircuit, LeafInput};
    // use plonky2_poseidon2::poseidon2_hash::poseidon2::{Poseidon2, Poseidon2Hash};
    use crate::gen_input::gen_testing_circuit_input;
    use crate::params::Params;
    use codex_plonky2_circuits::recursion::tree2::{tree_circuit::TreeRecursion};


    /// Uses node recursion to sample the dataset
    #[test]
    fn test_leaf_circuit() -> anyhow::Result<()> {
        const M: usize = 1;
        const N: usize = 2;

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let params = Params::default();

        let one_circ_input = gen_testing_circuit_input::<F,D>(&params.input_params);
        let samp_circ = SampleCircuit::<F,D, HF>::new(params.circuit_params);
        let inner_tar = samp_circ.sample_slot_circuit_with_public_input(&mut builder)?;
        let mut pw = PartialWitness::<F>::new();
        samp_circ.sample_slot_assign_witness(&mut pw,&inner_tar,&one_circ_input);
        let inner_d = builder.build::<C>();
        let inner_prf = inner_d.prove(pw)?;

        let leaf_in = LeafInput::<F,D,C,M>{
            inner_proof:[inner_prf; M],
            verifier_data: inner_d.verifier_data(),
        };
        let config2 = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config2);

        let inner_circ = SamplingRecursion::<F,D,HF,C>::new(Params::default().circuit_params);
        let leaf_circuit = LeafCircuit::<F,D,_, M>::new(inner_circ);

        let s = Instant::now();
        let leaf_tar = leaf_circuit.build::<C,HF>(&mut builder)?;
        let circ_data =  builder.build::<C>();
        println!("build = {:?}", s.elapsed());
        println!("sampling circuit size = {:?}", circ_data.common.degree_bits());
        let s = Instant::now();
        let mut pw = PartialWitness::<F>::new();
        leaf_circuit.assign_targets::<C,HF>(&mut pw, &leaf_tar, &leaf_in)?;
        let proof = circ_data.prove(pw)?;
            println!("prove = {:?}", s.elapsed());
        println!("num of pi = {}", proof.public_inputs.len());
        let s = Instant::now();
        assert!(
            circ_data.verify(proof).is_ok(),
            "proof verification failed"
        );
        println!("verify = {:?}", s.elapsed());

        Ok(())
    }

    #[test]
    fn test_tree_recursion_approach2() -> anyhow::Result<()> {
        const M: usize = 1;
        const N: usize = 2; // binary tree
        const K: usize = 2; // number of leaves/slots sampled - should be power of 2

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
        let leaf_circuit = LeafCircuit::<F,D,_, M>::new(inner_circ);

        let leaf_in = LeafInput::<F,D,C, M>{
            inner_proof:[inner_proof; M],
            verifier_data: inner_data.verifier_data(),
        };
        let config = CircuitConfig::standard_recursion_config();
        let mut leaf_builder = CircuitBuilder::<F, D>::new(config);
        // build
        let s = Instant::now();
        let leaf_targets = leaf_circuit.build::<C,HF>(&mut leaf_builder)?;
        let leaf_circ_data =  leaf_builder.build::<C>();
        println!("build = {:?}", s.elapsed());
        println!("leaf circuit size = {:?}", leaf_circ_data.common.degree_bits());
        // prove
        let s = Instant::now();
        let mut pw = PartialWitness::<F>::new();
        leaf_circuit.assign_targets::<C,HF>(&mut pw, &leaf_targets, &leaf_in)?;
        let leaf_proof = leaf_circ_data.prove(pw)?;
        println!("prove = {:?}", s.elapsed());
        println!("num of pi = {}", leaf_proof.public_inputs.len());
        // verify
        let s = Instant::now();
        assert!(
            leaf_circ_data.verify(leaf_proof.clone()).is_ok(),
            "proof verification failed"
        );
        println!("verify = {:?}", s.elapsed());

        // ------------- tree circuit ------------------
        // node circuit that verifies leafs or itself
        // build
        let s = Instant::now();
        let mut tree  = TreeRecursion::<F,D,C,N>::build::<_,HF, M>(leaf_circuit)?;
        println!("build = {:?}", s.elapsed());
        println!("node circuit degree bits = {:?}", tree.node.node_data.node_circuit_data.common.degree_bits());

        // prove leaf
        let s = Instant::now();
        let leaf_proofs: Vec<ProofWithPublicInputs<F, C, D>> = (0..K)
            .map(|_| {
                leaf_proof.clone()
            })
            .collect::<Vec<_>>();

        let tree_root_proof = tree.prove_tree(leaf_proofs.clone())?;
        println!("prove = {:?}", s.elapsed());
        println!("num of pi = {}", tree_root_proof.public_inputs.len());
        let s = Instant::now();
        assert!(
            tree.verify_proof(tree_root_proof.clone(),false).is_ok(),
            "proof verification failed"
        );

        assert_eq!(
            tree_root_proof.public_inputs[0..4].to_vec(),
            get_expected_tree_root_pi_hash::<N>(leaf_proofs),
            "Public input of tree_root_proof does not match the expected root hash"
        );
        println!("verify = {:?}", s.elapsed());

        Ok(())
    }

    // ------------ Public Input Verification ------------
    /// Recompute the expected root public input hash outside the circuit
    fn get_expected_tree_root_pi_hash<const N:usize>(leaf_proofs: Vec<ProofWithPublicInputs<F, C, D>>)
    -> Vec<F>{
        // Step 1: Extract relevant public inputs from each leaf proof
        let mut current_hashes: Vec<HashOut<F>> = leaf_proofs
            .iter()
            .map(|p|HashOut::from_vec(p.public_inputs.clone())) // Adjust index if different
            .collect();

        // Step 2: Iteratively compute parent hashes until one root hash remains
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

        // The final hash is the expected root hash
        current_hashes[0].elements.to_vec()
    }
}