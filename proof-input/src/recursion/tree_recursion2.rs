// some tests for approach 2 of the tree recursion

#[cfg(test)]
mod tests {
    use std::time::Instant;
    use anyhow::{anyhow, Result};
    use plonky2::iop::witness::PartialWitness;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitData, VerifierCircuitTarget, VerifierOnlyCircuitData};
    use plonky2::plonk::config::{AlgebraicHasher, GenericConfig, GenericHashOut, Hasher, PoseidonGoldilocksConfig};
    use plonky2::plonk::proof::ProofWithPublicInputs;
    use codex_plonky2_circuits::circuits::params::CircuitParams;
    use codex_plonky2_circuits::circuits::sample_cells::{SampleCircuit, SampleCircuitInput};
    use codex_plonky2_circuits::params::{F, D, C, Plonky2Proof};
    use codex_plonky2_circuits::recursion::circuits::sampling_inner_circuit::SamplingRecursion;
    use codex_plonky2_circuits::recursion::circuits::inner_circuit::InnerCircuit;
    use codex_plonky2_circuits::recursion::leaf_circuit::{LeafCircuit, LeafInput};
    use plonky2_poseidon2::poseidon2_hash::poseidon2::{Poseidon2, Poseidon2Hash};
    use crate::gen_input::gen_testing_circuit_input;
    use crate::params::TestParams;
    use codex_plonky2_circuits::recursion::tree_recursion2::{NodeCircuit as nodeC, TreeRecursion as TR};
    use codex_plonky2_circuits::recursion::tree2::utils::{get_dummy_leaf_proof, get_dummy_node_proof};
    use crate::gen_input::get_m_default_circ_input;

    /// Uses node recursion to sample the dataset
    #[test]
    fn test_leaf_circuit() -> Result<()> {
        // const D: usize = 2;
        // type C = PoseidonGoldilocksConfig;
        // type F = <C as GenericConfig<D>>::F;
        const M: usize = 1;
        const N: usize = 2;

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let params = TestParams::default();

        let one_circ_input = gen_testing_circuit_input::<F,D>(&params);
        let samp_circ = SampleCircuit::<F,D>::new(CircuitParams::default());
        let inner_tar = samp_circ.sample_slot_circuit_with_public_input(&mut builder);
        let mut pw = PartialWitness::<F>::new();
        samp_circ.sample_slot_assign_witness(&mut pw,&inner_tar,&one_circ_input);
        let inner_d = builder.build::<C>();
        let inner_prf = inner_d.prove(pw)?;

        let leaf_in = LeafInput{
            inner_proof:inner_prf,
            verifier_data: inner_d.verifier_data(),
        };
        let config2 = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config2);

        let inner_circ = SamplingRecursion::default();
        let leaf_circuit = LeafCircuit::new(inner_circ);

        let s = Instant::now();
        let leaf_tar = leaf_circuit.build(&mut builder)?;
        let circ_data =  builder.build::<C>();
        println!("build = {:?}", s.elapsed());
        let s = Instant::now();
        // let proof = tree_circ.prove(&[leaf_in],None, true)?;
        let mut pw = PartialWitness::<F>::new();
        leaf_circuit.assign_targets(&mut pw, &leaf_tar, &leaf_in)?;
        let proof = circ_data.prove(pw)?;
            println!("prove = {:?}", s.elapsed());
        println!("num of pi = {}", proof.public_inputs.len());
        println!("pub input: {:?}", proof.public_inputs);
        let s = Instant::now();
        assert!(
            circ_data.verify(proof).is_ok(),
            "proof verification failed"
        );
        println!("verify = {:?}", s.elapsed());

        Ok(())
    }

    #[test]
    fn test_node_circuit_approach2() -> Result<()> {
        // use predefined: C, D, F c
        const N: usize = 2; // binary tree

        let config = CircuitConfig::standard_recursion_config();
        let mut sampling_builder = CircuitBuilder::<F, D>::new(config);

        //------------ sampling inner circuit ----------------------
        // Circuit that does the sampling - default input
        let mut params = TestParams::default();
        // params.n_samples = 10;
        let one_circ_input = gen_testing_circuit_input::<F,D>(&params);
        let samp_circ = SampleCircuit::<F,D>::new(CircuitParams::default());
        let inner_tar = samp_circ.sample_slot_circuit_with_public_input(&mut sampling_builder);
        // get generate a sampling proof
        let mut pw = PartialWitness::<F>::new();
        samp_circ.sample_slot_assign_witness(&mut pw,&inner_tar,&one_circ_input);
        let inner_data = sampling_builder.build::<C>();
        let inner_proof = inner_data.prove(pw)?;

        // ------------------- leaf --------------------
        // leaf circuit that verifies the sampling proof
        let inner_circ = SamplingRecursion::default();
        let leaf_circuit = LeafCircuit::new(inner_circ);

        let leaf_in = LeafInput{
            inner_proof,
            verifier_data: inner_data.verifier_data(),
        };
        let config = CircuitConfig::standard_recursion_config();
        let mut leaf_builder = CircuitBuilder::<F, D>::new(config);
        // build
        let s = Instant::now();
        let leaf_targets = leaf_circuit.build(&mut leaf_builder)?;
        let leaf_circ_data =  leaf_builder.build::<C>();
        println!("build = {:?}", s.elapsed());
        // prove
        let s = Instant::now();
        let mut pw = PartialWitness::<F>::new();
        leaf_circuit.assign_targets(&mut pw, &leaf_targets, &leaf_in)?;
        let leaf_proof = leaf_circ_data.prove(pw)?;
        println!("prove = {:?}", s.elapsed());
        println!("num of pi = {}", leaf_proof.public_inputs.len());
        println!("pub input: {:?}", leaf_proof.public_inputs);
        // verify
        let s = Instant::now();
        assert!(
            leaf_circ_data.verify(leaf_proof.clone()).is_ok(),
            "proof verification failed"
        );
        println!("verify = {:?}", s.elapsed());

        // ------------- Node circuit ------------------
        // node circuit that verifies leafs or itself
        // build
        let s = Instant::now();
        let mut node = nodeC::build_circuit()?;
        println!("build = {:?}", s.elapsed());

        // prove leaf
        let s = Instant::now();
        let mut pw = PartialWitness::<F>::new();
        let leaf_proofs: [ProofWithPublicInputs<F, C, D>; N] = (0..N)
            .map(|_| {
                leaf_proof.clone()
            })
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| anyhow!("Expected exactly M inner circuits"))?;
        let dummy_node_proof = get_dummy_node_proof(
            &node.node_data.inner_node_common_data,
            &node.node_data.node_circuit_data.verifier_only,
        );
        let dummy_node_proofs: [ProofWithPublicInputs<F, C, D>; N] = (0..N)
            .map(|_| {
                dummy_node_proof.clone()
            })
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| anyhow!("Expected exactly M inner circuits"))?;
        nodeC::<N>::assign_targets(
            node.node_targets.clone(), //targets
            Some(leaf_proofs), // leaf proofs
            Some(dummy_node_proofs), // node proofs (dummy here)
            &node.node_data.leaf_circuit_data.verifier_only, // leaf verifier data
            &mut pw, // partial witness
            true // is leaf
        )?;
        let node_proof = node.node_data.node_circuit_data.prove(pw)?;
        println!("prove = {:?}", s.elapsed());
        println!("num of pi = {}", node_proof.public_inputs.len());
        println!("pub input: {:?}", node_proof.public_inputs);
        let s = Instant::now();
        assert!(
            node.node_data.node_circuit_data.verify(node_proof.clone()).is_ok(),
            "proof verification failed"
        );
        println!("verify = {:?}", s.elapsed());

        // prove node
        let s = Instant::now();
        let mut pw = PartialWitness::<F>::new();
        let node_proofs: [ProofWithPublicInputs<F, C, D>; N] = (0..N)
            .map(|_| {
                node_proof.clone()
            })
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| anyhow!("Expected exactly M inner circuits"))?;
        let dummy_leaf_proof = get_dummy_leaf_proof(
            &node.node_data.leaf_circuit_data.common
        );
        let dummy_leaf_proofs: [ProofWithPublicInputs<F, C, D>; N] = (0..N)
            .map(|_| {
                dummy_leaf_proof.clone()
            })
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| anyhow!("Expected exactly M inner circuits"))?;
        nodeC::<N>::assign_targets(
            node.node_targets.clone(), //targets
            Some(dummy_leaf_proofs), // leaf proofs
            Some(node_proofs), // node proofs (dummy here)
            &node.node_data.leaf_circuit_data.verifier_only, // leaf verifier data
            &mut pw, // partial witness
            false // is leaf
        )?;
        let node_proof = node.node_data.node_circuit_data.prove(pw)?;
        // let node_proof = node_d.prove(pw)?;
        println!("prove = {:?}", s.elapsed());
        println!("num of pi = {}", node_proof.public_inputs.len());
        println!("pub input: {:?}", node_proof.public_inputs);
        let s = Instant::now();
        assert!(
            node.node_data.node_circuit_data.verify(node_proof.clone()).is_ok(),
            "proof verification failed"
        );
        println!("verify = {:?}", s.elapsed());

        Ok(())
    }

    #[test]
    fn test_tree_recursion_approach2() -> Result<()> {
        // use predefined: C, D, F c
        const N: usize = 2; // binary tree
        const K: usize = 4; // number of leaves/slots sampled - should be power of 2

        let config = CircuitConfig::standard_recursion_config();
        let mut sampling_builder = CircuitBuilder::<F, D>::new(config);

        //------------ sampling inner circuit ----------------------
        // Circuit that does the sampling - default input
        let mut params = TestParams::default();
        params.n_samples = 10;
        let one_circ_input = gen_testing_circuit_input::<F,D>(&params);
        let samp_circ = SampleCircuit::<F,D>::new(CircuitParams::default());
        let inner_tar = samp_circ.sample_slot_circuit_with_public_input(&mut sampling_builder);
        // get generate a sampling proof
        let mut pw = PartialWitness::<F>::new();
        samp_circ.sample_slot_assign_witness(&mut pw,&inner_tar,&one_circ_input);
        let inner_data = sampling_builder.build::<C>();
        println!("sampling circuit degree bits = {:?}", inner_data.common.degree_bits());
        let inner_proof = inner_data.prove(pw)?;

        // ------------------- leaf --------------------
        // leaf circuit that verifies the sampling proof
        let inner_circ = SamplingRecursion::default();
        let leaf_circuit = LeafCircuit::new(inner_circ);

        let leaf_in = LeafInput{
            inner_proof,
            verifier_data: inner_data.verifier_data(),
        };
        let config = CircuitConfig::standard_recursion_config();
        let mut leaf_builder = CircuitBuilder::<F, D>::new(config);
        // build
        let s = Instant::now();
        let leaf_targets = leaf_circuit.build(&mut leaf_builder)?;
        let leaf_circ_data =  leaf_builder.build::<C>();
        println!("build = {:?}", s.elapsed());
        println!("leaf circuit degree bits = {:?}", leaf_circ_data.common.degree_bits());
        // prove
        let s = Instant::now();
        let mut pw = PartialWitness::<F>::new();
        leaf_circuit.assign_targets(&mut pw, &leaf_targets, &leaf_in)?;
        let leaf_proof = leaf_circ_data.prove(pw)?;
        println!("prove = {:?}", s.elapsed());
        println!("num of pi = {}", leaf_proof.public_inputs.len());
        println!("pub input: {:?}", leaf_proof.public_inputs);
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
        let mut tree  = TR::<N>::build()?;
        println!("build = {:?}", s.elapsed());
        println!("tree circuit degree bits = {:?}", tree.node.node_data.node_circuit_data.common.degree_bits());

        // prove leaf
        let s = Instant::now();
        // let mut pw = PartialWitness::<F>::new();
        let leaf_proofs: Vec<ProofWithPublicInputs<F, C, D>> = (0..K)
            .map(|_| {
                leaf_proof.clone()
            })
            .collect::<Vec<_>>();

        let tree_root_proof = tree.prove_tree(leaf_proofs)?;
        println!("prove = {:?}", s.elapsed());
        println!("num of pi = {}", tree_root_proof.public_inputs.len());
        println!("pub input: {:?}", tree_root_proof.public_inputs);
        let s = Instant::now();
        assert!(
            tree.verify_proof(tree_root_proof.clone()).is_ok(),
            "proof verification failed"
        );
        println!("verify = {:?}", s.elapsed());

        Ok(())
    }
}