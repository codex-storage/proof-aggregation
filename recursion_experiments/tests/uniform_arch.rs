// some tests for approach 2 of the tree recursion

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::Instant;
    use plonky2::gates::constant::ConstantGate;
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::{CircuitConfig, CommonCircuitData, VerifierCircuitTarget};
    use plonky2::plonk::config::{AlgebraicHasher, GenericConfig, Hasher};
    use plonky2::plonk::proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget};
    use codex_plonky2_circuits::circuits::sample_cells::SampleCircuit;
    use crate::params::{F, D, C, HF};
    use codex_plonky2_circuits::recursion::circuits::sampling_inner_circuit::SamplingRecursion;
    // use codex_plonky2_circuits::recursion::circuits::inner_circuit::InnerCircuit;
    // use codex_plonky2_circuits::recursion::circuits::leaf_circuit::{LeafCircuit};
    // use plonky2_poseidon2::poseidon2_hash::poseidon2::{Poseidon2, Poseidon2Hash};
    use crate::gen_input::gen_testing_circuit_input;
    use crate::params::Params;
    use codex_plonky2_circuits::recursion::uniform::{leaf::{LeafCircuit,LeafInput,LeafTargets},node::{NodeCircuit,NodeInput,NodeTargets}, tree::TreeRecursion};

    #[test]
    fn test_treeuniform() -> anyhow::Result<()> {

        let config = CircuitConfig::standard_recursion_config();
        let mut sampling_builder = CircuitBuilder::<F, D>::new(config);

        //------------ sampling inner circuit ----------------------
        // Circuit that does the sampling - default input
        let mut params = Params::default();
        params.input_params.n_samples = 100;
        params.circuit_params.n_samples = 100;
        let one_circ_input = gen_testing_circuit_input::<F,D>(&params.input_params);
        let samp_circ = SampleCircuit::<F,D,HF>::new(params.circuit_params);
        let inner_tar = samp_circ.sample_slot_circuit_with_public_input(&mut sampling_builder)?;
        // get generate a sampling proof
        let mut pw = PartialWitness::<F>::new();
        samp_circ.sample_slot_assign_witness(&mut pw,&inner_tar,&one_circ_input)?;
        let inner_data = sampling_builder.build::<C>();
        println!("sampling circuit degree bits = {:?}", inner_data.common.degree_bits());
        let inner_proof = inner_data.prove(pw)?;

        let proofs: Vec<ProofWithPublicInputs<F, C, D>> = (0..4).map(|i| inner_proof.clone()).collect();

        // ------------------- tree --------------------

        let mut tree = TreeRecursion::<F,D,C,HF>::build(inner_data.common.clone())?;

        let root = tree.prove_tree(&proofs, inner_data.verifier_data())?;

        Ok(())
    }

    #[test]
    fn test_2uniform() -> anyhow::Result<()> {

        let config = CircuitConfig::standard_recursion_config();
        let mut sampling_builder = CircuitBuilder::<F, D>::new(config);

        //------------ sampling inner circuit ----------------------
        // Circuit that does the sampling - default input
        let mut params = Params::default();
        params.input_params.n_samples = 100;
        params.circuit_params.n_samples = 100;
        let one_circ_input = gen_testing_circuit_input::<F,D>(&params.input_params);
        let samp_circ = SampleCircuit::<F,D,HF>::new(params.circuit_params);
        let inner_tar = samp_circ.sample_slot_circuit_with_public_input(&mut sampling_builder)?;
        // get generate a sampling proof
        let mut pw = PartialWitness::<F>::new();
        samp_circ.sample_slot_assign_witness(&mut pw,&inner_tar,&one_circ_input)?;
        let inner_data = sampling_builder.build::<C>();
        println!("sampling circuit degree bits = {:?}", inner_data.common.degree_bits());
        let inner_proof = inner_data.prove(pw)?;

        // serialize circuit into JSON
        let common_circuit_data_serialized        = serde_json::to_string(&inner_data.common       ).unwrap();
        fs::write("circ_common.json" , common_circuit_data_serialized)       .expect("Unable to write file");


        // ------------------- leaf --------------------

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config.clone());

        let leaf_circ = LeafCircuit::<F,D,C,HF>::new(inner_data.common.clone());
        let leaf_targ = leaf_circ.build(&mut builder)?;

        // let (proof_targ, vd_targ) = build_proof_ver_circuit::<HF>(&mut builder,&inner_data.common).unwrap();
        // let leaf_targets = leaf_circuit.build::<C,HF>(&mut builder)?;

        // // add a ConstantGate
        // builder.add_gate(
        //     ConstantGate::new(config.num_constants),
        //     vec![],
        // );

        let leaf_data = builder.build::<C>();
        println!("leaf circuit size = {:?}", leaf_data.common.degree_bits());

        // serialize circuit into JSON
        let common_circuit_data_serialized        = serde_json::to_string(&leaf_data.common       ).unwrap();
        fs::write("leaf_common.json" , common_circuit_data_serialized)       .expect("Unable to write file");

        // prove
        let mut pw = PartialWitness::<F>::new();
        // pw.set_proof_with_pis_target(&proof_targ, &inner_proof)?;
        // pw.set_verifier_data_target(&vd_targ,&inner_data.verifier_only)?;
        let leaf_in = LeafInput{
            inner_proof: inner_proof.clone(),
            verifier_data: inner_data.verifier_data().clone(),
        };

        leaf_circ.assign_targets(&mut pw, &leaf_targ, &leaf_in)?;

        let leaf_proof = leaf_data.prove(pw)?;

        leaf_data.verify(leaf_proof.clone())?;

        // ------------- node1 circuit ------------------
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let node_circ = NodeCircuit::<F,D,C,HF>::new(leaf_data.common.clone());
        let node_targ = node_circ.build(&mut builder)?;

        // let (proof_targ, vd_targ) = build_node_proof_circuit::<HF>(&mut builder,&leaf_data.common).unwrap();
        // let leaf_targets = leaf_circuit.build::<C,HF>(&mut builder)?;

        let node_data = builder.build::<C>();
        println!("node circuit size = {:?}", node_data.common.degree_bits());

        // serialize circuit into JSON
        let common_circuit_data_serialized        = serde_json::to_string(&node_data.common       ).unwrap();
        fs::write("node_common.json" , common_circuit_data_serialized)       .expect("Unable to write file");

        // prove
        let mut pw = PartialWitness::<F>::new();
        // pw.set_proof_with_pis_target(&proof_targ[0], &leaf_proof)?;
        // pw.set_proof_with_pis_target(&proof_targ[1], &leaf_proof)?;
        // pw.set_verifier_data_target(&vd_targ,&leaf_data.verifier_only)?;

        let node_in = NodeInput{
            node_proofs: [leaf_proof.clone(),leaf_proof.clone()],
            verifier_data: leaf_data.verifier_data(),
        };

        node_circ.assign_targets(&mut pw, &node_targ,&node_in)?;

        let node_proof = node_data.prove(pw)?;

        node_data.verify(node_proof.clone())?;


        // ------------- check ----------------
        // prove
        let mut pw = PartialWitness::<F>::new();

        let node_in = NodeInput{
            node_proofs: [node_proof.clone(),node_proof.clone()],
            verifier_data: node_data.verifier_data(),
        };

        node_circ.assign_targets(&mut pw, &node_targ,&node_in)?;

        let node2_proof = node_data.prove(pw)?;

        node_data.verify(node2_proof.clone())?;


        // ------------- node2 circuit ------------------
        // let config = CircuitConfig::standard_recursion_config();
        // let mut builder = CircuitBuilder::<F, D>::new(config);
        //
        // let (proof_targ, vd_targ) = build_node_proof_circuit::<HF>(&mut builder,&node_data.common).unwrap();
        // // let leaf_targets = leaf_circuit.build::<C,HF>(&mut builder)?;
        //
        // let node2_data = builder.build::<C>();
        // println!("node2 circuit size = {:?}", node2_data.common.degree_bits());
        //
        // // serialize circuit into JSON
        // let common_circuit_data_serialized        = serde_json::to_string(&node2_data.common       ).unwrap();
        // fs::write("node2_common.json" , common_circuit_data_serialized)       .expect("Unable to write file");
        //
        // // prove
        // let mut pw = PartialWitness::<F>::new();
        // pw.set_proof_with_pis_target(&proof_targ[0], &leaf_proof)?;
        // pw.set_proof_with_pis_target(&proof_targ[1], &leaf_proof)?;
        // pw.set_verifier_data_target(&vd_targ,&leaf_data.verifier_only)?;
        //
        // let node_proof = node2_data.prove(pw)?;


        // prove node
        // let mut pw = PartialWitness::<F>::new();
        // pw.set_proof_with_pis_target(&proof_targ[0], &node_proof)?;
        // pw.set_proof_with_pis_target(&proof_targ[1], &node_proof)?;
        // pw.set_verifier_data_target(&vd_targ,&node_data.verifier_only)?;
        //
        // let node2_proof = node_data.prove(pw)?;


        Ok(())
    }

    #[test]
    fn test_uniform_recursion() -> anyhow::Result<()> {
        // const N: usize = 2; // binary tree
        // const M: usize = 1; // number of proofs in leaves
        // const K: usize = 8;

        let config = CircuitConfig::standard_recursion_config();
        let mut sampling_builder = CircuitBuilder::<F, D>::new(config);

        //------------ sampling inner circuit ----------------------
        // Circuit that does the sampling - default input
        let mut params = Params::default();
        params.input_params.n_samples = 100;
        params.circuit_params.n_samples = 100;
        let one_circ_input = gen_testing_circuit_input::<F,D>(&params.input_params);
        let samp_circ = SampleCircuit::<F,D,HF>::new(params.circuit_params);
        let inner_tar = samp_circ.sample_slot_circuit_with_public_input(&mut sampling_builder)?;
        // get generate a sampling proof
        let mut pw = PartialWitness::<F>::new();
        samp_circ.sample_slot_assign_witness(&mut pw,&inner_tar,&one_circ_input)?;
        let inner_data = sampling_builder.build::<C>();
        println!("sampling circuit degree bits = {:?}", inner_data.common.degree_bits());
        let inner_proof = inner_data.prove(pw)?;

        // serialize circuit into JSON
        let common_circuit_data_serialized        = serde_json::to_string(&inner_data.common       ).unwrap();
        fs::write("circ_common.json" , common_circuit_data_serialized)       .expect("Unable to write file");


        // ------------------- leaf --------------------

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config.clone());

        let (proof_targ, vd_targ) = build_proof_ver_circuit::<HF>(&mut builder,&inner_data.common).unwrap();
        // let leaf_targets = leaf_circuit.build::<C,HF>(&mut builder)?;

        // // add a ConstantGate
        // builder.add_gate(
        //     ConstantGate::new(config.num_constants),
        //     vec![],
        // );

        let leaf_data = builder.build::<C>();
        println!("leaf circuit size = {:?}", leaf_data.common.degree_bits());

        // serialize circuit into JSON
        let common_circuit_data_serialized        = serde_json::to_string(&leaf_data.common       ).unwrap();
        fs::write("leaf_common.json" , common_circuit_data_serialized)       .expect("Unable to write file");

        // prove
        let mut pw = PartialWitness::<F>::new();
        pw.set_proof_with_pis_target(&proof_targ, &inner_proof)?;
        pw.set_verifier_data_target(&vd_targ,&inner_data.verifier_only)?;

        let leaf_proof = leaf_data.prove(pw)?;

        // ------------- node1 circuit ------------------
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let (proof_targ, vd_targ) = build_node_proof_circuit::<HF>(&mut builder,&leaf_data.common).unwrap();
        // let leaf_targets = leaf_circuit.build::<C,HF>(&mut builder)?;

        let node_data = builder.build::<C>();
        println!("node circuit size = {:?}", node_data.common.degree_bits());

        // serialize circuit into JSON
        let common_circuit_data_serialized        = serde_json::to_string(&node_data.common       ).unwrap();
        fs::write("node_common.json" , common_circuit_data_serialized)       .expect("Unable to write file");

        // prove
        let mut pw = PartialWitness::<F>::new();
        pw.set_proof_with_pis_target(&proof_targ[0], &leaf_proof)?;
        pw.set_proof_with_pis_target(&proof_targ[1], &leaf_proof)?;
        pw.set_verifier_data_target(&vd_targ,&leaf_data.verifier_only)?;

        let node_proof = node_data.prove(pw)?;


        // ------------- node2 circuit ------------------
        // let config = CircuitConfig::standard_recursion_config();
        // let mut builder = CircuitBuilder::<F, D>::new(config);
        //
        // let (proof_targ, vd_targ) = build_node_proof_circuit::<HF>(&mut builder,&node_data.common).unwrap();
        // // let leaf_targets = leaf_circuit.build::<C,HF>(&mut builder)?;
        //
        // let node2_data = builder.build::<C>();
        // println!("node2 circuit size = {:?}", node2_data.common.degree_bits());
        //
        // // serialize circuit into JSON
        // let common_circuit_data_serialized        = serde_json::to_string(&node2_data.common       ).unwrap();
        // fs::write("node2_common.json" , common_circuit_data_serialized)       .expect("Unable to write file");
        //
        // // prove
        // let mut pw = PartialWitness::<F>::new();
        // pw.set_proof_with_pis_target(&proof_targ[0], &leaf_proof)?;
        // pw.set_proof_with_pis_target(&proof_targ[1], &leaf_proof)?;
        // pw.set_verifier_data_target(&vd_targ,&leaf_data.verifier_only)?;
        //
        // let node_proof = node2_data.prove(pw)?;


        // prove node
        let mut pw = PartialWitness::<F>::new();
        pw.set_proof_with_pis_target(&proof_targ[0], &node_proof)?;
        pw.set_proof_with_pis_target(&proof_targ[1], &node_proof)?;
        pw.set_verifier_data_target(&vd_targ,&node_data.verifier_only)?;

        let node2_proof = node_data.prove(pw)?;


        Ok(())
    }

    /// builds the node circuit
    pub fn build_proof_ver_circuit<
        H: AlgebraicHasher<F>,
    >(
        builder: &mut CircuitBuilder<F, D>,
        common_data: &CommonCircuitData<F, D>,
    ) -> anyhow::Result<(ProofWithPublicInputsTarget<D>, VerifierCircuitTarget)>{

        // the proof virtual targets
        // let mut proof_targets = vec![];
        let mut inner_pub_input = vec![];
        // for _i in 0..N {
        let vir_proof = builder.add_virtual_proof_with_pis(common_data);
        // collect the public input
        inner_pub_input.extend_from_slice(&vir_proof.public_inputs);
        // collect the proof targets
        // proof_targets.push(vir_proof);
        // }
        // hash the public input & make it public
        let hash_inner_pub_input = builder.hash_n_to_hash_no_pad::<H>(inner_pub_input);
        builder.register_public_inputs(&hash_inner_pub_input.elements);

        // virtual target for the verifier data
        let inner_verifier_data = builder.add_virtual_verifier_data(common_data.config.fri_config.cap_height);

        // verify the proofs in-circuit
        // for i in 0..N {
        builder.verify_proof::<C>(&vir_proof,&inner_verifier_data,&common_data);
        // }
        // let proof_target_array = vec_to_array::<N,ProofWithPublicInputsTarget<D>>(proof_targets)?;

        Ok(
            (vir_proof,
             inner_verifier_data)
        )
    }

    /// builds the node circuit
    pub fn build_node_proof_circuit<
        H: AlgebraicHasher<F>,
    >(
        builder: &mut CircuitBuilder<F, D>,
        common_data: &CommonCircuitData<F, D>,
    ) -> anyhow::Result<(Vec<ProofWithPublicInputsTarget<D>>, VerifierCircuitTarget)>{

        // the proof virtual targets
        let mut proof_targets = vec![];
        let mut inner_pub_input = vec![];
        for _i in 0..2 {
            let vir_proof = builder.add_virtual_proof_with_pis(common_data);
            // collect the public input
            inner_pub_input.extend_from_slice(&vir_proof.public_inputs);
            // collect the proof targets
            proof_targets.push(vir_proof);
        }
        // hash the public input & make it public
        let hash_inner_pub_input = builder.hash_n_to_hash_no_pad::<H>(inner_pub_input);
        builder.register_public_inputs(&hash_inner_pub_input.elements);

        // virtual target for the verifier data
        let inner_verifier_data = builder.add_virtual_verifier_data(common_data.config.fri_config.cap_height);

        // verify the proofs in-circuit
        for i in 0..2 {
            builder.verify_proof::<C>(&proof_targets[i],&inner_verifier_data,&common_data);
        }
        // let proof_target_array = vec_to_array::<N,ProofWithPublicInputsTarget<D>>(proof_targets)?;

        Ok(
            (proof_targets,
             inner_verifier_data)
        )
    }

}