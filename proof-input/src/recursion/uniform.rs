// some tests for the tree recursion

#[cfg(test)]
mod tests {
    use plonky2::iop::witness::{PartialWitness};
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::{CircuitConfig};
    use plonky2::plonk::config::{ GenericConfig};
    use plonky2::plonk::proof::{ProofWithPublicInputs};
    use codex_plonky2_circuits::circuits::sample_cells::SampleCircuit;
    use crate::params::{F, D, C, HF};
    use crate::gen_input::gen_testing_circuit_input;
    use crate::params::Params;
    use codex_plonky2_circuits::recursion::uniform::{tree::TreeRecursion};
    use codex_plonky2_circuits::recursion::uniform::pi_verifier::PublicInputVerificationCircuit;

    #[test]
    fn test_uniform_recursion() -> anyhow::Result<()> {

        let config = CircuitConfig::standard_recursion_config();
        let mut sampling_builder = CircuitBuilder::<F, D>::new(config);

        //------------ sampling inner circuit ----------------------
        // Circuit that does the sampling - 100 samples
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

        let num_of_proofs = 4;
        let proofs: Vec<ProofWithPublicInputs<F, C, D>> = (0..num_of_proofs).map(|i| inner_proof.clone()).collect();

        // ------------------- tree --------------------
        const N: usize = 1;
        const M: usize = 2;

        let mut tree = TreeRecursion::<F,D,C,HF, N, M>::build(inner_data.common.clone())?;

        let root = tree.prove_tree(&proofs, &inner_data.verifier_only)?;
        println!("pub input size = {}", root.public_inputs.len());
        println!("proof size = {:?} bytes", root.to_bytes().len());

        let root_compressed = tree.prove_tree_and_compress(&proofs, &inner_data.verifier_only)?;
        println!("pub input size (compressed) = {}", root_compressed.public_inputs.len());
        println!("proof size compressed = {:?} bytes", root_compressed.to_bytes().len());

        let inner_pi: Vec<Vec<F>> = proofs.iter().map(|p| p.public_inputs.clone()).collect();

        assert!(
            tree.verify_proof_and_public_input(root,inner_pi.clone(),&inner_data.verifier_data(), false).is_ok(),
            "proof verification failed"
        );

        assert!(
            tree.verify_proof_and_public_input(root_compressed,inner_pi,&inner_data.verifier_data(), true).is_ok(),
            "compressed proof verification failed"
        );


        Ok(())
    }

    #[test]
    fn test_pi_verifier() -> anyhow::Result<()> {

        let config = CircuitConfig::standard_recursion_config();
        let mut sampling_builder = CircuitBuilder::<F, D>::new(config);

        //------------ sampling inner circuit ----------------------
        // Circuit that does the sampling - 100 samples
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

        // 9 field elems as public inputs in the sampling circuit
        const K:usize = 9;
        // change the following as needed.
        const T: usize = 4;
        let proofs: Vec<ProofWithPublicInputs<F, C, D>> = (0..T).map(|i| inner_proof.clone()).collect();

        // ------------------- tree --------------------
        const N: usize = 1;
        const M: usize = 2;

        let mut tree = TreeRecursion::<F,D,C,HF, N, M>::build(inner_data.common.clone())?;

        let root = tree.prove_tree(&proofs, &inner_data.verifier_only)?;
        println!("pub input size = {}", root.public_inputs.len());
        println!("proof size = {:?} bytes", root.to_bytes().len());

        let inner_pi: Vec<Vec<F>> = proofs.iter().map(|p| p.public_inputs.clone()).collect();

        assert!(
            tree.verify_proof_and_public_input(root.clone(),inner_pi.clone(),&inner_data.verifier_data(), false).is_ok(),
            "proof verification failed"
        );

        // ------------------- Public input verifier Circuit --------------------

        let pi_verifier_circ = PublicInputVerificationCircuit::<F, D, C, HF, N, M, T, K>::new(tree.get_node_common_data());

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let pi_tarq = pi_verifier_circ.build(&mut builder)?;

        let pi_circ_data = builder.build::<C>();
        println!("PI verifier circuit degree bits = {:?}", pi_circ_data.common.degree_bits());

        let mut pw = PartialWitness::<F>::new();

        pi_verifier_circ.assign_targets(&mut pw, &pi_tarq, root, inner_pi.clone(), &tree.get_node_verifier_data(), &tree.get_leaf_verifier_data(), &inner_data.verifier_data())?;

        let proof = pi_circ_data.prove(pw)?;
        println!("pub input size = {}", proof.public_inputs.len());
        println!("proof size = {:?} bytes", proof.to_bytes().len());

        let pub_input_flat: Vec<F> = inner_pi.iter().cloned().flatten().collect();
        let num_pi = proof.public_inputs.len();

        // sanity check
        for (i, e) in proof.public_inputs.iter().enumerate(){
            if i < pub_input_flat.len() {
                assert_eq!(*e, pub_input_flat[i])
            }
        }

        assert!(
            pi_circ_data.verify(proof).is_ok(),
            "pi-verifier proof verification failed"
        );

        Ok(())
    }
}