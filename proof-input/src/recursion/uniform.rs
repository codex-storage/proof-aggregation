// some tests for the tree recursion

#[cfg(test)]
mod tests {
    use plonky2::plonk::proof::{ProofWithPublicInputs};
    use codex_plonky2_circuits::circuit_helper::Plonky2Circuit;
    use codex_plonky2_circuits::circuits::sample_cells::SampleCircuit;
    use crate::params::{F, D, C, HF};
    use crate::gen_input::gen_testing_circuit_input;
    use crate::params::Params;
    use codex_plonky2_circuits::recursion::{tree::TreeRecursion};
    use codex_plonky2_circuits::recursion::pi_verifier::{PublicInputVerificationCircuit, PublicInputVerificationInput};
    use codex_plonky2_circuits::recursion::tree::get_hash_of_verifier_data;

    #[test]
    fn test_uniform_recursion() -> anyhow::Result<()> {

        // total number of proofs to aggregate
        const T:usize = 4;

        //------------ sampling inner circuit ----------------------
        // Circuit that does the sampling - 100 samples
        let mut params = Params::default();
        params.input_params.n_samples = 100;
        params.circuit_params.n_samples = 100;
        let one_circ_input = gen_testing_circuit_input::<F,D>(&params.input_params);
        let samp_circ = SampleCircuit::<F,D,HF>::new(params.circuit_params);
        let (inner_tar, inner_data) = samp_circ.build_with_standard_config()?;

        let inner_verifier_data = inner_data.verifier_data();
        let inner_prover_data = inner_data.prover_data();

        println!("sampling circuit degree bits = {:?}", inner_verifier_data.common.degree_bits());
        let inner_proof = samp_circ.prove(&inner_tar, &one_circ_input, &inner_prover_data)?;

        let proofs: Vec<ProofWithPublicInputs<F, C, D>> = (0..T).map(|_i| inner_proof.clone()).collect();

        // ------------------- tree --------------------
        // 2-to-1 tree aggregation
        const N: usize = 1;
        const M: usize = 2;

        let mut tree = TreeRecursion::<F,D,C,HF, N, M, T>::build_with_standard_config(inner_verifier_data.common.clone(), inner_verifier_data.verifier_only.clone())?;

        // aggregate - no compression
        let root = tree.prove_tree(&proofs)?;
        println!("pub input size = {}", root.public_inputs.len());
        println!("pub input = {:?}", root.public_inputs);
        println!("proof size = {:?} bytes", root.to_bytes().len());

        // aggregate with compression
        // let root_compressed = tree.prove_tree_and_compress(&proofs)?;
        // println!("pub input size (compressed) = {}", root_compressed.public_inputs.len());
        // println!("proof size compressed = {:?} bytes", root_compressed.to_bytes().len());

        let inner_pi: Vec<Vec<F>> = proofs.iter().map(|p| p.public_inputs.clone()).collect();

        assert!(
            tree.verify_proof_and_public_input(root,inner_pi.clone(), false).is_ok(),
            "proof verification failed"
        );

        // assert!(
        //     tree.verify_proof_and_public_input(root_compressed,inner_pi, true).is_ok(),
        //     "compressed proof verification failed"
        // );


        Ok(())
    }

    #[test]
    fn test_pi_verifier() -> anyhow::Result<()> {

        // total number of proofs to aggregate
        const T:usize = 4;
        // 9 field elems as public inputs in the sampling circuit
        const K:usize = 9;

        //------------ sampling inner circuit ----------------------
        // Circuit that does the sampling - 100 samples
        let mut params = Params::default();
        params.input_params.n_samples = 100;
        params.circuit_params.n_samples = 100;
        let one_circ_input = gen_testing_circuit_input::<F,D>(&params.input_params);
        let samp_circ = SampleCircuit::<F,D,HF>::new(params.circuit_params);
        let (inner_tar, inner_data) = samp_circ.build_with_standard_config()?;

        let inner_verifier_data = inner_data.verifier_data();
        let inner_prover_data = inner_data.prover_data();

        // get generate a sampling proof
        println!("sampling circuit degree bits = {:?}", inner_verifier_data.common.degree_bits());
        let inner_proof = samp_circ.prove(&inner_tar, &one_circ_input, &inner_prover_data)?;

        let proofs: Vec<ProofWithPublicInputs<F, C, D>> = (0..T).map(|_i| inner_proof.clone()).collect();

        // ------------------- tree --------------------
        const N: usize = 1;
        const M: usize = 2;

        let mut tree = TreeRecursion::<F,D,C,HF, N, M, T>::build_with_standard_config(inner_verifier_data.common.clone(), inner_verifier_data.verifier_only.clone())?;

        let root = tree.prove_tree(&proofs)?;
        println!("pub input size = {}", root.public_inputs.len());
        println!("proof size = {:?} bytes", root.to_bytes().len());

        let inner_pi: Vec<Vec<F>> = proofs.iter().map(|p| p.public_inputs.clone()).collect();

        assert!(
            tree.verify_proof_and_public_input(root.clone(),inner_pi.clone(), false).is_ok(),
            "proof verification failed"
        );

        // ------------------- Public input verifier Circuit --------------------

        let pi_verifier_circ = PublicInputVerificationCircuit::<F, D, C, HF, N, M, T, K>::new(tree.get_node_common_data(), tree.get_node_verifier_data().verifier_only);

        let (pi_tarq, pi_circ_data) = pi_verifier_circ.build_with_standard_config()?;
        println!("PI verifier circuit degree bits = {:?}", pi_circ_data.common.degree_bits());

        let pi_circ_input = PublicInputVerificationInput{
            inner_proof:root,
            inner_pub_inputs_vals: inner_pi.clone()
        };

        let pi_circ_verifier_data = pi_circ_data.verifier_data();
        let pi_circ_prover_data = pi_circ_data.prover_data();

        let proof =pi_verifier_circ.prove(&pi_tarq, &pi_circ_input, &pi_circ_prover_data)?;

        println!("pub input size = {}", proof.public_inputs.len());
        println!("proof size = {:?} bytes", proof.to_bytes().len());

        let pub_input_flat: Vec<F> = inner_pi.iter().cloned().flatten().collect();

        // sanity check on public input
        for (i, e) in proof.public_inputs.iter().enumerate(){
            if i < pub_input_flat.len() {
                assert_eq!(*e, pub_input_flat[i])
            }
        }

        // sanity check on the verifier data
        let hashed_node_vd = get_hash_of_verifier_data::<F,D,C,HF>(&tree.get_node_verifier_data());
        for (i, &e) in proof.public_inputs[proof.public_inputs.len()-4 ..].iter().enumerate(){
            assert_eq!(e, hashed_node_vd.elements[i])
        }


        assert!(
            pi_circ_verifier_data.verify(proof).is_ok(),
            "pi-verifier proof verification failed"
        );

        Ok(())
    }
}