// some tests for the leaf in tree recursion

#[cfg(test)]
mod tests {
    use plonky2::plonk::circuit_data::VerifierCircuitData;
    use plonky2::plonk::proof::ProofWithPublicInputs;
    use codex_plonky2_circuits::circuit_helper::Plonky2Circuit;
    use codex_plonky2_circuits::recursion::node::{NodeCircuit, NodeInput};
    use crate::params::{F, D, C, HF};
    use crate::recursion::leaf_test::tests::run_leaf_circ;
    use crate::recursion::run_sampling_circ;

    fn run_node_circ<const N: usize, const T: usize>(leaf_proofs: Vec<ProofWithPublicInputs<F, C, D>>, leaf_verifier_data: VerifierCircuitData<F, C, D>, flag: bool, index: usize) -> anyhow::Result<()> {

        // ------------------- Node --------------------
        // N leaf proofs
        assert_eq!(leaf_proofs.len(), N);
        let node = NodeCircuit::<F,D,C,HF, N, T>::new(leaf_verifier_data.clone());

        // build
        let (targets, data) = node.build_with_standard_config()?;
        let verifier_data: VerifierCircuitData<F,C,D> = data.verifier_data();
        let prover_data = data.prover_data();
        println!("node circuit degree bits = {:?}", prover_data.common.degree_bits());

        // prove
        let input = NodeInput{
            inner_proofs: leaf_proofs,
            verifier_only_data: leaf_verifier_data.verifier_only,
            condition: false,
            flags: [true; N].to_vec(),
            index,
        };

        let proof = node.prove(&targets, &input, &prover_data)?;
        println!("pub input size = {}", proof.public_inputs.len());
        println!("proof size = {:?} bytes", proof.to_bytes().len());
        println!("pub input = {:?}", proof.public_inputs);

        // verify
        assert!(
            verifier_data.verify(proof.clone()).is_ok(),
            "proof verification failed"
        );

        // TODO: check flags

        Ok(())
    }


    #[test]
    fn test_real_node_circ() -> anyhow::Result<()> {
        let (inner_proof, _, inner_verifier) = run_sampling_circ()?;
        // this is a bit wasteful to build leaf twice, TODO: fix this
        let (leaf_proof_1, _, leaf_verifier) = run_leaf_circ::<128>(inner_proof.clone(), inner_verifier.clone(), true, 0)?;
        let (leaf_proof_2, _, leaf_verifier) = run_leaf_circ::<128>(inner_proof, inner_verifier, true, 1)?;
        let leaf_proofs = vec![leaf_proof_1,leaf_proof_2];
        run_node_circ::<2,128>(leaf_proofs, leaf_verifier, true, 0)
    }

}