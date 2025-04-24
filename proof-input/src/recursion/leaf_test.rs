// some tests for the leaf in tree recursion

#[cfg(test)]
mod tests {
    use plonky2::plonk::circuit_data::{ProverCircuitData, VerifierCircuitData};
    use plonky2::plonk::proof::ProofWithPublicInputs;
    use plonky2_field::types::{Field, PrimeField64};
    use codex_plonky2_circuits::circuit_helper::Plonky2Circuit;
    use codex_plonky2_circuits::circuits::sample_cells::SampleCircuit;
    use codex_plonky2_circuits::recursion::leaf::{LeafCircuit, LeafInput};
    use codex_plonky2_circuits::recursion::node::{NodeCircuit, NodeInput};
    use codex_plonky2_circuits::recursion::dummy_gen::DummyProofGen;
    use crate::params::{F, D, C, HF};
    use crate::gen_input::gen_testing_circuit_input;
    use crate::params::Params;

    fn run_sampling_circ() -> anyhow::Result<(ProofWithPublicInputs<F, C, D>, ProverCircuitData<F, C, D>, VerifierCircuitData<F, C, D>)> {
        //------------ sampling inner circuit ----------------------
        // Circuit that does the sampling - 100 samples
        let mut params = Params::default();
        params.set_n_samples(100);
        let one_circ_input = gen_testing_circuit_input::<F,D>(&params.input_params);
        let samp_circ = SampleCircuit::<F,D,HF>::new(params.circuit_params);
        let (inner_tar, inner_data) = samp_circ.build_with_standard_config()?;

        let inner_verifier_data = inner_data.verifier_data();
        let inner_prover_data = inner_data.prover_data();

        println!("sampling circuit degree bits = {:?}", inner_verifier_data.common.degree_bits());
        let inner_proof = samp_circ.prove(&inner_tar, &one_circ_input, &inner_prover_data)?;

        Ok((inner_proof, inner_prover_data, inner_verifier_data))
    }

    fn run_leaf_circ<const N: usize, const T: usize>(inner_proof: ProofWithPublicInputs<F, C, D>, inner_verifier_data: VerifierCircuitData<F, C, D>, flag: bool, index: usize) -> anyhow::Result<()> {

        // ------------------- leaf --------------------
        // N inner proofs

        let leaf = LeafCircuit::<F,D,C,HF,N, T>::new(inner_verifier_data.common.clone(),inner_verifier_data.verifier_only.clone());

        // build
        let (targets, data) = leaf.build_with_standard_config()?;
        let verifier_data: VerifierCircuitData<F,C,D> = data.verifier_data();
        let prover_data = data.prover_data();
        println!("leaf circuit degree bits = {:?}", prover_data.common.degree_bits());

        // prove
        let input = LeafInput{
            inner_proof: vec![inner_proof],
            flag,
            index,
        };
        let proof = leaf.prove(&targets, &input, &prover_data)?;
        println!("pub input size = {}", proof.public_inputs.len());
        println!("proof size = {:?} bytes", proof.to_bytes().len());
        println!("pub input = {:?}", proof.public_inputs);

        // verify
        assert!(
            verifier_data.verify(proof.clone()).is_ok(),
            "proof verification failed"
        );

        let flag_buckets: Vec<F> = proof.public_inputs[9..13].to_vec();
        if flag {
            check_flag_buckets(index, flag_buckets);
        } else {
            for i in 0..flag_buckets.len() {
                assert_eq!(flag_buckets[i], F::ZERO, "bucket not valid");
            }
        }

        Ok(())
    }

    fn check_flag_buckets(index: usize, flag_buckets: Vec<F>) {
        // Compute the bucket and bit position from the input index.
        let bucket = index / 32;
        let bit = index % 32;
        // For each flag target (bucket), assign the appropriate 32-bit one-hot value.
        for (i, &flag_bucket) in flag_buckets.iter().enumerate() {
            let value: u64 = if i == bucket {
                    1 << bit
            } else {
                0
            };
            assert_eq!(value, flag_bucket.to_canonical_u64(), "bucket value mismatch");
        }
    }

    fn run_node_circ<const M: usize, const T: usize>(leaf_proof: ProofWithPublicInputs<F, C, D>, leaf_verifier_data: VerifierCircuitData<F, C, D>, flag: bool, index: usize) -> anyhow::Result<()> {

        // ------------------- Node --------------------
        // M leaf proofs

        let node = NodeCircuit::<F,D,C,HF,M, T>::new(leaf_verifier_data.common.clone(), leaf_verifier_data.verifier_only.clone());

        // build
        let (targets, data) = node.build_with_standard_config()?;
        let verifier_data: VerifierCircuitData<F,C,D> = data.verifier_data();
        let prover_data = data.prover_data();
        println!("node circuit degree bits = {:?}", prover_data.common.degree_bits());

        // prove
        let input = NodeInput{
            node_proofs: vec![leaf_proof.clone(), leaf_proof.clone()],
            verifier_only_data: leaf_verifier_data.verifier_only,
            condition: false,
            flags: [true; M].to_vec(),
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

        // let flag_buckets: Vec<F> = proof.public_inputs[9..13].to_vec();
        // if flag {
        //     check_flag_buckets(index, flag_buckets);
        // } else {
        //     for i in 0..flag_buckets.len() {
        //         assert_eq!(flag_buckets[i], F::ZERO, "bucket not valid");
        //     }
        // }

        Ok(())
    }

    #[test]
    fn test_real_leaf_circ() -> anyhow::Result<()> {
        let (inner_proof, _, inner_verifier) = run_sampling_circ()?;

        run_leaf_circ::<1, 1>(inner_proof, inner_verifier, true, 1)
    }

    #[test]
    fn test_dummy_leaf_circ() -> anyhow::Result<()> {
        let (_, _, inner_verifier) = run_sampling_circ()?;
        let (dummy_proof, dummy_vd) = DummyProofGen::gen_dummy_proof_and_vd_zero_pi(&inner_verifier.common)?;
        run_leaf_circ::<1, 1>(dummy_proof, dummy_vd, false, 0)
    }

}