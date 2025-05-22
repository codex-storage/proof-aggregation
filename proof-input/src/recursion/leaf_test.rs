// some tests for the leaf in tree recursion

#[cfg(test)]
pub mod tests {
    use plonky2::plonk::circuit_data::{ProverCircuitData, VerifierCircuitData};
    use plonky2::plonk::proof::ProofWithPublicInputs;
    use plonky2_field::types::{Field, PrimeField64};
    use codex_plonky2_circuits::circuit_helper::Plonky2Circuit;
    use codex_plonky2_circuits::recursion::leaf::{LeafCircuit, LeafInput};
    use codex_plonky2_circuits::recursion::dummy_gen::DummyProofGen;
    use crate::params::{F, D, C, HF};
    use crate::recursion::run_sampling_circ;

    pub fn run_leaf_circ<const T: usize>(inner_proof: ProofWithPublicInputs<F, C, D>, inner_verifier_data: VerifierCircuitData<F, C, D>, flag: bool, index: usize) -> anyhow::Result<(ProofWithPublicInputs<F, C, D>, ProverCircuitData<F, C, D>, VerifierCircuitData<F, C, D>)> {

        // ------------------- leaf --------------------
        let leaf = LeafCircuit::<F,D,C,HF,T>::new(inner_verifier_data.clone());

        // build
        let (targets, data) = leaf.build_with_standard_config()?;
        let verifier_data: VerifierCircuitData<F,C,D> = data.verifier_data();
        let prover_data = data.prover_data();
        println!("leaf circuit degree bits = {:?}", prover_data.common.degree_bits());

        // prove
        let input = LeafInput{
            inner_proof,
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

        Ok((proof, prover_data, verifier_data))
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

    #[test]
    fn test_real_leaf_circ() -> anyhow::Result<()> {
        let (inner_proof, _, inner_verifier) = run_sampling_circ()?;

        run_leaf_circ::<128>(inner_proof, inner_verifier, true, 1)?;
        Ok(())
    }

    #[test]
    fn test_dummy_leaf_circ() -> anyhow::Result<()> {
        let (_, _, inner_verifier) = run_sampling_circ()?;
        let (dummy_proof, dummy_vd) = DummyProofGen::gen_dummy_proof_and_vd_zero_pi(&inner_verifier.common)?;
        run_leaf_circ::<128>(dummy_proof, dummy_vd, false, 0)?;
        Ok(())
    }

}