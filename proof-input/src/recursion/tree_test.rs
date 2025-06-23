// some tests for the tree recursion

#[cfg(test)]
mod tests {
    use plonky2::plonk::proof::{ProofWithPublicInputs};
    use crate::params::{F, D, C, HF};
    use codex_plonky2_circuits::recursion::{tree::TreeRecursion};
    use crate::recursion::run_sampling_circ;

    fn run_tree_recursion<const N: usize, const T: usize>(compress: bool) -> anyhow::Result<()> {

        //------------ sampling inner circuit ----------------------
        // Circuit that does the sampling - 100 samples
        let (inner_proof, _inner_prover_data, inner_verifier_data) = run_sampling_circ()?;

        let proofs: Vec<ProofWithPublicInputs<F, C, D>> = (0..T).map(|_i| inner_proof.clone()).collect();

        // ------------------- tree --------------------
        // N-to-1 tree aggregation

        let mut tree = TreeRecursion::<F,D,C,HF, N, T>::build_with_standard_config(inner_verifier_data.clone())?;

        // aggregate
        let root = if !compress {
            tree.prove_tree(&proofs)?
        } else {
            println!("Mode: tree with compression");
            tree.prove_tree_and_compress(&proofs)?
        };
        println!("pub input size = {}", root.public_inputs.len());
        println!("pub input = {:?}", root.public_inputs);
        println!("proof size = {:?} bytes", root.to_bytes().len());

        let inner_pi: Vec<Vec<F>> = proofs.iter().map(|p| p.public_inputs.clone()).collect();

        assert!(
            tree.verify_proof_and_public_input(root,inner_pi.clone(), compress).is_ok(),
            "proof verification failed"
        );

        Ok(())
    }

    #[test]
    fn test_tree_recursion() -> anyhow::Result<()> {
        // total number of proofs to aggregate
        const T:usize = 4;
        run_tree_recursion::<2, T>(false)
    }

    #[test]
    fn test_tree_recursion_with_compression() -> anyhow::Result<()> {
        // total number of proofs to aggregate
        const T:usize = 4;
        run_tree_recursion::<2, T>(true)
    }

}