// some tests for approach 1 of the tree recursion

#[cfg(test)]
mod tests {
    use std::time::Instant;
    use plonky2::plonk::config::{GenericConfig, GenericHashOut, Hasher};
    use plonky2_field::types::Field;
    use codex_plonky2_circuits::circuits::sample_cells::SampleCircuitInput;
    use crate::params::{C, D, F, HF, Params};
    use codex_plonky2_circuits::recursion::circuits::sampling_inner_circuit::SamplingRecursion;
    use codex_plonky2_circuits::recursion::circuits::inner_circuit::InnerCircuit;
    use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2;
    use crate::gen_input::get_m_default_circ_input;
    use codex_plonky2_circuits::recursion::tree1::tree_circuit::TreeRecursion;

    /// Uses node recursion to sample the dataset
    #[test]
    fn test_tree1_node_recursion() -> anyhow::Result<()> {
        const M: usize = 1;
        const N: usize = 2;

        let default_params = Params::default().circuit_params;
        let inner_sampling_circuit = SamplingRecursion::<F,D,HF,C>::new(default_params);

        let circ_input = get_m_default_circ_input::<M>();

        let s = Instant::now();
        let mut tree_circ = TreeRecursion::<F,D,_,M,N,C>::build::<HF>(inner_sampling_circuit)?;
        println!("build = {:?}", s.elapsed());
        println!("tree circuit size = {:?}", tree_circ.node_circ.cyclic_circuit_data.common.degree_bits());
        let s = Instant::now();
        let proof = tree_circ.prove(&circ_input,None, true)?;
        println!("prove = {:?}", s.elapsed());
        println!("num of pi = {}", proof.public_inputs.len());
        let s = Instant::now();
        assert!(
            tree_circ.verify_proof(proof).is_ok(),
            "proof verification failed"
        );
        println!("verify = {:?}", s.elapsed());

        Ok(())
    }

    /// Uses node recursion to sample the dataset
    #[test]
    fn test_tree_recursion_approach1() -> anyhow::Result<()> {
        const M: usize = 1;
        const N: usize = 2;

        const DEPTH: usize = 3;
        const TOTAL_INPUT: usize = (N.pow(DEPTH as u32) - 1) / (N - 1);

        let default_params = Params::default().circuit_params;
        let inner_sampling_circuit = SamplingRecursion::<F,D,HF,C>::new(default_params);

        let all_circ_input = get_m_default_circ_input::<TOTAL_INPUT>().to_vec();

        let s = Instant::now();
        let mut tree_circ = TreeRecursion::<F,D,_,M,N,C>::build::<HF>(inner_sampling_circuit)?;
        println!("build = {:?}", s.elapsed());
        println!("tree circuit size = {:?}", tree_circ.node_circ.cyclic_circuit_data.common.degree_bits());
        let s = Instant::now();
        let proof = tree_circ.prove_tree(all_circ_input.clone(),DEPTH)?;
        println!("prove = {:?}", s.elapsed());
        println!("num of pi = {}", proof.public_inputs.len());

        // Extract the final public input hash from the proof
        let final_proof_hash = &proof.public_inputs[0..4];

        // Recompute the expected final public input hash (outside the circuit)
        let expected_hash = compute_expected_pub_input_hash(
            &all_circ_input,
            DEPTH,
            M,
            N
        )?;

        // Check that the final hash in the proof matches the expected hash
        assert_eq!(final_proof_hash, expected_hash.as_slice(), "Public input hash mismatch");

        let s = Instant::now();
        assert!(
            tree_circ.verify_proof(proof).is_ok(),
            "proof verification failed"
        );
        println!("verify = {:?}", s.elapsed());

        Ok(())
    }

    /// Recursively compute the final public input hash for a single node in the recursion tree.
    /// This is the same logic from `NodeCircuit::build_circuit`
    /// TODO: optimize this
    fn compute_node_hash(
        all_circ_inputs: &[SampleCircuitInput<F, D>],
        depth: usize,
        current_depth: usize,
        node_idx: usize,
        M: usize,
        N: usize,
    ) -> [F; 4] {
        // Calculate the index in all_circ_inputs for this node's M inputs.
        // Total inputs per layer: sum_{k=0}^{current_depth-1} M*N^k = M * ((N^current_depth - 1)/(N-1))
        let offset_for_layer = ((N.pow(current_depth as u32) - 1) / (N - 1)) * M;
        let node_start = offset_for_layer + node_idx * M;
        let node_inputs = &all_circ_inputs[node_start..node_start + M];

        // Compute the outer public input hash:
        // public inputs are [slot_index, dataset_root.elements, entropy.elements].
        let mut outer_pi_hashes = vec![];
        for inp in node_inputs {
            let mut pi_vec = vec![inp.slot_index];
            pi_vec.extend_from_slice(&inp.dataset_root.elements);
            pi_vec.extend_from_slice(&inp.entropy.elements);
            let hash_res = HF::hash_no_pad(&pi_vec);
            outer_pi_hashes.extend_from_slice(&hash_res.elements);
        }

        // hash all these M hashes into one
        let outer_pi_hash = HF::hash_no_pad(&outer_pi_hashes);

        let is_leaf = current_depth == depth - 1;

        // Compute the inner proof hash (or zero hash if leaf)
        let inner_pi_hash_or_zero = if is_leaf {
            // condition = false at leaf, so inner proofs = zero hash
            [F::ZERO; 4]
        } else {
            // condition = true at non-leaf node -> recursively compute child hashes
            let next_depth = current_depth + 1;
            let child_start = node_idx * N;

            let mut inner_pub_input_hashes = vec![];
            for i in child_start..child_start + N {
                let child_hash = compute_node_hash(all_circ_inputs, depth, next_depth, i, M, N);
                inner_pub_input_hashes.extend_from_slice(&child_hash);
            }

            let inner_pub_input_hash = HF::hash_no_pad(&inner_pub_input_hashes);
            inner_pub_input_hash.elements
        };

        // Combine outer_pi_hash and inner_pi_hash_or_zero
        let mut final_input = vec![];
        final_input.extend_from_slice(&outer_pi_hash.elements);
        final_input.extend_from_slice(&inner_pi_hash_or_zero);

        let final_hash = HF::hash_no_pad(&final_input);
        final_hash.elements
    }

    /// Compute the expected public input hash for the entire recursion tree.
    /// This function calls `compute_node_hash` starting from the root (layer 0, node 0).
    pub fn compute_expected_pub_input_hash(
        all_circ_inputs: &[SampleCircuitInput<F, D>],
        depth: usize,
        M: usize,
        N: usize,
    ) -> anyhow::Result<Vec<F>> {
        // The root node is at layer = 0 and node_idx = 0
        let final_hash = compute_node_hash(all_circ_inputs, depth, 0, 0, M, N);
        Ok(final_hash.to_vec())
    }
}