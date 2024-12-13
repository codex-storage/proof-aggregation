// some tests for cyclic recursion

#[cfg(test)]
mod tests {
    use std::time::Instant;
    use anyhow::{anyhow, Result};
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitData, VerifierCircuitTarget, VerifierOnlyCircuitData};
    use plonky2::plonk::config::{AlgebraicHasher, GenericConfig, GenericHashOut, Hasher, PoseidonGoldilocksConfig};
    use codex_plonky2_circuits::circuits::sample_cells::SampleCircuitInput;
    use codex_plonky2_circuits::recursion::params::{F, D, C, Plonky2Proof};
    use codex_plonky2_circuits::recursion::sampling_inner_circuit::SamplingRecursion;
    use codex_plonky2_circuits::recursion::inner_circuit::InnerCircuit;
    use plonky2_poseidon2::poseidon2_hash::poseidon2::{Poseidon2, Poseidon2Hash};
    use crate::gen_input::gen_testing_circuit_input;
    use crate::params::TestParams;
    use codex_plonky2_circuits::recursion::tree_recursion::{NodeCircuit, TreeRecursion};

    fn get_m_default_circ_input<const M: usize>() -> [SampleCircuitInput<F,D>; M]{
        let mut params = TestParams::default();
        params.n_samples = 10;
        let one_circ_input = gen_testing_circuit_input::<F,D>(&params);
        let circ_input: [SampleCircuitInput<F,D>; M] = (0..M)
            .map(|_| one_circ_input.clone())
            .collect::<Vec<_>>()
            .try_into().unwrap();
        circ_input
    }

    /// Uses node recursion to sample the dataset
    #[test]
    fn test_node_recursion() -> Result<()> {
        // const D: usize = 2;
        // type C = PoseidonGoldilocksConfig;
        // type F = <C as GenericConfig<D>>::F;
        const M: usize = 1;
        const N: usize = 2;

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let one = builder.one();

        // Circuit that does the sampling
        let inner_sampling_circuit = SamplingRecursion::default();

        let mut cyclic_circ = NodeCircuit::<_,M,N>::new(inner_sampling_circuit);
        let mut tree_circ = TreeRecursion::new(cyclic_circ);
        let circ_input = get_m_default_circ_input::<M>();

        let s = Instant::now();
        tree_circ.build()?;
        println!("build = {:?}", s.elapsed());
        let s = Instant::now();
        let proof = tree_circ.prove(&circ_input,None, true)?;
        println!("prove = {:?}", s.elapsed());
        println!("num of pi = {}", proof.public_inputs.len());
        println!("pub input: {:?}", proof.public_inputs);
        let s = Instant::now();
        assert!(
            tree_circ.verify_proof(proof).is_ok(),
            "proof verification failed"
        );
        println!("verify = {:?}", s.elapsed());

        Ok(())
    }

}