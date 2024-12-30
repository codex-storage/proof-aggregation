// some tests for cyclic recursion

#[cfg(test)]
mod tests {
    use std::time::Instant;
    use anyhow::Result;
    use plonky2::hash::hash_types::HashOut;
    use plonky2::hash::hashing::hash_n_to_hash_no_pad;
    use plonky2::hash::poseidon::PoseidonPermutation;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::GenericConfig;
    use codex_plonky2_circuits::recursion::params::{F, D, C, Plonky2Proof};
    use codex_plonky2_circuits::recursion::sampling_inner_circuit::SamplingRecursion;
    use plonky2_poseidon2::poseidon2_hash::poseidon2::{Poseidon2, Poseidon2Hash};
    use crate::gen_input::gen_testing_circuit_input;
    use crate::params::TestParams;
    use codex_plonky2_circuits::recursion::cyclic_recursion::CyclicCircuit;


    /// Uses cyclic recursion to sample the dataset
    #[test]
    fn test_cyclic_recursion() -> Result<()> {
        // const D: usize = 2;
        // type C = PoseidonGoldilocksConfig;
        // type F = <C as GenericConfig<D>>::F;

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let one = builder.one();

        let inner_sampling_circuit = SamplingRecursion::default();
        let mut params = TestParams::default();
        params.n_samples = 10;
        let circ_input = gen_testing_circuit_input::<F,D>(&params);

        let mut cyclic_circ = CyclicCircuit::new(inner_sampling_circuit);

        let s = Instant::now();
        cyclic_circ.build_circuit()?;
        println!("build = {:?}", s.elapsed());
        let s = Instant::now();
        let proof = cyclic_circ.prove_one_layer(&circ_input)?;
        println!("prove = {:?}", s.elapsed());
        println!("num of pi = {}", proof.public_inputs.len());
        println!("pub input: {:?}", proof.public_inputs);
        let s = Instant::now();
        assert!(
            cyclic_circ.verify_latest_proof().is_ok(),
            "proof verification failed"
        );
        println!("verify = {:?}", s.elapsed());

        let mut hash_input = vec![];
        hash_input.push(circ_input.slot_index);
        hash_input.extend_from_slice(&circ_input.dataset_root.elements);
        hash_input.extend_from_slice(&circ_input.entropy.elements);

        // let hash_res = PoseidonHash::hash_no_pad(&hash_input);
        let hash_res = hash_n_to_hash_no_pad::<F, PoseidonPermutation<F>>(&hash_input);
        let zero_hash = HashOut::<F>::ZERO;
        let mut hash_input2 = vec![];
        hash_input2.extend_from_slice(&hash_res.elements);
        hash_input2.extend_from_slice(&zero_hash.elements);
        let hash_res = hash_n_to_hash_no_pad::<F, PoseidonPermutation<F>>(&hash_input2);

        println!("hash input = {:?}", hash_res.elements);


        Ok(())
    }

    /// Uses cyclic recursion to sample the dataset n times
    #[test]
    fn test_cyclic_recursion_n_layers() -> Result<()> {
        // const D: usize = 2;
        // type C = PoseidonGoldilocksConfig;
        // type F = <C as GenericConfig<D>>::F;
        const N : usize = 2;

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let one = builder.one();

        let inner_sampling_circuit = SamplingRecursion::default();
        let mut params = TestParams::default();
        params.n_samples = 10;
        let mut circ_inputs = vec![];
        for i in 0..N {
            circ_inputs.push(gen_testing_circuit_input::<F, D>(&params));
        }

        let mut cyclic_circ = CyclicCircuit::new(inner_sampling_circuit);

        let s = Instant::now();
        cyclic_circ.build_circuit()?;
        println!("build = {:?}", s.elapsed());
        let s = Instant::now();
        let proof = cyclic_circ.prove_n_layers(N,circ_inputs)?;
        println!("prove = {:?}", s.elapsed());
        println!("num of pi = {}", proof.public_inputs.len());
        println!("pub input: {:?}", proof.public_inputs);
        let s = Instant::now();
        assert!(
            cyclic_circ.verify_latest_proof().is_ok(),
            "proof verification failed"
        );
        println!("verify = {:?}", s.elapsed());

        Ok(())
    }
}