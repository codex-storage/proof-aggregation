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
    use crate::params::{F, D, C, HF};
    use codex_plonky2_circuits::recursion::circuits::sampling_inner_circuit::SamplingRecursion;
    use crate::gen_input::gen_testing_circuit_input;
    use crate::params::Params;
    use codex_plonky2_circuits::recursion::cyclic::CyclicCircuit;


    /// Uses cyclic recursion to sample the dataset
    #[test]
    fn test_cyclic_recursion() -> Result<()> {

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let one = builder.one();


        let mut params = Params::default();
        let inner_sampling_circuit = SamplingRecursion::<F,D,HF,C>::new(params.circuit_params);
        let circ_input = gen_testing_circuit_input::<F,D>(&params.input_params);

        let s = Instant::now();
        let mut cyclic_circ = CyclicCircuit::<F,D,_,C>::build_circuit::<HF>(inner_sampling_circuit)?;
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

        // check public input hash is correct
        let mut hash_input = vec![];
        hash_input.push(circ_input.slot_index);
        hash_input.extend_from_slice(&circ_input.dataset_root.elements);
        hash_input.extend_from_slice(&circ_input.entropy.elements);

        let hash_res = hash_n_to_hash_no_pad::<F, PoseidonPermutation<F>>(&hash_input);
        let zero_hash = HashOut::<F>::ZERO;
        let mut hash_input2 = vec![];
        hash_input2.extend_from_slice(&hash_res.elements);
        hash_input2.extend_from_slice(&zero_hash.elements);
        let hash_res = hash_n_to_hash_no_pad::<F, PoseidonPermutation<F>>(&hash_input2);

        println!("hash input = {:?}", hash_res.elements);
        assert_eq!(
            proof.public_inputs[0..4].to_vec(),
            hash_res.elements.to_vec(),
            "public input hash incorrect"
        );

        Ok(())
    }

    /// Uses cyclic recursion to sample the dataset n times
    #[test]
    fn test_cyclic_recursion_n_layers() -> Result<()> {
        const N : usize = 2;

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let one = builder.one();

        let mut params = Params::default();
        let inner_sampling_circuit = SamplingRecursion::<F,D,HF,C>::new(params.circuit_params);
        let mut circ_inputs = vec![];
        for i in 0..N {
            circ_inputs.push(gen_testing_circuit_input::<F, D>(&params.input_params));
        }

        let s = Instant::now();
        let mut cyclic_circ = CyclicCircuit::<F,D,_,C>::build_circuit::<HF>(inner_sampling_circuit)?;
        println!("build = {:?}", s.elapsed());
        let s = Instant::now();
        let proof = cyclic_circ.prove_n_layers(circ_inputs)?;
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