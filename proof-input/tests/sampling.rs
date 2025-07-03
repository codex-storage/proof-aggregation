use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use plonky2_field::goldilocks_field::GoldilocksField;

// types used in all tests
type F = GoldilocksField;
const D: usize = 2;
type H = PoseidonHash;
type C = PoseidonGoldilocksConfig;


#[cfg(test)]
mod sampling_tests {
    use super::*;
    use proof_input::input_generator::InputGenerator;

    // Test sample cells (non-circuit)
    #[test]
    fn test_gen_verify_proof(){
        let input_gen = InputGenerator::<F,D,H>::default();
        let w = input_gen.gen_testing_circuit_input();
        assert!(input_gen.verify_circuit_input(w));
    }
}

#[cfg(test)]
mod sampling_circuit_tests {
    use super::*;
    use std::time::Instant;
    use plonky2::plonk::proof::ProofWithPublicInputs;
    use codex_plonky2_circuits::circuit_helper::Plonky2Circuit;
    use codex_plonky2_circuits::circuits::sample_cells::SampleCircuit;
    use proof_input::input_generator::InputGenerator;
    use proof_input::params::Params;

    // Test sample cells in-circuit for a selected slot
    #[test]
    fn test_proof_in_circuit() -> anyhow::Result<()> {
        // get input
        let mut params = Params::default();
        params.set_n_samples(10);
        let input_params = params.input_params;
        let circuit_params = params.circuit_params;
        let input_gen = InputGenerator::<F,D,H>::new(input_params);
        let circ_input = input_gen.gen_testing_circuit_input();

        // build the circuit
        let circ = SampleCircuit::<F,D,H>::new(circuit_params.clone());
        let (targets, data) = circ.build_with_standard_config()?;
        println!("circuit size = {:?}", data.common.degree_bits());

        // separate the prover and verifier
        let verifier_data = data.verifier_data();
        let prover_data = data.prover_data();

        // Prove the circuit using the circuit input
        let start_time = Instant::now();
        let proof_with_pis: ProofWithPublicInputs<F, C, D> = circ.prove(&targets, &circ_input, &prover_data)?;
        println!("prove_time = {:?}", start_time.elapsed());

        // Verify the proof
        assert!(
            verifier_data.verify(proof_with_pis).is_ok(),
            "Merkle proof verification failed"
        );

        Ok(())
    }

}