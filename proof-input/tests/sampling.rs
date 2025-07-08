use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig, Hasher, PoseidonGoldilocksConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2_field::goldilocks_field::GoldilocksField;
use codex_plonky2_circuits::circuit_trait::Plonky2Circuit;
use codex_plonky2_circuits::circuits::sample_cells::SampleCircuit;
use proof_input::input_generator::InputGenerator;
use proof_input::params::Params;

// types used in all tests
type F = GoldilocksField;
const D: usize = 2;
type C = PoseidonGoldilocksConfig;

fn test_sampling_proof<H: Hasher<F>>(){
    let input_gen = InputGenerator::<F,D, H>::default();
    let w = input_gen.gen_testing_circuit_input();
    assert!(input_gen.verify_circuit_input(w));
}

fn test_sampling_proof_in_circuit<C: GenericConfig<D, F = F>, H: AlgebraicHasher<F>>(config: CircuitConfig) -> anyhow::Result<()> {
    // get input
    let mut params = Params::default();
    params.set_n_samples(10);
    let input_params = params.input_params;
    let circuit_params = params.circuit_params;
    let input_gen = InputGenerator::<F,D,H>::new(input_params);
    let circ_input = input_gen.gen_testing_circuit_input();

    // build the circuit
    let circ = SampleCircuit::<F,D,H>::new(circuit_params.clone());
    let (targets, data) = circ.build(config)?;

    // separate the prover and verifier
    let verifier_data = data.verifier_data();
    let prover_data = data.prover_data();

    // Prove the circuit using the circuit input
    let proof_with_pis: ProofWithPublicInputs<F, C, D> = circ.prove(&targets, &circ_input, &prover_data)?;

    // Verify the proof
    assert!(
        verifier_data.verify(proof_with_pis).is_ok(),
        "Merkle proof verification failed"
    );

    Ok(())
}

#[cfg(test)]
mod poseidon2_sampling_tests {
    use super::*;
    use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2Hash;

    type H = Poseidon2Hash;

    // Test sample cells (non-circuit)
    #[test]
    fn test_poseidon2_sampling_proof(){
        test_sampling_proof::<H>();
    }

    // Test sample cells in-circuit for a selected slot
    #[test]
    fn test_poseidon2_sampling_proof_in_circuit() -> anyhow::Result<()> {
        let config = CircuitConfig::standard_recursion_config();
        test_sampling_proof_in_circuit::<C,H>(config)
    }
}

#[cfg(test)]
mod monolith_sampling_tests {
    use plonky2_monolith::gates::generate_config_for_monolith_gate;
    use super::*;
    use plonky2_monolith::monolith_hash::MonolithHash;

    type H = MonolithHash;

    // Test sample cells (non-circuit)
    #[test]
    fn test_monolith_sampling_proof(){
        test_sampling_proof::<H>();
    }

    // Test sample cells in-circuit for a selected slot
    #[test]
    fn test_monolith_sampling_proof_in_circuit() -> anyhow::Result<()> {
        let config = generate_config_for_monolith_gate::<F, D>();
        test_sampling_proof_in_circuit::<C,H>(config)
    }
}