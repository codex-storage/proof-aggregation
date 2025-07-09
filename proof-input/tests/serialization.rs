use plonky2_field::goldilocks_field::GoldilocksField;

// types used in all tests
type F = GoldilocksField;
const D: usize = 2;

pub(crate) mod serialization_test_functions {
    use super::*;
    use codex_plonky2_circuits::circuits::sample_cells::SampleCircuitInput;
    use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
    use proof_input::input_generator::InputGenerator;
    use proof_input::input_generator::serialization::{export_circ_input_to_json, import_circ_input_from_json};
    use std::path::Path;
    use plonky2::gates::noop::NoopGate;
    use plonky2::iop::target::Target;
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::config::{AlgebraicHasher, GenericConfig, Hasher};
    use plonky2::plonk::proof::ProofWithPublicInputs;
    use plonky2_field::types::Field;
    use serde::Serialize;
    use codex_plonky2_circuits::serialization::{export_circuit_data, export_proof_with_pi, import_circuit_data, import_proof_with_pi, import_targets};

    pub(crate) const CIRC_BASE_PATH: &str = "../output/test/circuit/";

    #[derive(Clone, Debug, PartialEq, Serialize, serde::Deserialize)]
    struct DummyTargets {
        a: Target,
    }

    fn dummy_circuit<C: GenericConfig<D, F = F> + Serialize + Default + 'static>(
        config: CircuitConfig,
    ) -> anyhow::Result<(CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>, DummyTargets)> where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let mut builder =  CircuitBuilder::<F, D>::new(config);
        for _ in 0..128 {
            builder.add_gate(NoopGate, vec![]);
        }
        let t = builder.add_virtual_public_input();

        let dummy_circuit = builder.build::<C>();
        let mut pw = PartialWitness::new();
        pw.set_target(t, F::ZERO).expect("faulty assign");
        let dummy_inner_proof = dummy_circuit.prove(pw).unwrap();
        assert!(dummy_circuit.verify(dummy_inner_proof.clone()).is_ok());
        let dummy_t = DummyTargets{a: t};

        Ok((dummy_circuit, dummy_inner_proof, dummy_t))
    }

    pub(crate) fn test_export_and_import_circuit_data<C: GenericConfig<D, F = F> + Serialize + Default + 'static>(
        config: CircuitConfig,
    ) -> anyhow::Result<()> where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {

        let (dummy_circuit, dummy_inner_proof, dummy_t) = dummy_circuit(config)?;

        let base_output = Path::new(CIRC_BASE_PATH);
        export_circuit_data::<F,C,D,_>(dummy_circuit, &dummy_t, base_output)?;

        let imported_circuit: CircuitData<F, C, D> = import_circuit_data(base_output)?;
        let imported_target: DummyTargets = import_targets(base_output)?;
        assert!(
            imported_circuit.verify(dummy_inner_proof).is_ok(),
            "imported circuit data failed to verify valid proof"
        );

        let mut pw = PartialWitness::new();
        pw.set_target(imported_target.a, F::ZERO).expect("faulty assign");
        let new_proof = imported_circuit.prove(pw).unwrap();
        assert!(
            imported_circuit.verify(new_proof).is_ok(),
            "imported target failed usage"
        );

        Ok(())
    }

    pub(crate) fn test_export_and_import_proof_with_pi<C: GenericConfig<D, F = F> + Serialize + Default + 'static>(
        config: CircuitConfig,
    ) -> anyhow::Result<()> where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let (dummy_circuit, dummy_inner_proof, _) = dummy_circuit(config)?;

        let base_output = Path::new(CIRC_BASE_PATH);
        export_proof_with_pi(&dummy_inner_proof, base_output)?;

        let imported_proof: ProofWithPublicInputs<F, C, D> =
            import_proof_with_pi(base_output)?;
        assert_eq!(dummy_inner_proof.clone(), imported_proof.clone(), "proofs are not equal");
        assert!(
            dummy_circuit.verify(imported_proof).is_ok(),
            "Imported proof failed verification"
        );

        Ok(())
    }

    // export the circuit input and then import it and checks equality
    pub(crate) fn test_export_import_circ_input<H: Hasher<F>>() -> anyhow::Result<()> {
        // Create InputGenerator
        let input_gen = InputGenerator::<F,D,H>::default();

        // Export the circuit input to JSON
        let original_circ_input = input_gen.gen_testing_circuit_input();
        export_circ_input_to_json(original_circ_input.clone(), CIRC_BASE_PATH)?;
        println!("circuit input exported to input.json");

        // Import the circuit input from JSON
        let imported_circ_input: SampleCircuitInput<F, D> = import_circ_input_from_json(CIRC_BASE_PATH)?;
        println!("circuit input imported from input.json");

        // Compare the original and imported circuit input
        assert_eq!(original_circ_input, imported_circ_input, "circuit input are not equal");

        println!("Test passed: Original and imported circuit input are equal.");

        Ok(())
    }

}

#[cfg(test)]
mod poseidon_serialization_tests {
    use plonky2::hash::poseidon::PoseidonHash;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;
    use super::serialization_test_functions::*;

    type H = PoseidonHash;
    pub type C = PoseidonGoldilocksConfig;

    #[test]
    fn test_poseidon_export_import_circ_input() -> anyhow::Result<()> {
        test_export_import_circ_input::<H>()
    }

    #[test]
    fn test_poseidon_export_and_import_circuit_data() -> anyhow::Result<()> {
        let config = CircuitConfig::standard_recursion_config();
        test_export_and_import_circuit_data::<C>(config)
    }

    #[test]
    fn test_poseidon_export_and_import_proof_with_pi() -> anyhow::Result<()> {
        let config = CircuitConfig::standard_recursion_config();
        test_export_and_import_proof_with_pi::<C>(config)
    }
}

#[cfg(test)]
mod poseidon2_serialization_tests {
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;
    use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2Hash;
    use super::serialization_test_functions::*;

    type H = Poseidon2Hash;
    pub type C = PoseidonGoldilocksConfig;

    #[test]
    fn test_poseidon_export_import_circ_input() -> anyhow::Result<()> {
        test_export_import_circ_input::<H>()
    }

    #[test]
    fn test_poseidon_export_and_import_circuit_data() -> anyhow::Result<()> {
        let config = CircuitConfig::standard_recursion_config();
        test_export_and_import_circuit_data::<C>(config)
    }

    #[test]
    fn test_poseidon_export_and_import_proof_with_pi() -> anyhow::Result<()> {
        let config = CircuitConfig::standard_recursion_config();
        test_export_and_import_proof_with_pi::<C>(config)
    }
}

#[cfg(test)]
mod monolith_serialization_tests {
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;
    use plonky2_monolith::monolith_hash::MonolithHash;
    use super::serialization_test_functions::*;

    type H = MonolithHash;
    pub type C = PoseidonGoldilocksConfig;

    #[test]
    fn test_poseidon_export_import_circ_input() -> anyhow::Result<()> {
        test_export_import_circ_input::<H>()
    }

    #[test]
    fn test_poseidon_export_and_import_circuit_data() -> anyhow::Result<()> {
        let config = CircuitConfig::standard_recursion_config();
        test_export_and_import_circuit_data::<C>(config)
    }

    #[test]
    fn test_poseidon_export_and_import_proof_with_pi() -> anyhow::Result<()> {
        let config = CircuitConfig::standard_recursion_config();
        test_export_and_import_proof_with_pi::<C>(config)
    }
}