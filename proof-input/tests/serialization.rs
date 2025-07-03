use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use plonky2_field::goldilocks_field::GoldilocksField;
use proof_input::params::Params;

// types used in all tests
type F = GoldilocksField;
const D: usize = 2;
type H = PoseidonHash;
type C = PoseidonGoldilocksConfig;

#[cfg(test)]
mod serialization_tests {
    use super::*;
    use codex_plonky2_circuits::circuits::sample_cells::{SampleCircuit, SampleCircuitInput};
    use plonky2::plonk::circuit_data::{CircuitConfig, ProverCircuitData, VerifierCircuitData};
    use codex_plonky2_circuits::circuit_trait::Plonky2Circuit;
    use proof_input::input_generator::InputGenerator;
    use proof_input::input_generator::serialization::{export_circ_input_to_json, import_circ_input_from_json};
    use std::path::Path;
    use plonky2::gates::noop::NoopGate;
    use plonky2::iop::target::Target;
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;
    use plonky2::plonk::proof::ProofWithPublicInputs;
    use plonky2_field::goldilocks_field::GoldilocksField;
    use plonky2_field::types::Field;
    use codex_plonky2_circuits::serialization::{export_circuit_data, export_proof_with_pi, import_proof_with_pi, import_prover_circuit_data, import_targets, import_verifier_circuit_data};

    #[test]
    fn test_export_and_import_circuit_data_roundtrip() -> anyhow::Result<()> {
        use serde::Serialize;

        #[derive(Clone, Debug, PartialEq, Serialize, serde::Deserialize)]
        struct DummyTargets {
            a: Target,
        }

        let conf = CircuitConfig::standard_recursion_config();
        let mut builder =  CircuitBuilder::<F, D>::new(conf);
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

        let base_output = Path::new("../output/sampling_circ");
        export_circuit_data::<F,C,D,_>(dummy_circuit, &dummy_t, base_output)?;

        let imported_prover: ProverCircuitData<F, C, D> =
            import_prover_circuit_data(base_output)?;
        let imported_verifier: VerifierCircuitData<F, C, D> =
            import_verifier_circuit_data(base_output)?;
        let imported_target: DummyTargets = import_targets(base_output)?;

        let mut pw = PartialWitness::new();
        pw.set_target(imported_target.a, F::ZERO).expect("faulty assign");
        let proof_with_pis = imported_prover.prove(pw).unwrap();
        assert!(
            imported_verifier.verify(proof_with_pis).is_ok(),
            "imported verifier failed to verify"
        );

        Ok(())
    }

    #[test]
    fn test_export_and_import_proof_with_pi() -> anyhow::Result<()> {
        let conf = CircuitConfig::standard_recursion_config();
        let mut builder =  CircuitBuilder::<F, D>::new(conf);
        for _ in 0..128 {
            builder.add_gate(NoopGate, vec![]);
        }
        let t = builder.add_virtual_public_input();

        let dummy_circuit = builder.build::<C>();
        let mut pw = PartialWitness::new();
        pw.set_target(t, F::ZERO).expect("faulty assign");
        let dummy_inner_proof = dummy_circuit.prove(pw).unwrap();
        assert!(dummy_circuit.verify(dummy_inner_proof.clone()).is_ok());

        let base_output = Path::new("../output/sampling_circ");
        export_proof_with_pi(&dummy_inner_proof, base_output)?;

        let imported_proof: ProofWithPublicInputs<F, C, D> =
            import_proof_with_pi(base_output)?;
        assert!(
            dummy_circuit.verify(imported_proof).is_ok(),
            "Imported proof failed verification"
        );

        Ok(())
    }

    // Test to generate the JSON file
    #[test]
    fn test_export_circ_input_to_json() -> anyhow::Result<()> {
        // Create InputGenerator
        let input_gen = InputGenerator::<F,D,H>::default();
        // Export the circuit input to JSON
        input_gen.generate_and_export_circ_input_to_json( "../output/test/")?;

        println!("Circuit input exported to input.json");

        Ok(())
    }

    #[test]
    fn test_import_circ_input_from_json() -> anyhow::Result<()> {
        // Import the circuit input from the JSON file
        // NOTE: MAKE SURE THE FILE EXISTS
        let _circ_input: SampleCircuitInput<F, D> = import_circ_input_from_json("../output/test/")?;
        println!("circuit input imported successfully");

        Ok(())
    }

    // export the circuit input and then import it and checks equality
    #[test]
    fn test_export_import_circ_input() -> anyhow::Result<()> {
        // Create InputGenerator
        let input_gen = InputGenerator::<F,D,H>::default();

        // Export the circuit input to JSON
        let original_circ_input = input_gen.gen_testing_circuit_input();
        export_circ_input_to_json(original_circ_input.clone(), "../output/test/")?;
        println!("circuit input exported to input.json");

        // Import the circuit input from JSON
        let imported_circ_input: SampleCircuitInput<F, D> = import_circ_input_from_json("../output/test/")?;
        println!("circuit input imported from input.json");

        // Compare the original and imported circuit input
        assert_eq!(original_circ_input, imported_circ_input, "circuit input are not equal");

        // cleanup: Remove the generated JSON file
        // fs::remove_file("input.json")?;

        println!("Test passed: Original and imported circuit input are equal.");

        Ok(())
    }

    // reads the json input from file and runs the circuit
    #[test]
    fn test_read_json_and_run_circuit() -> anyhow::Result<()> {
        // Create the circuit
        let circuit_params = Params::default().circuit_params;

        let circ = SampleCircuit::<F, D, H>::new(circuit_params.clone());
        let (targets, data) = circ.build_with_standard_config()?;

        let verifier_data: VerifierCircuitData<F, C, D> = data.verifier_data();
        let prover_data: ProverCircuitData<F, C, D> = data.prover_data();
        println!("circuit size = {:?}", verifier_data.common.degree_bits());

        // Import the circuit input from JSON
        let imported_circ_input: SampleCircuitInput<F, D> = import_circ_input_from_json("../output/test/")?;
        println!("circuit input imported from input.json");

        let proof = circ.prove(&targets, &imported_circ_input, &prover_data)?;

        // Verify the proof
        assert!(
            verifier_data.verify(proof).is_ok(),
            "Merkle proof verification failed"
        );

        Ok(())
    }

    // reads the json input and verify (non-circuit)
    // NOTE: expects that the json input proof uses the default params
    #[test]
    fn test_read_json_and_verify() -> anyhow::Result<()> {
        // Create InputGenerator
        let input_gen = InputGenerator::<F,D,H>::default();

        // Import the circuit input from JSON
        let imported_circ_input: SampleCircuitInput<F, D> = import_circ_input_from_json("../output/test/")?;
        println!("circuit input imported from input.json");

        // Verify the proof
        let ver = input_gen.verify_circuit_input(imported_circ_input);
        assert!(
            ver,
            "Merkle proof verification failed"
        );

        Ok(())
    }
}