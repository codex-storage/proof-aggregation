use serde::{Deserialize, Serialize};
use std::fs::File;
use std::{fs, io};
use std::io::{BufWriter, Write};
use std::path::Path;
use crate::gen_input::gen_testing_circuit_input;
use plonky2::hash::hash_types::RichField;
use plonky2::plonk::config::{GenericConfig, Hasher};
use plonky2_field::extension::Extendable;
use plonky2_field::types::Field;
use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2;
use codex_plonky2_circuits::circuits::sample_cells::SampleCircuitInput;
use plonky2::plonk::proof::ProofWithPublicInputs;
use serde_json::to_writer_pretty;

// Function to export proof with public input to json file
fn export_proof_with_pi_to_json<F, C, const D: usize>(
    instance: &ProofWithPublicInputs<F, C, D>,
    path: &str,
) -> io::Result<()>
    where
        F: RichField + Extendable<D> + Poseidon2 + Serialize,
        C: GenericConfig<D, F = F> + Serialize,
{
    // Create or overwrite the file at the given path
    let file = File::create(path)?;
    let writer = BufWriter::new(file);

    // Serialize the struct to JSON and write it to the file
    to_writer_pretty(writer, instance)?;

    Ok(())
}

/// Writes the provided bytes to the specified file path using `std::fs::write`.
pub fn write_bytes_to_file<P: AsRef<Path>>(data: Vec<u8>, path: P) -> io::Result<()> {
    fs::write(path, data)
}

/// Reads the contents of the specified file and returns them as a vector of bytes using `std::fs::read`.
pub fn read_bytes_from_file<P: AsRef<Path>>(path: P) -> io::Result<Vec<u8>> {
    fs::read(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::{C, D, F, HF, Params};
    use std::time::Instant;
    use codex_plonky2_circuits::circuits::sample_cells::SampleCircuit;
    use plonky2::iop::witness::PartialWitness;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, ProverCircuitData, VerifierCircuitData};
    use codex_plonky2_circuits::circuit_helper::Plonky2Circuit;
    use plonky2_poseidon2::serialization::{DefaultGateSerializer, DefaultGeneratorSerializer};
    use crate::gen_input::verify_circuit_input;
    use crate::serialization::circuit_input::{export_circ_input_to_json, generate_and_export_circ_input_to_json, import_circ_input_from_json};

    // Test to generate the JSON file
    #[test]
    fn test_export_circ_input_to_json() -> anyhow::Result<()> {
        // Create Params
        let params = Params::default().input_params;
        // Export the circuit input to JSON
        generate_and_export_circ_input_to_json::<F,D>(&params, "input.json")?;

        println!("Circuit input exported to input.json");

        Ok(())
    }

    #[test]
    fn test_import_circ_input_from_json() -> anyhow::Result<()> {
        // Import the circuit input from the JSON file
        // NOTE: MAKE SURE THE FILE EXISTS
        let _circ_input: SampleCircuitInput<F, D> = import_circ_input_from_json("input.json")?;
        println!("circuit input imported successfully");

        Ok(())
    }

    // export the circuit input and then import it and checks equality
    #[test]
    fn test_export_import_circ_input() -> anyhow::Result<()> {
        // Create Params instance
        let params = Params::default().input_params;

        // Export the circuit input to JSON
        let original_circ_input = gen_testing_circuit_input(&params);
        export_circ_input_to_json(original_circ_input.clone(), "input.json")?;
        println!("circuit input exported to input.json");

        // Import the circuit input from JSON
        let imported_circ_input: SampleCircuitInput<F, D> = import_circ_input_from_json("input.json")?;
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

        let circ = SampleCircuit::<F,D,HF>::new(circuit_params.clone());
        let (targets, data) = circ.build_with_standard_config()?;

        let verifier_data: VerifierCircuitData<F, C, D> = data.verifier_data();
        let prover_data: ProverCircuitData<F, C, D> = data.prover_data();
        println!("circuit size = {:?}", verifier_data.common.degree_bits());

        // Import the circuit input from JSON
        let imported_circ_input: SampleCircuitInput<F, D> = import_circ_input_from_json("input.json")?;
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
        let params = Params::default().input_params;

        // Import the circuit input from JSON
        let imported_circ_input: SampleCircuitInput<F, D> = import_circ_input_from_json("input.json")?;
        println!("circuit input imported from input.json");

        // Verify the proof
        let ver = verify_circuit_input(imported_circ_input, &params);
        assert!(
            ver,
            "Merkle proof verification failed"
        );

        Ok(())
    }

    // test out custom default gate and generator serializers to export/import circuit data
    #[test]
    fn test_circuit_data_serializer() -> anyhow::Result<()> {
        let params = Params::default();
        let input_params = params.input_params;

        // Create the circuit
        let circuit_params = params.circuit_params;
        let circ = SampleCircuit::<F,D,HF>::new(circuit_params.clone());
        let (targets, data) = circ.build_with_standard_config()?;
        println!("circuit size = {:?}", data.common.degree_bits());

        let verifier_data: VerifierCircuitData<F, C, D> = data.verifier_data();
        let prover_data: ProverCircuitData<F, C, D> = data.prover_data();

        // gen circ input
        let imported_circ_input: SampleCircuitInput<F, D> = gen_testing_circuit_input::<F,D>(&input_params);

        let gate_serializer = DefaultGateSerializer;
        let generator_serializer =DefaultGeneratorSerializer::<C, D>::default();
        let data_bytes = prover_data.to_bytes(&gate_serializer, &generator_serializer).unwrap();

        let file_path = "circ_data.bin";
        // Write data to the file
        write_bytes_to_file(data_bytes.clone(), file_path).unwrap();
        println!("Data written to {}", file_path);

        // Read data back from the file
        let read_data = read_bytes_from_file(file_path).unwrap();
        let prover_data = ProverCircuitData::<F,C,D>::from_bytes(&read_data, &gate_serializer, &generator_serializer).unwrap();

        // Prove the circuit with the assigned witness
        let start_time = Instant::now();
        let proof_with_pis = circ.prove(&targets, &imported_circ_input, &prover_data)?;
        println!("prove_time = {:?}", start_time.elapsed());

        // Verify the proof
        assert!(
            verifier_data.verify(proof_with_pis).is_ok(),
            "Merkle proof verification failed"
        );

        Ok(())
    }

    // test proof with public input serialization
    #[test]
    fn test_proof_with_pi_serializer() -> anyhow::Result<()> {
        let params = Params::default();
        let input_params = params.input_params;

        // Create the circuit
        let circuit_params = params.circuit_params;
        let circ = SampleCircuit::<F,D,HF>::new(circuit_params.clone());
        let (targets, data) = circ.build_with_standard_config()?;
        println!("circuit size = {:?}", data.common.degree_bits());

        let verifier_data: VerifierCircuitData<F, C, D> = data.verifier_data();
        let prover_data: ProverCircuitData<F, C, D> = data.prover_data();

        // gen circ input
        let imported_circ_input: SampleCircuitInput<F, D> = gen_testing_circuit_input::<F,D>(&input_params);

        // Prove the circuit with the assigned witness
        let start_time = Instant::now();
        let proof_with_pis = circ.prove(&targets, &imported_circ_input, &prover_data)?;
        println!("prove_time = {:?}", start_time.elapsed());
        println!("Proof size: {} bytes", proof_with_pis.to_bytes().len());

        let filename = "proof_with_pi.json";
        export_proof_with_pi_to_json(&proof_with_pis,filename)?;
        println!("Proof size: {} bytes", proof_with_pis.to_bytes().len());

        // Verify the proof
        assert!(
            verifier_data.verify(proof_with_pis).is_ok(),
            "Merkle proof verification failed"
        );

        Ok(())
    }
}