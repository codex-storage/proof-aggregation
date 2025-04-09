use serde::{Deserialize, Serialize};
use std::{fs, io};
use std::path::Path;
use anyhow::Context;
use crate::gen_input::gen_testing_circuit_input;
use plonky2::hash::hash_types::RichField;
use plonky2::plonk::circuit_data::{CircuitData, ProverCircuitData, VerifierCircuitData};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2_field::extension::Extendable;
use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2;
use codex_plonky2_circuits::circuits::sample_cells::SampleCircuitInput;
use plonky2::plonk::proof::ProofWithPublicInputs;
use serde::de::DeserializeOwned;
use plonky2_poseidon2::serialization::{DefaultGateSerializer, DefaultGeneratorSerializer};
use crate::serialization::file_paths::{PROOF_JSON, PROVER_CIRC_DATA_JSON, TARGETS_JSON, VERIFIER_CIRC_DATA_JSON};

/// Writes the provided bytes to the specified file path using `std::fs::write`.
pub fn write_bytes_to_file<P: AsRef<Path>>(data: Vec<u8>, path: P) -> io::Result<()> {
    fs::write(path, data)
}

/// Reads the contents of the specified file and returns them as a vector of bytes using `std::fs::read`.
pub fn read_bytes_from_file<P: AsRef<Path>>(path: P) -> io::Result<Vec<u8>> {
    fs::read(path)
}

/// Ensures that the parent directory of the given file path exists.
/// If it does not exist, the function creates the entire directory path.
pub fn ensure_parent_directory_exists(path: &str) -> anyhow::Result<()> {
    if let Some(parent) = Path::new(path).parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create directory {:?}", parent))?;
    }
    Ok(())
}

/// Export the circuit data to disk. This function serializes the prover data,
/// verifier data, and circuit targets, and then writes them to their respective files.
/// The function uses the file paths defined in file_paths.rs
pub fn export_circuit_data<F, C, const D: usize>(
    circ_data: CircuitData<F,C,D>,
    targets: &impl Serialize,
) -> anyhow::Result<()>
    where
        F: RichField + Extendable<D> + Poseidon2 + Serialize,
        C: GenericConfig<D, F = F> + 'static + Serialize, C:Default,
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>
{
    // separate the prover and verifier data
    let verifier_data: VerifierCircuitData<F, C,D> = circ_data.verifier_data();
    let prover_data = circ_data.prover_data();

    let gate_serializer = DefaultGateSerializer;
    let generator_serializer =DefaultGeneratorSerializer::<C, D>::default();

    // Serialize the prover data.
    let prover_data_bytes = prover_data
        .to_bytes(&gate_serializer, &generator_serializer)
        .map_err(|e| anyhow::anyhow!("Failed to serialize prover data: {:?}", e))?;
    // Serialize the verifier data.
    let verifier_data_bytes = verifier_data
        .to_bytes(&gate_serializer)
        .map_err(|e| anyhow::anyhow!("Failed to serialize verifier data: {:?}", e))?;
    // Serialize the circuit targets using serde_json.
    let targets_bytes = serde_json::to_vec(targets)
        .context("Failed to serialize circuit targets")?;

    // Ensure that the parent directories exist.
    ensure_parent_directory_exists(PROVER_CIRC_DATA_JSON)?;
    ensure_parent_directory_exists(VERIFIER_CIRC_DATA_JSON)?;
    ensure_parent_directory_exists(TARGETS_JSON)?;

    // Write all data to the corresponding files.
    write_bytes_to_file(prover_data_bytes, PROVER_CIRC_DATA_JSON)
        .with_context(|| format!("Failed to write prover data to {}", PROVER_CIRC_DATA_JSON))?;
    write_bytes_to_file(verifier_data_bytes, VERIFIER_CIRC_DATA_JSON)
        .with_context(|| format!("Failed to write verifier data to {}", VERIFIER_CIRC_DATA_JSON))?;
    write_bytes_to_file(targets_bytes, TARGETS_JSON)
        .with_context(|| format!("Failed to write circuit targets to {}", TARGETS_JSON))?;

    Ok(())
}

/// Import the prover circuit data from disk and deserialize it.
pub fn import_prover_circuit_data<F, C, const D: usize>() -> anyhow::Result<ProverCircuitData<F, C, D>>
    where
        F: RichField + Extendable<D> + Poseidon2 + Serialize,
        C: GenericConfig<D, F = F> + 'static + Serialize, C:Default,
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>
{
    let gate_serializer = DefaultGateSerializer;
    let generator_serializer =DefaultGeneratorSerializer::<C, D>::default();

    let bytes = read_bytes_from_file(PROVER_CIRC_DATA_JSON)
        .with_context(|| format!("Failed to read prover circuit data from {}", PROVER_CIRC_DATA_JSON))?;
    let prover_data = ProverCircuitData::<F,C,D>::from_bytes(&bytes, &gate_serializer, &generator_serializer)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize prover data: {:?}", e))?;
    Ok(prover_data)
}

/// Import the verifier circuit data from disk and deserialize it.
pub fn import_verifier_circuit_data<F, C, const D: usize>(
) -> anyhow::Result<VerifierCircuitData<F, C, D>>
    where
        F: RichField + Extendable<D> + Poseidon2 + Serialize,
        C: GenericConfig<D, F = F> + Serialize,
{
    let gate_serializer = DefaultGateSerializer;

    let bytes = read_bytes_from_file(VERIFIER_CIRC_DATA_JSON)
        .with_context(|| format!("Failed to read verifier circuit data from {}", VERIFIER_CIRC_DATA_JSON))?;
    let verifier_data = VerifierCircuitData::<F,C,D>::from_bytes(bytes, &gate_serializer)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize verifier data: {:?}", e))?;
    Ok(verifier_data)
}

/// Import the proof with public input from the JSON file.
pub fn import_proof_with_pi<F, C, const D: usize>() -> anyhow::Result<ProofWithPublicInputs<F, C, D>>
    where
        F: RichField + Extendable<D> + Poseidon2,
        C: GenericConfig<D, F = F>,
{
    let proof_json = fs::read_to_string(PROOF_JSON)
        .with_context(|| format!("Failed to read file {}", PROOF_JSON))?;
    let proof = serde_json::from_str(&proof_json)
        .context("Failed to deserialize proof with public input")?;
    Ok(proof)
}

/// Import the circuit targets from the JSON file.
/// This function is generic over the type `T` that represents the targets and
/// must implement `DeserializeOwned` so that it can be deserialized.
pub fn import_targets<T>() -> anyhow::Result<T>
    where
        T: DeserializeOwned,
{
    let targets_json = fs::read_to_string(TARGETS_JSON)
        .with_context(|| format!("Failed to read file {}", TARGETS_JSON))?;
    let targets = serde_json::from_str(&targets_json)
        .context("Failed to deserialize targets")?;
    Ok(targets)
}

/// Function to export proof with public input to json file
pub fn export_proof_with_pi<F, C, const D: usize>(
    proof_with_pis: &ProofWithPublicInputs<F, C, D>,
) -> anyhow::Result<()>
    where
        F: RichField + Extendable<D> + Poseidon2 + Serialize,
        C: GenericConfig<D, F = F> + Serialize,
{
    let proof_serialized= serde_json::to_vec(&proof_with_pis)
        .map_err(|e| anyhow::anyhow!("Failed to serialize proof with public input: {:?}", e))?;
    fs::write(PROOF_JSON  , &proof_serialized).expect("Unable to write file");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::{C, D, F, HF, Params};
    use std::time::Instant;
    use codex_plonky2_circuits::circuits::sample_cells::SampleCircuit;
    use plonky2::plonk::circuit_data::{ ProverCircuitData, VerifierCircuitData};
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
        generate_and_export_circ_input_to_json::<F,D>(&params)?;

        println!("Circuit input exported to input.json");

        Ok(())
    }

    #[test]
    fn test_import_circ_input_from_json() -> anyhow::Result<()> {
        // Import the circuit input from the JSON file
        // NOTE: MAKE SURE THE FILE EXISTS
        let _circ_input: SampleCircuitInput<F, D> = import_circ_input_from_json()?;
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
        export_circ_input_to_json(original_circ_input.clone())?;
        println!("circuit input exported to input.json");

        // Import the circuit input from JSON
        let imported_circ_input: SampleCircuitInput<F, D> = import_circ_input_from_json()?;
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
        let imported_circ_input: SampleCircuitInput<F, D> = import_circ_input_from_json()?;
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
        let imported_circ_input: SampleCircuitInput<F, D> = import_circ_input_from_json()?;
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

        export_proof_with_pi(&proof_with_pis)?;
        println!("Proof size: {} bytes", proof_with_pis.to_bytes().len());

        // Verify the proof
        assert!(
            verifier_data.verify(proof_with_pis).is_ok(),
            "Merkle proof verification failed"
        );

        Ok(())
    }
}