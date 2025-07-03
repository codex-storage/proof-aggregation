use serde::Serialize;
use std::{fs, io};
use std::path::Path;
use anyhow::Context;
use plonky2::hash::hash_types::RichField;
use plonky2::plonk::circuit_data::{CircuitData, ProverCircuitData, VerifierCircuitData};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2_field::extension::Extendable;
use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2;
use plonky2::plonk::proof::ProofWithPublicInputs;
use serde::de::DeserializeOwned;
use plonky2_poseidon2::serialization::{DefaultGateSerializer, DefaultGeneratorSerializer};

/// File constants paths - Prover
pub const PROVER_CIRC_DATA_JSON: &str = "prover_data/prover_circuit_data.bin";
pub const TARGETS_JSON: &str = "prover_data/targets.json";

/// File constants paths - Verifier
pub const VERIFIER_CIRC_DATA_JSON: &str = "verifier_data/verifier_circuit_data.bin";
pub const PROOF_JSON: &str = "verifier_data/proof_with_public_inputs.json";

// --------------------- helper fn --------------------------

/// Writes the provided bytes to the specified file path using `std::fs::write`.
pub fn write_bytes_to_file<P: AsRef<Path>>(data: &[u8], path: P) -> io::Result<()> {
    fs::write(path, data)
}

/// Reads the contents of the specified file and returns them as a vector of bytes using `std::fs::read`.
pub fn read_bytes_from_file<P: AsRef<Path>>(path: P) -> io::Result<Vec<u8>> {
    fs::read(path)
}

/// Ensures that the parent directory of the given file path exists.
/// If it does not exist, the function creates the entire directory path.
pub fn ensure_parent_directory_exists<P: AsRef<Path>>(path: P) -> anyhow::Result<()> {
    if let Some(parent) = path.as_ref().parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create directory {:?}", parent))?;
    }
    Ok(())
}

//--------------------- EXPORT -----------------------------

pub fn export_prover_circuit_data<
    F: RichField + Extendable<D> + Poseidon2 + Serialize,
    C: GenericConfig<D, F = F> + Default + Serialize + 'static,
    const D: usize,
    P: AsRef<Path>,
>(
    prover_data: ProverCircuitData<F, C, D>,
    base_path: P,
) -> anyhow::Result<()>
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    let gate_serializer = DefaultGateSerializer;
    let generator_serializer = DefaultGeneratorSerializer::<C, D>::default();

    // Serialize prover_data → Vec<u8>
    let bytes = prover_data
        .to_bytes(&gate_serializer, &generator_serializer)
        .map_err(|e| anyhow::anyhow!("Failed to serialize prover data: {:?}", e))?;

    // Build output path: `{base_path}/prover_data/prover_circ_data.bin`
    let out_path = base_path.as_ref().join(PROVER_CIRC_DATA_JSON);

    // Ensure parent directory exists
    ensure_parent_directory_exists(&out_path)
        .with_context(|| format!("Could not create directory for {:?}", out_path))?;

    // Write file
    write_bytes_to_file(&bytes, &out_path)
        .with_context(|| format!("Failed to write prover data to {:?}", out_path))?;

    Ok(())
}

/// Export only the VerifierCircuitData to `{base_path}/verifier_data/verifier_circ_data.bin`.
pub fn export_verifier_circuit_data<
    F: RichField + Extendable<D> + Poseidon2 + Serialize,
    C: GenericConfig<D, F = F> + Serialize,
    const D: usize,
    P: AsRef<Path>,
>(
    verifier_data: VerifierCircuitData<F, C, D>,
    base_path: P,
) -> anyhow::Result<()>
{
    let gate_serializer = DefaultGateSerializer;

    // Serialize verifier_data → Vec<u8>
    let bytes = verifier_data
        .to_bytes(&gate_serializer)
        .map_err(|e| anyhow::anyhow!("Failed to serialize verifier data: {:?}", e))?;

    // Build output path: `{base_path}/verifier_data/verifier_circ_data.bin`
    let out_path = base_path.as_ref().join(VERIFIER_CIRC_DATA_JSON);

    // Ensure parent directory exists
    ensure_parent_directory_exists(&out_path)
        .with_context(|| format!("Could not create directory for {:?}", out_path))?;

    // Write file
    write_bytes_to_file(&bytes, &out_path)
        .with_context(|| format!("Failed to write verifier data to {:?}", out_path))?;

    Ok(())
}

/// Export only the “targets” (any `T: Serialize`) to `{base_path}/prover_data/targets.json`.
pub fn export_circuit_targets<
    T: Serialize,
    P: AsRef<Path>,
>(
    targets: &T,
    base_path: P,
) -> anyhow::Result<()>
{
    // Serialize `targets` → Vec<u8> (JSON)
    let bytes = serde_json::to_vec(targets)
        .context("Failed to serialize circuit targets to JSON")?;

    // Build output path: `{base_path}/prover_data/targets.json`
    let out_path = base_path.as_ref().join(TARGETS_JSON);

    // Ensure parent directory exists
    ensure_parent_directory_exists(&out_path)
        .with_context(|| format!("Could not create directory for {:?}", out_path))?;

    // Write file
    write_bytes_to_file(&bytes, &out_path)
        .with_context(|| format!("Failed to write circuit targets to {:?}", out_path))?;

    Ok(())
}

/// Convenience function that calls all three exports in one shot.
/// ‣ Exports prover data, verifier data, and targets under `base_path`.
pub fn export_circuit_data<
    F: RichField + Extendable<D> + Poseidon2 + Serialize,
    C: GenericConfig<D, F = F> + Default + Serialize + 'static,
    const D: usize,
    P: AsRef<Path>,
>(
    circ_data: CircuitData<F, C, D>,
    targets: &impl Serialize,
    base_path: P,
) -> anyhow::Result<()>
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    // 1. Split into prover_data + verifier_data
    let verifier_data: VerifierCircuitData<F, C, D> = circ_data.verifier_data();
    let prover_data = circ_data.prover_data();


    // 2. Export each separately
    export_prover_circuit_data(prover_data, &base_path)
        .context("export_prover_circuit_data failed")?;
    export_verifier_circuit_data(verifier_data, &base_path)
        .context("export_verifier_circuit_data failed")?;
    export_circuit_targets(targets, &base_path)
        .context("export_circuit_targets failed")?;

    Ok(())
}

/// Serialize `proof_with_pis` into JSON and write it under a base directory
pub fn export_proof_with_pi<F, C, const D: usize, P: AsRef<Path>>(
    proof_with_pis: &ProofWithPublicInputs<F, C, D>,
    base_path: P,
) -> anyhow::Result<()>
    where
        F: RichField + Extendable<D> + Poseidon2 + Serialize,
        C: GenericConfig<D, F = F> + Serialize,
{
    // Serialize to JSON bytes
    let proof_serialized = serde_json::to_vec(&proof_with_pis)
        .map_err(|e| anyhow::anyhow!("Failed to serialize proof with public input: {:?}", e))?;

    // the full file path
    let proof_file_path = base_path.as_ref().join(PROOF_JSON);

    // ensure parent directory exists
    ensure_parent_directory_exists(&proof_file_path)?;

    // write it out
    write_bytes_to_file(&proof_serialized, &proof_file_path)
        .with_context(|| format!("Failed to write proof to {:?}", proof_file_path))?;
    Ok(())
}

//------------------------- IMPORT --------------------------

/// Import `ProverCircuitData<F, C, D>` from disk under the given `base_path`.
pub fn import_prover_circuit_data<F, C, const D: usize, P: AsRef<Path>>(
    base_path: P,
) -> anyhow::Result<ProverCircuitData<F, C, D>>
    where
        F: RichField + Extendable<D> + Poseidon2 + Serialize,
        C: GenericConfig<D, F = F> + Default + Serialize + 'static,
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    let gate_serializer = DefaultGateSerializer;
    let generator_serializer = DefaultGeneratorSerializer::<C, D>::default();

    // the full path`
    let full_path = base_path.as_ref().join(PROVER_CIRC_DATA_JSON);

    // Read raw bytes
    let bytes = read_bytes_from_file(&full_path)
        .with_context(|| format!("Failed to read prover circuit data from {:?}", full_path))?;

    // Deserialize
    let prover_data = ProverCircuitData::<F, C, D>::from_bytes(
        &bytes,
        &gate_serializer,
        &generator_serializer,
    )
        .map_err(|e| anyhow::anyhow!("Failed to deserialize prover data from {:?}: {:?}", full_path, e))?;

    Ok(prover_data)
}

/// Import `VerifierCircuitData<F, C, D>` from disk under `base_path`.
pub fn import_verifier_circuit_data<F, C, const D: usize, P: AsRef<Path>>(
    base_path: P,
) -> anyhow::Result<VerifierCircuitData<F, C, D>>
    where
        F: RichField + Extendable<D> + Poseidon2 + Serialize,
        C: GenericConfig<D, F = F> + Serialize,
{
    let gate_serializer = DefaultGateSerializer;

    let full_path = base_path.as_ref().join(VERIFIER_CIRC_DATA_JSON);
    let bytes = read_bytes_from_file(&full_path)
        .with_context(|| format!("Failed to read verifier circuit data from {:?}", full_path))?;

    let verifier_data = VerifierCircuitData::<F, C, D>::from_bytes(bytes, &gate_serializer)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize verifier data from {:?}: {:?}", full_path, e))?;

    Ok(verifier_data)
}

/// Import a `ProofWithPublicInputs<F, C, D>` from JSON under `base_path`.
pub fn import_proof_with_pi<F, C, const D: usize, P: AsRef<Path>>(
    base_path: P,
) -> anyhow::Result<ProofWithPublicInputs<F, C, D>>
    where
        F: RichField + Extendable<D> + Poseidon2,
        C: GenericConfig<D, F = F>,
{
    // Build full path
    let full_path = base_path.as_ref().join(PROOF_JSON);

    // Read JSON string
    let proof_json_str = fs::read_to_string(&full_path)
        .with_context(|| format!("Failed to read proof from {:?}", full_path))?;

    // Deserialize
    let proof = serde_json::from_str(&proof_json_str)
        .with_context(|| format!("Failed to deserialize proof at {:?}", full_path))?;

    Ok(proof)
}

/// Import the circuit targets from the JSON file.
/// This function is generic over the type `T` that represents the targets and
/// must implement `DeserializeOwned` so that it can be deserialized.
pub fn import_targets<T, P: AsRef<Path>>(base_path: P) -> anyhow::Result<T>
    where
        T: DeserializeOwned,
{
    let full_path = base_path.as_ref().join(TARGETS_JSON);
    let targets_str = fs::read_to_string(&full_path)
        .with_context(|| format!("Failed to read targets from {:?}", full_path))?;
    let targets = serde_json::from_str(&targets_str)
        .with_context(|| format!("Failed to deserialize targets from {:?}", full_path))?;
    Ok(targets)
}
