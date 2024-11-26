use anyhow::{anyhow, Error, Result};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::{fs, io};
use std::io::{BufReader, BufWriter, Write};
use std::path::Path;
use crate::gen_input::{DatasetTree, gen_testing_circuit_input};
use plonky2::hash::hash_types::{HashOut, RichField};
use plonky2::plonk::config::{GenericConfig, Hasher};
use plonky2_field::extension::Extendable;
use plonky2_field::types::Field;
use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2;
use codex_plonky2_circuits::circuits::sample_cells::{Cell, MerklePath, SampleCircuitInput};
use plonky2::plonk::proof::CompressedProofWithPublicInputs;
use serde_json::to_writer_pretty;
use crate::params::TestParams;

/// export circuit input to json file
pub fn export_circ_input_to_json<
    F: RichField + Extendable<D> + Poseidon2 + Serialize,
    const D: usize,
> (circ_input:SampleCircuitInput<F, D>, filename: &str) -> Result<()>{
    // Convert the circuit input to a serializable format
    let serializable_circ_input = SerializableCircuitInput::from_circ_input(&circ_input);

    // Serialize to JSON
    let json_data = serde_json::to_string_pretty(&serializable_circ_input)?;

    // Write to file
    let mut file = File::create(filename)?;
    file.write_all(json_data.as_bytes())?;
    Ok(())
}

// Function to export proof with public input to json file
fn export_proof_with_pi_to_json<F, C, const D: usize>(
    instance: &CompressedProofWithPublicInputs<F, C, D>,
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


/// Function to generate circuit input and export to JSON
pub fn generate_and_export_circ_input_to_json<
    F: RichField + Extendable<D> + Poseidon2 + Serialize,
    const D: usize,
>(params: &TestParams, filename: &str) -> Result<()> {

    let circ_input = gen_testing_circuit_input::<F,D>(params);

    export_circ_input_to_json(circ_input, filename)?;

    Ok(())
}


// Serializable versions of the circuit input
#[derive(Serialize, Deserialize)]
struct SerializableCircuitInput<
> {
    dataSetRoot: Vec<String>,
    entropy: Vec<String>,
    nCellsPerSlot: usize,
    nSlotsPerDataSet: usize,
    slotIndex: u64,
    slotRoot: Vec<String>,
    slotProof: Vec<String>,
    cellData: Vec<Vec<String>>,
    merklePaths: Vec<Vec<String>>,
}

impl<
> SerializableCircuitInput {
    /// from the circuit input to serializable circuit input
    pub fn from_circ_input<
        F: RichField + Extendable<D> + Poseidon2 + Serialize,
        const D: usize,
    >(circ_input: &SampleCircuitInput<F, D>) -> Self {
        SerializableCircuitInput {
            dataSetRoot: circ_input
                .dataset_root
                .elements
                .iter()
                .map(|e| e.to_canonical_u64().to_string())
                .collect(),
            entropy: circ_input
                .entropy
                .elements
                .iter()
                .map(|e| e.to_canonical_u64().to_string())
                .collect(),
            nCellsPerSlot: circ_input.n_cells_per_slot.to_canonical_u64() as usize,
            nSlotsPerDataSet: circ_input.n_slots_per_dataset.to_canonical_u64() as usize,
            slotIndex: circ_input.slot_index.to_canonical_u64(),
            slotRoot: circ_input
                .slot_root
                .elements
                .iter()
                .map(|e| e.to_canonical_u64().to_string())
                .collect(),
            slotProof: circ_input
                .slot_proof
                .iter()
                .flat_map(|hash| hash.elements.iter())
                .map(|e| e.to_canonical_u64().to_string())
                .collect(),
            cellData: circ_input
                .cell_data
                .iter()
                .map(|data_vec| {
                    data_vec.data
                        .iter()
                        .map(|e| e.to_canonical_u64().to_string())
                        .collect()
                })
                .collect(),
            merklePaths: circ_input
                .merkle_paths
                .iter()
                .map(|path| {
                    path.path.iter()
                        .flat_map(|hash| hash.elements.iter())
                        .map(|e| e.to_canonical_u64().to_string())
                        .collect()
                })
                .collect(),
        }
    }
}

impl<> SerializableCircuitInput {
    /// from serializable circuit input to circuit input
    pub fn to_circ_input<
        F: RichField + Extendable<D> + Poseidon2,
        const D: usize
    >(&self) -> Result<SampleCircuitInput<F, D>> {
        // Convert entropy
        let entropy_elements = self
            .entropy
            .iter()
            .map(|s| -> Result<F, Error> {
                let n = s.parse::<u64>()?;
                Ok(F::from_canonical_u64(n))
            })
            .collect::<Result<Vec<F>, Error>>()?;
        let entropy = HashOut {
            elements: entropy_elements
                .try_into()
                .map_err(|_| anyhow!("Invalid entropy length"))?,
        };

        // Convert dataset_root
        let dataset_root_elements = self
            .dataSetRoot
            .iter()
            .map(|s| -> Result<F, Error> {
                let n = s.parse::<u64>()?;
                Ok(F::from_canonical_u64(n))
            })
            .collect::<Result<Vec<F>, Error>>()?;
        let dataset_root = HashOut {
            elements: dataset_root_elements
                .try_into()
                .map_err(|_| anyhow!("Invalid dataset_root length"))?,
        };

        // slot_index
        let slot_index = F::from_canonical_u64(self.slotIndex);

        // slot_root
        let slot_root_elements = self
            .slotRoot
            .iter()
            .map(|s| -> Result<F, Error> {
                let n = s.parse::<u64>()?;
                Ok(F::from_canonical_u64(n))
            })
            .collect::<Result<Vec<F>, Error>>()?;
        let slot_root = HashOut {
            elements: slot_root_elements
                .try_into()
                .map_err(|_| anyhow!("Invalid slot_root length"))?,
        };

        // n_cells_per_slot
        let n_cells_per_slot = F::from_canonical_usize(self.nCellsPerSlot);

        // n_slots_per_dataset
        let n_slots_per_dataset = F::from_canonical_usize(self.nSlotsPerDataSet);

        // slot_proof
        let slot_proof_elements = self
            .slotProof
            .iter()
            .map(|s| -> Result<F, Error> {
                let n = s.parse::<u64>()?;
                Ok(F::from_canonical_u64(n))
            })
            .collect::<Result<Vec<F>, Error>>()?;
        if slot_proof_elements.len() % 4 != 0 {
            return Err(anyhow!("Invalid slot_proof length"));
        }
        let slot_proof = slot_proof_elements
            .chunks(4)
            .map(|chunk| -> Result<HashOut<F>, Error> {
                let elements: [F; 4] = chunk
                    .try_into()
                    .map_err(|_| anyhow!("Invalid chunk length"))?;
                Ok(HashOut { elements })
            })
            .collect::<Result<Vec<HashOut<F>>, Error>>()?;

        // cell_data
        let cell_data = self
            .cellData
            .iter()
            .map(|vec_of_strings| -> Result<Cell<F,D>, Error> {
                let cell = vec_of_strings
                    .iter()
                    .map(|s| -> Result<F, Error> {
                        let n = s.parse::<u64>()?;
                        Ok(F::from_canonical_u64(n))
                    })
                    .collect::<Result<Vec<F>, Error>>();
                Ok(Cell::<F,D>{
                    data: cell.unwrap(),
                })
            })
            .collect::<Result<Vec<Cell<F,D>>, Error>>()?;

        // merkle_paths
        let merkle_paths = self
            .merklePaths
            .iter()
            .map(|path_strings| -> Result<MerklePath<F,D>, Error> {
                let path_elements = path_strings
                    .iter()
                    .map(|s| -> Result<F, Error> {
                        let n = s.parse::<u64>()?;
                        Ok(F::from_canonical_u64(n))
                    })
                    .collect::<Result<Vec<F>, Error>>()?;

                if path_elements.len() % 4 != 0 {
                    return Err(anyhow!("Invalid merkle path length"));
                }

                let path = path_elements
                    .chunks(4)
                    .map(|chunk| -> Result<HashOut<F>, Error> {
                        let elements: [F; 4] = chunk
                            .try_into()
                            .map_err(|_| anyhow!("Invalid chunk length"))?;
                        Ok(HashOut { elements })
                    })
                    .collect::<Result<Vec<HashOut<F>>, Error>>()?;

                let mp = MerklePath::<F,D>{
                    path,
                };
                Ok(mp)
            })
            .collect::<Result<Vec<MerklePath<F,D>>, Error>>()?;

        Ok(SampleCircuitInput {
            entropy,
            dataset_root,
            slot_index,
            slot_root,
            n_cells_per_slot,
            n_slots_per_dataset,
            slot_proof,
            cell_data,
            merkle_paths,
        })
    }
}

/// reads the json file, converts it to circuit input (SampleCircuitInput) and returns it
pub fn import_circ_input_from_json<F: RichField + Extendable<D> + Poseidon2, const D: usize>(
    filename: &str,
) -> Result<SampleCircuitInput<F, D>> {
    let file = File::open(filename)?;
    let reader = BufReader::new(file);
    let serializable_circ_input: SerializableCircuitInput = serde_json::from_reader(reader)?;

    let circ_input = serializable_circ_input.to_circ_input()?;
    Ok(circ_input)
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
    use crate::params::{C, D, F};
    use std::time::Instant;
    use codex_plonky2_circuits::circuits::params::CircuitParams;
    use codex_plonky2_circuits::circuits::sample_cells::SampleCircuit;
    use plonky2::iop::witness::PartialWitness;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
    use plonky2_poseidon2::serialization::{DefaultGateSerializer, DefaultGeneratorSerializer};
    use crate::gen_input::verify_circuit_input;

    // Test to generate the JSON file
    #[test]
    fn test_export_circ_input_to_json() -> Result<()> {
        // Create Params
        let params = TestParams::default();
        // Export the circuit input to JSON
        generate_and_export_circ_input_to_json::<F,D>(&params, "input.json")?;

        println!("Circuit input exported to input.json");

        Ok(())
    }

    #[test]
    fn test_import_circ_input_from_json() -> anyhow::Result<()> {
        // Import the circuit input from the JSON file
        // NOTE: MAKE SURE THE FILE EXISTS
        let circ_input: SampleCircuitInput<F, D> = import_circ_input_from_json("input.json")?;
        println!("circuit input imported successfully");

        Ok(())
    }

    // export the circuit input and then import it and checks equality
    #[test]
    fn test_export_import_circ_input() -> anyhow::Result<()> {
        // Create Params instance
        let params = TestParams::default();

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
        let params = TestParams::default();

        // Create the circuit
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let circuit_params = CircuitParams::default();

        let circ = SampleCircuit::new(circuit_params.clone());
        let mut targets = circ.sample_slot_circuit(&mut builder);

        // Create a PartialWitness and assign
        let mut pw = PartialWitness::new();

        // Import the circuit input from JSON
        let imported_circ_input: SampleCircuitInput<F, D> = import_circ_input_from_json("input.json")?;
        println!("circuit input imported from input.json");

        circ.sample_slot_assign_witness(&mut pw, &mut targets, imported_circ_input);

        // Build the circuit
        let data = builder.build::<C>();
        println!("circuit size = {:?}", data.common.degree_bits());

        // Prove the circuit with the assigned witness
        let start_time = Instant::now();
        let proof_with_pis = data.prove(pw)?;
        println!("prove_time = {:?}", start_time.elapsed());

        // Verify the proof
        let verifier_data = data.verifier_data();
        assert!(
            verifier_data.verify(proof_with_pis).is_ok(),
            "Merkle proof verification failed"
        );

        Ok(())
    }

    // reads the json input and verify (non-circuit)
    // NOTE: expects that the json input proof uses the default params
    #[test]
    fn test_read_json_and_verify() -> Result<()> {
        let params = TestParams::default();

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
        let params = TestParams::default();

        // Create the circuit
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let circuit_params = CircuitParams::default();
        let circ = SampleCircuit::new(circuit_params.clone());
        let mut targets = circ.sample_slot_circuit(&mut builder);

        // Create a PartialWitness and assign
        let mut pw = PartialWitness::new();

        // gen circ input
        let imported_circ_input: SampleCircuitInput<F, D> = gen_testing_circuit_input::<F,D>(&params);
        circ.sample_slot_assign_witness(&mut pw, &mut targets, imported_circ_input);

        // Build the circuit
        let data = builder.build::<C>();
        println!("circuit size = {:?}", data.common.degree_bits());

        let gate_serializer = DefaultGateSerializer;
        let generator_serializer =DefaultGeneratorSerializer::<C, D>::default();
        let data_bytes = data.to_bytes(&gate_serializer, &generator_serializer).unwrap();

        let file_path = "circ_data.bin";
        // Write data to the file
        write_bytes_to_file(data_bytes.clone(), file_path).unwrap();
        println!("Data written to {}", file_path);

        // Read data back from the file
        let read_data = read_bytes_from_file(file_path).unwrap();
        let data = CircuitData::<F,C,D>::from_bytes(&read_data, &gate_serializer, &generator_serializer).unwrap();

        // Prove the circuit with the assigned witness
        let start_time = Instant::now();
        let proof_with_pis = data.prove(pw)?;
        println!("prove_time = {:?}", start_time.elapsed());

        // Verify the proof
        let verifier_data = data.verifier_data();
        assert!(
            verifier_data.verify(proof_with_pis).is_ok(),
            "Merkle proof verification failed"
        );

        Ok(())
    }

    // test proof with public input serialization
    #[test]
    fn test_proof_with_pi_serializer() -> anyhow::Result<()> {
        let params = TestParams::default();

        // Create the circuit
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let circuit_params = CircuitParams::default();
        let circ = SampleCircuit::new(circuit_params.clone());
        let mut targets = circ.sample_slot_circuit(&mut builder);

        // Create a PartialWitness and assign
        let mut pw = PartialWitness::new();

        // gen circ input
        let imported_circ_input: SampleCircuitInput<F, D> = gen_testing_circuit_input::<F,D>(&params);
        circ.sample_slot_assign_witness(&mut pw, &mut targets, imported_circ_input);

        // Build the circuit
        let data = builder.build::<C>();
        println!("circuit size = {:?}", data.common.degree_bits());

        // Prove the circuit with the assigned witness
        let start_time = Instant::now();
        let proof_with_pis = data.prove(pw)?;
        println!("prove_time = {:?}", start_time.elapsed());
        println!("Proof size: {} bytes", proof_with_pis.to_bytes().len());

        let compressed_proof_with_pi = data.compress(proof_with_pis.clone())?;
        let filename = "proof_with_pi.json";
        export_proof_with_pi_to_json(&compressed_proof_with_pi,filename)?;
        println!("Proof size: {} bytes", compressed_proof_with_pi.to_bytes().len());

        // Verify the proof
        let verifier_data = data.verifier_data();
        assert!(
            verifier_data.verify(proof_with_pis).is_ok(),
            "Merkle proof verification failed"
        );

        Ok(())
    }
}