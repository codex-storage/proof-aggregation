use plonky2::hash::hash_types::{HashOut, RichField};
use plonky2_field::extension::Extendable;
use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2;
use serde::{Deserialize, Serialize};
use anyhow::{anyhow, Error};
use codex_plonky2_circuits::circuits::sample_cells::{Cell, MerklePath, SampleCircuitInput};
use std::fs::File;
use std::io::{BufReader, Write};
use std::path::Path;
use codex_plonky2_circuits::serialization::ensure_parent_directory_exists;

pub const CIRC_INPUT_JSON: &str = "prover_data/input.json";

// Serializable versions of the circuit input
// naming here is not Rust friendly but only so that its compatible with Nim code.
#[allow(non_snake_case)]
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
    >(&self) -> anyhow::Result<SampleCircuitInput<F, D>> {
        // Convert entropy
        let entropy_elements = self
            .entropy
            .iter()
            .map(|s| -> anyhow::Result<F, Error> {
                let n = s.parse::<u64>()?;
                Ok(F::from_canonical_u64(n))
            })
            .collect::<anyhow::Result<Vec<F>, Error>>()?;
        let entropy = HashOut {
            elements: entropy_elements
                .try_into()
                .map_err(|_| anyhow!("Invalid entropy length"))?,
        };

        // Convert dataset_root
        let dataset_root_elements = self
            .dataSetRoot
            .iter()
            .map(|s| -> anyhow::Result<F, Error> {
                let n = s.parse::<u64>()?;
                Ok(F::from_canonical_u64(n))
            })
            .collect::<anyhow::Result<Vec<F>, Error>>()?;
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
            .map(|s| -> anyhow::Result<F, Error> {
                let n = s.parse::<u64>()?;
                Ok(F::from_canonical_u64(n))
            })
            .collect::<anyhow::Result<Vec<F>, Error>>()?;
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
            .map(|s| -> anyhow::Result<F, Error> {
                let n = s.parse::<u64>()?;
                Ok(F::from_canonical_u64(n))
            })
            .collect::<anyhow::Result<Vec<F>, Error>>()?;
        if slot_proof_elements.len() % 4 != 0 {
            return Err(anyhow!("Invalid slot_proof length"));
        }
        let slot_proof = slot_proof_elements
            .chunks(4)
            .map(|chunk| -> anyhow::Result<HashOut<F>, Error> {
                let elements: [F; 4] = chunk
                    .try_into()
                    .map_err(|_| anyhow!("Invalid chunk length"))?;
                Ok(HashOut { elements })
            })
            .collect::<anyhow::Result<Vec<HashOut<F>>, Error>>()?;

        // cell_data
        let cell_data = self
            .cellData
            .iter()
            .map(|vec_of_strings| -> anyhow::Result<Cell<F,D>, Error> {
                let cell = vec_of_strings
                    .iter()
                    .map(|s| -> anyhow::Result<F, Error> {
                        let n = s.parse::<u64>()?;
                        Ok(F::from_canonical_u64(n))
                    })
                    .collect::<anyhow::Result<Vec<F>, Error>>();
                Ok(Cell::<F,D>{
                    data: cell.unwrap(),
                })
            })
            .collect::<anyhow::Result<Vec<Cell<F,D>>, Error>>()?;

        // merkle_paths
        let merkle_paths = self
            .merklePaths
            .iter()
            .map(|path_strings| -> anyhow::Result<MerklePath<F,D>, Error> {
                let path_elements = path_strings
                    .iter()
                    .map(|s| -> anyhow::Result<F, Error> {
                        let n = s.parse::<u64>()?;
                        Ok(F::from_canonical_u64(n))
                    })
                    .collect::<anyhow::Result<Vec<F>, Error>>()?;

                if path_elements.len() % 4 != 0 {
                    return Err(anyhow!("Invalid merkle path length"));
                }

                let path = path_elements
                    .chunks(4)
                    .map(|chunk| -> anyhow::Result<HashOut<F>, Error> {
                        let elements: [F; 4] = chunk
                            .try_into()
                            .map_err(|_| anyhow!("Invalid chunk length"))?;
                        Ok(HashOut { elements })
                    })
                    .collect::<anyhow::Result<Vec<HashOut<F>>, Error>>()?;

                let mp = MerklePath::<F,D>{
                    path,
                };
                Ok(mp)
            })
            .collect::<anyhow::Result<Vec<MerklePath<F,D>>, Error>>()?;

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

/// export circuit input to json file
pub fn export_circ_input_to_json<
    F: RichField + Extendable<D> + Poseidon2 + Serialize,
    const D: usize,
    P: AsRef<Path>,
>(
    circ_input: SampleCircuitInput<F, D>,
    base_path: P,
) -> anyhow::Result<()> {
    // Convert the circuit input to a serializable format
    let serializable_circ_input = SerializableCircuitInput::from_circ_input(&circ_input);

    // Serialize to JSON
    let json_data = serde_json::to_string_pretty(&serializable_circ_input)?;

    let full_path = base_path.as_ref().join(CIRC_INPUT_JSON);

    // Write to file
    ensure_parent_directory_exists(&full_path)?;
    let mut file = File::create(&full_path)?;
    file.write_all(json_data.as_bytes())?;
    Ok(())
}

/// reads the json file, converts it to circuit input (SampleCircuitInput) and returns it
pub fn import_circ_input_from_json<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    P: AsRef<Path>,
>(
    base_path: P,
) -> anyhow::Result<SampleCircuitInput<F, D>> {
    let full_path = base_path.as_ref().join(CIRC_INPUT_JSON);

    let file = File::open(&full_path)?;
    let reader = BufReader::new(file);
    let serializable_circ_input: SerializableCircuitInput = serde_json::from_reader(reader)?;

    let circ_input = serializable_circ_input.to_circ_input()?;
    Ok(circ_input)
}

#[cfg(test)]
mod tests {
    use crate::params::{C, D, F, HF, Params};
    use codex_plonky2_circuits::circuits::sample_cells::{SampleCircuit, SampleCircuitInput};
    use plonky2::plonk::circuit_data::{ProverCircuitData, VerifierCircuitData};
    use codex_plonky2_circuits::circuit_helper::Plonky2Circuit;
    use crate::gen_input::InputGenerator;
    use crate::serialization::circuit_input::{export_circ_input_to_json, import_circ_input_from_json};

    // Test to generate the JSON file
    #[test]
    fn test_export_circ_input_to_json() -> anyhow::Result<()> {
        // Create InputGenerator
        let input_gen = InputGenerator::<F,D,HF>::default();
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
        let input_gen = InputGenerator::<F,D,HF>::default();

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

        let circ = SampleCircuit::<F, D, HF>::new(circuit_params.clone());
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
        let input_gen = InputGenerator::<F,D,HF>::default();

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
