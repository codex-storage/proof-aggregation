// use std::fmt::Error;
use anyhow::{anyhow, Result, Error};
use std::num::ParseIntError;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::fs::File;
use std::io::{BufReader, Write};
use crate::proof_input::gen_input::DatasetTree;
use plonky2::hash::hash_types::{HashOut, RichField};
use plonky2::plonk::config::{GenericConfig, Hasher};
use plonky2_field::extension::Extendable;
use plonky2_field::types::Field;
use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2;
use crate::circuits::sample_cells::{Cell, MerklePath, SampleCircuitInput};
use crate::proof_input::test_params::Params;

// ... (Include necessary imports and your existing code)

impl<
    F: RichField + Extendable<D> + Poseidon2 + Serialize,
    const D: usize,
> DatasetTree<F, D> {
    /// Function to generate witness and export to JSON
    pub fn export_witness_to_json(&self, params: &Params, filename: &str) -> anyhow::Result<()> {
        // Sample the slot
        let slot_index = params.testing_slot_index;
        let entropy = params.entropy;

        let proof = self.sample_slot(slot_index, entropy);
        let slot_root = self.slot_trees[slot_index].tree.root().unwrap();

        // Prepare the witness data
        let mut slot_paths = vec![];
        for i in 0..params.n_samples {
            let path = proof.slot_proofs[i].path.clone();
            let mp = MerklePath::<F,D>{
                path,
            };
            slot_paths.push(mp);
        }

        // Create the witness
        let witness = SampleCircuitInput::<F, D> {
            entropy: proof.entropy.elements.clone().to_vec(),
            dataset_root: self.tree.root().unwrap(),
            slot_index: proof.slot_index.clone(),
            slot_root,
            n_cells_per_slot: F::from_canonical_usize(params.n_cells_per_slot()),
            n_slots_per_dataset: F::from_canonical_usize(params.n_slots_per_dataset()),
            slot_proof: proof.dataset_proof.path.clone(),
            cell_data: proof.cell_data.clone(),
            merkle_paths: slot_paths,
        };

        // Convert the witness to a serializable format
        let serializable_witness = SerializableWitness::from_witness(&witness);

        // Serialize to JSON
        let json_data = serde_json::to_string_pretty(&serializable_witness)?;

        // Write to file
        let mut file = File::create(filename)?;
        file.write_all(json_data.as_bytes())?;

        Ok(())
    }
}

// Serializable versions of your data structures
#[derive(Serialize, Deserialize)]
struct SerializableWitness<
    // F: RichField + Extendable<D> + Poseidon2 + Serialize,
    // const D: usize,
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
    // F: RichField + Extendable<D> + Poseidon2 + Serialize,
    // const D: usize,
> SerializableWitness{
    pub fn from_witness<
        F: RichField + Extendable<D> + Poseidon2 + Serialize,
        const D: usize,
    >(witness: &SampleCircuitInput<F, D>) -> Self {
        SerializableWitness {
            dataSetRoot: witness
                .dataset_root
                .elements
                .iter()
                .map(|e| e.to_canonical_u64().to_string())
                .collect(),
            entropy: witness
                .entropy
                .iter()
                .map(|e| e.to_canonical_u64().to_string())
                .collect(),
            nCellsPerSlot: witness.n_cells_per_slot.to_canonical_u64() as usize,
            nSlotsPerDataSet: witness.n_slots_per_dataset.to_canonical_u64() as usize,
            slotIndex: witness.slot_index.to_canonical_u64(),
            slotRoot: witness
                .slot_root
                .elements
                .iter()
                .map(|e| e.to_canonical_u64().to_string())
                .collect(),
            slotProof: witness
                .slot_proof
                .iter()
                .flat_map(|hash| hash.elements.iter())
                .map(|e| e.to_canonical_u64().to_string())
                .collect(),
            cellData: witness
                .cell_data
                .iter()
                .map(|data_vec| {
                    data_vec.data
                        .iter()
                        .map(|e| e.to_canonical_u64().to_string())
                        .collect()
                })
                .collect(),
            merklePaths: witness
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

// pub struct SampleCircuitInput<
//     F: RichField + Extendable<D> + Poseidon2,
//     const D: usize,
// > {
//     pub entropy: Vec<F>,
//     pub dataset_root: HashOut<F>,
//     pub slot_index: F,
//     pub slot_root: HashOut<F>,
//     pub n_cells_per_slot: F,
//     pub n_slots_per_dataset: F,
//     pub slot_proof: Vec<HashOut<F>>,
//     pub cell_data: Vec<Vec<F>>,
//     pub merkle_paths: Vec<Vec<HashOut<F>>>,
// }

impl<> SerializableWitness {
    pub fn to_witness<
        F: RichField + Extendable<D> + Poseidon2, const D: usize
    >(&self) -> Result<SampleCircuitInput<F, D>> {
        // Convert entropy
        let entropy = self
            .entropy
            .iter()
            .map(|s| -> Result<F, Error> {
                let n = s.parse::<u64>()?;
                Ok(F::from_canonical_u64(n))
            })
            .collect::<Result<Vec<F>, Error>>()?;

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

pub fn import_witness_from_json<F: RichField + Extendable<D> + Poseidon2, const D: usize>(
    filename: &str,
) -> Result<SampleCircuitInput<F, D>> {
    let file = File::open(filename)?;
    let reader = BufReader::new(file);
    let serializable_witness: SerializableWitness = serde_json::from_reader(reader)?;

    let witness = serializable_witness.to_witness()?;
    Ok(witness)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proof_input::test_params::{F,D};
    use std::fs;

    // Test to generate the JSON file
    #[test]
    fn test_export_witness_to_json() -> anyhow::Result<()> {
        // Create Params instance
        let params = Params::default();

        // Create the dataset tree
        let dataset_t = DatasetTree::<F, D>::new_for_testing(&params);

        // Export the witness to JSON
        dataset_t.export_witness_to_json(&params, "input.json")?;

        println!("Witness exported to input.json");

        Ok(())
    }

    #[test]
    fn test_import_witness_from_json() -> anyhow::Result<()> {
        // First, ensure that the JSON file exists
        // You can generate it using the export function if needed

        // Import the witness from the JSON file
        let witness: SampleCircuitInput<F, D> = import_witness_from_json("input.json")?;

        // Perform some checks to verify that the data was imported correctly
        assert_eq!(witness.entropy.len(), 4); // Example check
        // Add more assertions as needed

        println!("Witness imported successfully");

        Ok(())
    }

    #[test]
    fn test_export_import_witness() -> anyhow::Result<()> {
        // Create Params instance
        let params = Params::default();

        // Create the dataset tree
        let dataset_t = DatasetTree::<F, D>::new_for_testing(&params);

        // Generate the witness data
        let slot_index = params.testing_slot_index;
        let entropy = params.entropy;

        let proof = dataset_t.sample_slot(slot_index, entropy);
        let slot_root = dataset_t.slot_trees[slot_index].tree.root().unwrap();

        let mut slot_paths = vec![];
        for i in 0..params.n_samples {
            let path = proof.slot_proofs[i].path.clone();
            let mp = MerklePath::<F,D>{
                path,
            };
            slot_paths.push(mp);
        }

        let original_witness = SampleCircuitInput::<F, D> {
            entropy: proof.entropy.elements.clone().to_vec(),
            dataset_root: dataset_t.tree.root().unwrap(),
            slot_index: proof.slot_index.clone(),
            slot_root,
            n_cells_per_slot: F::from_canonical_usize(params.n_cells_per_slot()),
            n_slots_per_dataset: F::from_canonical_usize(params.n_slots_per_dataset()),
            slot_proof: proof.dataset_proof.path.clone(),
            cell_data: proof.cell_data.clone(),
            merkle_paths: slot_paths,
        };

        // Export the witness to JSON
        dataset_t.export_witness_to_json(&params, "input.json")?;
        println!("Witness exported to input.json");

        // Import the witness from JSON
        let imported_witness: SampleCircuitInput<F, D> = import_witness_from_json("input.json")?;
        println!("Witness imported from input.json");

        // Compare the original and imported witnesses
        assert_eq!(original_witness, imported_witness, "Witnesses are not equal");

        // Cleanup: Remove the generated JSON file
        fs::remove_file("input.json")?;

        println!("Test passed: Original and imported witnesses are equal.");

        Ok(())
    }
}