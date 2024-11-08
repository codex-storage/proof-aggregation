use anyhow::{anyhow, Error, Result};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{BufReader, Write};
use crate::gen_input::{DatasetTree, gen_witness};
use plonky2::hash::hash_types::{HashOut, RichField};
use plonky2::plonk::config::{GenericConfig, Hasher};
use plonky2_field::extension::Extendable;
use plonky2_field::types::Field;
use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2;
use codex_plonky2_circuits::circuits::sample_cells::{Cell, MerklePath, SampleCircuitInput};
use crate::params::Params;

pub fn export_witness_to_json<
    F: RichField + Extendable<D> + Poseidon2 + Serialize,
    const D: usize,
> (witness :SampleCircuitInput<F, D>, filename: &str) -> Result<()>{
    // Convert the witness to a serializable format
    let serializable_witness = SerializableWitness::from_witness(&witness);

    // Serialize to JSON
    let json_data = serde_json::to_string_pretty(&serializable_witness)?;

    // Write to file
    let mut file = File::create(filename)?;
    file.write_all(json_data.as_bytes())?;
    Ok(())
}


/// Function to generate witness and export to JSON
pub fn generate_and_export_witness_to_json<
    F: RichField + Extendable<D> + Poseidon2 + Serialize,
    const D: usize,
>( params: &Params, filename: &str) -> anyhow::Result<()> {

    let witness = gen_witness::<F,D>(params);

    export_witness_to_json(witness, filename)?;

    Ok(())
}


// Serializable versions of the witness
#[derive(Serialize, Deserialize)]
struct SerializableWitness<
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
> SerializableWitness{
    /// from the witness to serializable witness
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

impl<> SerializableWitness {
    /// from serializable witness to witness
    pub fn to_witness<
        F: RichField + Extendable<D> + Poseidon2,
        const D: usize
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

/// reads the json file, converts it to witness (SampleCircuitInput) and returns it
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
    use crate::params::{BOT_DEPTH, C, D, F, MAX_DEPTH, N_CELLS};
    use std::fs;
    use std::time::Instant;
    use codex_plonky2_circuits::circuits::params::{CircuitParams, HF};
    use codex_plonky2_circuits::circuits::sample_cells::SampleCircuit;
    use codex_plonky2_circuits::merkle_tree::merkle_safe::MerkleProof;
    use plonky2::iop::witness::PartialWitness;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use crate::gen_input::verify_witness;
    use crate::sponge::hash_n_with_padding;
    use crate::utils::{bits_le_padded_to_usize, calculate_cell_index_bits, usize_to_bits_le_padded};

    // Test to generate the JSON file
    #[test]
    fn test_export_witness_to_json() -> anyhow::Result<()> {
        // Create Params
        let params = Params::default();
        // Export the witness to JSON
        generate_and_export_witness_to_json::<F,D>(&params, "input.json")?;

        println!("Witness exported to input.json");

        Ok(())
    }

    #[test]
    fn test_import_witness_from_json() -> anyhow::Result<()> {
        // Import the witness from the JSON file
        // NOTE: MAKE SURE THE FILE EXISTS
        let witness: SampleCircuitInput<F, D> = import_witness_from_json("input.json")?;
        println!("Witness imported successfully");

        Ok(())
    }

    // export the witness and then import it and checks equality
    #[test]
    fn test_export_import_witness() -> anyhow::Result<()> {
        // Create Params instance
        let params = Params::default();

        // Export the witness to JSON
        let original_witness = gen_witness(&params);
        export_witness_to_json(original_witness.clone(), "input.json")?;
        println!("Witness exported to input.json");

        // Import the witness from JSON
        let imported_witness: SampleCircuitInput<F, D> = import_witness_from_json("input.json")?;
        println!("Witness imported from input.json");

        // Compare the original and imported witnesses
        assert_eq!(original_witness, imported_witness, "Witnesses are not equal");

        // cleanup: Remove the generated JSON file
        fs::remove_file("input.json")?;

        println!("Test passed: Original and imported witnesses are equal.");

        Ok(())
    }

    // reads the json input and runs the circuit
    #[test]
    fn test_json_witness_circuit() -> anyhow::Result<()> {
        let params = Params::default();

        // Create the circuit
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let circuit_params = CircuitParams {
            max_depth: params.max_depth,
            max_log2_n_slots: params.dataset_depth(),
            block_tree_depth: params.bot_depth(),
            n_field_elems_per_cell: params.n_field_elems_per_cell(),
            n_samples: params.n_samples,
        };
        let circ = SampleCircuit::new(circuit_params.clone());
        let mut targets = circ.sample_slot_circuit(&mut builder);

        // Create a PartialWitness and assign
        let mut pw = PartialWitness::new();

        // Import the witness from JSON
        let imported_witness: SampleCircuitInput<F, D> = import_witness_from_json("input.json")?;
        println!("Witness imported from input.json");

        circ.sample_slot_assign_witness(&mut pw, &mut targets, imported_witness);

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
    // NOTE: expects the json input proof uses the default params
    #[test]
    fn test_json_witness() -> anyhow::Result<()> {
        let params = Params::default();

        // Import the witness from JSON
        let imported_witness: SampleCircuitInput<F, D> = import_witness_from_json("input.json")?;
        println!("Witness imported from input.json");

        // Verify the proof
        let ver = verify_witness(imported_witness, &params);
        assert!(
            ver,
            "Merkle proof verification failed"
        );

        Ok(())
    }
}