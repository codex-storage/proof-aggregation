use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::GenericConfig;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use anyhow::Result;
use std::time::Instant;
use codex_plonky2_circuits::circuits::sample_cells::SampleCircuit;
use plonky2_poseidon2::serialization::{DefaultGateSerializer,DefaultGeneratorSerializer};
use proof_input::json::write_bytes_to_file;
use proof_input::params::Params;
use proof_input::params::{D, C, F};

fn main() -> Result<()> {
    // Load the parameters from environment variables
    let params = Params::from_env()?;

    // Create the circuit
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let circuit_params = params.circuit_params;
    let circ = SampleCircuit::new(circuit_params);
    let mut targets = circ.sample_slot_circuit(&mut builder);

    // Build the circuit
    let build_time = Instant::now();
    let data = builder.build::<C>();
    println!("Build time: {:?}", build_time.elapsed());
    println!("Circuit size (degree bits): {:?}", data.common.degree_bits());

    let gate_serializer = DefaultGateSerializer;
    let generator_serializer =DefaultGeneratorSerializer::<C, D>::default();
    let data_bytes = data.to_bytes(&gate_serializer, &generator_serializer).unwrap();

    let file_path = "circ_data.bin";
    // Write data to the file
    write_bytes_to_file(data_bytes.clone(), file_path).unwrap();
    println!("Data written to {}", file_path);

    Ok(())
}
