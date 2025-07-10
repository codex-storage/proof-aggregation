use std::time::Instant;
use anyhow::Result;
use proof_input::input_generator::serialization::export_circ_input_to_json;
use proof_input::input_generator::InputGenerator;
use proof_input::params::Params;
use crate::params::{D, H, F};
use crate::file_paths::SAMPLING_CIRC_BASE_PATH;

pub fn run() -> Result<()> {
    // Load the parameters from environment variables
    let params = Params::from_env()?;

    // generate circuit input with given parameters
    let start_time = Instant::now();
    let input_gen = InputGenerator::<F,D,H>::new(params.input_params);
    let circ_input = input_gen.gen_testing_circuit_input();
    println!("Generating input time: {:?}", start_time.elapsed());

    // export circuit parameters to json file
    export_circ_input_to_json(circ_input, SAMPLING_CIRC_BASE_PATH)?;
    println!("proof input written to {}", SAMPLING_CIRC_BASE_PATH);

    Ok(())
}
