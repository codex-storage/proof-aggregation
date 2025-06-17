use std::time::Instant;
use anyhow::Result;
use proof_input::serialization::circuit_input::export_circ_input_to_json;
use proof_input::gen_input::gen_testing_circuit_input;
use proof_input::params::Params;
use proof_input::params::{D, F};
use crate::file_paths::SAMPLING_CIRC_BASE_PATH;

pub fn run() -> Result<()> {
    // Load the parameters from environment variables
    let params = Params::from_env()?;

    // generate circuit input with given parameters
    let start_time = Instant::now();
    let circ_input = gen_testing_circuit_input::<F,D>(&params.input_params);
    println!("Generating input time: {:?}", start_time.elapsed());

    // export circuit parameters to json file
    export_circ_input_to_json(circ_input, SAMPLING_CIRC_BASE_PATH)?;
    println!("proof input written to {}", SAMPLING_CIRC_BASE_PATH);

    Ok(())
}
