use plonky2::plonk::config::GenericConfig;
use anyhow::Result;
use proof_input::serialization::circuit_input::export_circ_input_to_json;
use proof_input::gen_input::gen_testing_circuit_input;
use proof_input::params::Params;
use proof_input::params::{D, F};

fn main() -> Result<()> {
    // Load the parameters from environment variables
    let params = Params::from_env()?;

    // generate circuit input with given parameters
    let circ_input = gen_testing_circuit_input::<F,D>(&params.test);

    // export circuit parameters to json file
    let filename= "input.json";
    export_circ_input_to_json(circ_input, filename)?;
    println!("proof input written to {}", filename);

    Ok(())
}
