use std::env;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::GenericConfig;
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use anyhow::Result;
use plonky2::plonk::proof::ProofWithPublicInputs;
use codex_plonky2_circuits::circuits::sample_cells::SampleCircuit;
use codex_plonky2_circuits::recursion::uniform::tree::TreeRecursion;
use proof_input::gen_input::gen_testing_circuit_input;
use proof_input::params::{D, C, F, HF, Params};

fn main() -> Result<()> {
    // load the parameters from environment variables
    let params = Params::from_env()?;
    const N: usize = 1;
    const M: usize = 2;

    // take k = "number of proofs" from env arguments; default to 4 if not there
    let args: Vec<String> = env::args().collect();
    let k: usize = if args.len() > 1 {
        args[1]
            .parse()
            .expect("k not valid")
    } else {
        4
    };

    // generate circuit input with given parameters
    let circ_input = gen_testing_circuit_input::<F,D>(&params.input_params);

    // create the circuit
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let circ = SampleCircuit::<F,D,HF>::new(params.circuit_params);
    let mut targets = circ.sample_slot_circuit_with_public_input(&mut builder)?;

    // create a PartialWitness and assign
    let mut pw = PartialWitness::new();
    circ.sample_slot_assign_witness(&mut pw, &targets, &circ_input)?;

    // Build the circuit
    let data = builder.build::<C>();

    // Prove the inner-circuit with the assigned witness
    let inner_proof = data.prove(pw)?;

    // dummy proofs
    let proofs: Vec<ProofWithPublicInputs<F, C, D>> = (0..k).map(|i| inner_proof.clone()).collect();

    let mut tree = TreeRecursion::<F,D,C,HF, N, M>::build(data.common.clone()).unwrap();

    let tree_proof = tree.prove_tree(&proofs, &data.verifier_only).unwrap();

    let inner_pi: Vec<Vec<F>> = proofs.iter().map(|p| p.public_inputs.clone()).collect();

    assert!(tree.verify_proof_and_public_input(tree_proof,inner_pi.clone(),&data.verifier_data(), false).is_ok());

    Ok(())
}
