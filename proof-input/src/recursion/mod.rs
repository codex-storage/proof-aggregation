use plonky2::plonk::circuit_data::{ProverCircuitData, VerifierCircuitData};
use plonky2::plonk::proof::ProofWithPublicInputs;
use codex_plonky2_circuits::circuit_helper::Plonky2Circuit;
use codex_plonky2_circuits::circuits::sample_cells::SampleCircuit;
use crate::gen_input::gen_testing_circuit_input;
use crate::params::{C, D, F, HF, Params};

pub mod tree_test;
pub mod leaf_test;
pub mod node_test;


pub fn run_sampling_circ() -> anyhow::Result<(ProofWithPublicInputs<F, C, D>, ProverCircuitData<F, C, D>, VerifierCircuitData<F, C, D>)> {
    //------------ sampling inner circuit ----------------------
    // Circuit that does the sampling - 100 samples
    let mut params = Params::default();
    params.set_n_samples(100);
    let one_circ_input = gen_testing_circuit_input::<F, D>(&params.input_params);
    let samp_circ = SampleCircuit::<F,D,HF>::new(params.circuit_params);
    let (inner_tar, inner_data) = samp_circ.build_with_standard_config()?;

    let inner_verifier_data = inner_data.verifier_data();
    let inner_prover_data = inner_data.prover_data();

    println!("sampling circuit degree bits = {:?}", inner_verifier_data.common.degree_bits());
    let inner_proof = samp_circ.prove(&inner_tar, &one_circ_input, &inner_prover_data)?;

    Ok((inner_proof, inner_prover_data, inner_verifier_data))
}