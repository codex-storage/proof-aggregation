use std::env;
use anyhow::Result;
use plonky2::plonk::proof::ProofWithPublicInputs;
use codex_plonky2_circuits::recursion::tree::TreeRecursion;
use proof_input::params::{D, C, F, HF};
use proof_input::serialization::file_paths::{PROOF_JSON, TREE_PROOF_JSON, VERIFIER_CIRC_DATA_JSON};
use proof_input::serialization::json::{export_tree_proof_with_pi, import_proof_with_pi, import_verifier_circuit_data};

fn main() -> Result<()> {
    // load the parameters from environment variables
    const N: usize = 2;

    // take k = "number of proofs" from env arguments; default to 4 if not there
    let args: Vec<String> = env::args().collect();
    let t: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(4);

    match t {
        2 => run_tree::<N,2>()?,
        4 => run_tree::<N, 4>()?,
        8 => run_tree::<N, 8>()?,
        16 => run_tree::<N, 16>()?,
        32 => run_tree::<N, 32>()?,
        64 => run_tree::<N, 64>()?,
        128 => run_tree::<N, 128>()?,
        256 => run_tree::<N, 256>()?,
        512 => run_tree::<N, 512>()?,
        1024 => run_tree::<N, 1024>()?,
        other => panic!("unsupported proof count: {}", other),
    }

    Ok(())
}

fn run_tree<const N: usize, const T: usize>() -> Result<()> {
    // Read the proof
    let proof_with_pi = import_proof_with_pi::<F,C,D>()?;
    println!("Proof with public input imported from: {}", PROOF_JSON);

    // read the circuit data
    let verifier_data = import_verifier_circuit_data::<F,C,D>()?;
    println!("Verifier circuit data imported from: {}", VERIFIER_CIRC_DATA_JSON);

    // duplicate the proof to get k proofs
    // this is just for testing - in real scenario we would need to load k proofs
    let proofs: Vec<ProofWithPublicInputs<F, C, D>> = (0..T).map(|_i| proof_with_pi.clone()).collect();

    let mut tree = TreeRecursion::<F,D,C,HF, N, T>::build_with_standard_config(verifier_data.clone()).unwrap();

    let tree_proof = tree.prove_tree_and_compress(&proofs).unwrap();
    //export the proof to json file
    export_tree_proof_with_pi(&tree_proof)?;
    println!("Tree proof written to: {}", TREE_PROOF_JSON);

    let inner_pi: Vec<Vec<F>> = proofs.iter().map(|p| p.public_inputs.clone()).collect();

    assert!(tree.verify_proof_and_public_input(tree_proof,inner_pi.clone(),false).is_ok());

    Ok(())
}