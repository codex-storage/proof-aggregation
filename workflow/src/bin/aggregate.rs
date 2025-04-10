use std::env;
use anyhow::Result;
use plonky2::plonk::proof::ProofWithPublicInputs;
use codex_plonky2_circuits::recursion::uniform::tree::TreeRecursion;
use proof_input::params::{D, C, F, HF};
use proof_input::serialization::file_paths::{PROOF_JSON, TREE_PROOF_JSON, VERIFIER_CIRC_DATA_JSON};
use proof_input::serialization::json::{export_tree_proof_with_pi, import_proof_with_pi, import_verifier_circuit_data};

fn main() -> Result<()> {
    // load the parameters from environment variables
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

    // Read the proof
    let proof_with_pi = import_proof_with_pi::<F,C,D>()?;
    println!("Proof with public input imported from: {}", PROOF_JSON);

    // read the circuit data
    let verifier_data = import_verifier_circuit_data::<F,C,D>()?;
    println!("Verifier circuit data imported from: {}", VERIFIER_CIRC_DATA_JSON);

    // duplicate the proof to get k proofs
    // this is just for testing - in real scenario we would need to load k proofs
    let proofs: Vec<ProofWithPublicInputs<F, C, D>> = (0..k).map(|_i| proof_with_pi.clone()).collect();

    let mut tree = TreeRecursion::<F,D,C,HF, N, M>::build_with_standard_config(verifier_data.common.clone(), verifier_data.verifier_only.clone()).unwrap();

    let tree_proof = tree.prove_tree(&proofs).unwrap();
    //export the proof to json file
    export_tree_proof_with_pi(&tree_proof)?;
    println!("Tree proof written to: {}", TREE_PROOF_JSON);

    let inner_pi: Vec<Vec<F>> = proofs.iter().map(|p| p.public_inputs.clone()).collect();

    assert!(tree.verify_proof_and_public_input(tree_proof,inner_pi.clone(),false).is_ok());

    Ok(())
}
