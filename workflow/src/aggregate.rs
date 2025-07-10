use std::env;
use std::time::Instant;
use anyhow::{Context, Result};
use plonky2::plonk::proof::ProofWithPublicInputs;
use codex_plonky2_circuits::recursion::tree::TreeRecursion;
use crate::params::{D, C, F, H};
use codex_plonky2_circuits::serialization::{export_proof_with_pi, export_verifier_circuit_data, import_proof_with_pi, import_verifier_circuit_data};
use crate::file_paths::{SAMPLING_CIRC_BASE_PATH, TREE_CIRC_BASE_PATH, COMPRESS_CIRC_BASE_PATH};
pub fn run(compress: bool) -> Result<()> {
    // load the parameters from environment variables
    const N: usize = 2;

    // take k = "number of proofs" from env
    let t: usize = env::var("T")
        .context("T not set")?
        .parse::<usize>()
        .context("Invalid T")?;

    match t {
        2 => run_tree::<N,2>(compress)?,
        4 => run_tree::<N, 4>(compress)?,
        8 => run_tree::<N, 8>(compress)?,
        16 => run_tree::<N, 16>(compress)?,
        32 => run_tree::<N, 32>(compress)?,
        64 => run_tree::<N, 64>(compress)?,
        128 => run_tree::<N, 128>(compress)?,
        256 => run_tree::<N, 256>(compress)?,
        512 => run_tree::<N, 512>(compress)?,
        1024 => run_tree::<N, 1024>(compress)?,
        other => panic!("unsupported proof count: {}", other),
    }

    Ok(())
}

fn run_tree<const N: usize, const T: usize>(compress: bool) -> Result<()> {
    let circuit_path = SAMPLING_CIRC_BASE_PATH;
    // Read the proof
    let proof_with_pi = import_proof_with_pi::<F,C,D,_>(circuit_path)?;
    println!("Proof with public input imported from: {}", circuit_path);

    // read the circuit data
    let verifier_data = import_verifier_circuit_data::<F,C,D,_>(circuit_path)?;
    println!("Verifier circuit data imported from: {}", circuit_path);

    // duplicate the proof to get k proofs
    // this is just for testing - in real scenario we would need to load k proofs
    let proofs: Vec<ProofWithPublicInputs<F, C, D>> = (0..T).map(|_i| proof_with_pi.clone()).collect();

    let start_time = Instant::now();
    let mut tree = TreeRecursion::<F,D,C,H, N, T>::build_with_standard_config(verifier_data.clone()).unwrap();
    println!("build tree time: {:?}", start_time.elapsed());

    let start_time = Instant::now();
    let tree_proof = if !compress {
        tree.prove_tree(&proofs)?
    } else { tree.prove_tree_and_compress(&proofs)? };
    println!("aggregate time: {:?}", start_time.elapsed());

    //export the proof to json file
    let dis_path = if !compress {TREE_CIRC_BASE_PATH} else { COMPRESS_CIRC_BASE_PATH };
    export_proof_with_pi(&tree_proof, dis_path)?;
    println!("Tree proof written to: {}", dis_path);

    let node_ver_data = tree.get_node_verifier_data();
    export_verifier_circuit_data(node_ver_data, TREE_CIRC_BASE_PATH)?;

    let compression_ver_data = tree.get_compression_verifier_data();
    export_verifier_circuit_data(compression_ver_data, COMPRESS_CIRC_BASE_PATH)?;

    let inner_pi: Vec<Vec<F>> = proofs.iter().map(|p| p.public_inputs.clone()).collect();

    assert!(tree.verify_proof_and_public_input(tree_proof,inner_pi.clone(),compress).is_ok());

    Ok(())
}