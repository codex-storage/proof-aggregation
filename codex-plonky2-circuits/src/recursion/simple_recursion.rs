use plonky2::hash::hash_types::{HashOut, HashOutTarget, RichField};
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, VerifierCircuitData, VerifierCircuitTarget};
use plonky2::plonk::config::GenericConfig;
use plonky2::plonk::proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget};
use plonky2_field::extension::Extendable;
use plonky2_field::goldilocks_field::GoldilocksField;
use plonky2_poseidon2::config::Poseidon2GoldilocksConfig;
use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2;
use plonky2_poseidon2::serialization::{DefaultGateSerializer, DefaultGeneratorSerializer};
use crate::circuits::utils::read_bytes_from_file;
use crate::recursion::params::{F,C,D,Plonky2Proof};

/// aggregate sampling proofs
pub fn aggregate_sampling_proofs<
>(
    proofs_with_pi: &Vec<Plonky2Proof>,
    verifier_data: &VerifierCircuitData<F, C, D>,
    builder: &mut CircuitBuilder::<F, D>,
    pw: &mut PartialWitness<F>,
)-> anyhow::Result<()>{
    // the proof virtual targets
    let mut proof_targets = vec![];
    let mut inner_entropy_targets = vec![];
    let num_pub_input = proofs_with_pi[0].public_inputs.len(); // assuming num of public input is the same for all proofs
    for i in 0..proofs_with_pi.len() {
        let vir_proof = builder.add_virtual_proof_with_pis(&verifier_data.common);
        // register the inner public input as public input
        // only register the slot index and dataset root, entropy later
        // assuming public input are ordered:
        // [slot_root (1 element), dataset_root (4 element), entropy (4 element)]
        for j in 0..(num_pub_input-4){
            builder.register_public_input(vir_proof.public_inputs[j]);
        }
        // collect entropy targets
        let mut entropy_i = vec![];
        for k in (num_pub_input-4)..num_pub_input{
            entropy_i.push(vir_proof.public_inputs[k])
        }
        inner_entropy_targets.push(entropy_i);
        proof_targets.push(vir_proof);
    }
    // assign the proofs with public input
    for i in 0..proofs_with_pi.len(){
        pw.set_proof_with_pis_target(&proof_targets[i],&proofs_with_pi[i])?;
    }
    // virtual target for the verifier data
     let inner_verifier_data = builder.add_virtual_verifier_data(verifier_data.common.config.fri_config.cap_height);

    // assign the verifier data
    pw.set_cap_target(
        &inner_verifier_data.constants_sigmas_cap,
        &verifier_data.verifier_only.constants_sigmas_cap,
    )?;
    pw.set_hash_target(inner_verifier_data.circuit_digest, verifier_data.verifier_only.circuit_digest)?;

    // verify the proofs in-circuit
    for i in 0..proofs_with_pi.len() {
        builder.verify_proof::<C>(&proof_targets[i],&inner_verifier_data,&verifier_data.common);
    }

    // register entropy as public input
    let outer_entropy_target = builder.add_virtual_hash_public_input();
    let entropy_as_hash = HashOut::from_vec(
        [
            proofs_with_pi[0].public_inputs[num_pub_input-4],
            proofs_with_pi[0].public_inputs[num_pub_input-3],
            proofs_with_pi[0].public_inputs[num_pub_input-2],
            proofs_with_pi[0].public_inputs[num_pub_input-1]
        ].to_vec()
    ); // entropy is last 4 elements
    pw.set_hash_target(outer_entropy_target, entropy_as_hash)?;
    // connect the public input of the recursion circuit to the inner proofs
    for i in 0..proofs_with_pi.len() {
        for j in 0..4 {
            builder.connect(inner_entropy_targets[i][j], outer_entropy_target.elements[j]);
        }
    }

    Ok(())
}

// recursion tree width or the number of proofs in each node in the tree
const RECURSION_TREE_WIDTH: usize = 2;

/// aggregate sampling proofs in tree like structure
/// uses the const params: `RECURSION_TREE_WIDTH`
pub fn aggregate_sampling_proofs_tree(
    proofs_with_pi: &[ProofWithPublicInputs<F, C, D>],
    data: CircuitData<F, C, D>,
) -> anyhow::Result<(ProofWithPublicInputs<F, C, D>, CircuitData<F, C, D>)> {
    // base case: if only one proof remains, return it
    if proofs_with_pi.len() == 1 {
        return Ok((proofs_with_pi[0].clone(), data));
    }

    let mut new_proofs = vec![];
    let mut new_circuit_data: Option<CircuitData<F, C, D>> = None;

    // group proofs according to the tree's width
    for chunk in proofs_with_pi.chunks(RECURSION_TREE_WIDTH) {
        let proofs_chunk = chunk.to_vec();

        // Build an inner-circuit to verify and aggregate the proofs in the chunk
        let inner_config = CircuitConfig::standard_recursion_config();
        let mut inner_builder = CircuitBuilder::<F, D>::new(inner_config);
        let mut inner_pw = PartialWitness::new();

        // aggregate proofs
        aggregate_sampling_proofs(
            &proofs_chunk,
            &data.verifier_data(),
            &mut inner_builder,
            &mut inner_pw,
        )?;

        // Build the inner-circuit
        // this causes major delay - we can load it but better if we split build and prove
        let inner_data = inner_builder.build::<C>();

        // Prove the inner-circuit
        let proof = inner_data.prove(inner_pw)?;
        new_proofs.push(proof);
        new_circuit_data = Some(inner_data);
    }

    // Recursively aggregate the new proofs
    aggregate_sampling_proofs_tree(&new_proofs, new_circuit_data.unwrap())
}

/// same as above but takes `VerifierCircuitData`
pub fn aggregate_sampling_proofs_tree2(
    proofs_with_pi: &[ProofWithPublicInputs<F, C, D>],
    vd: VerifierCircuitData<F, C, D>
) -> anyhow::Result<(ProofWithPublicInputs<F, C, D>, VerifierCircuitData<F, C, D>)> {
    if proofs_with_pi.len() == 1 {
        return Ok((proofs_with_pi[0].clone(), vd));
    }

    let mut new_proofs = vec![];
    let mut new_circuit_data: Option<VerifierCircuitData<F, C, D>> = None;

    for chunk in proofs_with_pi.chunks(RECURSION_TREE_WIDTH) {
        let proofs_chunk = chunk.to_vec();

        let inner_config = CircuitConfig::standard_recursion_config();
        let mut inner_builder = CircuitBuilder::<F, D>::new(inner_config);
        let mut inner_pw = PartialWitness::new();

        aggregate_sampling_proofs(
            &proofs_chunk,
            &vd,
            &mut inner_builder,
            &mut inner_pw,
        )?;

        let inner_data = inner_builder.build::<C>();

        let proof = inner_data.prove(inner_pw)?;
        new_proofs.push(proof);
        new_circuit_data = Some(inner_data.verifier_data());
    }

    aggregate_sampling_proofs_tree2(&new_proofs, new_circuit_data.unwrap())
}