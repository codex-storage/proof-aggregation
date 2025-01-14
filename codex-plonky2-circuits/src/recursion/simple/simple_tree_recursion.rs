use plonky2::hash::hash_types::RichField;
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::plonk::circuit_data::{CircuitConfig, VerifierCircuitData};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2_field::extension::Extendable;
use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2;
use crate::error::CircuitError;
use crate::Result;

// recursion tree width or the number of proofs in each node in the tree
const RECURSION_TREE_WIDTH: usize = 2;

/// aggregate sampling proofs
/// This function takes:
/// - N number of proofs (it has to be sampling proofs here)
/// - verifier_data of the sampling circuit
/// - circuit builder
/// - partial witness
///
/// The function doesn't return anything but sets the targets in the builder and assigns the witness
pub fn aggregate_sampling_proofs<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    C: GenericConfig<D, F = F>,
    H: AlgebraicHasher<F>
>(
    proofs_with_pi: &Vec<ProofWithPublicInputs<F, C, D>>,
    verifier_data: &VerifierCircuitData<F, C, D>,
    builder: &mut CircuitBuilder<F, D>,
    pw: &mut PartialWitness<F>,
)-> Result<()>where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>
{
    // the proof virtual targets
    let mut proof_targets = vec![];
    let mut inner_pub_input = vec![];
    for _i in 0..proofs_with_pi.len() {
        let vir_proof = builder.add_virtual_proof_with_pis(&verifier_data.common);
        // collect the public input
        inner_pub_input.extend_from_slice(&vir_proof.public_inputs);
        // collect the proof targets
        proof_targets.push(vir_proof);
    }
    // hash the public input & make it public
    let hash_inner_pub_input = builder.hash_n_to_hash_no_pad::<H>(inner_pub_input);
    builder.register_public_inputs(&hash_inner_pub_input.elements);
    // assign the proofs with public input
    for i in 0..proofs_with_pi.len(){
        pw.set_proof_with_pis_target(&proof_targets[i],&proofs_with_pi[i])
            .map_err(|e| {
                CircuitError::ProofTargetAssignmentError(format!("proof {}", i), e.to_string())
            })?;
    }
    // virtual target for the verifier data
     let inner_verifier_data = builder.add_virtual_verifier_data(verifier_data.common.config.fri_config.cap_height);

    // assign the verifier data
    pw.set_verifier_data_target(&inner_verifier_data, &verifier_data.verifier_only)
        .map_err(|e| {
            CircuitError::VerifierDataTargetAssignmentError(e.to_string())
        })?;

    // verify the proofs in-circuit
    for i in 0..proofs_with_pi.len() {
        builder.verify_proof::<C>(&proof_targets[i],&inner_verifier_data,&verifier_data.common);
    }

    Ok(())
}

/// aggregate sampling proofs in tree like structure
/// uses the const params: `RECURSION_TREE_WIDTH`
/// In this tree approach the building is done at each level -> very slow!
/// takes `VerifierCircuitData`
pub fn aggregate_sampling_proofs_tree
<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    C: GenericConfig<D, F = F>,
    H: AlgebraicHasher<F>
>(
    proofs_with_pi: &[ProofWithPublicInputs<F, C, D>],
    vd: VerifierCircuitData<F, C, D>
) -> Result<(ProofWithPublicInputs<F, C, D>, VerifierCircuitData<F, C, D>)> where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>
{
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

        aggregate_sampling_proofs::<F,D,C,H>(
            &proofs_chunk,
            &vd,
            &mut inner_builder,
            &mut inner_pw,
        )?;

        let inner_data = inner_builder.build::<C>();

        let proof = inner_data.prove(inner_pw)
            .map_err(|e| CircuitError::ProofGenerationError(e.to_string()))?;
        new_proofs.push(proof);
        new_circuit_data = Some(inner_data.verifier_data());
    }

    aggregate_sampling_proofs_tree::<F,D,C,H>(&new_proofs, new_circuit_data.unwrap())
}
