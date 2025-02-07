use std::marker::PhantomData;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CommonCircuitData, VerifierCircuitData, VerifierCircuitTarget};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2::plonk::proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget};
use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2;
use plonky2_field::extension::Extendable;
use crate::circuits::utils::{vec_to_array};
use crate::{error::CircuitError, Result};

/// Node circuit struct
/// contains necessary data
/// N: number of proofs verified in-circuit (so num of child nodes)
pub struct NodeCircuit<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    C: GenericConfig<D, F = F>,
    const N: usize,
>{
    phantom_data: PhantomData<(F,C)>
}

/// Node circuit targets
/// assumes that all proofs use the same verifier data
#[derive(Clone, Debug)]
pub struct NodeCircuitTargets<
    const D: usize,
    const N: usize,
>{
    pub proof_targets: [ProofWithPublicInputsTarget<D>; N],
    pub verifier_data_target: VerifierCircuitTarget,
}

impl<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    C: GenericConfig<D, F = F> + 'static,
    const N: usize,
> NodeCircuit<F, D, C, N>
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>
{

    /// builds the node circuit
    pub fn build_circuit<
        H: AlgebraicHasher<F>,
    >(
        builder: &mut CircuitBuilder<F, D>,
        common_data: &CommonCircuitData<F, D>,
    ) -> Result<(NodeCircuitTargets<D, N>)>{

        // the proof virtual targets
        let mut proof_targets = vec![];
        let mut inner_pub_input = vec![];
        for _i in 0..N {
            let vir_proof = builder.add_virtual_proof_with_pis(common_data);
            // collect the public input
            inner_pub_input.extend_from_slice(&vir_proof.public_inputs);
            // collect the proof targets
            proof_targets.push(vir_proof);
        }
        // hash the public input & make it public
        let hash_inner_pub_input = builder.hash_n_to_hash_no_pad::<H>(inner_pub_input);
        builder.register_public_inputs(&hash_inner_pub_input.elements);

        // virtual target for the verifier data
        let inner_verifier_data = builder.add_virtual_verifier_data(common_data.config.fri_config.cap_height);

        // verify the proofs in-circuit
        for i in 0..N {
            builder.verify_proof::<C>(&proof_targets[i],&inner_verifier_data,&common_data);
        }
        let proof_target_array = vec_to_array::<N,ProofWithPublicInputsTarget<D>>(proof_targets)?;

        Ok(NodeCircuitTargets{
            proof_targets: proof_target_array,
            verifier_data_target: inner_verifier_data,
        })
    }

    /// assigns the targets for the Node circuit
    pub fn assign_targets(
        node_targets: NodeCircuitTargets<D, N>,
        proofs_with_pi: &[ProofWithPublicInputs<F, C, D>; N],
        verifier_data: &VerifierCircuitData<F, C, D>,
        pw: &mut PartialWitness<F>,
    ) -> Result<()>{
        for i in 0..N{
            pw.set_proof_with_pis_target(&node_targets.proof_targets[i],&proofs_with_pi[i])
                .map_err(|e| {
                    CircuitError::ProofTargetAssignmentError(format!("proof {}", i), e.to_string())
                })?;
        }
        // assign the verifier data
        pw.set_verifier_data_target(&node_targets.verifier_data_target, &verifier_data.verifier_only)
            .map_err(|e| {
                CircuitError::VerifierDataTargetAssignmentError(e.to_string())
            })?;

        Ok(())
    }
}