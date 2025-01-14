// the simple aggregation approach is verifying N proofs in-circuit and generating one final proof

use std::marker::PhantomData;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{VerifierCircuitData, VerifierCircuitTarget};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2::plonk::proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget};
use plonky2_field::extension::Extendable;
use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2;
use crate::error::CircuitError;
use crate::recursion::circuits::inner_circuit::InnerCircuit;
use crate::Result;

// ---------------------- Simple recursion Approach 2 ---------------------------
// The simple approach here separates the build (setting the targets) and assigning the witness.
// ** the Hash of public input of the inner-proofs is the public input of the final proof **

pub struct SimpleRecursionCircuitHashedPI<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    I: InnerCircuit<F, D>,
    const N: usize,
    C: GenericConfig<D, F = F>,
> {
    pub inner_circuit: I,
    phantom_data: PhantomData<(F,C)>
}

#[derive(Clone)]
pub struct SimpleRecursionTargetsHashedPI<
    const D: usize,
> {
    pub proofs_with_pi: Vec<ProofWithPublicInputsTarget<D>>,
    pub verifier_data: VerifierCircuitTarget,
}

pub struct SimpleRecursionInputHashedPI<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    C: GenericConfig<D, F = F>,
>{
    pub proofs: Vec<ProofWithPublicInputs<F, C, D>>,
    pub verifier_data: VerifierCircuitData<F, C, D>,
}

impl<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    I: InnerCircuit<F, D>,
    const N: usize,
    C: GenericConfig<D, F = F>,
> SimpleRecursionCircuitHashedPI<F, D, I, N, C> where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{

    pub fn new(
        inner_circuit: I,
    )->Self{
        Self{
            inner_circuit,
            phantom_data: PhantomData::default(),
        }
    }

    /// contains the circuit logic and returns the witness & public input targets
    pub fn build_circuit<
        H: AlgebraicHasher<F>,
    >(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Result<SimpleRecursionTargetsHashedPI<D>>{
        // the proof virtual targets
        let mut proof_targets = vec![];
        let mut inner_pub_input = vec![];
        let inner_common =  self.inner_circuit.get_common_data()?;

        for _i in 0..N {
            let vir_proof = builder.add_virtual_proof_with_pis(&inner_common);
            // collect the public input
            inner_pub_input.extend_from_slice(&vir_proof.public_inputs);
            // collect the proof targets
            proof_targets.push(vir_proof);
        }

        // hash the public input & make it public
        let hash_inner_pub_input = builder.hash_n_to_hash_no_pad::<H>(inner_pub_input);
        builder.register_public_inputs(&hash_inner_pub_input.elements);

        // virtual target for the verifier data
        let inner_verifier_data = builder.add_virtual_verifier_data(inner_common.config.fri_config.cap_height);

        // verify the proofs in-circuit
        for i in 0..N {
            builder.verify_proof::<C>(&proof_targets[i],&inner_verifier_data,&inner_common);
        }

        // return targets
        let srt = SimpleRecursionTargetsHashedPI {
            proofs_with_pi: proof_targets,
            verifier_data: inner_verifier_data,
        };
        Ok(srt)
    }

    /// assign the targets
    pub fn assign_witness<
    >(
        &self,
        pw: &mut PartialWitness<F>,
        targets: &SimpleRecursionTargetsHashedPI<D>,
        witnesses: SimpleRecursionInputHashedPI<F, D, C>,
    ) -> Result<()>{
        // assign the proofs with public input
        for i in 0..N{
            pw.set_proof_with_pis_target(&targets.proofs_with_pi[i],&witnesses.proofs[i])
                .map_err(|e| {
                    CircuitError::ProofTargetAssignmentError(format!("proof {}", i), e.to_string())
                })?;
        }

        // assign the verifier data
        pw.set_verifier_data_target(&targets.verifier_data, &witnesses.verifier_data.verifier_only)
            .map_err(|e| {
                CircuitError::VerifierDataTargetAssignmentError(e.to_string())
            })?;

        Ok(())

    }
}