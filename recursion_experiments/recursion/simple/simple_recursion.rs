// the simple aggregation approach is verifying N proofs in-circuit and generating one final proof

use std::marker::PhantomData;
use plonky2::hash::hash_types::{HashOut, HashOutTarget, RichField};
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

// ---------------------- Simple recursion Approach 1 ---------------------------
// The simple approach here separates the build (setting the targets) and assigning the witness.
// the public input of the inner-proofs is the public input of the final proof except that
// the entropy is expected to be the same therefore only one entropy public input is in the final proof

pub struct SimpleRecursionCircuit<
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
pub struct SimpleRecursionTargets<
    const D: usize,
> {
    pub proofs_with_pi: Vec<ProofWithPublicInputsTarget<D>>,
    pub verifier_data: VerifierCircuitTarget,
    pub entropy: HashOutTarget,
}

pub struct SimpleRecursionInput<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    C: GenericConfig<D, F = F>,
>{
    pub proofs: Vec<ProofWithPublicInputs<F, C, D>>,
    pub verifier_data: VerifierCircuitData<F, C, D>,
    pub entropy: HashOut<F>,
}

impl<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    I: InnerCircuit<F, D>,
    const N: usize,
    C: GenericConfig<D, F = F>,
> SimpleRecursionCircuit<F, D, I, N, C> where
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
    >(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Result<SimpleRecursionTargets<D>>{
        // the proof virtual targets
        let mut proof_targets = vec![];
        let mut inner_entropy_targets = vec![];
        let inner_common =  self.inner_circuit.get_common_data()?;

        for _ in 0..N {
            let vir_proof = builder.add_virtual_proof_with_pis(&inner_common);
            // register the inner public input as public input
            // only register the slot index and dataset root, entropy later
            // assuming public input are ordered:
            // [slot_root (1 element), dataset_root (4 element), entropy (4 element)]
            let num_pub_input = vir_proof.public_inputs.len();
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
        // virtual target for the verifier data
        let inner_verifier_data = builder.add_virtual_verifier_data(inner_common.config.fri_config.cap_height);

        // verify the proofs in-circuit
        for i in 0..N {
            builder.verify_proof::<C>(&proof_targets[i],&inner_verifier_data,&inner_common);
        }

        // register entropy as public input
        let outer_entropy_target = builder.add_virtual_hash_public_input();

        // connect the public input of the recursion circuit to the inner proofs
        for i in 0..N {
            for j in 0..4 {
                builder.connect(inner_entropy_targets[i][j], outer_entropy_target.elements[j]);
            }
        }
        // return targets
        let srt = SimpleRecursionTargets {
            proofs_with_pi: proof_targets,
            verifier_data: inner_verifier_data,
            entropy: outer_entropy_target,
        };
        Ok(srt)
    }

    /// assign the targets
    pub fn assign_witness<
    >(
        &self,
        pw: &mut PartialWitness<F>,
        targets: &SimpleRecursionTargets<D>,
        witnesses: SimpleRecursionInput<F, D, C>,
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

        // set the entropy hash target
        pw.set_hash_target(targets.entropy, witnesses.entropy)
            .map_err(|e| {
                CircuitError::HashTargetAssignmentError("entropy".to_string(), e.to_string())
            })?;

        Ok(())

    }
}