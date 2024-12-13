// this is still simple recursion approach but written differently,
// still needs to be improved/removed.

use plonky2::hash::hash_types::{HashOut, HashOutTarget, RichField};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{VerifierCircuitData, VerifierCircuitTarget};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2::plonk::proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget};
use plonky2_field::extension::Extendable;
use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2;
use crate::recursion::params::RecursionTreeParams;

pub struct SimpleRecursionCircuit<
    F: RichField + Extendable<D> + Poseidon2,
    C: GenericConfig<D, F = F>,
    const D: usize,
>{
    pub recursion_tree_params: RecursionTreeParams,
    pub verifier_data: VerifierCircuitData<F, C, D>
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
    C: GenericConfig<D, F = F>,
    const D: usize,
>{
    pub proofs: Vec<ProofWithPublicInputs<F, C, D>>,
    pub verifier_data: VerifierCircuitData<F, C, D>,
    pub entropy: HashOut<F>,
}

impl<
    F: RichField + Extendable<D> + Poseidon2,
    C: GenericConfig<D, F = F>,
    const D: usize,
> SimpleRecursionCircuit<F,C,D> where
    C::Hasher: AlgebraicHasher<F>,
{

    pub fn new(
        recursion_tree_params: RecursionTreeParams,
        verifier_data: VerifierCircuitData<F, C, D>
    )->Self{
        Self{
            recursion_tree_params,
            verifier_data,
        }
    }

    /// contains the circuit logic and returns the witness & public input targets
    pub fn build_circuit(
        &self,
        builder: &mut CircuitBuilder::<F, D>,
    ) -> SimpleRecursionTargets<D> {
        // the proof virtual targets
        let mut proof_targets = vec![];
        let mut inner_entropy_targets = vec![];

        for i in 0..self.recursion_tree_params.tree_width {
            let vir_proof = builder.add_virtual_proof_with_pis(&self.verifier_data.common);
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
        let inner_verifier_data = builder.add_virtual_verifier_data(self.verifier_data.common.config.fri_config.cap_height);

        // verify the proofs in-circuit
        for i in 0..self.recursion_tree_params.tree_width {
            builder.verify_proof::<C>(&proof_targets[i],&inner_verifier_data,&self.verifier_data.common);
        }

        // register entropy as public input
        let outer_entropy_target = builder.add_virtual_hash_public_input();

        // connect the public input of the recursion circuit to the inner proofs
        for i in 0..self.recursion_tree_params.tree_width {
            for j in 0..4 {
                builder.connect(inner_entropy_targets[i][j], outer_entropy_target.elements[j]);
            }
        }
        // return targets
        SimpleRecursionTargets {
            proofs_with_pi: proof_targets,
            verifier_data: inner_verifier_data,
            entropy: outer_entropy_target,
        }

    }

    /// assign the targets
    pub fn assign_witness(
        &self,
        pw: &mut PartialWitness<F>,
        targets: &SimpleRecursionTargets<D>,
        witnesses: SimpleRecursionInput<F, C, D>,
    ) -> anyhow::Result<()>{
        // assign the proofs with public input
        for i in 0..self.recursion_tree_params.tree_width{
            pw.set_proof_with_pis_target(&targets.proofs_with_pi[i],&witnesses.proofs[i])?;
        }

        // assign the verifier data
        pw.set_cap_target(
            &targets.verifier_data.constants_sigmas_cap,
            &witnesses.verifier_data.verifier_only.constants_sigmas_cap,
        )?;
        pw.set_hash_target(targets.verifier_data.circuit_digest, witnesses.verifier_data.verifier_only.circuit_digest)?;

        // set the entropy hash target
        pw.set_hash_target(targets.entropy, witnesses.entropy)?;

        Ok(())

    }
}