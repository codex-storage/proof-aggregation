// this file is mainly draft implementation and experimentation of multiple simple approaches
// the simple aggregation approach is verifying N proofs in-circuit and generating one final proof

use plonky2::hash::hash_types::{HashOut, HashOutTarget};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{VerifierCircuitData, VerifierCircuitTarget};
use plonky2::plonk::config::GenericConfig;
use plonky2::plonk::proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget};
use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2;
use crate::recursion::circuits::inner_circuit::InnerCircuit;
use crate::params::{C, D, F, Plonky2Proof};
use crate::Result;

/// aggregate sampling proofs
/// This function takes:
/// - N number of proofs (it has to be sampling proofs here)
/// - verifier_data of the sampling circuit
/// - circuit builder
/// - partial witness
///
/// The function doesn't return anything but sets the targets in the builder and assigns the witness
pub fn aggregate_sampling_proofs<
>(
    proofs_with_pi: &Vec<Plonky2Proof>,
    verifier_data: &VerifierCircuitData<F, C, D>,
    builder: &mut CircuitBuilder::<F, D>,
    pw: &mut PartialWitness<F>,
)-> Result<()>{
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

// ---------------------- Simple Approach 2 ---------------------------
// this is still simple recursion approach but written differently,
// The simple approach here separates the build (setting the targets) and assigning the witness.

pub struct SimpleRecursionCircuit<
    I: InnerCircuit,
    const N: usize,
>{
    pub inner_circuit: I,
}

#[derive(Clone)]
pub struct SimpleRecursionTargets<
> {
    pub proofs_with_pi: Vec<ProofWithPublicInputsTarget<D>>,
    pub verifier_data: VerifierCircuitTarget,
    pub entropy: HashOutTarget,
}

pub struct SimpleRecursionInput<
>{
    pub proofs: Vec<ProofWithPublicInputs<F, C, D>>,
    pub verifier_data: VerifierCircuitData<F, C, D>,
    pub entropy: HashOut<F>,
}

impl<
    I: InnerCircuit,
    const N: usize,
> SimpleRecursionCircuit<I, N>
{

    pub fn new(
        inner_circuit: I,
    )->Self{
        Self{
            inner_circuit,
        }
    }

    /// contains the circuit logic and returns the witness & public input targets
    pub fn build_circuit(
        &self,
        builder: &mut CircuitBuilder::<F, D>,
    ) -> anyhow::Result<SimpleRecursionTargets> {
        // the proof virtual targets
        let mut proof_targets = vec![];
        let mut inner_entropy_targets = vec![];
        let inner_common =  self.inner_circuit.get_common_data()?;

        for i in 0..N {
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
    pub fn assign_witness(
        &self,
        pw: &mut PartialWitness<F>,
        targets: &SimpleRecursionTargets,
        witnesses: SimpleRecursionInput,
    ) -> anyhow::Result<()>{
        // assign the proofs with public input
        for i in 0..N{
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