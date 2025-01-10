use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitData, VerifierCircuitTarget};
use plonky2::plonk::proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget};
use crate::circuits::params::CircuitParams;
use crate::circuits::sample_cells::SampleCircuit;
use crate::params::{C, D, F, H};
use crate::recursion::circuits::inner_circuit::InnerCircuit;
use crate::recursion::circuits::sampling_inner_circuit::SamplingRecursion;

/// recursion Inner circuit for the sampling circuit
#[derive(Clone, Debug)]
pub struct LeafCircuit<
    I: InnerCircuit
> {
    pub inner_circ: I
}

impl<I: InnerCircuit> LeafCircuit<I> {
    pub fn new(inner_circ: I) -> Self {
        Self{
            // sampling_circ: SampleCircuit::new(CircuitParams::default()),
            inner_circ,
        }
    }
}
#[derive(Clone, Debug)]
pub struct LeafTargets {
    pub inner_proof: ProofWithPublicInputsTarget<D>,
    pub verifier_data: VerifierCircuitTarget,
}
#[derive(Clone, Debug)]
pub struct LeafInput{
    pub inner_proof: ProofWithPublicInputs<F, C, D>,
    pub verifier_data: VerifierCircuitData<F, C, D>
}

impl<I: InnerCircuit> LeafCircuit<I>{

    /// build the leaf circuit
    pub fn build(&self, builder: &mut CircuitBuilder<F, D>) -> anyhow::Result<LeafTargets> {

        let common = self.inner_circ.get_common_data()?;

        // the proof virtual targets - only one for now
        // TODO: make it M proofs
        let vir_proof = builder.add_virtual_proof_with_pis(&common);

        // hash the public input & make it public
        let inner_pub_input = vir_proof.public_inputs.clone();
        let hash_inner_pub_input = builder.hash_n_to_hash_no_pad::<H>(inner_pub_input);
        builder.register_public_inputs(&hash_inner_pub_input.elements);

        // virtual target for the verifier data
        let inner_verifier_data = builder.add_virtual_verifier_data(common.config.fri_config.cap_height);

        // verify the proofs in-circuit (only one now)
        builder.verify_proof::<C>(&vir_proof.clone(),&inner_verifier_data,&common);

        // return targets
        let t = LeafTargets {
            inner_proof: vir_proof,
            verifier_data: inner_verifier_data,
        };
        Ok(t)

    }

    /// assign the leaf targets with given input
    pub fn assign_targets(&self, pw: &mut PartialWitness<F>, targets: &LeafTargets, input: &LeafInput) -> anyhow::Result<()> {
        // assign the proof
        pw.set_proof_with_pis_target(&targets.inner_proof, &input.inner_proof)?;

        // assign the verifier data
        pw.set_cap_target(
            &targets.verifier_data.constants_sigmas_cap,
            &input.verifier_data.verifier_only.constants_sigmas_cap,
        )?;
        pw.set_hash_target(targets.verifier_data.circuit_digest, input.verifier_data.verifier_only.circuit_digest)?;

        Ok(())
    }

}

/// returns the leaf circuit data
/// NOTE: this is for the default leaf only
/// TODO: adjust for varying leaf types
pub fn circuit_data_for_leaf() -> anyhow::Result<CircuitData<F, C, D>>{
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    let inner_circ = SamplingRecursion::default();
    let leaf = LeafCircuit::new(inner_circ);
    leaf.build(&mut builder)?;

    let circ_data = builder.build::<C>();

    Ok(circ_data)
}
