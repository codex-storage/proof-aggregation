use std::marker::PhantomData;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitTarget, VerifierOnlyCircuitData};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2::plonk::proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget};
use plonky2_field::extension::Extendable;
use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2;
use crate::recursion::circuits::inner_circuit::InnerCircuit;
use crate::{error::CircuitError,Result};

/// recursion leaf circuit - verifies one inner proof
#[derive(Clone, Debug)]
pub struct LeafCircuit<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    C: GenericConfig<D, F = F>,
    H: AlgebraicHasher<F>,
> where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>
{
    inner_common_data: CommonCircuitData<F, D>,
    phantom_data: PhantomData<(C,H)>
}

impl<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    C: GenericConfig<D, F = F>,
    H: AlgebraicHasher<F>,
> LeafCircuit<F,D,C,H> where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>
{
    pub fn new(inner_common_data: CommonCircuitData<F,D>) -> Self {
        Self{
            inner_common_data,
            phantom_data:PhantomData::default(),
        }
    }
}
#[derive(Clone, Debug)]
pub struct LeafTargets <
    const D: usize,
>{
    pub inner_proof: ProofWithPublicInputsTarget<D>,
    pub verifier_data: VerifierCircuitTarget,
}

impl<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    C: GenericConfig<D, F = F>,
    H: AlgebraicHasher<F>,
> LeafCircuit<F,D,C,H> where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>
{

    /// build the leaf circuit
    pub fn build(&self, builder: &mut CircuitBuilder<F, D>) -> Result<LeafTargets<D>> {

        let inner_common = self.inner_common_data.clone();

        // the proof virtual targets - only one
        let mut pub_input = vec![];
        let vir_proof = builder.add_virtual_proof_with_pis(&inner_common);
        let inner_pub_input = vir_proof.public_inputs.clone();
        pub_input.extend_from_slice(&inner_pub_input);

        // hash the public input & make it public
        let hash_inner_pub_input = builder.hash_n_to_hash_no_pad::<H>(pub_input);
        builder.register_public_inputs(&hash_inner_pub_input.elements);

        // virtual target for the verifier data
        let inner_verifier_data = builder.add_virtual_verifier_data(inner_common.config.fri_config.cap_height);

        // register verifier data hash as public input.
        let mut vd_pub_input = vec![];
        vd_pub_input.extend_from_slice(&inner_verifier_data.circuit_digest.elements);
        for i in 0..builder.config.fri_config.num_cap_elements() {
            vd_pub_input.extend_from_slice(&inner_verifier_data.constants_sigmas_cap.0[i].elements);
        }
        let hash_inner_vd_pub_input = builder.hash_n_to_hash_no_pad::<H>(vd_pub_input);
        builder.register_public_inputs(&hash_inner_vd_pub_input.elements);

        // verify the proofs in-circuit (only one )
        builder.verify_proof::<C>(&vir_proof, &inner_verifier_data, &inner_common);

        // return targets
        let t = LeafTargets {
            inner_proof: vir_proof,
            verifier_data: inner_verifier_data,
        };
        Ok(t)

    }

    /// assign the leaf targets with given input
    pub fn assign_targets(
        &self, pw: &mut PartialWitness<F>,
        targets: &LeafTargets<D>,
        inner_proof: &ProofWithPublicInputs<F, C, D>,
        verifier_only_data: &VerifierOnlyCircuitData<C, D>,
    ) -> Result<()> {
        // assign the proofs
        pw.set_proof_with_pis_target(&targets.inner_proof, inner_proof)
            .map_err(|e| {
                CircuitError::ProofTargetAssignmentError("inner-proof".to_string(), e.to_string())
            })?;

        // assign the verifier data
        pw.set_verifier_data_target(&targets.verifier_data, verifier_only_data)
            .map_err(|e| {
                CircuitError::VerifierDataTargetAssignmentError(e.to_string())
            })?;

        Ok(())
    }

    /// returns the leaf circuit data
    pub fn get_circuit_data (&self) -> Result<CircuitData<F, C, D>>
        where
            <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>
    {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config.clone());

        self.build(&mut builder)?;

        let circ_data = builder.build::<C>();

        Ok(circ_data)
    }

}


