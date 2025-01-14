use std::marker::PhantomData;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, VerifierCircuitData, VerifierCircuitTarget};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2::plonk::proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget};
use plonky2_field::extension::Extendable;
use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2;
use crate::recursion::circuits::inner_circuit::InnerCircuit;
use crate::{error::CircuitError,Result};

/// recursion leaf circuit for the recursion tree circuit
#[derive(Clone, Debug)]
pub struct LeafCircuit<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    I: InnerCircuit<F, D>
> {
    pub inner_circ: I,
    phantom_data: PhantomData<F>
}

impl<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    I: InnerCircuit<F, D>
> LeafCircuit<F,D,I> {
    pub fn new(inner_circ: I) -> Self {
        Self{
            inner_circ,
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
#[derive(Clone, Debug)]
pub struct LeafInput<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    C: GenericConfig<D, F = F>,
>{
    pub inner_proof: ProofWithPublicInputs<F, C, D>,
    pub verifier_data: VerifierCircuitData<F, C, D>
}

impl<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    I: InnerCircuit<F, D>,
> LeafCircuit<F,D,I>{

    /// build the leaf circuit
    pub fn build<
        C: GenericConfig<D, F = F>,
        H: AlgebraicHasher<F>,
    >(&self, builder: &mut CircuitBuilder<F, D>) -> Result<LeafTargets<D>>
        where
            <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>
    {

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
    pub fn assign_targets<
        C: GenericConfig<D, F = F>,
        H: AlgebraicHasher<F>,
    >(&self, pw: &mut PartialWitness<F>, targets: &LeafTargets<D>, input: &LeafInput<F, D, C>) -> Result<()>
        where
            <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>
    {
        // assign the proof
        pw.set_proof_with_pis_target(&targets.inner_proof,&input.inner_proof)
            .map_err(|e| {
                CircuitError::ProofTargetAssignmentError("inner-proof".to_string(), e.to_string())
            })?;

        // assign the verifier data
        pw.set_verifier_data_target(&targets.verifier_data, &input.verifier_data.verifier_only)
            .map_err(|e| {
                CircuitError::VerifierDataTargetAssignmentError(e.to_string())
            })?;

        Ok(())
    }

    /// returns the leaf circuit data
    /// TODO: make generic recursion config
    pub fn get_circuit_data<
        C: GenericConfig<D, F = F>,
        H: AlgebraicHasher<F>,
    >(&self) -> Result<CircuitData<F, C, D>>
        where
            <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>
    {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        self.build::<C,H>(&mut builder)?;

        let circ_data = builder.build::<C>();

        Ok(circ_data)
    }

}


