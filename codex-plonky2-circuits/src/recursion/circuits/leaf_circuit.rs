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
use crate::circuits::utils::vec_to_array;

/// recursion leaf circuit for the recursion tree circuit
#[derive(Clone, Debug)]
pub struct LeafCircuit<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    I: InnerCircuit<F, D>,
    const M: usize,
> {
    pub inner_circ: I,
    phantom_data: PhantomData<F>
}

impl<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    I: InnerCircuit<F, D>,
    const M: usize,
> LeafCircuit<F,D,I, M> {
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
    const M: usize
>{
    pub inner_proof: [ProofWithPublicInputsTarget<D>; M],
    pub verifier_data: VerifierCircuitTarget,
}
#[derive(Clone, Debug)]
pub struct LeafInput<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    C: GenericConfig<D, F = F>,
    const M: usize,
>{
    pub inner_proof: [ProofWithPublicInputs<F, C, D>; M],
    pub verifier_data: VerifierCircuitData<F, C, D>
}

impl<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    I: InnerCircuit<F, D>,
    const M: usize,
> LeafCircuit<F,D,I, M>{

    /// build the leaf circuit
    pub fn build<
        C: GenericConfig<D, F = F>,
        H: AlgebraicHasher<F>,
    >(&self, builder: &mut CircuitBuilder<F, D>) -> Result<LeafTargets<D,M>>
        where
            <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>
    {

        let common = self.inner_circ.get_common_data()?;

        // the proof virtual targets - only one for now
        let mut vir_proofs = vec![];
        let mut pub_input = vec![];
        for _i in 0..M {
            let vir_proof = builder.add_virtual_proof_with_pis(&common);
            let inner_pub_input = vir_proof.public_inputs.clone();
            vir_proofs.push(vir_proof);
            pub_input.extend_from_slice(&inner_pub_input);
        }

        // hash the public input & make it public
        let hash_inner_pub_input = builder.hash_n_to_hash_no_pad::<H>(pub_input);
        builder.register_public_inputs(&hash_inner_pub_input.elements);

        // virtual target for the verifier data
        let inner_verifier_data = builder.add_virtual_verifier_data(common.config.fri_config.cap_height);

        // verify the proofs in-circuit (only one now)
        for i in 0..M {
            builder.verify_proof::<C>(&vir_proofs[i], &inner_verifier_data, &common);
        }

        let proofs = vec_to_array::<M, ProofWithPublicInputsTarget<D>>(vir_proofs)?;

        // return targets
        let t = LeafTargets {
            inner_proof: proofs,
            verifier_data: inner_verifier_data,
        };
        Ok(t)

    }

    /// assign the leaf targets with given input
    pub fn assign_targets<
        C: GenericConfig<D, F = F>,
        H: AlgebraicHasher<F>,
    >(&self, pw: &mut PartialWitness<F>, targets: &LeafTargets<D,M>, input: &LeafInput<F, D, C, M>) -> Result<()>
        where
            <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>
    {
        // assign the proofs
        for i in 0..M {
            pw.set_proof_with_pis_target(&targets.inner_proof[i], &input.inner_proof[i])
                .map_err(|e| {
                    CircuitError::ProofTargetAssignmentError("inner-proof".to_string(), e.to_string())
                })?;
        }

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
        let mut builder = CircuitBuilder::<F, D>::new(config.clone());

        self.build::<C,H>(&mut builder)?;

        let circ_data = builder.build::<C>();

        Ok(circ_data)
    }

}


