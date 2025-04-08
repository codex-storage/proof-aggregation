use std::marker::PhantomData;
use plonky2::hash::hash_types::{HashOutTarget, RichField};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CommonCircuitData, VerifierOnlyCircuitData};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2::plonk::proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget};
use plonky2_field::extension::Extendable;
use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2;
use crate::{error::CircuitError,Result};
use crate::circuit_helper::Plonky2Circuit;

/// recursion compression circuit
/// verifies 1 inner proof and as result should shrink it
#[derive(Clone, Debug)]
pub struct CompressionCircuit<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    C: GenericConfig<D, F = F>,
    H: AlgebraicHasher<F>,
> where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>
{
    inner_common_data: CommonCircuitData<F, D>,
    inner_verifier_data: VerifierOnlyCircuitData<C, D>,
    phantom_data: PhantomData<H>
}

#[derive(Clone, Debug)]
pub struct CompressionTargets<
    const D: usize,
>{
    pub inner_proof: ProofWithPublicInputsTarget<D>,
}

#[derive(Clone, Debug)]
pub struct CompressionInput<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    C: GenericConfig<D, F = F>,
>{
    pub inner_proof: ProofWithPublicInputs<F, C, D>
}

impl<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    C: GenericConfig<D, F = F>,
    H: AlgebraicHasher<F>,
> CompressionCircuit<F,D,C,H> where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>
{
    pub fn new(
        inner_common_data: CommonCircuitData<F,D>,
        inner_verifier_data: VerifierOnlyCircuitData<C, D>,
    ) -> Self {
        Self{
            inner_common_data,
            inner_verifier_data,
            phantom_data:PhantomData::default(),
        }
    }

}

impl<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    C: GenericConfig<D, F = F>,
    H: AlgebraicHasher<F>,
> Plonky2Circuit<F, C, D> for CompressionCircuit<F, D, C, H> where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>
{
    type Targets = CompressionTargets<D>;
    type Input = CompressionInput<F, D, C>;

    fn add_targets(&self, builder: &mut CircuitBuilder<F, D>, register_pi: bool) -> Result<Self::Targets> {
        let inner_common = self.inner_common_data.clone();

        // the proof virtual targets
        let vir_proof = builder.add_virtual_proof_with_pis(&inner_common);
        let inner_pub_input = vir_proof.public_inputs.clone();

        // take the public input from inner proof & make it public
        assert_eq!(inner_pub_input.len(), 8);
        if register_pi {
            builder.register_public_inputs(&inner_pub_input[0..4]);
        }

        // constant target for the verifier data
        let const_verifier_data = builder.constant_verifier_data(&self.inner_verifier_data);

        // register verifier data hash as public input.
        let mut vd_pub_input = vec![];
        vd_pub_input.extend_from_slice(&const_verifier_data.circuit_digest.elements);
        for i in 0..builder.config.fri_config.num_cap_elements() {
            vd_pub_input.extend_from_slice(&const_verifier_data.constants_sigmas_cap.0[i].elements);
        }

        let hash_inner_vd_pub_input = builder.hash_n_to_hash_no_pad::<H>(vd_pub_input);

        // make sure the VerifierData we use is the same as the tree root hash of the VerifierData
        builder.connect_hashes(hash_inner_vd_pub_input,HashOutTarget::from_vec(inner_pub_input[4..8].to_vec()));

        if register_pi {
            builder.register_public_inputs(&hash_inner_vd_pub_input.elements);
        }

        // verify the proofs in-circuit
        builder.verify_proof::<C>(&vir_proof, &const_verifier_data, &inner_common);

        // return targets
        let t = CompressionTargets {
            inner_proof: vir_proof,
        };
        Ok(t)
    }

    fn assign_targets(&self, pw: &mut PartialWitness<F>, targets: &Self::Targets, input: &Self::Input) -> Result<()> {
        // assign the proof
        pw.set_proof_with_pis_target(&targets.inner_proof, &input.inner_proof)
            .map_err(|e| {
                CircuitError::ProofTargetAssignmentError("inner-proof".to_string(), e.to_string())
            })?;

        Ok(())
    }
}


