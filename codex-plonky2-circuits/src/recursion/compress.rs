use plonky2::hash::hash_types::RichField;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::VerifierCircuitData;
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
> where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>
{
    inner_verifier_data: VerifierCircuitData<F, C, D>,
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
> CompressionCircuit<F,D,C> where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>
{
    pub fn new(
        inner_verifier_data: VerifierCircuitData<F, C, D>,
    ) -> Self {
        Self{
            inner_verifier_data,
        }
    }

}

impl<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    C: GenericConfig<D, F = F>,
> Plonky2Circuit<F, C, D> for CompressionCircuit<F, D, C> where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>
{
    type Targets = CompressionTargets<D>;
    type Input = CompressionInput<F, D, C>;

    fn add_targets(&self, builder: &mut CircuitBuilder<F, D>, register_pi: bool) -> Result<Self::Targets> {
        let inner_common = self.inner_verifier_data.common.clone();

        // the proof virtual targets
        let vir_proof = builder.add_virtual_proof_with_pis(&inner_common);

        // take the public input from inner proof & make it public
        if register_pi {
            builder.register_public_inputs(&vir_proof.public_inputs);
        }

        // constant target for the verifier data
        let const_verifier_data = builder.constant_verifier_data(&self.inner_verifier_data.verifier_only);

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


