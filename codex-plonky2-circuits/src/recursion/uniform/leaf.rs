use std::marker::PhantomData;
use plonky2::hash::hash_types::{HashOut, RichField};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierOnlyCircuitData};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2::plonk::proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget};
use plonky2_field::extension::Extendable;
use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2;
use crate::{error::CircuitError,Result};

/// recursion leaf circuit - verifies N inner proof
#[derive(Clone, Debug)]
pub struct LeafCircuit<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    C: GenericConfig<D, F = F>,
    H: AlgebraicHasher<F>,
    const N: usize,
> where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>
{
    inner_common_data: CommonCircuitData<F, D>,
    inner_verifier_data: VerifierOnlyCircuitData<C, D>,
    phantom_data: PhantomData<H>
}

#[derive(Clone, Debug)]
pub struct LeafTargets <
    const D: usize,
>{
    pub inner_proof: Vec<ProofWithPublicInputsTarget<D>>,
}

impl<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    C: GenericConfig<D, F = F>,
    H: AlgebraicHasher<F>,
    const N: usize,
> LeafCircuit<F,D,C,H,N> where
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

    /// build the leaf circuit
    pub fn build(&self, builder: &mut CircuitBuilder<F, D>) -> Result<LeafTargets<D>> {

        let inner_common = self.inner_common_data.clone();

        // the proof virtual targets
        let mut pub_input = vec![];
        let mut vir_proofs = vec![];
        for _i in 0..N {
            let vir_proof = builder.add_virtual_proof_with_pis(&inner_common);
            let inner_pub_input = vir_proof.public_inputs.clone();
            vir_proofs.push(vir_proof);
            pub_input.extend_from_slice(&inner_pub_input);
        }

        // hash the public input & make it public
        let hash_inner_pub_input = builder.hash_n_to_hash_no_pad::<H>(pub_input);
        builder.register_public_inputs(&hash_inner_pub_input.elements);

        // pad the public input with constants so that it shares the same structure as the node
        let zero_hash = builder.constant_hash(HashOut::<F>::default());
        builder.register_public_inputs(&zero_hash.elements);

        // virtual constant target for the verifier data
        let const_verifier_data = builder.constant_verifier_data(&self.inner_verifier_data);

        // verify the proofs in-circuit
        for i in 0..N {
            builder.verify_proof::<C>(&vir_proofs[i], &const_verifier_data, &inner_common);
        }

        // return targets
        let t = LeafTargets {
            inner_proof: vir_proofs,
        };
        Ok(t)

    }

    /// assign the leaf targets with given input
    pub fn assign_targets(
        &self, pw: &mut PartialWitness<F>,
        targets: &LeafTargets<D>,
        inner_proof: &[ProofWithPublicInputs<F, C, D>],
    ) -> Result<()> {
        assert_eq!(inner_proof.len(), N);
        // assign the proofs
        for i in 0..N {
            pw.set_proof_with_pis_target(&targets.inner_proof[i], &inner_proof[i])
                .map_err(|e| {
                    CircuitError::ProofTargetAssignmentError("inner-proof".to_string(), e.to_string())
                })?;
        }

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


