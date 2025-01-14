use std::marker::PhantomData;
use plonky2::plonk::circuit_data::{CommonCircuitData, VerifierOnlyCircuitData};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::recursion::dummy_circuit::{cyclic_base_proof, dummy_circuit, dummy_proof};
use hashbrown::HashMap;
use plonky2::hash::hash_types::RichField;
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2_field::extension::Extendable;
use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2;
use crate::{error::CircuitError, Result};
use crate::circuits::utils::vec_to_array;

/// A generator for creating dummy proofs.
pub struct DummyProofGen<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    C: GenericConfig<D, F = F>,
    > where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>
{
    phantom_data: PhantomData<(F,C)>,
}

impl<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    C: GenericConfig<D, F = F>,
> DummyProofGen<F, D, C>
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>
{

    /// Generates a single dummy leaf proof.
    pub fn gen_dummy_leaf_proof(
        common_data: &CommonCircuitData<F, D>,
    ) -> Result<ProofWithPublicInputs<F, C, D>> {
        dummy_proof::<F, C, D>(&dummy_circuit::<F, C, D>(common_data), HashMap::new())
            .map_err(|e| CircuitError::DummyProofGenerationError(e.to_string()))
    }

    /// Generates a single dummy node proof.
    pub fn get_dummy_node_proof(
        node_common: &CommonCircuitData<F, D>,
        node_verifier_only_data: &VerifierOnlyCircuitData<C, D>,
    ) -> ProofWithPublicInputs<F, C, D> {
        cyclic_base_proof(node_common, node_verifier_only_data, HashMap::new())
    }

    /// Generates an array of `N` dummy leaf proofs.
    pub fn gen_n_dummy_leaf_proofs<const N: usize>(
        common_data: &CommonCircuitData<F, D>,
    ) -> Result<[ProofWithPublicInputs<F, C, D>; N]> {
        let dummy_proof = Self::gen_dummy_leaf_proof(common_data)?;
        let n_dummy_vec = (0..N).map(|_| dummy_proof.clone()).collect::<Vec<_>>();
        vec_to_array::<N, ProofWithPublicInputs<F, C, D>>(n_dummy_vec)
    }

    /// Generates an array of `N` dummy node proofs.
    pub fn gen_n_dummy_node_proofs<const N: usize>(
        node_common: &CommonCircuitData<F, D>,
        node_verifier_only_data: &VerifierOnlyCircuitData<C, D>,
    ) -> Result<[ProofWithPublicInputs<F, C, D>; N]> {
        let dummy_proof = Self::get_dummy_node_proof(node_common, node_verifier_only_data);
        let n_dummy_vec = (0..N).map(|_| dummy_proof.clone()).collect::<Vec<_>>();
        vec_to_array::<N, ProofWithPublicInputs<F, C, D>>(n_dummy_vec)
    }
}



