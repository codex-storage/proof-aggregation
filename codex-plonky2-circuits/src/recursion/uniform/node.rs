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
use crate::circuits::utils::vec_to_array;

/// recursion node circuit - verifies 2 leaf proofs
#[derive(Clone, Debug)]
pub struct NodeCircuit<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    C: GenericConfig<D, F = F>,
    H: AlgebraicHasher<F>,
    const M: usize,
> where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>
{
    leaf_common_data: CommonCircuitData<F, D>,
    phantom_data: PhantomData<(C,H)>
}

#[derive(Clone, Debug)]
pub struct NodeTargets<
    const D: usize,
>{
    pub leaf_proofs: Vec<ProofWithPublicInputsTarget<D>>,
    pub verifier_data: VerifierCircuitTarget,
}

impl<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    C: GenericConfig<D, F = F>,
    H: AlgebraicHasher<F>,
    const M: usize,
> NodeCircuit<F,D,C,H,M> where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>
{

    pub fn new(inner_common_data: CommonCircuitData<F,D>) -> Self {
        Self{
            leaf_common_data: inner_common_data,
            phantom_data:PhantomData::default(),
        }
    }

    /// build the leaf circuit
    pub fn build(&self, builder: &mut CircuitBuilder<F, D>) -> Result<NodeTargets<D>> {

        let inner_common = self.leaf_common_data.clone();

        // assert public input is of size 8 - 2 hashout
        assert_eq!(inner_common.num_public_inputs, 8);

        // the proof virtual targets - M proofs
        let mut vir_proofs = vec![];
        let mut pub_input = vec![];
        let mut inner_vd_hashes = vec![];
        for _i in 0..M {
            let vir_proof = builder.add_virtual_proof_with_pis(&inner_common);
            let inner_pub_input = vir_proof.public_inputs.clone();
            vir_proofs.push(vir_proof);
            pub_input.extend_from_slice(&inner_pub_input[0..4]);
            inner_vd_hashes.extend_from_slice(&inner_pub_input[4..8]);
        }

        // hash the public input & make it public
        let hash_inner_pub_input = builder.hash_n_to_hash_no_pad::<H>(pub_input);
        builder.register_public_inputs(&hash_inner_pub_input.elements);

        // virtual target for the verifier data
        let inner_verifier_data = builder.add_virtual_verifier_data(inner_common.config.fri_config.cap_height);

        // register verifier data hash as public input. H(H_l, H_l, H_n) -> public input
        let mut vd_pub_input = vec![];
        vd_pub_input.extend_from_slice(&inner_verifier_data.circuit_digest.elements);
        for i in 0..builder.config.fri_config.num_cap_elements() {
            vd_pub_input.extend_from_slice(&inner_verifier_data.constants_sigmas_cap.0[i].elements);
        }
        let vd_hash = builder.hash_n_to_hash_no_pad::<H>(vd_pub_input);
        inner_vd_hashes.extend_from_slice(&vd_hash.elements);
        let vd_hash_all = builder.hash_n_to_hash_no_pad::<H>(inner_vd_hashes);
        builder.register_public_inputs(&vd_hash_all.elements);

        // verify the proofs in-circuit  - M proofs
        for i in 0..M {
        builder.verify_proof::<C>(&vir_proofs[i], &inner_verifier_data, &inner_common);
        }

        // let proofs = vec_to_array::<2, ProofWithPublicInputsTarget<D>>(vir_proofs)?;

        // return targets
        let t = NodeTargets {
            leaf_proofs: vir_proofs,
            verifier_data: inner_verifier_data,
        };
        Ok(t)

    }

    /// assign the leaf targets with given input
    pub fn assign_targets(
        &self, pw: &mut PartialWitness<F>,
        targets: &NodeTargets<D>,
        node_proofs: &[ProofWithPublicInputs<F, C, D>],
        verifier_only_data: &VerifierOnlyCircuitData<C, D>,
    ) -> Result<()> {
        // assert size of proofs vec
        assert_eq!(node_proofs.len(), M);

        // assign the proofs
        for i in 0..M {
            pw.set_proof_with_pis_target(&targets.leaf_proofs[i], &node_proofs[i])
                .map_err(|e| {
                    CircuitError::ProofTargetAssignmentError("inner-proof".to_string(), e.to_string())
                })?;
        }

        // assign the verifier data
        pw.set_verifier_data_target(&targets.verifier_data, &verifier_only_data)
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


