use std::marker::PhantomData;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitData, VerifierCircuitTarget};
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
> where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>
{
    leaf_common_data: CommonCircuitData<F, D>,
    phantom_data: PhantomData<(C,H)>
}

impl<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    C: GenericConfig<D, F = F>,
    H: AlgebraicHasher<F>,
> NodeCircuit<F,D,C,H> where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>
{
    pub fn new(inner_common_data: CommonCircuitData<F,D>) -> Self {
        Self{
            leaf_common_data: inner_common_data,
            phantom_data:PhantomData::default(),
        }
    }
}
#[derive(Clone, Debug)]
pub struct NodeTargets<
    const D: usize,
>{
    pub leaf_proofs: [ProofWithPublicInputsTarget<D>; 2],
    pub verifier_data: VerifierCircuitTarget,
}
#[derive(Clone, Debug)]
pub struct NodeInput<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    C: GenericConfig<D, F = F>,
>{
    pub node_proofs: [ProofWithPublicInputs<F, C, D>;2],
    pub verifier_data: VerifierCircuitData<F, C, D>
}

impl<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    C: GenericConfig<D, F = F>,
    H: AlgebraicHasher<F>,
> NodeCircuit<F,D,C,H> where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>
{

    /// build the leaf circuit
    pub fn build(&self, builder: &mut CircuitBuilder<F, D>) -> Result<NodeTargets<D>> {

        let inner_common = self.leaf_common_data.clone();

        // the proof virtual targets - 2 proofs
        let mut vir_proofs = vec![];
        let mut pub_input = vec![];
        for _i in 0..2 {
            let vir_proof = builder.add_virtual_proof_with_pis(&inner_common);
            let inner_pub_input = vir_proof.public_inputs.clone();
            vir_proofs.push(vir_proof);
            pub_input.extend_from_slice(&inner_pub_input);
        }

        // hash the public input & make it public
        let hash_inner_pub_input = builder.hash_n_to_hash_no_pad::<H>(pub_input);
        builder.register_public_inputs(&hash_inner_pub_input.elements);

        // virtual target for the verifier data
        let inner_verifier_data = builder.add_virtual_verifier_data(inner_common.config.fri_config.cap_height);

        // verify the proofs in-circuit  - 2 proofs
        for i in 0..2 {
        builder.verify_proof::<C>(&vir_proofs[i], &inner_verifier_data, &inner_common);
        }

        let proofs = vec_to_array::<2, ProofWithPublicInputsTarget<D>>(vir_proofs)?;

        // return targets
        let t = NodeTargets {
            leaf_proofs: proofs,
            verifier_data: inner_verifier_data,
        };
        Ok(t)

    }

    /// assign the leaf targets with given input
    pub fn assign_targets(
        &self, pw: &mut PartialWitness<F>,
        targets: &NodeTargets<D>,
        input: &NodeInput<F, D, C>
    ) -> Result<()> {
        // assign the proofs
        for i in 0..2 {
            pw.set_proof_with_pis_target(&targets.leaf_proofs[i], &input.node_proofs[i])
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


