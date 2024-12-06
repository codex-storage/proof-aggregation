use hashbrown::HashMap;
use plonky2::hash::hash_types::{HashOut, HashOutTarget, RichField};
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitData, VerifierCircuitData, VerifierCircuitTarget};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2::plonk::proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget};
use plonky2::recursion::dummy_circuit::cyclic_base_proof;
use plonky2_field::extension::Extendable;
use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2;
use crate::recursion::params::RecursionTreeParams;
use crate::recursion::params::{F,D,C,Plonky2Proof};
use crate::recursion::traits::InnerCircuit;

pub struct RecursionCircuit<
    I: InnerCircuit,
>{
    pub recursion_tree_params: RecursionTreeParams,
    pub inner_circuit_targets: Vec<I::Targets>,
    pub proof_targets: Vec<ProofWithPublicInputsTarget<D>>,
    pub verifier_data_targets: VerifierCircuitTarget,
    pub verifier_data: VerifierCircuitData<F, C, D>,
    pub condition_targets: Vec<Target>,
}

pub struct RecursionCircuitInput<
    I: InnerCircuit,
>{
    pub inner_circuit_input: Vec<I::Targets>,
    pub proofs: Plonky2Proof,
    pub conditions: Vec<F>
}

impl<
    I: InnerCircuit,
> RecursionCircuit<I> {

    pub fn build_circuit(
        &self,
        builder: &mut CircuitBuilder::<F, D>,
    ) -> Self {
        todo!()
    }

    pub fn get_circuit_data() -> CircuitData<F, C, D>{
        todo!()
    }

    pub fn get_dummy_proof(circuit_data: CircuitData<F, C, D>) -> Plonky2Proof {
        let verifier_data = circuit_data.verifier_data();
        let dummy_proof_with_pis = cyclic_base_proof(
            &circuit_data.common,
            &verifier_data.verifier_only,
            HashMap::new(),
        );
        dummy_proof_with_pis
    }

    pub fn assign_witness(
        &self,
        pw: &mut PartialWitness<F>,
        witnesses: RecursionCircuitInput<I>
    )-> anyhow::Result<()>{
        todo!()
        // Ok(())

    }
}