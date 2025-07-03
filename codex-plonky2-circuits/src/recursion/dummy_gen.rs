use std::marker::PhantomData;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitData, VerifierOnlyCircuitData};
use plonky2::plonk::proof::{ProofWithPublicInputs};
use plonky2::recursion::dummy_circuit::{dummy_proof};
use hashbrown::HashMap;
use plonky2::gates::constant::ConstantGate;
use plonky2::gates::noop::NoopGate;
use plonky2::hash::hash_types::{ RichField};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2_field::extension::Extendable;
use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2;
use crate::{error::CircuitError, Result};

/// A generator for creating dummy proofs and verifier data.
pub struct DummyProofGen<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    C: GenericConfig<D, F = F>,
>
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    phantom_data: PhantomData<(F, C)>,
}

impl<F, const D: usize, C> DummyProofGen<F, D, C>
    where
        F: RichField + Extendable<D> + Poseidon2,
        C: GenericConfig<D, F = F>,
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    /// Builds a dummy circuit from the provided common circuit data.
    pub fn gen_dummy_common_data(
    ) -> CommonCircuitData<F, D> {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        // Add one virtual public input so that the circuit has minimal structure.
        builder.add_virtual_public_input();
        let circuit = builder.build::<C>();
        circuit.common.clone()
    }

    /// Builds a dummy circuit from the provided common circuit data.
    pub fn gen_dummy_circ_data(
        common_data: &CommonCircuitData<F, D>,
    ) -> CircuitData<F, C, D> {
        dummy_circuit::<F, C, D>(common_data)
    }

    /// Extracts the verifier-only data from the dummy circuit.
    pub fn gen_dummy_verifier_data(
        common_data: &CommonCircuitData<F, D>,
    ) -> VerifierOnlyCircuitData<C, D> {
        Self::gen_dummy_circ_data(common_data).verifier_only
    }

    /// Generates a dummy proof and returns it along with the verifier-only data.
    /// The `nonzero_public_inputs` argument allows you to supply a mapping of public input indices
    /// to nonzero field element values.
    pub fn gen_dummy_proof_and_vd_with_pi(
        common_data: &CommonCircuitData<F, D>,
        nonzero_public_inputs: HashMap<usize, F>,
    ) -> Result<(ProofWithPublicInputs<F, C, D>, VerifierCircuitData<F, C, D>)> {
        let circuit_data = Self::gen_dummy_circ_data(common_data);
        let proof = dummy_proof::<F, C, D>(&circuit_data, nonzero_public_inputs)
            .map_err(|e| CircuitError::ProofGenerationError(e.to_string()))?;
        Ok((proof, circuit_data.verifier_data()))
    }

    /// Generates a dummy proof and verifier data with zero public inputs.
    pub fn gen_dummy_proof_and_vd_zero_pi(
        common_data: &CommonCircuitData<F, D>,
    ) -> Result<(ProofWithPublicInputs<F, C, D>, VerifierCircuitData<F, C, D>)> {
        Self::gen_dummy_proof_and_vd_with_pi(common_data, HashMap::new())
    }
}

/// Generate a circuit matching a given `CommonCircuitData`.
/// This extends the Plonky2 one with Poseidon2 support
pub(crate) fn dummy_circuit<F: RichField + Extendable<D> + Poseidon2, C: GenericConfig<D, F = F>, const D: usize>(
    common_data: &CommonCircuitData<F, D>,
) -> CircuitData<F, C, D> {
    let config = common_data.config.clone();
    assert!(
        !common_data.config.zero_knowledge,
        "Degree calculation can be off if zero-knowledge is on."
    );

    // Number of `NoopGate`s to add to get a circuit of size `degree` in the end.
    // Need to account for public input hashing, a `PublicInputGate` and a `ConstantGate`.
    let degree = common_data.degree();
    let num_noop_gate = degree - common_data.num_public_inputs.div_ceil(8) - 2;

    let mut builder = CircuitBuilder::<F, D>::new(config.clone());

    // add a ConstantGate
    builder.add_gate(
        ConstantGate::new(config.num_constants),
        vec![],
    );

    for _ in 0..num_noop_gate {
        builder.add_gate(NoopGate, vec![]);
    }
    for gate in &common_data.gates {
        builder.add_gate_to_gate_set(gate.clone());
    }
    for _ in 0..common_data.num_public_inputs {
        builder.add_virtual_public_input();
    }

    let circuit = builder.build::<C>();
    assert_eq!(&circuit.common, common_data);
    circuit
}