use plonky2::gates::noop::NoopGate;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::BoolTarget;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitData, CommonCircuitData, VerifierCircuitTarget};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2::plonk::proof::ProofWithPublicInputsTarget;
use plonky2_field::extension::Extendable;
use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2;

/// this takes verifier data (not public) and doesn't check the verifier data for consistency
pub fn conditionally_verify_recursion_proof_or_dummy<F: RichField + Extendable<D> + Poseidon2, const D: usize ,C: GenericConfig<D, F = F> + 'static>(
    builder: &mut CircuitBuilder<F, D>,
    condition: BoolTarget,
    cyclic_proof_with_pis: &ProofWithPublicInputsTarget<D>,
    verifier_data: &VerifierCircuitTarget,
    common_data: &CommonCircuitData<F, D>,
) -> anyhow::Result<()>
    where
        C::Hasher: AlgebraicHasher<F>,
{
    let (dummy_proof_with_pis_target, dummy_verifier_data_target) =
        dummy_proof_and_vk_no_generator::<F, D, C>(builder, common_data)?;

    // TODO: make verifier data public
    // // Connect previous verifier data to current one. This guarantees that every proof in the cycle uses the same verifier data.
    // self.connect_hashes(
    //     inner_cyclic_pis.circuit_digest,
    //     verifier_data.circuit_digest,
    // );
    // self.connect_merkle_caps(
    //     &inner_cyclic_pis.constants_sigmas_cap,
    //     &verifier_data.constants_sigmas_cap,
    // );

    // Verify the cyclic proof if `condition` is set to true, otherwise verify the other proof.
    builder.conditionally_verify_proof::<C>(
        condition,
        cyclic_proof_with_pis,
        verifier_data,
        &dummy_proof_with_pis_target,
        &dummy_verifier_data_target,
        common_data,
    );

    // Make sure we have every gate to match `common_data`.
    for g in &common_data.gates {
        builder.add_gate_to_gate_set(g.clone());
    }

    Ok(())
}

/// Conditionally verify a proof with a new generated dummy proof.
pub fn conditionally_verify_proof_or_dummy<F: RichField + Extendable<D> + Poseidon2, const D: usize ,C: GenericConfig<D, F = F> + 'static>(
    builder: &mut CircuitBuilder<F, D>,
    condition: BoolTarget,
    proof_with_pis: &ProofWithPublicInputsTarget<D>,
    inner_verifier_data: &VerifierCircuitTarget,
    inner_common_data: &CommonCircuitData<F, D>,
) -> anyhow::Result<()>
    where
        C::Hasher: AlgebraicHasher<F>,
{
    let (dummy_proof_with_pis_target, dummy_verifier_data_target) =
        dummy_proof_and_vk_no_generator::<F, D, C>(builder, inner_common_data)?;
    builder.conditionally_verify_proof::<C>(
        condition,
        proof_with_pis,
        inner_verifier_data,
        &dummy_proof_with_pis_target,
        &dummy_verifier_data_target,
        inner_common_data,
    );
    Ok(())
}

/// Generate a circuit matching a given `CommonCircuitData`.
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

    let mut builder = CircuitBuilder::<F, D>::new(config);
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

pub(crate) fn dummy_proof_and_vk_no_generator<F: RichField + Extendable<D> + Poseidon2, const D: usize ,C: GenericConfig<D, F = F> + 'static> (
    builder: &mut CircuitBuilder<F, D>,
    common_data: &CommonCircuitData<F, D>,
) -> anyhow::Result<(ProofWithPublicInputsTarget<D>, VerifierCircuitTarget)>
    where
        C::Hasher: AlgebraicHasher<F>,
{
    let dummy_circuit = dummy_circuit::<F, C, D>(common_data);
    let dummy_proof_with_pis_target = builder.add_virtual_proof_with_pis(common_data);
    let dummy_verifier_data_target = builder.constant_verifier_data(&dummy_circuit.verifier_only);

    Ok((dummy_proof_with_pis_target, dummy_verifier_data_target))
}
