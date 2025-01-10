use plonky2::plonk::circuit_data::{CircuitConfig, CommonCircuitData, VerifierOnlyCircuitData};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::gates::noop::NoopGate;
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::recursion::dummy_circuit::{cyclic_base_proof, dummy_circuit, dummy_proof};
use hashbrown::HashMap;
use crate::params::{C, D, F};

/// Generates `CommonCircuitData` usable for node recursion.
/// the circuit being built here depends on M and N so must be re-generated
/// if the params change
pub fn common_data_for_node<const N: usize>() -> anyhow::Result<CommonCircuitData<F, D>>
{
    // layer 1
    let config = CircuitConfig::standard_recursion_config();
    let builder = CircuitBuilder::<F, D>::new(config);
    let data = builder.build::<C>();

    // layer 2
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config.clone());
    let verifier_data = builder.add_virtual_verifier_data(data.common.config.fri_config.cap_height);
    // generate and verify N number of proofs
    for _ in 0..1 {
        let proof = builder.add_virtual_proof_with_pis(&data.common);
        builder.verify_proof::<C>(&proof, &verifier_data, &data.common);
    }
    let data = builder.build::<C>();

    // layer 3
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config.clone());

    // add a ConstantGate
    builder.add_gate(
        plonky2::gates::constant::ConstantGate::new(config.num_constants),
        vec![],
    );

    // generate and verify N number of proofs
    let verifier_data = builder.add_verifier_data_public_inputs();
    for _ in 0..N {
        let proof = builder.add_virtual_proof_with_pis(&data.common);
        builder.verify_proof::<C>(&proof, &verifier_data, &data.common);
    }
    // pad. TODO: optimize this padding to only needed number of gates
    while builder.num_gates() < 1 << 14 {
        builder.add_gate(NoopGate, vec![]);
    }
    Ok(builder.build::<C>().common)
}

// creates a dummy proof with given common circuit data
pub fn get_dummy_leaf_proof(common_data: &CommonCircuitData<F, D>) -> ProofWithPublicInputs<F, C, D> {
    dummy_proof::<F, C, D>(
        &dummy_circuit::<F, C, D>(common_data),
        HashMap::new(),
    ).unwrap()
}

pub fn get_dummy_node_proof(node_common: &CommonCircuitData<F, D>, node_verifier_only_data: &VerifierOnlyCircuitData<C, D>) -> ProofWithPublicInputs<F, C, D>{
    cyclic_base_proof(
        node_common,
        node_verifier_only_data,
        HashMap::new(),
    )
}


