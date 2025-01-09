use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, VerifierCircuitData};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::iop::witness::PartialWitness;
use crate::recursion::params::{C, D, F};
use crate::recursion::simple_recursion;

// recursion tree width or the number of proofs in each node in the tree
const RECURSION_TREE_WIDTH: usize = 2;

/// aggregate sampling proofs in tree like structure
/// uses the const params: `RECURSION_TREE_WIDTH`
/// In this tree approach the building is done at each level -> very slow!
pub fn aggregate_sampling_proofs_tree(
    proofs_with_pi: &[ProofWithPublicInputs<F, C, D>],
    data: CircuitData<F, C, D>,
) -> anyhow::Result<(ProofWithPublicInputs<F, C, D>, CircuitData<F, C, D>)> {
    // base case: if only one proof remains, return it
    if proofs_with_pi.len() == 1 {
        return Ok((proofs_with_pi[0].clone(), data));
    }

    let mut new_proofs = vec![];
    let mut new_circuit_data: Option<CircuitData<F, C, D>> = None;

    // group proofs according to the tree's width
    for chunk in proofs_with_pi.chunks(RECURSION_TREE_WIDTH) {
        let proofs_chunk = chunk.to_vec();

        // Build an inner-circuit to verify and aggregate the proofs in the chunk
        let inner_config = CircuitConfig::standard_recursion_config();
        let mut inner_builder = CircuitBuilder::<F, D>::new(inner_config);
        let mut inner_pw = PartialWitness::new();

        // aggregate proofs
        simple_recursion::aggregate_sampling_proofs(
            &proofs_chunk,
            &data.verifier_data(),
            &mut inner_builder,
            &mut inner_pw,
        )?;

        // Build the inner-circuit
        // this causes major delay - we can load it but better if we split build and prove
        let inner_data = inner_builder.build::<C>();

        // Prove the inner-circuit
        let proof = inner_data.prove(inner_pw)?;
        new_proofs.push(proof);
        new_circuit_data = Some(inner_data);
    }

    // Recursively aggregate the new proofs
    aggregate_sampling_proofs_tree(&new_proofs, new_circuit_data.unwrap())
}

/// same as above but takes `VerifierCircuitData`
pub fn aggregate_sampling_proofs_tree2(
    proofs_with_pi: &[ProofWithPublicInputs<F, C, D>],
    vd: VerifierCircuitData<F, C, D>
) -> anyhow::Result<(ProofWithPublicInputs<F, C, D>, VerifierCircuitData<F, C, D>)> {
    if proofs_with_pi.len() == 1 {
        return Ok((proofs_with_pi[0].clone(), vd));
    }

    let mut new_proofs = vec![];
    let mut new_circuit_data: Option<VerifierCircuitData<F, C, D>> = None;

    for chunk in proofs_with_pi.chunks(RECURSION_TREE_WIDTH) {
        let proofs_chunk = chunk.to_vec();

        let inner_config = CircuitConfig::standard_recursion_config();
        let mut inner_builder = CircuitBuilder::<F, D>::new(inner_config);
        let mut inner_pw = PartialWitness::new();

        simple_recursion::aggregate_sampling_proofs(
            &proofs_chunk,
            &vd,
            &mut inner_builder,
            &mut inner_pw,
        )?;

        let inner_data = inner_builder.build::<C>();

        let proof = inner_data.prove(inner_pw)?;
        new_proofs.push(proof);
        new_circuit_data = Some(inner_data.verifier_data());
    }

    aggregate_sampling_proofs_tree2(&new_proofs, new_circuit_data.unwrap())
}
