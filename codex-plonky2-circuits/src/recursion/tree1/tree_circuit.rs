use std::array::from_fn;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2_field::extension::Extendable;
use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2;
use crate::recursion::circuits::inner_circuit::InnerCircuit;
use plonky2::recursion::cyclic_recursion::check_cyclic_proof_verifier_data;
use crate::{error::CircuitError, Result};
use crate::recursion::tree1::node_circuit::NodeCircuit;

/// the tree recursion struct simplifies the process
/// of building, proving and verifying
/// the two consts are:
/// - M: number of inner circuits to run
/// - N: number of inner proofs to verify
pub struct TreeRecursion<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    I: InnerCircuit<F, D>,
    const M: usize,
    const N: usize,
    C: GenericConfig<D, F = F>,
>{
    pub node_circ: NodeCircuit<F,D, I, M, N, C>
}

impl<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    I: InnerCircuit<F, D>,
    const M: usize,
    const N: usize,
    C: GenericConfig<D, F = F> + 'static,
> TreeRecursion<F, D, I, M, N, C> where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>
{

    pub fn build<
        H: AlgebraicHasher<F>,
    >(
        inner_circuit: I,
    ) -> Result<(Self)>{
        Ok(Self {
            node_circ: NodeCircuit:: < F,
            D,
            I,
            M,
            N,
            C>::build_circuit:: < H>(inner_circuit)?
        })
    }

    /// generates a proof - only one node
    /// takes M circuit input and N proofs
    pub fn prove(
        &mut self,
        circ_input: &[I::Input; M],
        proofs_option: Option<[ProofWithPublicInputs<F, C, D>; N]>,
        is_leaf: bool,
    ) -> Result<ProofWithPublicInputs<F, C, D>>{

        let mut pw = PartialWitness::new();
        self.node_circ.assign_targets(
            circ_input,
            proofs_option,
            &mut pw,
            is_leaf,
        )?;

        let circ_data = &self.node_circ.cyclic_circuit_data;
        let cyc_targets = &self.node_circ.cyclic_target;

        pw.set_verifier_data_target(&cyc_targets.verifier_data, &circ_data.verifier_only)
            .map_err(|e| CircuitError::VerifierDataTargetAssignmentError(e.to_string()))?;

        let proof = circ_data.prove(pw)
            .map_err(|e| CircuitError::InvalidProofError(e.to_string()))?;

        Ok(proof)
    }

    /// prove n in a tree structure recursively
    /// the function takes
    /// - circ_input:  vector of circuit inputs
    pub fn prove_tree(
        &mut self,
        circ_input: Vec<I::Input>,
        depth: usize,
    ) -> Result<ProofWithPublicInputs<F, C, D>>{
        // Total input size check
        let total_input = (N.pow(depth as u32) - 1) / (N - 1);

        if circ_input.len() != total_input{
            return Err(CircuitError::RecursionTreeError(
                "Invalid input size for tree depth".to_string()
            ));
        }

        let mut cur_proofs: Vec<ProofWithPublicInputs<F, C, D>> = vec![];

        // Iterate from leaf layer to root
        for layer in (0..depth).rev() {
            let layer_num_nodes = N.pow(layer as u32); // Number of nodes at this layer
            let mut next_proofs = Vec::new();

            for node_idx in 0..layer_num_nodes {
                // Get the inputs for the current node
                let node_inputs: [I::Input; M] = from_fn(|i| {
                    circ_input
                        .get(node_idx * M + i)
                        .cloned()
                        .unwrap_or_else(|| panic!("Index out of bounds at node {node_idx}, input {i}"))
                });

                let proof = if layer == depth - 1 {
                    // Leaf layer: no child proofs
                    self.prove(&node_inputs, None, true)?
                } else {
                    // Non-leaf layer: collect child proofs
                    let proofs_array: [ProofWithPublicInputs<F, C, D>; N] = cur_proofs
                        .drain(..N)
                        .collect::<Vec<_>>()
                        .try_into()
                        .map_err(|_| CircuitError::ArrayLengthMismatchError("Incorrect number of proofs for node".to_string()))?;
                    self.prove(&node_inputs, Some(proofs_array), false)?
                };
                next_proofs.push(proof);
            }
            cur_proofs = next_proofs;
        }

        // Check that exactly one proof remains
        if cur_proofs.len() != 1 {
            return Err(CircuitError::RecursionTreeError(
                format!("Expected exactly 1 final proof, found {}",
                        cur_proofs.len())
            ));
        }

        Ok(cur_proofs.remove(0))
    }

    /// verifies the proof generated
    pub fn verify_proof(
        &self,
        proof: ProofWithPublicInputs<F, C, D>
    ) -> Result<()>{

        let circ_data = &self.node_circ.cyclic_circuit_data;

        check_cyclic_proof_verifier_data(
            &proof,
            &circ_data.verifier_only,
            &circ_data.common,
        ).map_err(|e| CircuitError::RecursiveProofVerifierDataCheckError(e.to_string()))?;

        circ_data.verify(proof).map_err(|e|CircuitError::InvalidProofError(e.to_string()))?;

        Ok(())
    }
}
