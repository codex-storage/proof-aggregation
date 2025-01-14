use plonky2::hash::hash_types::RichField;
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2;
use crate::recursion::circuits::inner_circuit::InnerCircuit;
use plonky2::recursion::cyclic_recursion::check_cyclic_proof_verifier_data;
use plonky2_field::extension::Extendable;
use crate::recursion::tree2::dummy_gen::DummyProofGen;
use crate::{error::CircuitError, Result};
use crate::circuits::utils::vec_to_array;
use crate::recursion::tree2::leaf_circuit::LeafCircuit;
use crate::recursion::tree2::node_circuit::NodeCircuit;

/// the tree recursion struct simplifies the process
/// of building, proving and verifying
/// - N: number of inner proofs to verify in the node circuit
pub struct TreeRecursion<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    C: GenericConfig<D, F = F> + 'static,
    const N: usize,
> where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>
{
    pub node: NodeCircuit<F, D, C, N>
}

impl<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    C: GenericConfig<D, F = F> + 'static,
    const N: usize,
> TreeRecursion<F, D, C, N> where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>
{



    pub fn build<
        I: InnerCircuit<F, D>,
        H: AlgebraicHasher<F>,
    >(
        leaf_circuit: LeafCircuit<F, D, I>
    ) -> Result<Self>{
        Ok(
            Self{
                node: NodeCircuit::<F, D, C, N>::build_circuit::<I,H>(leaf_circuit)?,
            }
        )
    }

    /// generates a proof - only one node
    /// takes N proofs
    pub fn prove(
        &mut self,
        leaf_proofs: [ProofWithPublicInputs<F, C, D>; N],
        node_proofs: [ProofWithPublicInputs<F, C, D>; N],
        is_leaf: bool,
    ) -> Result<ProofWithPublicInputs<F, C, D>>{

        let mut pw = PartialWitness::new();

        NodeCircuit::assign_targets(
            self.node.node_targets.clone(),
            leaf_proofs,
            node_proofs,
            &self.node.node_data.leaf_circuit_data.verifier_only,
            &mut pw,
            is_leaf,
        )?;

        let proof = self.node.node_data.node_circuit_data.prove(pw)
            .map_err(|e| CircuitError::ProofGenerationError(e.to_string()))?;

        Ok(proof)
    }

    /// prove n leaf proofs in a tree structure
    /// the function uses circuit data from self takes
    /// - leaf_proofs:  vector of circuit inputs
    /// NOTE: Expects the number of leaf proofs to be divisible by N, e.g. by 2 if binary tree
    pub fn prove_tree(
        &mut self,
        leaf_proofs: Vec<ProofWithPublicInputs<F, C, D>>,
    ) -> Result<ProofWithPublicInputs<F, C, D>> {
        // 1. Check the total number of leaf_proofs is divisible by N
        if leaf_proofs.len() % N != 0 {
            return
                Err(CircuitError::RecursionTreeError(format!(
                    "input proofs must be divisible by {}, got {}", N, leaf_proofs.len())
                ))
        }

        // 2. Prepare the dummy proofs
        let dummy_node_proofs = DummyProofGen::<F, D, C>::gen_n_dummy_node_proofs(
            &self.node.node_data.inner_node_common_data,
            &self.node.node_data.node_circuit_data.verifier_only,
        )?;

        let dummy_leaf_proofs = DummyProofGen::<F, D, C>::gen_n_dummy_leaf_proofs(
            &self.node.node_data.leaf_circuit_data.common
        )?;

        // 3. Work through levels of proofs until only one remains
        let mut current_level_proofs = leaf_proofs;

        // Keep reducing until we’re left with 1 proof
        let mut level: usize = 0;
        while current_level_proofs.len() >= N {
            let mut next_level_proofs = Vec::new();

            // Process in chunks of N
            for chunk in current_level_proofs.chunks_exact(N) {
                // Convert the chunk slice into a fixed-size array
                let chunk_array: [ProofWithPublicInputs<F, C, D>; N] =
                    vec_to_array::<N,ProofWithPublicInputs<F, C, D>>(chunk.to_vec())?;

                // Decide leaf or node based on level
                // assumes the first chunk is the leaf
                let (leaf_chunk, node_chunk, is_leaf) = if level == 0 {
                    (chunk_array, dummy_node_proofs.clone(), true)
                } else {
                    (dummy_leaf_proofs.clone(), chunk_array, false)
                };

                let node = self.prove(
                    leaf_chunk,
                    node_chunk,
                    is_leaf,
                )?;

                next_level_proofs.push(node);
            }

            current_level_proofs = next_level_proofs;
            level = level + 1;
        }

        // 4. Check that exactly one proof remains
        if current_level_proofs.len() != 1 {
            return Err(CircuitError::RecursionTreeError(
                format!("Expected exactly 1 final proof, found {}",
            current_level_proofs.len())
        ));
        }

        // 5. Return the final root proof
        Ok(current_level_proofs.remove(0))
    }

    /// verifies the proof generated
    /// TODO: separate prover from verifier.
    pub fn verify_proof(
        &self,
        proof: ProofWithPublicInputs<F, C, D>,
        is_leaf: bool,
    ) -> Result<()>{

        if !is_leaf {
            check_cyclic_proof_verifier_data(
                &proof,
                &self.node.node_data.node_circuit_data.verifier_only,
                &self.node.node_data.node_circuit_data.common,
            ).map_err(|e| CircuitError::InvalidProofError(e.to_string()))?;
        }

        self.node.node_data.node_circuit_data.verify(proof)
            .map_err(|e| CircuitError::InvalidProofError(e.to_string()))?;

        Ok(())
    }
}

