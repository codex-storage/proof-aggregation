use std::marker::PhantomData;
use plonky2::hash::hash_types::{ HashOutTarget, RichField};
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::{CircuitBuilder};
use plonky2::plonk::circuit_data::{CommonCircuitData, VerifierOnlyCircuitData};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2::plonk::proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget};
use plonky2_field::extension::Extendable;
use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2;
use crate::{error::CircuitError, Result};
use crate::circuit_helper::Plonky2Circuit;

// TODO: include the flag_buckets in the public input
/// A circuit that verifies the aggregated public inputs from inner circuits.
///
/// - `N`: Number of inner-proofs aggregated at the leaf level.
/// - `M`: Number of leaf proofs aggregated at the node level.
/// - `T`: Total Number of inner-proofs.
/// - `K`: Number of public input field elements per inner-proof (sampling proof).
#[derive(Clone, Debug)]
pub struct PublicInputVerificationCircuit<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    C: GenericConfig<D, F = F>,
    H: AlgebraicHasher<F>,
    const N: usize,
    const M: usize,
    const T: usize,
    const K: usize,
> where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub node_common_data: CommonCircuitData<F, D>,
    pub node_verifier_data: VerifierOnlyCircuitData<C, D>,
    phantom: PhantomData<H>,
}

/// Holds the virtual targets for the circuit.
/// - `inner_proof`: the proof to be verified and contains the public input to be verified.
/// - `inner_pub_inputs`: A nested vector of targets with dimensions T×K.
#[derive(Clone, Debug)]
pub struct PublicInputVerificationTargets<const D: usize> {
    pub inner_proof: ProofWithPublicInputsTarget<D>,
    pub inner_pub_inputs: Vec<Vec<Target>>,
}

/// input to the circuit for public input verification
/// - `inner_proof`: The tree root proof with 2 hash digests (8 Goldilocks field elements) public inputs [pi_hash, vd_hash].
/// - `inner_pub_inputs_vals`: T×K public input values from inner proofs.
#[derive(Clone, Debug)]
pub struct PublicInputVerificationInput<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    C: GenericConfig<D, F = F>,
>{
    pub inner_proof: ProofWithPublicInputs<F, C, D>,
    pub inner_pub_inputs_vals: Vec<Vec<F>>,
}

impl<F, const D: usize, C, H, const N: usize, const M: usize, const T: usize, const K: usize>
PublicInputVerificationCircuit<F, D, C, H, N, M, T, K>
    where
        F: RichField + Extendable<D> + Poseidon2,
        C: GenericConfig<D, F = F>,
        H: AlgebraicHasher<F>,
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    /// Create a new instance of the circuit.
    pub fn new(
        node_common_data: CommonCircuitData<F, D>,
        node_verifier_data: VerifierOnlyCircuitData<C, D>,
    ) -> Self {
        // we expect exactly 8 public inputs from the tree root proof
        // 4 for the final aggregated public-input hash, 4 for the node verifier-data hash
        assert_eq!(node_common_data.num_public_inputs, 8);

        Self {
            node_common_data,
            node_verifier_data,
            phantom: PhantomData,
        }
    }
}
impl<F, const D: usize, C, H, const N: usize, const M: usize, const T: usize, const K: usize>
Plonky2Circuit<F, C, D> for PublicInputVerificationCircuit<F, D, C, H, N, M, T, K>
    where
        F: RichField + Extendable<D> + Poseidon2,
        C: GenericConfig<D, F = F>,
        H: AlgebraicHasher<F>,
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    type Targets = PublicInputVerificationTargets<D>;
    type Input = PublicInputVerificationInput<F, D, C>;

    /// Builds the circuit by:
    /// 1. Verifies a proof target with 8 public inputs (the final [pi_hash, vd_hash]).
    /// 2. verifies correct tree hashing of all T×K targets to represent all inner public inputs.
    /// 3. verifies correct node_verifier_date used is the same as in public input (last 4 field elements).
    fn add_targets(&self, builder: &mut CircuitBuilder<F, D>, register_pi: bool) -> Result<PublicInputVerificationTargets<D>> {
        // Add a virtual proof with 8 public inputs. This is the final root proof whose
        // public inputs we want to check in-circuit.
        let inner_proof = builder.add_virtual_proof_with_pis(&self.node_common_data);

        // Create a constant VerifierCircuitTarget for the node's verifier data.
        let const_node_vd = builder.constant_verifier_data(&self.node_verifier_data);

        // verify the proof
        builder.verify_proof::<C>(&inner_proof, &const_node_vd, &self.node_common_data);

        // create T×K targets for all inner public inputs from the base level.
        let mut inner_pub_inputs = Vec::with_capacity(T);
        for _ in 0..T {
            let mut row = Vec::with_capacity(K);
            for _ in 0..K {
                if register_pi {
                    row.push(builder.add_virtual_public_input()); // public input
                } else{
                    row.push(builder.add_virtual_target());
                }
            }
            inner_pub_inputs.push(row);
        }

        // ------------------------------------------------------------------
        //   Summary of the logic:
        //
        //   let final_pi = proof.public_inputs[0..4];
        //   let node_vd = proof.public_inputs[4..8];
        //   ...
        //   leaf-level pub inputs tree hashing: chunks of N -> hash
        //   node-level pub inputs tree hashing: chunks of M -> hash
        //   ...
        //   check final result matches final_pi
        // ------------------------------------------------------------------

        // Extract the final 4 field elements for the public-input hash & next 4 for the verifier-data hash.
        let final_pi_hash_t = &inner_proof.public_inputs[0..4];
        let node_vd_hash_t = &inner_proof.public_inputs[4..8];

        // Compute node_hash in-circuit
        let mut node_vd_input_t = Vec::new();
        node_vd_input_t.extend_from_slice(&const_node_vd.circuit_digest.elements);
        for cap_elem in const_node_vd.constants_sigmas_cap.0.iter() {
            node_vd_input_t.extend_from_slice(&cap_elem.elements);
        }
        let node_hash_t = builder.hash_n_to_hash_no_pad::<H>(node_vd_input_t);
        // make sure the VerifierData we use is the same as the tree root hash of the VerifierData
        builder.connect_hashes(node_hash_t,HashOutTarget::from_vec(node_vd_hash_t.to_vec()));
        if register_pi {
            builder.register_public_inputs(&node_hash_t.elements); // public input
        }

        let mut pub_in_hashes_t = Vec::new();

        // Leaf level hashing: chunks of N
        let base_chunks = T / N; // T is assumed to be multiple of N
        for i in 0..base_chunks {
            // flatten the inputs from i*N .. i*N + N
            let mut chunk_targets = Vec::with_capacity(N * K);
            for row_idx in (i * N)..(i * N + N) {
                chunk_targets.extend_from_slice(&inner_pub_inputs[row_idx]);
            }
            // hash
            let pi_hash_chunk = builder.hash_n_to_hash_no_pad::<H>(chunk_targets);

            // track these in vectors
            pub_in_hashes_t.push(pi_hash_chunk);
        }

        // Now at the node level:
        let mut current_len = base_chunks;
        while current_len > 1 {

            let next_len = (current_len + (M - 1)) / M;

            let mut next_pub_in_hashes_t = Vec::with_capacity(next_len);

            for i in 0..next_len {
                let start_idx = i * M;
                let end_idx = (start_idx + M).min(current_len);

                // flatten all pub_in_hashes in [start_idx..end_idx]
                let mut pi_flat = Vec::with_capacity((end_idx - start_idx) * 4);
                for j in start_idx..end_idx {
                    pi_flat.extend_from_slice(&pub_in_hashes_t[j].elements);
                }
                let pi_hash = builder.hash_n_to_hash_no_pad::<H>(pi_flat);
                next_pub_in_hashes_t.push(pi_hash);
            }

            pub_in_hashes_t = next_pub_in_hashes_t;
            current_len = next_len;
        }

        // now have exactly one pub_in_hash
        let final_computed_pi_t = &pub_in_hashes_t[0];

        // connect them to the final 4 public inputs of `inner_proof`.
        for i in 0..4 {
            builder.connect(final_pi_hash_t[i], final_computed_pi_t.elements[i]);
        }

        // return all the targets
        Ok(PublicInputVerificationTargets {
            inner_proof,
            inner_pub_inputs,
        })
    }

    fn assign_targets(
        &self,
        pw: &mut PartialWitness<F>,
        targets: &Self::Targets,
        input: &Self::Input,
    ) -> Result<()> {
        // Assign the final proof - it should have 8 public inputs
        pw.set_proof_with_pis_target(&targets.inner_proof, &input.inner_proof)
            .map_err(|e| {
                CircuitError::ProofTargetAssignmentError("final-proof".to_string(), e.to_string())
            })?;

        // Assign T×K inner public inputs
        if input.inner_pub_inputs_vals.len() != T {
            return Err(CircuitError::InvalidArgument(format!(
                "Expected T={} rows of inner_pub_inputs_vals, got {}",
                T,
                input.inner_pub_inputs_vals.len()
            )));
        }
        for (i, row_vals) in input.inner_pub_inputs_vals.iter().enumerate() {
            if row_vals.len() != K {
                return Err(CircuitError::InvalidArgument(format!(
                    "Expected K={} values in row {}, got {}",
                    K,
                    i,
                    row_vals.len()
                )));
            }
            for (j, &val) in row_vals.into_iter().enumerate() {
                pw.set_target(targets.inner_pub_inputs[i][j], val).map_err(|e| {
                    CircuitError::TargetAssignmentError(format!("inner public input index [{}][{}]", i,j), e.to_string())
                })?;
            }
        }

        Ok(())
    }
}
