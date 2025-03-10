use std::marker::PhantomData;
use plonky2::hash::hash_types::{HashOut, HashOutTarget, RichField};
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::{CircuitBuilder};
use plonky2::plonk::circuit_data::{CommonCircuitData, VerifierCircuitData, VerifierCircuitTarget};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2::plonk::proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget};
use plonky2_field::extension::Extendable;
use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2;
use crate::{error::CircuitError, Result};

/// A circuit that verifies the aggregated public inputs from inner circuits.
///
/// - `N`: Number of inner-proofs aggregated at the leaf level.
/// - `M`: Number of leaf proofs aggregated at the node level.
/// - `T`: Total Number of inner-proofs.
/// - `K`: Number of public input field elements per inner-proof (sampling proof).
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
    phantom: PhantomData<(C, H)>,
}

/// Holds the virtual targets for the circuit.
/// - `inner_proof`: the proof to be verified and contains the public input to be verified.
/// - `inner_pub_inputs`: A nested vector of targets with dimensions T×K.
/// - `node_verifier_data`: Verifier data for the node circuit.
/// - `leaf_verifier_data`: Verifier data for the leaf circuit.
/// - `inner_verifier_data`: Verifier data for the inner circuit.
pub struct PublicInputVerificationTargets<const D: usize> {
    pub inner_proof: ProofWithPublicInputsTarget<D>,
    pub node_verifier_data: VerifierCircuitTarget,
    pub leaf_verifier_data: HashOutTarget,
    pub inner_verifier_data: HashOutTarget,
    pub inner_pub_inputs: Vec<Vec<Target>>,
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
    pub fn new(node_common_data: CommonCircuitData<F, D>) -> Self {
        // we expect exactly 8 public inputs from the tree root proof
        // 4 for the final aggregated public-input hash, 4 for the final aggregated verifier-data hash
        assert_eq!(node_common_data.num_public_inputs, 8);

        Self {
            node_common_data,
            phantom: PhantomData,
        }
    }

    /// Builds the circuit by:
    /// 1. Verifies a proof target with 8 public inputs (the final [pi_hash, vd_hash]).
    /// 2. verifies correct tree hashing of all T×K targets to represent all inner public inputs.
    /// 3. verifies correct tree hashing of node_verifier_date leaf_verifier_data and inner_verifier_data (each 4 field elements).
    pub fn build(&self, builder: &mut CircuitBuilder<F, D>) -> Result<PublicInputVerificationTargets<D>> {
        // Add a virtual proof with 8 public inputs. This is the final root proof whose
        //    public inputs we want to check in-circuit.
        let inner_proof = builder.add_virtual_proof_with_pis(&self.node_common_data);

        // Create a VerifierCircuitTarget for the node's verifier data (unhashed).
        let node_verifier_data = builder.add_virtual_verifier_data(
            self.node_common_data.config.fri_config.cap_height
        );

        // verify the proof
        builder.verify_proof::<C>(&inner_proof, &node_verifier_data, &self.node_common_data);

        // create T×K targets for all inner public inputs from the base level.
        let mut inner_pub_inputs = Vec::with_capacity(T);
        for _ in 0..T {
            let mut row = Vec::with_capacity(K);
            for _ in 0..K {
                row.push(builder.add_virtual_public_input()); // public input
            }
            inner_pub_inputs.push(row);
        }

        // ------------------------------------------------------------------
        //   Summary of the logic:
        //
        //   let final_pi = proof.public_inputs[0..4];
        //   let final_vd = proof.public_inputs[4..8];
        //   ...
        //   leaf-level pub inputs tree hashing: chunks of N -> hash -> combine with inner_verifier_data
        //   node-level pub inputs tree hashing: chunks of M -> hash -> combine with either leaf_hash (only level 0) or node_hash
        //   ...
        //   check final result matches final_pi, final_vd
        // ------------------------------------------------------------------

        // Extract the final 4 field elements for the public-input hash & next 4 for the verifier-data hash.
        let final_pi_hash_t = &inner_proof.public_inputs[0..4];
        let final_vd_hash_t = &inner_proof.public_inputs[4..8];

        // Compute node_hash in-circuit
        let mut node_vd_input_t = Vec::new();
        node_vd_input_t.extend_from_slice(&node_verifier_data.circuit_digest.elements);
        for cap_elem in node_verifier_data.constants_sigmas_cap.0.iter() {
            node_vd_input_t.extend_from_slice(&cap_elem.elements);
        }
        let node_hash_t = builder.hash_n_to_hash_no_pad::<H>(node_vd_input_t);
        builder.register_public_inputs(&node_hash_t.elements); // public input


        let mut pub_in_hashes_t = Vec::new();
        let mut vd_hashes_t = Vec::new();

        // hash targets for the leaf and inner circuit's verifier data.
        let leaf_hash_t = builder.add_virtual_hash_public_input(); // public input
        let inner_hash_t = builder.add_virtual_hash_public_input(); // public input

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
            vd_hashes_t.push(inner_hash_t);
        }

        // Now at the node level:

        let mut level = 0;
        let mut current_len = base_chunks;

        while current_len > 1 {

            let next_len = (current_len + (M - 1)) / M;

            let mut next_pub_in_hashes_t = Vec::with_capacity(next_len);
            let mut next_vd_hashes_t = Vec::with_capacity(next_len);

            for i in 0..next_len {
                let start_idx = i * M;
                let end_idx = (start_idx + M).min(current_len);

                // flatten all pub_in_hashes in [start_idx..end_idx]
                let mut pi_flat = Vec::with_capacity((end_idx - start_idx) * 4);
                for j in start_idx..end_idx {
                    pi_flat.extend_from_slice(&pub_in_hashes_t[j].elements);
                }
                let pi_hash = builder.hash_n_to_hash_no_pad::<H>(pi_flat);

                // flatten all vd_hashes in [start_idx..end_idx]
                let mut vd_flat = Vec::with_capacity((end_idx - start_idx) * 4);
                for j in start_idx..end_idx {
                    vd_flat.extend_from_slice(&vd_hashes_t[j].elements);
                }
                // use leaf_hash if level == 0, else node_hash
                let hash_n_t = if level == 0 { leaf_hash_t } else { node_hash_t };
                vd_flat.extend_from_slice(&hash_n_t.elements);

                let vd_hash = builder.hash_n_to_hash_no_pad::<H>(vd_flat);

                next_pub_in_hashes_t.push(pi_hash);
                next_vd_hashes_t.push(vd_hash);
            }

            pub_in_hashes_t = next_pub_in_hashes_t;
            vd_hashes_t = next_vd_hashes_t;
            current_len = next_len;
            level += 1;
        }

        // now have exactly one pub_in_hash and one vd_hash
        let final_computed_pi_t = &pub_in_hashes_t[0];
        let final_computed_vd_t = &vd_hashes_t[0];

        // connect them to the final 8 public inputs of `inner_proof`.
        for i in 0..4 {
            builder.connect(final_pi_hash_t[i], final_computed_pi_t.elements[i]);
            builder.connect(final_vd_hash_t[i], final_computed_vd_t.elements[i]);
        }

        // return all the targets
        Ok(PublicInputVerificationTargets {
            inner_proof,
            node_verifier_data,
            leaf_verifier_data: leaf_hash_t,
            inner_verifier_data: inner_hash_t,
            inner_pub_inputs,
        })
    }

    /// Assigns witness values to the targets.
    /// - `inner_proof`: The tree root proof with 8 public inputs [pi_hash, vd_hash].
    /// - `inner_pub_inputs_vals`: T×K public input values from inner proofs.
    /// - `node_verifier_data`: node verifier data
    /// - `leaf_verifier_data`: leaf circuit’s verifier data.
    /// - `inner_verifier_data`:inner-circuit’s verifier data.
    pub fn assign_targets(
        &self,
        pw: &mut PartialWitness<F>,
        targets: &PublicInputVerificationTargets<D>,
        inner_proof: ProofWithPublicInputs<F, C, D>,
        inner_pub_inputs_vals: Vec<Vec<F>>,
        node_verifier_data: &VerifierCircuitData<F, C, D>,
        leaf_verifier_data: &VerifierCircuitData<F, C, D>,
        inner_verifier_data: &VerifierCircuitData<F, C, D>,
    ) -> Result<()> {
        // Assign the final proof - it should have 8 public inputs
        pw.set_proof_with_pis_target(&targets.inner_proof, &inner_proof)
            .map_err(|e| {
                CircuitError::ProofTargetAssignmentError("final-proof".to_string(), e.to_string())
            })?;

        // Assign T×K inner public inputs
        if inner_pub_inputs_vals.len() != T {
            return Err(CircuitError::InvalidArgument(format!(
                "Expected T={} rows of inner_pub_inputs_vals, got {}",
                T,
                inner_pub_inputs_vals.len()
            )));
        }
        for (i, row_vals) in inner_pub_inputs_vals.into_iter().enumerate() {
            if row_vals.len() != K {
                return Err(CircuitError::InvalidArgument(format!(
                    "Expected K={} values in row {}, got {}",
                    K,
                    i,
                    row_vals.len()
                )));
            }
            for (j, val) in row_vals.into_iter().enumerate() {
                pw.set_target(targets.inner_pub_inputs[i][j], val).map_err(|e| {
                    CircuitError::TargetAssignmentError(format!("inner public input index [{}][{}]", i,j), e.to_string())
                })?;
            }
        }

        // Assign the node verifier data
        pw.set_verifier_data_target(&targets.node_verifier_data, &node_verifier_data.verifier_only)
            .map_err(|e| {
                CircuitError::VerifierDataTargetAssignmentError(e.to_string())
            })?;

        // Assign the leaf circuit’s verifier data
        let leaf_hash = Self::get_hash_of_verifier_data(leaf_verifier_data);
        pw.set_hash_target(targets.leaf_verifier_data, leaf_hash).map_err(|e| {
            CircuitError::HashTargetAssignmentError("leaf verifier data hash".to_string(), e.to_string())
        })?;

        // Assign the inner circuit’s verifier data
        let inner_hash = Self::get_hash_of_verifier_data(inner_verifier_data);
        pw.set_hash_target(targets.inner_verifier_data, inner_hash).map_err(|e| {
            CircuitError::HashTargetAssignmentError("inner verifier data hash".to_string(), e.to_string())
        })?;

        Ok(())
    }

    /// helper fn to generate hash of verifier data
    fn get_hash_of_verifier_data(verifier_data: &VerifierCircuitData<F, C, D>) -> HashOut<F>{
        let mut vd = vec![];
        let digest: &HashOut<F> = &verifier_data.verifier_only.circuit_digest;
        let caps = &verifier_data.verifier_only.constants_sigmas_cap;
        vd.extend_from_slice(&digest.elements);
        for i in 0..verifier_data.common.config.fri_config.num_cap_elements() {
            let cap_hash = caps.0[i] as HashOut<F>;
            vd.extend_from_slice(&cap_hash.elements);
        }

        H::hash_no_pad(&vd)
    }
}
