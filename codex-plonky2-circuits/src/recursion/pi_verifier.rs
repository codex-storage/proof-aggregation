use std::marker::PhantomData;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::{CircuitBuilder};
use plonky2::plonk::circuit_data::VerifierCircuitData;
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2::plonk::proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget};
use plonky2_field::extension::Extendable;
use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2;
use crate::{error::CircuitError, Result};
use crate::circuit_trait::Plonky2Circuit;

/// A circuit that verifies the aggregated public inputs from inner circuits.
/// - `N`: Number of leaf proofs aggregated at the node level.
/// - `T`: Total Number of inner-proofs.
/// - `K`: Number of public input field elements per inner-proof (sampling proof).
#[derive(Clone, Debug)]
pub struct PublicInputVerificationCircuit<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    C: GenericConfig<D, F = F>,
    H: AlgebraicHasher<F>,
    const N: usize,
    const T: usize,
    const K: usize,
> where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub node_verifier_data: VerifierCircuitData<F, C, D>,
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
/// - `inner_proof`: The tree root proof with public inputs: [pi_hash, vd_hash, ...].
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

impl<F, const D: usize, C, H, const N: usize, const T: usize, const K: usize>
PublicInputVerificationCircuit<F, D, C, H, N, T, K>
    where
        F: RichField + Extendable<D> + Poseidon2,
        C: GenericConfig<D, F = F>,
        H: AlgebraicHasher<F>,
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    /// Create a new instance of the circuit.
    pub fn new(
        node_verifier_data: VerifierCircuitData<F, C, D>,
    ) -> Self {
        // we expect at least 4 public inputs from the tree root proof
        // 1 hash digest (4 Goldilocks) for the final aggregated public-input hash
        assert!(node_verifier_data.common.num_public_inputs >= 4);

        Self {
            node_verifier_data,
            phantom: PhantomData,
        }
    }
}
impl<F, const D: usize, C, H, const N: usize, const T: usize, const K: usize>
Plonky2Circuit<F, C, D> for PublicInputVerificationCircuit<F, D, C, H, N, T, K>
    where
        F: RichField + Extendable<D> + Poseidon2,
        C: GenericConfig<D, F = F>,
        H: AlgebraicHasher<F>,
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    type Targets = PublicInputVerificationTargets<D>;
    type Input = PublicInputVerificationInput<F, D, C>;

    /// Builds the circuit by:
    /// 1. Verifies a proof target with public inputs (the final [pi_hash, vd_hash, ...]).
    /// 2. verifies correct tree hashing of all T×K targets to represent all inner public inputs.
    /// 3. register the un-hashed inner public input as this circuit public input + the rest of the inner public input
    fn add_targets(&self, builder: &mut CircuitBuilder<F, D>, register_pi: bool) -> Result<PublicInputVerificationTargets<D>> {
        // Add a virtual proof with 8 public inputs. This is the final root proof whose
        // public inputs we want to check in-circuit.
        let inner_proof = builder.add_virtual_proof_with_pis(&self.node_verifier_data.common);

        // Create a constant VerifierCircuitTarget for the node's verifier data.
        let const_node_vd = builder.constant_verifier_data(&self.node_verifier_data.verifier_only);

        // verify the proof
        builder.verify_proof::<C>(&inner_proof, &const_node_vd, &self.node_verifier_data.common);

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
        //   ...
        //   leaf-level pub inputs tree hashing
        //   node-level pub inputs tree hashing: chunks of N -> hash
        //   ...
        //   check final result matches final_pi
        // ------------------------------------------------------------------

        // Extract the final 4 field elements for the public-input hash & the rest for the verifier-data hash, index, and flags.
        let final_pi_hash_target = &inner_proof.public_inputs[0..4];
        let rest_of_inner_pi = &inner_proof.public_inputs[4..];
        builder.register_public_inputs(&rest_of_inner_pi); // public input

        let mut pub_in_hashes_t = Vec::new();

        // Leaf level hashing - hash each row i = 0..T of inner_pub_inputs matrix
        for i in 0..T {
            // hash
            let pi_hash_chunk = builder.hash_n_to_hash_no_pad::<H>(inner_pub_inputs[i].clone());
            // track these in hash digests
            pub_in_hashes_t.push(pi_hash_chunk);
        }

        // Now at the node level:
        let mut current_len = 0;
        while current_len > 1 {

            let next_len = (current_len + (N - 1)) / N;

            let mut next_pub_in_hashes_t = Vec::with_capacity(next_len);

            for i in 0..next_len {
                let start_idx = i * N;
                let end_idx = (start_idx + N).min(current_len);

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
            builder.connect(final_pi_hash_target[i], final_computed_pi_t.elements[i]);
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
        // Assign the tree root proof
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
