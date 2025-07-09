use std::marker::PhantomData;
use plonky2::hash::hash_types::{HashOut, RichField};
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::VerifierCircuitData;
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2::plonk::proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget};
use plonky2_field::extension::Extendable;
use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2;
use crate::{error::CircuitError,Result};
use crate::circuit_trait::Plonky2Circuit;
use crate::recursion::dummy_gen::DummyProofGen;
use crate::recursion::utils::{bucket_count, compute_flag_buckets};

/// the bucket size is the number of flags in each bucket where:
/// bucket: is a single Goldilocks field element where only `BUCKET_SIZE` bits are used for flags.
/// flags: is a boolean which indicates whether the inner proof is real or dummy.
/// flag_buckets: is a vector of M buckets, where each bucket contains `BUCKET_SIZE` flags.
/// Typically, M = ceil(T/BUCKET_SIZE) where T is the total number of inner proofs in the recursion tree.
pub const BUCKET_SIZE: usize = 32;

/// recursion leaf circuit - verifies 1 inner proof
/// the inner proof can be real or dummy
/// T: total number of inner (sampling) proofs
/// inner_verifier_data: is the verifier data for the inner (sampling) circuit
#[derive(Clone, Debug)]
pub struct LeafCircuit<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    C: GenericConfig<D, F = F>,
    H: AlgebraicHasher<F>,
    const T: usize,
> where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>
{
    inner_verifier_data: VerifierCircuitData<F, C, D>,
    phantom_data: PhantomData<H>
}

/// recursion leaf targets
/// inner_proof: inner (sampling) proofs
/// index: index of the leaf
/// flags: boolean target for each flag/signal for switching between real and dummy inner proof
#[derive(Clone, Debug)]
pub struct LeafTargets <
    const D: usize,
>{
    pub inner_proof: ProofWithPublicInputsTarget<D>,
    pub index: Target, // public input
    pub flag: BoolTarget,
}

#[derive(Clone, Debug)]
pub struct LeafInput<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    C: GenericConfig<D, F = F>,
>{
    pub inner_proof: ProofWithPublicInputs<F, C, D>,
    pub flag: bool,
    pub index: usize
}

impl<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    C: GenericConfig<D, F = F>,
    H: AlgebraicHasher<F>,
    const T: usize,
> LeafCircuit<F,D,C,H,T> where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>
{
    pub fn new(
        inner_verifier_data: VerifierCircuitData<F, C, D>,
    ) -> Self {
        Self {
            inner_verifier_data,
            phantom_data: PhantomData::default(),
        }
    }

}

impl<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    C: GenericConfig<D, F = F>,
    H: AlgebraicHasher<F>,
    const T: usize,
> Plonky2Circuit<F, C, D> for LeafCircuit<F,D,C,H,T> where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>
{
    type Targets = LeafTargets<D>;
    type Input = LeafInput<F, D, C>;

    /// The circuit logic:
    /// - create a virtual proof with public inputs
    /// - hash the public inputs of the virtual proof and make it public
    /// - add zero hash to the public inputs so that it shares the same structure as the tree node
    /// - add two virtual constant targets for the verifier data, one for real inner proof and one for dummy inner proof
    /// - add virtual target for the flag and index, and only assign the index as public.
    /// - compute the flag buckets from the index and flag and make them public
    /// - select the required verifier data based on the flag (either real or dummy).
    /// - verify the inner proof in-circuit using the selected verifier data.
    ///
    /// The public inputs are:
    /// - the hash of the public inputs of the inner proof (4 Goldilocks).
    /// - the zero hash (4 Goldilocks).
    /// - the flag buckets = M Goldilocks where M = ceil(T/BUCKET_SIZE).
    /// The private inputs are:
    /// - the inner proof with public inputs
    /// - the flag. We don't need this to be public since the flag_buckets (containing the flag) are public.
    fn add_targets(&self, builder: &mut CircuitBuilder<F, D>, register_pi: bool) -> Result<LeafTargets<D>> {

        let inner_common = self.inner_verifier_data.common.clone();
        let n_bucket: usize = bucket_count(T);

        // the proof virtual target
        let vir_proof = builder.add_virtual_proof_with_pis(&inner_common);
        let inner_pub_input = vir_proof.public_inputs.clone();

        // hash the public input & make it public
        let hash_inner_pub_input = builder.hash_n_to_hash_no_pad::<H>(inner_pub_input);
        if register_pi {
            builder.register_public_inputs(&hash_inner_pub_input.elements);
        }

        // pad the public input with constants so that it shares the same structure as the node
        let zero_hash = builder.constant_hash(HashOut::<F>::default());
        if register_pi {
            builder.register_public_inputs(&zero_hash.elements);
        }

        // virtual constant target for the verifier data
        let const_verifier_data = builder.constant_verifier_data(&self.inner_verifier_data.verifier_only);

        // virtual constant target for dummy verifier data
        let const_dummy_vd = builder.constant_verifier_data(
            &DummyProofGen::<F,D,C>::gen_dummy_verifier_data(&inner_common)
        );

        // index: 0 <= index < T where T = total number of proofs
        let index = builder.add_virtual_public_input();
        let flag = builder.add_virtual_bool_target_safe();

        // Instead of taking flag_buckets as external public inputs,
        // compute them internally from the index and flag.
        let computed_flag_buckets = compute_flag_buckets(builder, index, flag, BUCKET_SIZE, n_bucket)?;
        // register these outputs as part of your public input vector:
        if register_pi {
            builder.register_public_inputs(&computed_flag_buckets);
        }

        // verify the proofs in-circuit based on the
        // true (1) -> real proof, false (0) -> dummy proof
        let selected_vd = builder.select_verifier_data(flag.clone(), &const_verifier_data, &const_dummy_vd);
        builder.verify_proof::<C>(&vir_proof, &selected_vd, &inner_common);

        // Make sure we have every gate to match `common_data`.
        for g in &inner_common.gates {
            builder.add_gate_to_gate_set(g.clone());
        }

        // return targets
        let t = LeafTargets {
            inner_proof: vir_proof,
            index,
            flag,
        };
        Ok(t)

    }

    fn assign_targets(
        &self, pw: &mut PartialWitness<F>,
        targets: &Self::Targets,
        input: &Self::Input,
    ) -> Result<()> {
        assert!(input.index <= T, "given index is not valid");
        // assign the proofs
        pw.set_proof_with_pis_target(&targets.inner_proof, &input.inner_proof)
            .map_err(|e| {
                CircuitError::ProofTargetAssignmentError("inner-proof".to_string(), e.to_string())
            })?;

        // Assign the global index.
        pw.set_target(targets.index, F::from_canonical_u64(input.index as u64))
            .map_err(|e| CircuitError::TargetAssignmentError(format!("index {}", input.index),e.to_string()))?;
        // Assign the flag/condition for real/fake inner proof.
        pw.set_bool_target(targets.flag, input.flag)
            .map_err(|e| CircuitError::TargetAssignmentError(format!("flag {}", input.flag), e.to_string()))?;

        Ok(())
    }

}


