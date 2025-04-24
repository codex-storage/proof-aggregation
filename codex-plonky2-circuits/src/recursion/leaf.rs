use std::marker::PhantomData;
use plonky2::hash::hash_types::{HashOut, RichField};
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CommonCircuitData, VerifierOnlyCircuitData};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2::plonk::proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget};
use plonky2_field::extension::Extendable;
use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2;
use crate::{error::CircuitError,Result};
use crate::circuit_helper::Plonky2Circuit;
use crate::recursion::dummy_gen::DummyProofGen;
use crate::recursion::utils::{bucket_count, compute_flag_buckets};

pub const BUCKET_SIZE: usize = 32;

/// recursion leaf circuit - verifies N inner proof
/// N: number of inner proofs
/// T: total number of sampling proofs
#[derive(Clone, Debug)]
pub struct LeafCircuit<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    C: GenericConfig<D, F = F>,
    H: AlgebraicHasher<F>,
    const N: usize,
    const T: usize,
> where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>
{
    inner_common_data: CommonCircuitData<F, D>,
    inner_verifier_data: VerifierOnlyCircuitData<C, D>,
    phantom_data: PhantomData<H>
}

/// recursion leaf targets
/// inner_proof: inner (sampling) proofs
/// index: index of the node
/// flags: boolean target for each flag/signal for switching between real and dummy leaf proof
#[derive(Clone, Debug)]
pub struct LeafTargets <
    const D: usize,
>{
    pub inner_proof: Vec<ProofWithPublicInputsTarget<D>>,
    pub index: Target, // public input
    // TODO: change this to vec of size N so that one flag per inner-proof
    pub flag: BoolTarget,
}

#[derive(Clone, Debug)]
pub struct LeafInput<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    C: GenericConfig<D, F = F>,
>{
    pub inner_proof: Vec<ProofWithPublicInputs<F, C, D>>,
    pub flag: bool,
    pub index: usize
}

impl<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    C: GenericConfig<D, F = F>,
    H: AlgebraicHasher<F>,
    const N: usize,
    const T: usize,
> LeafCircuit<F,D,C,H,N,T> where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>
{
    pub fn new(
        inner_common_data: CommonCircuitData<F, D>,
        inner_verifier_data: VerifierOnlyCircuitData<C, D>,
    ) -> Self {
        Self {
            inner_common_data,
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
    const N: usize,
    const T: usize,
> Plonky2Circuit<F, C, D> for LeafCircuit<F,D,C,H,N,T> where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>
{
    type Targets = LeafTargets<D>;
    type Input = LeafInput<F, D, C>;

    fn add_targets(&self, builder: &mut CircuitBuilder<F, D>, register_pi: bool) -> Result<LeafTargets<D>> {

        let inner_common = self.inner_common_data.clone();
        let n_bucket: usize = bucket_count(T);

        // the proof virtual targets
        let mut pub_input = vec![];
        let mut vir_proofs = vec![];
        for _i in 0..N {
            let vir_proof = builder.add_virtual_proof_with_pis(&inner_common);
            let inner_pub_input = vir_proof.public_inputs.clone();
            vir_proofs.push(vir_proof);
            pub_input.extend_from_slice(&inner_pub_input);
        }

        // hash the public input & make it public
        let hash_inner_pub_input = builder.hash_n_to_hash_no_pad::<H>(pub_input);
        if register_pi {
            builder.register_public_inputs(&hash_inner_pub_input.elements);
        }

        // pad the public input with constants so that it shares the same structure as the node
        let zero_hash = builder.constant_hash(HashOut::<F>::default());
        if register_pi {
            builder.register_public_inputs(&zero_hash.elements);
        }

        // virtual constant target for the verifier data
        let const_verifier_data = builder.constant_verifier_data(&self.inner_verifier_data);

        // virtual constant target for dummy verifier data
        let const_dummy_vd = builder.constant_verifier_data(
            &DummyProofGen::<F,D,C>::gen_dummy_verifier_data(&self.inner_common_data)
        );

        // index: 0 <= index < T where T = total number of proofs
        let index = builder.add_virtual_public_input();
        let flag = builder.add_virtual_bool_target_safe();

        // Instead of taking flag_buckets as external public inputs,
        // compute them internally from the index and flag.
        let computed_flag_buckets = compute_flag_buckets(builder, index, flag, BUCKET_SIZE, n_bucket)?;
        // Then, for example, you could register these outputs as part of your public input vector:
        if register_pi {
            builder.register_public_inputs(&computed_flag_buckets);
        }

        // verify the proofs in-circuit based on the
        // true -> real proof, false -> dummy proof
        let selected_vd = builder.select_verifier_data(flag.clone(), &const_verifier_data, &const_dummy_vd);
        for i in 0..N {
            builder.verify_proof::<C>(&vir_proofs[i], &selected_vd, &inner_common);
        }

        // Make sure we have every gate to match `common_data`.
        for g in &inner_common.gates {
            builder.add_gate_to_gate_set(g.clone());
        }

        // return targets
        let t = LeafTargets {
            inner_proof: vir_proofs,
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
        assert_eq!(input.inner_proof.len(), N);
        assert!(input.index <= T && input.index >= 0, "given index is not valid");
        // assign the proofs
        for i in 0..N {
            pw.set_proof_with_pis_target(&targets.inner_proof[i], &input.inner_proof[i])
                .map_err(|e| {
                    CircuitError::ProofTargetAssignmentError("inner-proof".to_string(), e.to_string())
                })?;
        }

        // Assign the global index.
        pw.set_target(targets.index, F::from_canonical_u64(input.index as u64))
            .map_err(|e| CircuitError::TargetAssignmentError(format!("index {}", input.index),e.to_string()))?;
        // Assign the flag/condition for real/fake inner proof.
        pw.set_bool_target(targets.flag, input.flag)
            .map_err(|e| CircuitError::TargetAssignmentError(format!("flag {}", input.flag), e.to_string()))?;

        Ok(())
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::config::GenericConfig;
    use plonky2_field::types::{Field, PrimeField64};
    use plonky2::plonk::circuit_data::{CircuitConfig, CommonCircuitData};
    use plonky2_poseidon2::poseidon2_hash::poseidon2::{Poseidon2, Poseidon2Hash};

    // For our tests, we define:
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    type H = Poseidon2Hash;

    /// A helper to build a minimal circuit and return the common circuit data.
    fn dummy_common_circuit_data() -> CommonCircuitData<F, D> {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        // Add one virtual public input so that the circuit has minimal structure.
        builder.add_virtual_public_input();
        let circuit = builder.build::<C>();
        circuit.common.clone()
    }

    // ----------------------------------------------------------------------------
    // End-to-End test for the entire leaf circuit.
    #[test]
    fn test_full_leaf_circuit() -> anyhow::Result<()> {
        const N: usize = 1;

        // get inner common
        let common_data = dummy_common_circuit_data();

        // Generate a dummy inner proof for the leaf using DummyProofGen
        let (dummy_inner_proof, vd) = DummyProofGen::<F, D, C>::gen_dummy_proof_and_vd_zero_pi(&common_data)?;
        let dummy_verifier_data = DummyProofGen::<F, D, C>::gen_dummy_verifier_data(&common_data);

        // the leaf circuit.
        let leaf = LeafCircuit::<F, D, C, H, N, 4>::new(common_data.clone(), dummy_verifier_data);

        // Build the leaf circuit.
        let (targets, circuit_data) = leaf.build_with_standard_config()?;
        let verifier_data = circuit_data.verifier_data();
        let prover_data = circuit_data.prover_data();

        // test leaf input
        let input = LeafInput {
            inner_proof: vec![dummy_inner_proof],
            flag: true,
            index: 45,
        };

        let proof = leaf.prove(&targets, &input, &prover_data)?;

        // Verify the proof.
        assert!(verifier_data.verify(proof.clone()).is_ok(), "Proof verification failed");

        println!("Public inputs: {:?}", proof.public_inputs);

        // the flag buckets appeared at positions 8..12.
        let flag_buckets: Vec<u64> = proof.public_inputs[9..13]
            .iter()
            .map(|f| f.to_canonical_u64())
            .collect();

        // With index = 45, we expect bucket[1] = 2^13 = 8192, and the rest 0.
        let expected = vec![0, 8192, 0, 0];
        assert_eq!(flag_buckets, expected, "Flag bucket values mismatch");

        Ok(())
    }
}


