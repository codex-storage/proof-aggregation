use std::marker::PhantomData;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{VerifierCircuitData, VerifierCircuitTarget, VerifierOnlyCircuitData};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2::plonk::proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget};
use plonky2_field::extension::Extendable;
use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2;
use crate::{error::CircuitError,Result};
use crate::circuit_trait::Plonky2Circuit;
use crate::recursion::dummy_gen::DummyProofGen;
use crate::recursion::utils::bucket_count;

/// recursion node circuit
/// N: number of leaf proofs
/// T: total number of sampling proofs
#[derive(Clone, Debug)]
pub struct NodeCircuit<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    C: GenericConfig<D, F = F>,
    H: AlgebraicHasher<F>,
    const N: usize,
    const T: usize,
> where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>
{
    leaf_verifier_data: VerifierCircuitData<F, C, D>,
    phantom_data: PhantomData<H>
}

/// recursion node targets
/// leaf_proofs: leaf proofs
/// node_verifier_data: node verifier data, note: leaf verifier data is constant
/// condition: for switching between leaf and node verifier data
/// index: index of the node
/// flags: boolean target for each flag/signal for switching between real and dummy leaf proof
#[derive(Clone, Debug)]
pub struct NodeTargets<
    const D: usize,
>{
    pub inner_proofs: Vec<ProofWithPublicInputsTarget<D>>,
    pub inner_verifier_data: VerifierCircuitTarget,
    pub condition: BoolTarget,
    pub index: Target,
    pub flags: Vec<BoolTarget>,
}

#[derive(Clone, Debug)]
pub struct NodeInput<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    C: GenericConfig<D, F = F>,
>{
    pub inner_proofs: Vec<ProofWithPublicInputs<F, C, D>>,
    pub verifier_only_data: VerifierOnlyCircuitData<C, D>,
    pub condition: bool,
    pub flags: Vec<bool>,
    pub index: usize
}

impl<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    C: GenericConfig<D, F = F>,
    H: AlgebraicHasher<F>,
    const N: usize,
    const T: usize,
> NodeCircuit<F,D,C,H, N,T> where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>
{

    pub fn new(
        leaf_verifier_data: VerifierCircuitData<F, C, D>,
    ) -> Self {
        assert!(N.is_power_of_two(), "M is NOT a power of two");
        Self{
            leaf_verifier_data,
            phantom_data:PhantomData::default(),
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
> Plonky2Circuit<F, C, D> for NodeCircuit<F, D, C, H, N, T> where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>
{
    type Targets = NodeTargets<D>;
    type Input = NodeInput<F, D, C>;

    fn add_targets(&self, builder: &mut CircuitBuilder<F, D>, register_pi: bool) -> Result<Self::Targets> {
        let inner_common = self.leaf_verifier_data.common.clone();
        let zero_target = builder.zero();

        // assert public input is of size 8 + 1 (index) + B (flag buckets)
        let n_bucket: usize = bucket_count(T);
        assert_eq!(inner_common.num_public_inputs, 9+n_bucket);

        // the proof virtual targets - M proofs
        let mut vir_proofs = vec![];
        let mut pub_input = vec![];
        let mut inner_flag_buckets = vec![];
        let mut inner_indexes = vec![];
        for _i in 0..N {
            let vir_proof = builder.add_virtual_proof_with_pis(&inner_common);
            let inner_pub_input = vir_proof.public_inputs.clone();
            vir_proofs.push(vir_proof);
            pub_input.extend_from_slice(&inner_pub_input[0..4]);
            inner_indexes.push(inner_pub_input[8]);
            inner_flag_buckets.push(inner_pub_input[9..(9+n_bucket)].to_vec());
        }

        // hash the public input & make it public
        let hash_inner_pub_input = builder.hash_n_to_hash_no_pad::<H>(pub_input);
        if register_pi{
            builder.register_public_inputs(&hash_inner_pub_input.elements);
        }

        // virtual target for the verifier data
        let node_verifier_data = builder.add_virtual_verifier_data(inner_common.config.fri_config.cap_height);

        // virtual target for the verifier data
        let const_leaf_verifier_data = builder.constant_verifier_data(&self.leaf_verifier_data.verifier_only);

        // virtual constant target for dummy verifier data
        let const_dummy_vd = builder.constant_verifier_data(
            &DummyProofGen::<F,D,C>::gen_dummy_verifier_data(&inner_common)
        );

        // register only the node verifier data hash as public input.
        let mut vd_pub_input = vec![];
        vd_pub_input.extend_from_slice(&node_verifier_data.circuit_digest.elements);
        for i in 0..builder.config.fri_config.num_cap_elements() {
            vd_pub_input.extend_from_slice(&node_verifier_data.constants_sigmas_cap.0[i].elements);
        }
        let vd_hash = builder.hash_n_to_hash_no_pad::<H>(vd_pub_input);
        if register_pi {
            builder.register_public_inputs(&vd_hash.elements);
        }

        // condition for switching between node and leaf
        let condition = builder.add_virtual_bool_target_safe();

        // flag buckets targets
        let mut flag_buckets: Vec<Target> = (0..n_bucket).map(|_i| zero_target.clone()).collect();
        // index: 0 <= index < T where T = total number of proofs
        let index = builder.add_virtual_public_input();
        let flags: Vec<BoolTarget> = (0..N).map(|_i| builder.add_virtual_bool_target_safe()).collect();

        // condition: true -> node, false -> leaf
        let node_or_leaf_vd = builder.select_verifier_data(condition.clone(), &node_verifier_data, &const_leaf_verifier_data);
        // verify the proofs in-circuit  - M proofs
        for i in 0..N {
            // flag: true -> real, false -> dummy
            let selected_vd = builder.select_verifier_data(flags[i].clone(), &node_or_leaf_vd, &const_dummy_vd);
            builder.verify_proof::<C>(&vir_proofs[i], &selected_vd, &inner_common);
        }

        // Check flag buckets for dummy inner proofs:
        // For each inner proof, if its corresponding flag `flags[i]` is false,
        // then enforce that every bucket in inner_flag_buckets[i] is zero.
        for i in 0..N {
            let not_flag_i = builder.not(flags[i]);
            let not_flag_val = not_flag_i.target;
            for j in 0..n_bucket {
                // Enforce: inner_flag_buckets[i][j] * (not_flag_val) = 0.
                // If flag is false then not_flag_val = 1, forcing inner_flag_buckets[i][j] to be zero
                let product = builder.mul(inner_flag_buckets[i][j], not_flag_val);
                builder.connect(product, zero_target.clone());
            }
        }

        // check inner proof indexes are correct
        let m_const = builder.constant(F::from_canonical_u64(N as u64));
        let mut expected_inner_index = builder.mul(index, m_const);
        for i in 0..N {
            if i > 0 {
                let i_const = builder.constant(F::from_canonical_u64(i as u64));
                expected_inner_index = builder.add(expected_inner_index, i_const);
            }
            builder.connect(expected_inner_index, inner_indexes[i]);
        }

        // add flag buckets
        for i in 0..flag_buckets.len(){
            for j in 0..inner_flag_buckets.len() {
                flag_buckets[i] = builder.add(flag_buckets[i], inner_flag_buckets[j][i]);
            }
        }
        // make flag buckets public
        builder.register_public_inputs(&flag_buckets);

        // Make sure we have every gate
        for g in &inner_common.gates {
            builder.add_gate_to_gate_set(g.clone());
        }

        // return targets
        let t = NodeTargets {
            inner_proofs: vir_proofs,
            inner_verifier_data: node_verifier_data,
            condition,
            index,
            flags,
        };

        Ok(t)
    }

    fn assign_targets(&self, pw: &mut PartialWitness<F>, targets: &Self::Targets, input: &Self::Input) -> Result<()> {
        // assert size of proofs vec
        assert_eq!(input.inner_proofs.len(), N);
        assert_eq!(input.flags.len(), N);
        assert!(input.index <= T, "given index is not valid");

        // assign the proofs
        for i in 0..N {
            pw.set_proof_with_pis_target(&targets.inner_proofs[i], &input.inner_proofs[i])
                .map_err(|e| {
                    CircuitError::ProofTargetAssignmentError("inner-proof".to_string(), e.to_string())
                })?;
        }

        // assign the verifier data
        pw.set_verifier_data_target(&targets.inner_verifier_data, &input.verifier_only_data)
            .map_err(|e| {
                CircuitError::VerifierDataTargetAssignmentError(e.to_string())
            })?;

        // assign the condition - for switching between leaf & node
        pw.set_bool_target(targets.condition, input.condition)
            .map_err(|e| CircuitError::BoolTargetAssignmentError("condition".to_string(), e.to_string()))?;

        // Assign the global index.
        pw.set_target(targets.index, F::from_canonical_u64(input.index as u64))
            .map_err(|e| CircuitError::TargetAssignmentError(format!("index {}", input.index),e.to_string()))?;
        // Assign the flags - switch between real & fake proof
        for i in 0..N {
            pw.set_bool_target(targets.flags[i], input.flags[i])
                .map_err(|e| CircuitError::TargetAssignmentError(format!("flag {}", input.flags[i]), e.to_string()))?;
        }
        Ok(())
    }
}

