use plonky2::gates::constant::ConstantGate;
use plonky2::gates::noop::NoopGate;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::BoolTarget;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitTarget, VerifierOnlyCircuitData};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2::plonk::proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget};
use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2;
use crate::recursion::circuits::inner_circuit::InnerCircuit;
use plonky2_field::extension::Extendable;
use crate::circuits::utils::{select_hash, select_vec, vec_to_array};
use crate::{error::CircuitError, Result};
use crate::recursion::tree2::leaf_circuit::LeafCircuit;

/// Node circuit struct
/// contains necessary data
/// N: number of proofs verified in-circuit (so num of child nodes)
pub struct NodeCircuit<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    C: GenericConfig<D, F = F>,
    const N: usize,
>{
    pub node_targets: NodeCircuitTargets<D, N>,
    pub node_data: NodeData<F, D, C>,
}

/// Node circuit targets
/// assumes that all leaf proofs use the same verifier data
#[derive(Clone, Debug)]
pub struct NodeCircuitTargets<
    const D: usize,
    const N: usize,
>{
    pub leaf_proofs: [ProofWithPublicInputsTarget<D>; N],
    pub condition: BoolTarget,
    pub node_proofs: [ProofWithPublicInputsTarget<D>; N],
    pub leaf_verifier_data: VerifierCircuitTarget,
}

/// Node common data and verifier data
#[derive(Debug)]
pub struct NodeData<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    C: GenericConfig<D, F = F>,
>{
    pub node_circuit_data: CircuitData<F, C, D>,
    pub inner_node_common_data: CommonCircuitData<F, D>,
    pub leaf_circuit_data: CircuitData<F, C, D>,
}

impl<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    C: GenericConfig<D, F = F> + 'static,
    const N: usize,
> NodeCircuit<F, D, C, N>
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>
{

    /// builds the node circuit
    /// the circuit data and targets are stored in the node struct
    /// TODO: make generic recursion config
    pub fn build_circuit<
        I: InnerCircuit<F, D>,
        H: AlgebraicHasher<F>
    >(
        leaf_circuit:LeafCircuit<F, D, I>
    ) -> Result<NodeCircuit<F, D, C, N>>{

        // builder with standard recursion config
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        // circuit data for leaf
        let leaf_circ_data = leaf_circuit.get_circuit_data::<C,H>()?;

        // common data for leaf
        let leaf_common = leaf_circ_data.common.clone();

        // virtual proofs for leaf proofs
        let mut leaf_proofs = vec![];
        for _i in 0..N {
            let vir_proof = builder.add_virtual_proof_with_pis(&leaf_common);
            leaf_proofs.push(vir_proof);
        }

        // get the public input hash from all inner proof targets
        let mut leaf_pub_input_hashes = vec![];
        for i in 0..N {
            let inner_cyclic_pis = &leaf_proofs[i].public_inputs;
            leaf_pub_input_hashes.extend_from_slice(&inner_cyclic_pis[0..4]);
        }

        // leaf verifier data
        // TODO: double check that it is ok for this verifier data to be private/witness
        let leaf_verifier_data = builder.add_virtual_verifier_data(leaf_common.config.fri_config.cap_height);

        // condition
        let condition = builder.add_virtual_bool_target_safe();

        // verify leaf proofs in-circuit if it is a leaf node,
        // meaning that we are on bottom layer of the tree
        for i in 0..N{
            builder.conditionally_verify_proof_or_dummy::<C>(
                condition,
                &leaf_proofs[i],
                &leaf_verifier_data,
                &leaf_common
            ).map_err(|e| CircuitError::ConditionalVerificationError(e.to_string()))?;
        }

        // common data for recursion
        let mut common_data = Self::get_common_data_for_node()?;
        // public input hash. defined here so that is public_input[0..4]
        let pub_input_hash = builder.add_virtual_hash_public_input();
        // verifier data for the recursion.
        let _verifier_data_target = builder.add_verifier_data_public_inputs();
        common_data.num_public_inputs = builder.num_public_inputs();

        // flipped condition. used to conditionally verify the node proofs (recursive proofs)
        let one = builder.one();
        let flipped_condition = BoolTarget::new_unsafe(builder.sub(one,condition.target));

        let inner_cyclic_proof_with_pis: [ProofWithPublicInputsTarget<D>; N] =
            vec_to_array::<N, ProofWithPublicInputsTarget<D>>(
                (0..N)
                .map(|_| builder.add_virtual_proof_with_pis(&common_data))
                .collect::<Vec<_>>()
            )?;

        // get the public input hash from all inner proof targets
        let mut inner_pub_input_hashes = vec![];
        for i in 0..N {
            let inner_cyclic_pis = &inner_cyclic_proof_with_pis[i].public_inputs;
            inner_pub_input_hashes.extend_from_slice(&inner_cyclic_pis[0..4]);
        }

        // select the public input - either leaf or node
        let pub_input_to_be_hashed = select_vec(&mut builder, condition, &leaf_pub_input_hashes ,&inner_pub_input_hashes);
        // hash all the node public input h = H(h_1 | h_2 | ... | h_N)
        let node_hash_or_leaf_hash= builder.hash_n_to_hash_no_pad::<H>(pub_input_to_be_hashed);

        builder.connect_hashes(pub_input_hash,node_hash_or_leaf_hash);

        // verify all N proofs in-circuit
        for i in 0..N {
            builder.conditionally_verify_cyclic_proof_or_dummy::<C>(
                flipped_condition,
                &inner_cyclic_proof_with_pis[i],
                &common_data,
            ).map_err(|e| CircuitError::ConditionalVerificationError(e.to_string()))?;
        }

        // build the node circuit
        let node_circuit_data = builder.build::<C>();

        // collect the leaf proofs
        let leaf_proofs: [ProofWithPublicInputsTarget<D>; N] =
            vec_to_array::<N, ProofWithPublicInputsTarget<D>>(
                (0..N).map(|i| {
                    leaf_proofs[i].clone()
                }).collect::<Vec<_>>()
            )?;

        // store targets
        let node_targets = NodeCircuitTargets::<D, N>{
            leaf_proofs,
            condition,
            node_proofs: inner_cyclic_proof_with_pis,
            leaf_verifier_data
        };

        let node_data = NodeData{
            node_circuit_data,
            inner_node_common_data: common_data,
            leaf_circuit_data: leaf_circ_data,
        };

        let node = NodeCircuit{
            node_targets,
            node_data,
        };

        Ok(node)
    }

    /// assigns the targets for the Node circuit - takes
    /// - either leaf or circuit proofs
    /// - leaf circuit data
    /// - partial witness
    /// - bool value, true if leaf node, otherwise false.
    pub fn assign_targets(
        node_targets: NodeCircuitTargets<D, N>,
        leaf_proofs: [ProofWithPublicInputs<F, C, D>; N],
        node_proofs: [ProofWithPublicInputs<F, C, D>; N],
        leaf_verifier_only_data: &VerifierOnlyCircuitData<C, D>,
        pw: &mut PartialWitness<F>,
        is_leaf: bool,
    ) -> Result<()>{

        if is_leaf == true {
            let dummy_node = node_proofs;
            // assign the condition
            pw.set_bool_target(node_targets.condition, true)
                .map_err(|e| CircuitError::BoolTargetAssignmentError("condition".to_string(),e.to_string()))?;
            for i in 0..N {
                // assign the node proofs with dummy
                pw.set_proof_with_pis_target::<C, D>(
                    &node_targets.node_proofs[i],
                    &dummy_node[i],
                ).map_err(|e| CircuitError::ProofTargetAssignmentError("dummy node proofs".to_string(),e.to_string()))?;
                // assign the leaf proof with real proofs
                pw.set_proof_with_pis_target(
                    &node_targets.leaf_proofs[i],
                    &leaf_proofs[i]
                ).map_err(|e| CircuitError::ProofTargetAssignmentError("leaf proofs".to_string(),e.to_string()))?;
            }
        }else{
            // assign the condition
            pw.set_bool_target(node_targets.condition, false)
                .map_err(|e| CircuitError::BoolTargetAssignmentError("condition".to_string(),e.to_string()))?;

            // dummy leaf
            let dummy_leaf = leaf_proofs;
            for i in 0..N {
                // assign the node proofs
                pw.set_proof_with_pis_target(&node_targets.node_proofs[i], &node_proofs[i])
                    .map_err(|e| CircuitError::ProofTargetAssignmentError("node proofs".to_string(),e.to_string()))?;

                // assign leaf proofs with dummy
                pw.set_proof_with_pis_target::<C, D>(
                    &node_targets.leaf_proofs[i],
                    &dummy_leaf[i],
                ).map_err(|e| CircuitError::ProofTargetAssignmentError("dummy leaf proofs".to_string(),e.to_string()))?;
            }
        }
        // assign the verifier data (only for the leaf proofs)
        pw.set_verifier_data_target(&node_targets.leaf_verifier_data, leaf_verifier_only_data)
            .map_err(|e| CircuitError::VerifierDataTargetAssignmentError(e.to_string()))?;

        Ok(())
    }

    /// Generates `CommonCircuitData` usable for node recursion.
    /// the circuit being built here depends on M and N so must be re-generated
    /// if the params change
    pub fn get_common_data_for_node() -> Result<CommonCircuitData<F, D>>
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
            ConstantGate::new(config.num_constants),
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

}