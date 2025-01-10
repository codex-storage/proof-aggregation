use plonky2::iop::target::BoolTarget;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitTarget, VerifierOnlyCircuitData};
use plonky2::plonk::config::GenericConfig;
use plonky2::plonk::proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget};
use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2;
use crate::params::{C, D, F, H};
use crate::recursion::circuits::inner_circuit::InnerCircuit;
use anyhow::{anyhow, Result};
use plonky2::recursion::cyclic_recursion::check_cyclic_proof_verifier_data;
// use serde::de::Unexpected::Option;
use crate::circuits::utils::select_hash;
use crate::recursion::tree2::leaf_circuit;
use crate::recursion::tree2::utils;
use crate::recursion::tree2::utils::{get_dummy_leaf_proof, get_dummy_node_proof};

/// the tree recursion struct simplifies the process
/// of building, proving and verifying
/// - N: number of inner proofs to verify in the node circuit
pub struct TreeRecursion<
    const N: usize,
>{
    pub node: NodeCircuit<N>
}

impl<
    const N: usize,
> TreeRecursion<N> {

    // pub fn new(node_circ: NodeCircuit<N>) -> Self{
    //     Self{
    //         node_circ,
    //     }
    // }

    pub fn build(
    ) -> Result<Self>{
        Ok(
            Self{
                node: NodeCircuit::<N>::build_circuit()?,
            }
        )
    }

    /// generates a proof - only one node
    /// takes N proofs
    pub fn prove(
        &mut self,
        // node_targets: NodeCircuitTargets<N>,
        leaf_proof_options: Option<[ProofWithPublicInputs<F, C, D>; N]>,
        node_proof_options: Option<[ProofWithPublicInputs<F, C, D>; N]>,
        // leaf_verifier_only_data: &VerifierOnlyCircuitData<C, D>,
        is_leaf: bool,
    ) -> Result<ProofWithPublicInputs<F, C, D>>{

        let mut pw = PartialWitness::new();

        NodeCircuit::assign_targets(
            self.node.node_targets.clone(),
            leaf_proof_options,
            node_proof_options,
            &self.node.node_data.leaf_circuit_data.verifier_only,
            &mut pw,
            is_leaf,
        )?;

        let proof = self.node.node_data.node_circuit_data.prove(pw)?;

        //TODO: move this to verify function
        if !is_leaf {
            check_cyclic_proof_verifier_data(
                &proof,
                &self.node.node_data.node_circuit_data.verifier_only,
                &self.node.node_data.node_circuit_data.common,
            )?;
        }

        Ok(proof)
    }

    /// prove n leaf proofs in a tree structure
    /// the function uses circuit data from self takes
    /// - leaf_proofs:  vector of circuit inputs
    pub fn prove_tree(
        &mut self,
        leaf_proofs: Vec<ProofWithPublicInputs<F, C, D>>,
    ) -> Result<ProofWithPublicInputs<F, C, D>> {
        // 1. Check the total number of leaf_proofs is divisible by N
        if leaf_proofs.len() % N != 0 {
            return Err(anyhow!(
            "input proofs must be divisible by {}, got {}",
            N,
            leaf_proofs.len()
        ));
        }

        // 2. Prepare the dummy proofs
        // let node_targets = self.node.node_targets.clone();

        let dummy_node_proof = get_dummy_node_proof(
            &self.node.node_data.inner_node_common_data,
            &self.node.node_data.node_circuit_data.verifier_only,
        );
        let dummy_node_proofs: [ProofWithPublicInputs<F, C, D>; N] = (0..N)
            .map(|_| dummy_node_proof.clone())
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| anyhow!("Expected exactly N node dummy proofs"))?;

        let dummy_leaf_proof = get_dummy_leaf_proof(&self.node.node_data.leaf_circuit_data.common);
        let dummy_leaf_proofs: [ProofWithPublicInputs<F, C, D>; N] = (0..N)
            .map(|_| dummy_leaf_proof.clone())
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| anyhow!("Expected exactly N leaf dummy proofs"))?;

        // 3. Work through levels of proofs until only one remains
        let mut current_level_proofs = leaf_proofs;

        // Keep reducing until we’re left with 1 proof
        let mut level: usize = 0;
        while current_level_proofs.len() >= N {
            let mut next_level_proofs = Vec::new();

            // Process in chunks of N
            for chunk in current_level_proofs.chunks_exact(N) {
                // Convert the chunk slice into a fixed-size array
                let chunk_array: [ProofWithPublicInputs<F, C, D>; N] = chunk
                    .to_vec() // create a Vec
                    .try_into()
                    .map_err(|_| anyhow!("Failed to convert to array of size N"))?;

                // Decide which side is the leaf or node
                // The logic here assumes the "first" chunk is the leaf
                let (leaf_chunk, node_chunk, is_leaf) = if level == 0 {
                    (chunk_array, dummy_node_proofs.clone(), true)
                } else {
                    (dummy_leaf_proofs.clone(), chunk_array, false)
                };

                let node = self.prove(
                    // node_targets.clone(),
                    Some(leaf_chunk),
                    Some(node_chunk),
                    is_leaf,
                )?;

                next_level_proofs.push(node);
            }

            current_level_proofs = next_level_proofs;
            level = level + 1;
        }

        // 4. Check that exactly one proof remains
        if current_level_proofs.len() != 1 {
            return Err(anyhow!(
            "Expected exactly 1 final proof, found {}",
            current_level_proofs.len()
        ));
        }

        // 5. Return the final root proof
        Ok(current_level_proofs.remove(0))
    }

    /// verifies the proof generated
    /// TODO: separate prover from verifier.
    pub fn verify_proof(
        &self,
        proof: ProofWithPublicInputs<F, C, D>
    ) -> Result<()>{

        self.node.node_data.node_circuit_data.verify(proof)?;

        Ok(())
    }
}


/// Node circuit struct
/// contains necessary data
/// N: number of proofs verified in-circuit (so num of child nodes)
pub struct NodeCircuit<
    const N: usize,
>{
    pub node_targets: NodeCircuitTargets<N>,
    pub node_data: NodeData,
}

/// Node circuit targets
/// assumes that all leaf proofs use the same verifier data
#[derive(Clone, Debug)]
pub struct NodeCircuitTargets<
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
>{
    pub node_circuit_data: CircuitData<F, C, D>,
    pub inner_node_common_data: CommonCircuitData<F, D>,
    pub leaf_circuit_data: CircuitData<F, C, D>,
}

impl<
    const N: usize,
> NodeCircuit< N> {

    /// builds the node circuit
    /// the circuit data and targets are stored in the node struct
    pub fn build_circuit(
    ) -> Result<NodeCircuit<N>>{

        // builder with standard recursion config
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        // circuit data for leaf
        let leaf_circ_data = leaf_circuit::circuit_data_for_leaf()?;
        // common data for leaf
        let leaf_common = leaf_circ_data.common.clone();

        // virtual proofs for leaf proofs
        let mut leaf_proofs = vec![];
        for i in 0..N {
            let vir_proof = builder.add_virtual_proof_with_pis(&leaf_common);
            leaf_proofs.push(vir_proof);
        }

        // get the public input hash from all inner proof targets
        let mut leaf_pub_input_hashes = vec![];
        for i in 0..N {
            let inner_cyclic_pis = &leaf_proofs[i].public_inputs;
            leaf_pub_input_hashes.extend_from_slice(&inner_cyclic_pis[0..4]);
        }
        // hash the public input so H(H_0, ..., H_N)
        let leaf_pub_input_hash = builder.hash_n_to_hash_no_pad::<H>(leaf_pub_input_hashes);

        // leaf verifier data
        // TODO: double check that it is ok for this verifier data to be private/witness
        let leaf_verifier_data = builder.add_virtual_verifier_data(leaf_common.config.fri_config.cap_height);

        // condition
        let condition = builder.add_virtual_bool_target_safe();

        // verify leaf proofs in-circuit if it is a leaf node,
        // meaning that we are on bottom layer of the tree
        for i in 0..N{
            builder.conditionally_verify_proof_or_dummy::<C>(condition,&leaf_proofs[i],&leaf_verifier_data, &leaf_common)?;
        }

        // common data for recursion
        let mut common_data = utils::common_data_for_node::<N>()?;
        // public input hash. defined here so that is public_input[0..4]
        let pub_input_hash = builder.add_virtual_hash_public_input();
        // verifier data for the recursion.
        let _verifier_data_target = builder.add_verifier_data_public_inputs();
        common_data.num_public_inputs = builder.num_public_inputs();

        // flipped condition. used to conditionally verify the node proofs (recursive proofs)
        let one = builder.one();
        let flipped_condition = BoolTarget::new_unsafe(builder.sub(one,condition.target));

        let inner_cyclic_proof_with_pis: [ProofWithPublicInputsTarget<D>; N] = (0..N)
            .map(|_| builder.add_virtual_proof_with_pis(&common_data))
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| anyhow!("Expected exactly N proof targets"))?;

        // get the public input hash from all inner proof targets
        let mut inner_pub_input_hashes = vec![];
        for i in 0..N {
            let inner_cyclic_pis = &inner_cyclic_proof_with_pis[i].public_inputs;
            inner_pub_input_hashes.extend_from_slice(&inner_cyclic_pis[0..4]);
        }
        // hash all the node public input h = H(h_1 | h_2 | ... | h_N)
        // TODO: optimize by removing the need for 2 hashes and instead select then hash
        let inner_pub_input_hash = builder.hash_n_to_hash_no_pad::<H>(inner_pub_input_hashes);

        let node_hash_or_leaf_hash = select_hash(&mut builder, condition, leaf_pub_input_hash, inner_pub_input_hash);

        builder.connect_hashes(pub_input_hash,node_hash_or_leaf_hash);

        // verify all N proofs in-circuit
        for i in 0..N {
            builder.conditionally_verify_cyclic_proof_or_dummy::<C>(
                flipped_condition,
                &inner_cyclic_proof_with_pis[i],
                &common_data,
            )?;
        }

        // build the node circuit
        let node_circuit_data = builder.build::<C>();

        // collect the leaf proofs
        let leaf_proofs: [ProofWithPublicInputsTarget<D>; N] = (0..N)
            .map(|i| {
                leaf_proofs[i].clone()
            })
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| anyhow!("Expected exactly M inner circuits"))?;

        // store targets
        let node_targets = NodeCircuitTargets::<N>{
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
        node_targets: NodeCircuitTargets<N>,
        leaf_proof_options: Option<[ProofWithPublicInputs<F, C, D>; N]>,
        node_proof_options: Option<[ProofWithPublicInputs<F, C, D>; N]>,
        leaf_verifier_only_data: &VerifierOnlyCircuitData<C, D>,
        pw: &mut PartialWitness<F>,
        is_leaf: bool,
    ) -> Result<()>{

        if(is_leaf == true) {
            let leaf_proofs: [ProofWithPublicInputs<F, C, D>; N] = leaf_proof_options.unwrap();
            // dummy
            let dummy_node = node_proof_options.unwrap();
            // assign the condition
            pw.set_bool_target(node_targets.condition, true)?;
            for i in 0..N {
                // assign the node proofs with dummy
                pw.set_proof_with_pis_target::<C, D>(
                    &node_targets.node_proofs[i],
                    &dummy_node[i],
                )?;
                // assign the leaf proof with real proofs
                pw.set_proof_with_pis_target(
                    &node_targets.leaf_proofs[i],
                    &leaf_proofs[i]
                )?;
            }
        }else{
            // assign the condition
            pw.set_bool_target(node_targets.condition, false)?;
            // node proofs
            let node_proofs = node_proof_options.unwrap(); // add error check
            // dummy leaf
            let dummy_leaf = leaf_proof_options.unwrap();
            for i in 0..N {
                // assign the node proofs
                pw.set_proof_with_pis_target(&node_targets.node_proofs[i], &node_proofs[i])?;
                // assign leaf proofs with dummy
                pw.set_proof_with_pis_target::<C, D>(
                    &node_targets.leaf_proofs[i],
                    &dummy_leaf[i],
                )?;
            }
        }
        // assign the verifier data (only for the leaf proofs)
        pw.set_verifier_data_target(&node_targets.leaf_verifier_data, leaf_verifier_only_data)?;

        Ok(())
    }

}