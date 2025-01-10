use std::array::from_fn;
use hashbrown::HashMap;
use plonky2::hash::hash_types::{HashOut, HashOutTarget, RichField};
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitData, VerifierCircuitTarget};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2::plonk::proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget};
use plonky2::recursion::dummy_circuit::cyclic_base_proof;
use plonky2_field::extension::Extendable;
use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2;
// use crate::recursion::params::RecursionTreeParams;
use crate::params::{F, D, C, Plonky2Proof, H};
use crate::recursion::circuits::inner_circuit::InnerCircuit;
use anyhow::{anyhow, Result};
use plonky2::gates::noop::NoopGate;
use plonky2::recursion::cyclic_recursion::check_cyclic_proof_verifier_data;
use crate::circuits::utils::select_hash;

/// the tree recursion struct simplifies the process
/// of building, proving and verifying
/// the two consts are:
/// - M: number of inner circuits to run
/// - N: number of inner proofs to verify
pub struct TreeRecursion<
    I: InnerCircuit,
    const M: usize,
    const N: usize,
>{
    pub node_circ: NodeCircuit<I, M, N>
}

impl<
    I: InnerCircuit,
    const M: usize,
    const N: usize,
> TreeRecursion<I, M, N> {

    pub fn new(node_circ: NodeCircuit<I,M,N>) -> Self{
        Self{
            node_circ,
        }
    }

    pub fn build(
        &mut self
    ) -> Result<()>{
        self.node_circ.build_circuit()
    }

    /// generates a proof - only one node
    /// takes M circuit input and N proofs
    pub fn prove(
        &mut self,
        circ_input: &[I::Input; M],
        proofs_option: Option<[ProofWithPublicInputs<F, C, D>; N]>,
        is_leaf: bool,
    ) -> Result<ProofWithPublicInputs<F, C, D>>{

        if self.node_circ.cyclic_circuit_data.is_none(){
            panic!("circuit data not found") // TODO: replace with err
        }

        let mut pw = PartialWitness::new();
        self.node_circ.assign_targets(
            circ_input,
            proofs_option,
            &mut pw,
            is_leaf,
        )?;

        let circ_data = self.node_circ.cyclic_circuit_data.as_ref().unwrap();
        let cyc_targets = self.node_circ.cyclic_target.as_ref().unwrap();

        pw.set_verifier_data_target(&cyc_targets.verifier_data, &circ_data.verifier_only)?;
        let proof = circ_data.prove(pw)?;
        check_cyclic_proof_verifier_data(
            &proof,
            &circ_data.verifier_only,
            &circ_data.common,
        )?;

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
        assert_eq!(circ_input.len(), total_input, "Invalid input size for tree depth");

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
                        .map_err(|_| anyhow!("Incorrect number of proofs for node"))?;
                    self.prove(&node_inputs, Some(proofs_array), false)?
                };
                next_proofs.push(proof);
            }
            cur_proofs = next_proofs;
        }

        // Final root proof
        assert_eq!(cur_proofs.len(), 1, "Final proof count incorrect");
        Ok(cur_proofs.remove(0))
    }

    /// verifies the proof generated
    pub fn verify_proof(
        &self,
        proof: ProofWithPublicInputs<F, C, D>
    ) -> Result<()>{
        if self.node_circ.cyclic_circuit_data.is_none() {
            panic!("no circuit data or proof found");
        }
        let circ_data = self.node_circ.cyclic_circuit_data.as_ref().unwrap();
        circ_data.verify(proof)?;

        Ok(())
    }
}


/// Node circuit struct
/// contains necessary data
/// M: number of inner-circuits to run
/// N: number of proofs verified in-circuit (so num of child nodes)
pub struct NodeCircuit<
    I: InnerCircuit,
    const M: usize,
    const N: usize,
>{
    pub circ: I,
    pub cyclic_target: Option<NodeCircuitTargets<I,M,N>>,
    pub cyclic_circuit_data: Option<CircuitData<F, C, D>>,
    pub common_data: Option<CommonCircuitData<F, D>>,
}

/// Node circuit targets
/// assumes that all inner proofs use the same verifier data
#[derive(Clone, Debug)]
pub struct NodeCircuitTargets<
    I: InnerCircuit,
    const M: usize,
    const N: usize,
>{
    pub inner_targets: [I::Targets; M],
    pub condition: BoolTarget,
    pub inner_proofs_with_pis: [ProofWithPublicInputsTarget<D>; N],
    pub verifier_data: VerifierCircuitTarget,
}

impl<
    I: InnerCircuit,
    const M: usize,
    const N: usize,
> NodeCircuit<I, M, N> {

    /// create a new cyclic circuit
    pub fn new(circ: I) -> Self{
        Self{
            circ,
            cyclic_target: None,
            cyclic_circuit_data: None,
            common_data: None,
        }
    }

    /// builds the cyclic recursion circuit using any inner circuit I
    /// returns the circuit data
    pub fn build_circuit(
        &mut self,
    ) -> Result<()>{
        // if the circuit data is already build then no need to rebuild
        // if self.cyclic_circuit_data.is_some(){
        //     return Ok(());
        // }

        // builder with standard recursion config
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        //build M inner circuits
        // let mut inner_t = Vec::with_capacity(M);
        // for i in 0..M {
        //     inner_t.push( self.circ.build(&mut builder)?);
        // }

        let inner_t: [I::Targets; M] = (0..M)
            .map(|_| self.circ.build(&mut builder))
            .collect::<Result<Vec<_>>>()?
            .try_into()
            .map_err(|_| anyhow!("Expected exactly M inner circuits"))?;

        // common data for recursion
        let mut common_data = self.common_data_for_node()?;
        // let outer_pis = I::get_pub_input_targets(&inner_t)?;
        let pub_input_hash = builder.add_virtual_hash_public_input();
        let verifier_data_target = builder.add_verifier_data_public_inputs();
        common_data.num_public_inputs = builder.num_public_inputs();

        // condition
        let condition = builder.add_virtual_bool_target_safe();

        // inner proofs targets - N proof targets
        // let mut inner_cyclic_proof_with_pis = vec![];
        // for i in 0..N {
        //     inner_cyclic_proof_with_pis.push(builder.add_virtual_proof_with_pis(&common_data));
        // }

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
        // hash all the inner public input h = H(h_1 | h_2 | ... | h_N)
        let inner_pub_input_hash = builder.hash_n_to_hash_no_pad::<H>(inner_pub_input_hashes);

        // get the public input of the inner circuit
        let mut outer_pis = vec![];
        for i in 0..M {
            outer_pis.push( I::get_pub_input_targets(&inner_t[i])?);
        }
        // hash all the public input -> generate one hashout at the end
        // this is not an optimal way to do it, verification might be ugly if M > 1
        // TODO: optimize this
        let mut outer_pi_hashes = vec![];
        for i in 0..M {
            let hash_res = builder.hash_n_to_hash_no_pad::<H>(outer_pis[i].clone());
            outer_pi_hashes.extend_from_slice(&hash_res.elements)
        }
        // the final public input hash
        let outer_pi_hash = builder.hash_n_to_hash_no_pad::<H>(outer_pi_hashes);
        // zero hash for leaves
        let zero_hash = HashOutTarget::from_vec([builder.zero(); 4].to_vec());
        // if the inner proofs are dummy then use zero hash for public input
        let inner_pi_hash_or_zero_hash = select_hash(&mut builder, condition, inner_pub_input_hash, zero_hash);

        // now hash the public input of the inner proofs and outer proof so we have one public hash
        let mut hash_input = vec![];
        hash_input.extend_from_slice(&outer_pi_hash.elements);
        hash_input.extend_from_slice(&inner_pi_hash_or_zero_hash.elements);
        let outer_pi_hash = builder.hash_n_to_hash_no_pad::<H>(hash_input);
        // connect this up one to `pub_input_hash`
        builder.connect_hashes(pub_input_hash,outer_pi_hash);

        // we can connect entropy, since all share same entropy, but might be more work
        // TODO: look into entropy

        // verify all N proofs in-circuit
        for i in 0..N {
            builder.conditionally_verify_cyclic_proof_or_dummy::<C>(
                condition,
                &inner_cyclic_proof_with_pis[i],
                &common_data,
            )?;
        }

        // build the cyclic circuit
        let cyclic_circuit_data = builder.build::<C>();

        // assign targets
        let cyc_t = NodeCircuitTargets::<I, M, N>{
            inner_targets: inner_t,
            condition,
            inner_proofs_with_pis: inner_cyclic_proof_with_pis,
            verifier_data: verifier_data_target
        };
        // assign the data
        self.cyclic_circuit_data = Some(cyclic_circuit_data);
        self.common_data = Some(common_data);
        self.cyclic_target = Some(cyc_t);
        Ok(())
    }

    /// assigns the targets for the Node circuit
    /// takes circuit input
    pub fn assign_targets(
        &mut self,
        circ_input: &[I::Input; M],
        proof_options: Option<[ProofWithPublicInputs<F, C, D>; N]>,
        pw: &mut PartialWitness<F>,
        is_leaf: bool,
    ) -> Result<()>{

        if self.cyclic_circuit_data.is_none(){
            panic!("circuit data not found") // TODO: replace with err
        }

        let circ_data = self.cyclic_circuit_data.as_ref().unwrap();
        let cyc_targets = self.cyclic_target.as_ref().unwrap();
        let common_data = self.common_data.as_ref().unwrap();

        for i in 0..M {
            self.circ.assign_targets(pw, &cyc_targets.inner_targets[i], &circ_input[i])?;
        }

        if(is_leaf == true) {
            pw.set_bool_target(cyc_targets.condition, false)?;
            for i in 0..N {
                pw.set_proof_with_pis_target::<C, D>(
                    &cyc_targets.inner_proofs_with_pis[i],
                    &cyclic_base_proof(
                        common_data,
                        &circ_data.verifier_only,
                        HashMap::new(),
                    ),
                )?;
            }
        }else{
            pw.set_bool_target(cyc_targets.condition, true)?;
            let proofs = proof_options.unwrap(); // add error check
            for i in 0..N {
                pw.set_proof_with_pis_target(&cyc_targets.inner_proofs_with_pis[i], &proofs[i])?;
            }
        }

        pw.set_verifier_data_target(&cyc_targets.verifier_data, &circ_data.verifier_only)?;

        Ok(())
    }

    /// Generates `CommonCircuitData` usable for node recursion.
    /// the circuit being built here depends on M and N so must be re-generated
    /// if the params change
    pub fn common_data_for_node(&self) -> Result<CommonCircuitData<F, D>>
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
        for _ in 0..N {
            let proof = builder.add_virtual_proof_with_pis(&data.common);
            builder.verify_proof::<C>(&proof, &verifier_data, &data.common);
        }
        let data = builder.build::<C>();

        // layer 3
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config.clone());

        // add a ConstantGate
        builder.add_gate(
            plonky2::gates::constant::ConstantGate::new(config.num_constants),
            vec![],
        );

        // build M inner circuits
        for i in 0..M {
            self.circ.build(&mut builder)?;
        }

        // generate and verify N number of proofs
        let verifier_data = builder.add_verifier_data_public_inputs();
        for _ in 0..N {
            let proof = builder.add_virtual_proof_with_pis(&data.common);
            builder.verify_proof::<C>(&proof, &verifier_data, &data.common);
        }
        // pad. TODO: optimize this padding to only needed number of gates
        while builder.num_gates() < 1 << 13 {
            builder.add_gate(NoopGate, vec![]);
        }
        Ok(builder.build::<C>().common)
    }

}
