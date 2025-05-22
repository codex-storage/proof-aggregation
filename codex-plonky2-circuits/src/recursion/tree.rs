use std::marker::PhantomData;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitData, VerifierOnlyCircuitData};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2;
use plonky2_field::extension::Extendable;
use crate::{error::CircuitError, Result};
use crate::bundle::Bundle;
use crate::circuit_helper::Plonky2Circuit;
use crate::recursion::{leaf::{LeafTargets, LeafCircuit}, node::{NodeTargets, NodeCircuit}};
use crate::recursion::compress::{CompressionCircuit, CompressionInput, CompressionTargets};
use crate::recursion::leaf::LeafInput;
use crate::recursion::node::NodeInput;
use crate::recursion::utils::get_hash_of_verifier_data;

/// tree recursion
/// - `N`: Number of leaf proofs aggregated at the node level. set to 2 for 2-to-1 tree
pub struct TreeRecursion<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    C: GenericConfig<D, F = F>,
    H: AlgebraicHasher<F>,
    const N: usize,
    const T: usize,
> where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>
{
    leaf: LeafCircuit<F, D, C, H, T>,
    node: NodeCircuit<F, D, C, H, N, T>,
    compression: CompressionCircuit<F, D, C>,
    leaf_circ_data: CircuitData<F, C, D>,
    node_circ_data: CircuitData<F, C, D>,
    compression_circ_data: CircuitData<F, C, D>,
    leaf_targets: LeafTargets<D>,
    node_targets: NodeTargets<D>,
    compression_targets: CompressionTargets<D>,
    phantom_data: PhantomData<H>
}

impl<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    C: GenericConfig<D, F = F>,
    H: AlgebraicHasher<F>,
    const N: usize,
    const T: usize,
> TreeRecursion<F, D, C, H, N, T> where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>
{
    /// build with standard recursion config
    pub fn build_with_standard_config(
        inner_verifier_data: VerifierCircuitData<F, C, D>,
    ) -> Result<Self> {
        Self::build(
            inner_verifier_data,
            CircuitConfig::standard_recursion_config()
        )
    }

    /// build the tree with given config
    pub fn build(
        inner_verifier_data: VerifierCircuitData<F, C, D>,
        config: CircuitConfig,
    ) -> Result<Self> {
        // build leaf with standard recursion config
        let leaf = LeafCircuit::<_,D,_,_,T>::new(inner_verifier_data);
        let (leaf_targets, leaf_circ_data) = leaf.build(config.clone())?;
        println!("leaf circuit size = {:?}", leaf_circ_data.common.degree_bits());

        // build node with standard recursion config
        let node = NodeCircuit::<_,D,_,_,N, T>::new(leaf_circ_data.verifier_data());
        let (node_targets, node_circ_data) = node.build(config.clone())?;
        println!("node circuit size = {:?}", node_circ_data.common.degree_bits());

        // compression build
        let compression_circ = CompressionCircuit::new(node_circ_data.verifier_data());
        let (compression_targets, compression_circ_data) = compression_circ.build(config.clone())?;
        println!("compress circuit size = {:?}", compression_circ_data.common.degree_bits());

        Ok(Self{
            leaf,
            node,
            compression: compression_circ,
            leaf_circ_data,
            node_circ_data,
            compression_circ_data,
            leaf_targets,
            node_targets,
            compression_targets,
            phantom_data: Default::default(),
        })
    }

    pub fn get_leaf_verifier_data(&self) -> VerifierCircuitData<F, C, D>{
        self.leaf_circ_data.verifier_data()
    }

    pub fn get_node_common_data(&self) -> CommonCircuitData<F, D>{
        self.node_circ_data.common.clone()
    }

    pub fn get_leaf_common_data(&self) -> CommonCircuitData<F, D>{
        self.leaf_circ_data.common.clone()
    }

    pub fn get_node_verifier_data(&self) -> VerifierCircuitData<F, C, D>{
        self.node_circ_data.verifier_data()
    }

    pub fn prove_bundle(_bundle: Bundle<F, C, D, H>){
        todo!()
    }

    pub fn prove_tree_and_compress(
        &mut self,
        proofs_with_pi: &[ProofWithPublicInputs<F, C, D>],
    ) -> Result<ProofWithPublicInputs<F, C, D>>
    {
        let proof =
            self.prove_tree(proofs_with_pi)?;
        let mut pw = PartialWitness::<F>::new();
        self.compression.assign_targets(
            &mut pw,
            &self.compression_targets,
            &CompressionInput{ inner_proof: proof},
        )?;

        self.compression_circ_data.prove(pw).map_err(
            |e| CircuitError::InvalidProofError(e.to_string())
        )
    }

    pub fn prove_tree
    (
        &mut self,
        proofs_with_pi: &[ProofWithPublicInputs<F, C, D>],
    ) -> Result<ProofWithPublicInputs<F, C, D>>
    {
        if proofs_with_pi.len() % 2 != 0 {
            return
                Err(CircuitError::RecursionTreeError(format!(
                    "input proofs must be divisible by {}, got {}", 2, proofs_with_pi.len())
                ))
        }
        // process leaves
        let leaf_proofs = self.get_leaf_proofs(
            &proofs_with_pi,
        )?;

        // process nodes
        let (root_proof, _vd) =
            self.prove(&leaf_proofs,&self.leaf_circ_data.verifier_only, 0)?;

        Ok(root_proof)
    }

    fn get_leaf_proofs
    (
        &mut self,
        proofs_with_pi: &[ProofWithPublicInputs<F, C, D>],
    ) -> Result<Vec<ProofWithPublicInputs<F, C, D>>> {

        let mut leaf_proofs = vec![];

        for (i, proof) in proofs_with_pi.iter().enumerate(){
            let leaf_input = LeafInput{
                inner_proof: proof.clone(),
                flag: true,
                index: i,
            };

            let mut pw = PartialWitness::<F>::new();

            self.leaf.assign_targets(&mut pw,&self.leaf_targets,&leaf_input)?;
            let proof = self.leaf_circ_data.prove(pw).unwrap();
            leaf_proofs.push(proof);
        }

        Ok(leaf_proofs)
    }

    /// generates a proof
    fn prove(
        &self,
        proofs_with_pi: &[ProofWithPublicInputs<F, C, D>],
        verifier_only_data: &VerifierOnlyCircuitData<C, D>,
        level: usize,
    ) -> Result<(ProofWithPublicInputs<F, C, D>, VerifierOnlyCircuitData<C, D>)> where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>
    {

        if proofs_with_pi.len() == 1 {
            return Ok((proofs_with_pi[0].clone(), verifier_only_data.clone()));
        }

        let mut new_proofs = vec![];

        let condition = if level == 0 {false} else {true};

        for (i, chunk) in proofs_with_pi.chunks(N).enumerate() {

            let mut inner_pw = PartialWitness::new();

            let node_input = NodeInput{
                inner_proofs: chunk.to_vec().clone(),
                verifier_only_data: verifier_only_data.clone(),
                condition,
                flags: [true; N].to_vec(),
                index: i,
            };

            self.node.assign_targets(
                &mut inner_pw,
                &self.node_targets,
                &node_input
            )?;

            let proof = self.node_circ_data.prove(inner_pw)
                .map_err(|e| CircuitError::ProofGenerationError(e.to_string()))?;
            new_proofs.push(proof);
        }

        self.prove(&new_proofs, &self.node_circ_data.verifier_only, level+1)
    }

    pub fn verify_proof(
        &self,
        proof: ProofWithPublicInputs<F, C, D>,
        is_compressed: bool,
    ) -> Result<()>{
        if is_compressed{
            self.compression_circ_data.verify(proof)
                .map_err(|e| CircuitError::InvalidProofError(e.to_string()))
        }else {
            self.node_circ_data.verify(proof)
                .map_err(|e| CircuitError::InvalidProofError(e.to_string()))
        }
    }

    pub fn verify_proof_and_public_input(
        &self,
        proof: ProofWithPublicInputs<F, C, D>,
        inner_public_input: Vec<Vec<F>>,
        is_compressed: bool,
    ) -> Result<()>{
        let public_input = proof.public_inputs.clone();
        if is_compressed{
            self.compression_circ_data.verify(proof)
                .map_err(|e| CircuitError::InvalidProofError(e.to_string()))?;
            self.verify_public_input(public_input, inner_public_input)
        }else {
            self.node_circ_data.verify(proof)
                .map_err(|e| CircuitError::InvalidProofError(e.to_string()))?;
            self.verify_public_input(public_input, inner_public_input)
        }
    }

    pub fn verify_public_input(
        &self,
        public_input: Vec<F>,
        inner_public_input: Vec<Vec<F>>,
    ) -> Result<()>{
        assert!(public_input.len() >= 8);

        let given_input_hash = &public_input[0..4];
        let given_vd_hash = &public_input[4..8];

        let node_hash = get_hash_of_verifier_data::<F,D,C,H>(&self.node_circ_data.verifier_data());

        let mut pub_in_hashes = vec![];
        for pub_in in inner_public_input{
            let hash = H::hash_no_pad(&pub_in);
            pub_in_hashes.push(hash);
        }

        while pub_in_hashes.len() > 1 {
            let mut next_level_pi_hashes = Vec::new();
            for pi_chunk in pub_in_hashes.chunks(N) {
                // collect field elements
                let pi_chunk_f: Vec<F> = pi_chunk.iter()
                    .flat_map(|h| h.elements.iter().cloned())
                    .collect();
                // Compute hash of the concatenated chunk
                let pi_hash = H::hash_no_pad(&pi_chunk_f);
                next_level_pi_hashes.push(pi_hash);
            }
            pub_in_hashes = next_level_pi_hashes;
        }

        //check expected hash
        let expected_pi_hash = pub_in_hashes[0];

        assert_eq!(given_input_hash, expected_pi_hash.elements);
        assert_eq!(given_vd_hash, node_hash.elements);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use plonky2::gates::noop::NoopGate;
    use super::*;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::config::GenericConfig;
    use plonky2_field::types::Field;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2Hash;
    use plonky2::iop::witness::WitnessWrite;

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    type H = Poseidon2Hash;

    // A helper to build a minimal circuit and returns T proofs & circuit data.
    fn dummy_proofs<const T: usize>() -> (CircuitData<F, C, D>, Vec<ProofWithPublicInputs<F, C, D>>) {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        for _ in 0..(4096+10) {
            builder.add_gate(NoopGate, vec![]);
        }
        // Add one virtual public input so that the circuit has minimal structure.
        let t = builder.add_virtual_public_input();
        let circuit = builder.build::<C>();
        println!("inner circuit size = {}", circuit.common.degree_bits());
        let mut pw = PartialWitness::<F>::new();
        pw.set_target(t, F::ZERO).expect("faulty assign");
        let proofs = (0..T).map(|_i| circuit.prove(pw.clone()).unwrap()).collect();
        (circuit, proofs)
    }


    // End-to-End test for the entire Tree circuit.
    #[test]
    fn test_full_tree_circuit() -> anyhow::Result<()> {
        const N: usize = 2;
        const T: usize = 128;

        let (data, proofs) = dummy_proofs::<T>();

        let mut tree = TreeRecursion::<F,D,C,H, N, T>::build_with_standard_config(data.verifier_data())?;

        // aggregate - no compression
        let root = tree.prove_tree(&proofs)?;
        println!("pub input size = {}", root.public_inputs.len());
        println!("proof size = {:?} bytes", root.to_bytes().len());

        assert!(
            tree.verify_proof(root, false).is_ok(),
            "proof verification failed"
        );

        Ok(())
    }
}