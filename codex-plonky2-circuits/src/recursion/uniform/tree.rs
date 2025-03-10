use std::marker::PhantomData;
use plonky2::hash::hash_types::{HashOut, RichField};
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitData, VerifierOnlyCircuitData};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2;
use plonky2_field::extension::Extendable;
use crate::{error::CircuitError, Result};
use crate::recursion::uniform::{leaf::{LeafTargets,LeafCircuit},node::{NodeTargets,NodeCircuit}};
use crate::recursion::uniform::compress::{CompressionCircuit, CompressionTargets};

/// tree recursion
pub struct TreeRecursion<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    C: GenericConfig<D, F = F>,
    H: AlgebraicHasher<F>,
    const N: usize,
    const M: usize,
> where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>
{
    leaf: LeafCircuit<F, D, C, H, N>,
    node: NodeCircuit<F, D, C, H, M>,
    compression: CompressionCircuit<F, D, C, H>,
    leaf_circ_data: CircuitData<F, C, D>,
    node_circ_data: CircuitData<F, C, D>,
    compression_circ_data: CircuitData<F, C, D>,
    leaf_targets: LeafTargets<D>,
    node_targets: NodeTargets<D>,
    compression_targets: CompressionTargets<D>,
    phantom_data: PhantomData<(H)>
}

impl<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    C: GenericConfig<D, F = F>,
    H: AlgebraicHasher<F>,
    const N: usize,
    const M: usize,
> TreeRecursion<F, D, C, H, N, M> where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>
{

    pub fn build(
        inner_common_data: CommonCircuitData<F,D>
    ) -> Result<Self> {
        // build leaf with standard recursion config
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let leaf = LeafCircuit::<_,D,_,_,N>::new(inner_common_data.clone());
        let leaf_targets = leaf.build(&mut builder)?;
        let leaf_circ_data = builder.build::<C>();
        // println!("leaf circuit size = {:?}", leaf_circ_data.common.degree_bits());

        // build node with standard recursion config
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let node = NodeCircuit::<_,D,_,_,M>::new(leaf_circ_data.common.clone());
        let node_targets = node.build(&mut builder)?;
        let node_circ_data = builder.build::<C>();
        // println!("node circuit size = {:?}", node_circ_data.common.degree_bits());

        // compression build
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let node_common = node_circ_data.common.clone();
        let compression_circ = CompressionCircuit::new(node_common);
        let compression_targets = compression_circ.build(&mut builder)?;
        let compression_circ_data = builder.build::<C>();
        // println!("compress circuit size = {:?}", compression_circ_data.common.degree_bits());

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

    pub fn prove_tree_and_compress(
        &mut self,
        proofs_with_pi: &[ProofWithPublicInputs<F, C, D>],
        inner_verifier_only_data: &VerifierOnlyCircuitData<C, D>,
    ) -> Result<(ProofWithPublicInputs<F, C, D>)>
    {
        let proof =
            self.prove_tree(proofs_with_pi, inner_verifier_only_data)?;
        let mut pw = PartialWitness::<F>::new();
        self.compression.assign_targets(&mut pw, &self.compression_targets, proof, &self.node_circ_data.verifier_only)?;

        self.compression_circ_data.prove(pw).map_err(
            |e| CircuitError::InvalidProofError(e.to_string())
        )
    }

    pub fn prove_tree
    (
        &mut self,
        proofs_with_pi: &[ProofWithPublicInputs<F, C, D>],
        inner_verifier_only_data: &VerifierOnlyCircuitData<C, D>,
    ) -> Result<(ProofWithPublicInputs<F, C, D>)>
    {
        if proofs_with_pi.len() % 2 != 0 {
            return
                Err(CircuitError::RecursionTreeError(format!(
                    "input proofs must be divisible by {}, got {}", 2, proofs_with_pi.len())
                ))
        }
        // process leaves
        let leaf_proofs = self.get_leaf_proofs(
            proofs_with_pi,
            inner_verifier_only_data,
        )?;

        // process nodes
        let (root_proof, vd) =
            self.prove(&leaf_proofs,&self.leaf_circ_data.verifier_only)?;

        Ok(root_proof)
    }

    fn get_leaf_proofs
    (
        &mut self,
        proofs_with_pi: &[ProofWithPublicInputs<F, C, D>],
        inner_verifier_only_data: &VerifierOnlyCircuitData<C, D>,
    ) -> Result<(Vec<ProofWithPublicInputs<F, C, D>>)> {

        let mut leaf_proofs = vec![];

        for proof in proofs_with_pi.chunks(N){
            let mut pw = PartialWitness::<F>::new();

            self.leaf.assign_targets(&mut pw,&self.leaf_targets,proof,inner_verifier_only_data)?;
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
    ) -> Result<(ProofWithPublicInputs<F, C, D>, VerifierOnlyCircuitData<C, D>)> where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>
    {

        if proofs_with_pi.len() == 1 {
            return Ok((proofs_with_pi[0].clone(), verifier_only_data.clone()));
        }

        let mut new_proofs = vec![];

        for chunk in proofs_with_pi.chunks(M) {

            let mut inner_pw = PartialWitness::new();

            self.node.assign_targets(
                &mut inner_pw,
                &self.node_targets,
                chunk,
                verifier_only_data,
            )?;

            let proof = self.node_circ_data.prove(inner_pw)
                .map_err(|e| CircuitError::ProofGenerationError(e.to_string()))?;
            new_proofs.push(proof);
        }

        self.prove(&new_proofs, &self.node_circ_data.verifier_only)
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
        inner_verifier_data: &VerifierCircuitData<F, C, D>,
        is_compressed: bool,
    ) -> Result<()>{
        let public_input = proof.public_inputs.clone();
        if is_compressed{
            self.compression_circ_data.verify(proof)
                .map_err(|e| CircuitError::InvalidProofError(e.to_string()))?;
            self.verify_public_input(public_input, inner_public_input, inner_verifier_data, is_compressed)
        }else {
            self.node_circ_data.verify(proof)
                .map_err(|e| CircuitError::InvalidProofError(e.to_string()))?;
            self.verify_public_input(public_input, inner_public_input, inner_verifier_data, is_compressed)
        }
    }

    pub fn verify_public_input(
        &self,
        public_input: Vec<F>,
        inner_public_input: Vec<Vec<F>>,
        inner_verifier_data: &VerifierCircuitData<F, C, D>,
        is_compressed: bool,
    ) -> Result<()>{
        assert_eq!(public_input.len(), 8);

        let given_input_hash = &public_input[0..4];
        let given_vd_hash = &public_input[4..8];

        let inner_hash = Self::get_hash_of_verifier_data(&inner_verifier_data);

        let leaf_hash = Self::get_hash_of_verifier_data(&self.leaf_circ_data.verifier_data());

        let node_hash = Self::get_hash_of_verifier_data(&self.node_circ_data.verifier_data());


        let mut pub_in_hashes = vec![];
        let mut inner_vd_hashes = vec![];
        for pub_in in inner_public_input.chunks(N){
            let pub_in_flat: Vec<F> = pub_in
                .iter()
                .flat_map(|v| v.iter().cloned())
                .collect();
            let hash = H::hash_no_pad(&pub_in_flat);
            pub_in_hashes.push(hash);
            inner_vd_hashes.push(inner_hash.clone());
        }

        let mut level = 0;
        while pub_in_hashes.len() > 1 {
            let mut next_level_pi_hashes = Vec::new();
            let mut next_level_vd_hashes = Vec::new();
            for (pi_chunk, vd_chunk) in pub_in_hashes.chunks(M).zip(inner_vd_hashes.chunks(M)) {
                // collect field elements
                let pi_chunk_f: Vec<F> = pi_chunk.iter()
                    .flat_map(|h| h.elements.iter().cloned())
                    .collect();
                let mut vd_chunk_f: Vec<F> = vd_chunk.iter()
                    .flat_map(|h| h.elements.iter().cloned())
                    .collect();
                let hash_n = if level == 0 {leaf_hash} else{node_hash};
                vd_chunk_f.extend_from_slice(&hash_n.elements);

                // Compute Poseidon2 hash of the concatenated chunk
                let pi_hash = H::hash_no_pad(&pi_chunk_f);
                let vd_hash = H::hash_no_pad(&vd_chunk_f);
                next_level_pi_hashes.push(pi_hash);
                next_level_vd_hashes.push(vd_hash);
            }
            pub_in_hashes = next_level_pi_hashes;
            inner_vd_hashes = next_level_vd_hashes;
            level +=1;
        }

        //check expected hash
        let expected_pi_hash = pub_in_hashes[0];
        let mut expected_vd_hash = inner_vd_hashes[0];

        if is_compressed {
            let mut vd_to_hash = vec![];
            vd_to_hash.extend_from_slice(&expected_vd_hash.elements);
            vd_to_hash.extend_from_slice(&node_hash.elements);
            expected_vd_hash = H::hash_no_pad(&vd_to_hash);
        }

        assert_eq!(given_input_hash, expected_pi_hash.elements);
        assert_eq!(given_vd_hash, expected_vd_hash.elements);
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

