use std::marker::PhantomData;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitData};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2;
use crate::recursion::circuits::inner_circuit::InnerCircuit;
use plonky2_field::extension::Extendable;
use crate::{error::CircuitError, Result};
use crate::recursion::uniform::{leaf::{LeafTargets,LeafInput,LeafCircuit},node::{NodeTargets,NodeInput,NodeCircuit}};

/// tree recursion
pub struct TreeRecursion<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    C: GenericConfig<D, F = F>,
    H: AlgebraicHasher<F>,
> where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>
{
    leaf: LeafCircuit<F, D, C, H>,
    node: NodeCircuit<F, D, C, H>,
    leaf_circ_data: CircuitData<F, C, D>,
    node_circ_data: CircuitData<F, C, D>,
    leaf_targets: LeafTargets<D>,
    node_targets: NodeTargets<D>,
    phantom_data: PhantomData<(H)>
}

impl<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    C: GenericConfig<D, F = F>,
    H: AlgebraicHasher<F>,
> TreeRecursion<F, D, C, H> where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>
{

    pub fn build(
        inner_common_data: CommonCircuitData<F,D>
    ) -> Result<Self> {
        // build leaf with standard recursion config
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let leaf = LeafCircuit::new(inner_common_data.clone());
        let leaf_targets = leaf.build(&mut builder)?;
        let leaf_circ_data = builder.build::<C>();
        // println!("leaf circuit size = {:?}", leaf_circ_data.common.degree_bits());

        // build node with standard recursion config
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let node = NodeCircuit::new(leaf_circ_data.common.clone());
        let node_targets = node.build(&mut builder)?;
        let node_circ_data = builder.build::<C>();
        // println!("node circuit size = {:?}", node_circ_data.common.degree_bits());

        Ok(Self{
            leaf,
            node,
            leaf_circ_data,
            node_circ_data,
            leaf_targets,
            node_targets,
            phantom_data: Default::default(),
        })
    }

    pub fn prove_tree
    (
        &mut self,
        proofs_with_pi: &[ProofWithPublicInputs<F, C, D>],
        inner_verifier_data: VerifierCircuitData<F, C, D>,
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
            inner_verifier_data,
        )?;

        // process nodes
        let (root_proof, vd) =
            self.prove(&leaf_proofs,self.leaf_circ_data.verifier_data())?;

        Ok(root_proof)
    }


    fn get_leaf_proofs
    (
        &mut self,
        proofs_with_pi: &[ProofWithPublicInputs<F, C, D>],
        inner_verifier_data: VerifierCircuitData<F, C, D>,
    ) -> Result<(Vec<ProofWithPublicInputs<F, C, D>>)> {

        let mut leaf_proofs = vec![];

        for proof in proofs_with_pi{
            let mut pw = PartialWitness::<F>::new();
            let leaf_in = LeafInput{
                inner_proof: proof.clone(),
                verifier_data: inner_verifier_data.clone(),
            };
            self.leaf.assign_targets(&mut pw,&self.leaf_targets,&leaf_in)?;
            let proof = self.leaf_circ_data.prove(pw).unwrap();
            leaf_proofs.push(proof);
        }

        Ok(leaf_proofs)
    }

    /// generates a proof - only one node
    fn prove(
        &mut self,
        proofs_with_pi: &[ProofWithPublicInputs<F, C, D>],
        verifier_data: VerifierCircuitData<F, C, D>,
    ) -> Result<(ProofWithPublicInputs<F, C, D>, VerifierCircuitData<F, C, D>)> where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>
    {

        if proofs_with_pi.len() == 1 {
            return Ok((proofs_with_pi[0].clone(), verifier_data));
        }

        let mut new_proofs = vec![];

        for chunk in proofs_with_pi.chunks(2) {

            let mut inner_pw = PartialWitness::new();
            let node_in = NodeInput{
                node_proofs: [chunk[0].clone(), chunk[1].clone()],
                verifier_data: verifier_data.clone() ,
            };
            self.node.assign_targets(&mut inner_pw,&self.node_targets,&node_in)?;

            let proof = self.node_circ_data.prove(inner_pw)
                .map_err(|e| CircuitError::ProofGenerationError(e.to_string()))?;
            new_proofs.push(proof);
        }

        self.prove(&new_proofs, self.node_circ_data.verifier_data())
    }

}

