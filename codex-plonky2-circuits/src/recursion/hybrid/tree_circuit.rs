use plonky2::hash::hash_types::RichField;
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, VerifierCircuitData};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2;
use crate::recursion::circuits::inner_circuit::InnerCircuit;
use plonky2_field::extension::Extendable;
use crate::{error::CircuitError, Result};
use crate::circuits::utils::vec_to_array;
use crate::recursion::circuits::leaf_circuit::{LeafCircuit, LeafInput};
use crate::recursion::hybrid::node_circuit::{NodeCircuit, NodeCircuitTargets};

/// Hybrid tree recursion - combines simple and tree recursion
/// - N: number of leaf proofs to verify in the node circuit
/// - M: number of inner proofs to verify in the leaf circuit
pub struct HybridTreeRecursion<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    I: InnerCircuit<F, D>,
    const N: usize,
    const M: usize,
> {
    pub leaf: LeafCircuit<F, D, I, M>,
}

impl<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    I: InnerCircuit<F, D>,
    const N: usize,
    const M: usize,
> HybridTreeRecursion<F, D, I, N, M>
{

    pub fn new(
        leaf: LeafCircuit<F, D, I, M>
    ) -> Self {
            Self{
                leaf,
            }
    }

    pub fn prove_tree<
        C: GenericConfig<D, F = F> + 'static,
        H: AlgebraicHasher<F>,
    >(
        &mut self,
        proofs_with_pi: &[ProofWithPublicInputs<F, C, D>],
        inner_verifier_data: VerifierCircuitData<F, C, D>,
    ) -> Result<(ProofWithPublicInputs<F, C, D>, VerifierCircuitData<F, C, D>)> where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>
    {
        // process leaves
        let (leaf_proofs, leaf_data) = self.get_leaf_proofs::<C,H>(
            proofs_with_pi,
            inner_verifier_data,
        )?;
        
        // process nodes
        let (root_proof, last_verifier_data) =
            self.prove::<C,H>(&leaf_proofs,leaf_data.verifier_data(), None, None, 0)?;

        Ok((root_proof, last_verifier_data))
    }
    
    
    fn get_leaf_proofs<
        C: GenericConfig<D, F = F> + 'static,
        H: AlgebraicHasher<F>,
    >(
        &mut self,
        proofs_with_pi: &[ProofWithPublicInputs<F, C, D>],
        inner_verifier_data: VerifierCircuitData<F, C, D>,
    ) -> Result<(Vec<ProofWithPublicInputs<F, C, D>>, CircuitData<F, C, D>)> where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>{
        // builder with standard recursion config
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let leaf_targets = self.leaf.build::<C,H>(&mut builder)?;
        let leaf_data = builder.build::<C>();
        println!("leaf circuit size = {:?}", leaf_data.common.degree_bits());

        let mut leaf_proofs = vec![];
        
        for chunk in proofs_with_pi.chunks(M){
            let mut pw = PartialWitness::<F>::new();
            let chunk_arr = vec_to_array::<M,ProofWithPublicInputs<F, C, D>>(chunk.to_vec())?;
            let leaf_in = LeafInput{
                inner_proof: chunk_arr,
                verifier_data: inner_verifier_data.clone(),
            };
            self.leaf.assign_targets::<C,H>(&mut pw,&leaf_targets,&leaf_in)?;
            let proof = leaf_data.prove(pw).unwrap();
            leaf_proofs.push(proof);
        }
        
        Ok((leaf_proofs, leaf_data))
    }

    /// generates a proof - only one node
    /// takes N proofs
    fn prove<
        C: GenericConfig<D, F = F> + 'static,
        H: AlgebraicHasher<F>,
    >(
        &mut self,
        proofs_with_pi: &[ProofWithPublicInputs<F, C, D>],
        verifier_data: VerifierCircuitData<F, C, D>,
        node_target_options: Option<NodeCircuitTargets<D, N>>,
        node_data_option: Option<CircuitData<F, C, D>>,
        layer: usize,
    ) -> Result<(ProofWithPublicInputs<F, C, D>, VerifierCircuitData<F, C, D>)> where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>
    {

        if proofs_with_pi.len() == 1 {
            return Ok((proofs_with_pi[0].clone(), verifier_data));
        }

        let mut new_proofs = vec![];

        let (node_data, node_targets) = if layer<2 {
            let node_config = CircuitConfig::standard_recursion_config();
            let mut node_builder = CircuitBuilder::<F, D>::new(node_config);
            let targets = NodeCircuit::<F, D, C, N>::build_circuit::<H>(&mut node_builder, &verifier_data.common)?;
            let data = node_builder.build::<C>();
            (data, targets)
        }else{
            (node_data_option.unwrap(), node_target_options.unwrap())
        };

        for chunk in proofs_with_pi.chunks(N) {

            let chunk_arr = vec_to_array::<N,ProofWithPublicInputs<F, C, D>>(chunk.to_vec())?;

            let mut inner_pw = PartialWitness::new();

            NodeCircuit::<F,D,C,N>::assign_targets(node_targets.clone(),&chunk_arr,&verifier_data, &mut inner_pw)?;

            let proof = node_data.prove(inner_pw)
                .map_err(|e| CircuitError::ProofGenerationError(e.to_string()))?;
            new_proofs.push(proof);
        }

        self.prove::<C,H>(&new_proofs, node_data.verifier_data(), Some(node_targets),Some(node_data), layer+1)
    }

}

