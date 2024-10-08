use anyhow::Result;
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::hash::hashing::hash_n_to_m_no_pad;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::{PartialWitness, WitnessWrite, Witness};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, VerifierCircuitData};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig, Hasher, GenericHashOut};
use plonky2::plonk::proof::ProofWithPublicInputs;
use std::marker::PhantomData;
use itertools::Itertools;

use crate::merkle_tree::capped_tree::MerkleTree;
use plonky2::hash::poseidon::PoseidonHash;

use plonky2::hash::hash_types::{HashOutTarget, MerkleCapTarget, NUM_HASH_OUT_ELTS};
use crate::merkle_tree::capped_tree::{MerkleProof, MerkleProofTarget};
use plonky2_poseidon2::poseidon2_hash::poseidon2::{Poseidon2, Poseidon2Hash};

use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use plonky2::plonk::proof::Proof;

use plonky2::hash::hashing::PlonkyPermutation;
use plonky2::plonk::circuit_data::VerifierCircuitTarget;
use crate::merkle_tree::capped_tree::MerkleCap;

// size of leaf data (in number of field elements)
pub const LEAF_LEN: usize = 4;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MerkleTreeTargets<
    F: RichField + Extendable<D> + Poseidon2,
    C: GenericConfig<D, F = F>,
    const D: usize,
    H: Hasher<F> + AlgebraicHasher<F>,
> {
    pub proof_target: MerkleProofTarget,
    pub cap_target: MerkleCapTarget,
    pub leaf: Vec<Target>,
    pub leaf_index_target: Target,
    _phantom: PhantomData<(C,H)>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MerkleTreeCircuit<
    F: RichField + Extendable<D> + Poseidon2,
    C: GenericConfig<D, F = F>,
    const D: usize,
    H: Hasher<F> + AlgebraicHasher<F>,
> {
    pub tree: MerkleTree<F, H>,
    pub _phantom: PhantomData<C>,
}

impl<
    F: RichField + Extendable<D> + Poseidon2,
    C: GenericConfig<D, F = F>,
    const D: usize,
    H: Hasher<F> + AlgebraicHasher<F>,
> MerkleTreeCircuit<F, C, D, H>{

    pub fn tree_height(&self) -> usize {
        self.tree.leaves.len().trailing_zeros() as usize
    }

    // build the circuit and returns the circuit data
    // note, this fn generate circuit data with
    pub fn build_circuit(&mut self, builder: &mut CircuitBuilder::<F, D>) -> MerkleTreeTargets<F, C, D, H>{

        let proof_t = MerkleProofTarget {
            siblings: builder.add_virtual_hashes(self.tree_height()-self.tree.cap.height()),
        };

        let cap_t = builder.add_virtual_cap(self.tree.cap.height());

        let leaf_index_t = builder.add_virtual_target();

        let leaf_index_bits = builder.split_le(leaf_index_t, self.tree_height());

        // NOTE: takes the length from const LEAF_LEN and assume all lengths are the same
        let leaf_t: [Target; LEAF_LEN]  = builder.add_virtual_targets(LEAF_LEN).try_into().unwrap();

        let zero = builder.zero();
        // let mut mt = MT(self.tree.clone());
        self.verify_merkle_proof_to_cap_circuit(
            builder, leaf_t.to_vec(), &leaf_index_bits, &cap_t, &proof_t,
        );

        MerkleTreeTargets{
            // depth: 0,
            // cap_height: 0,
            proof_target: proof_t,
            cap_target: cap_t,
            leaf: leaf_t.to_vec(),
            leaf_index_target: leaf_index_t,
            _phantom: Default::default(),
        }
    }

    pub fn fill_targets(
        &self,
        pw: &mut PartialWitness<F>,
        // leaf_data: Vec<F>,
        leaf_index: usize,
        targets: MerkleTreeTargets<F, C, D, H>,
    ) {
        let proof = self.tree.prove(leaf_index);

        for i in 0..proof.siblings.len() {
            pw.set_hash_target(targets.proof_target.siblings[i], proof.siblings[i]);
        }

        // set cap target manually
        // pw.set_cap_target(&cap_t, &tree.cap);
        for (ht, h) in targets.cap_target.0.iter().zip(&self.tree.cap.0) {
            pw.set_hash_target(*ht, *h);
        }

        pw.set_target(
            targets.leaf_index_target,
            F::from_canonical_usize(leaf_index),
        );

        for j in 0..targets.leaf.len() {
            pw.set_target(targets.leaf[j], self.tree.leaves[leaf_index][j]);
        }

    }

    pub fn prove(
        &self,
        data: CircuitData<F, C, D>,
        pw: PartialWitness<F>
    ) -> Result<ProofWithPublicInputs<F, C, D>> {
        let proof = data.prove(pw);
        return proof
    }

    // function to automate build and prove, useful for quick testing
    pub fn build_and_prove(
        &mut self,
        // builder: &mut CircuitBuilder::<F, D>,
        config: CircuitConfig,
        // pw: &mut PartialWitness<F>,
        leaf_index: usize,
        // data: CircuitData<F, C, D>,
    ) -> Result<(CircuitData<F, C, D>,ProofWithPublicInputs<F, C, D>)> {
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let mut pw = PartialWitness::new();
        // merkle proof
        let merkle_proof = self.tree.prove(leaf_index);
        let proof_t = MerkleProofTarget {
            siblings: builder.add_virtual_hashes(merkle_proof.siblings.len()),
        };

        for i in 0..merkle_proof.siblings.len() {
            pw.set_hash_target(proof_t.siblings[i], merkle_proof.siblings[i]);
        }

        // merkle cap target
        let cap_t = builder.add_virtual_cap(self.tree.cap.height());
        // set cap target manually
        // pw.set_cap_target(&cap_t, &tree.cap);
        for (ht, h) in cap_t.0.iter().zip(&self.tree.cap.0) {
            pw.set_hash_target(*ht, *h);
        }

        // leaf index target
        let leaf_index_t = builder.constant(F::from_canonical_usize(leaf_index));
        let leaf_index_bits = builder.split_le(leaf_index_t, self.tree_height());

        // leaf targets
        // NOTE: takes the length from const LEAF_LEN and assume all lengths are the same
        // let leaf_t = builder.add_virtual_targets(LEAF_LEN);
        let leaf_t = builder.add_virtual_targets(self.tree.leaves[leaf_index].len());
        for j in 0..leaf_t.len() {
            pw.set_target(leaf_t[j], self.tree.leaves[leaf_index][j]);
        }

        // let mut mt = MT(self.tree.clone());
        self.verify_merkle_proof_to_cap_circuit(
            &mut builder, leaf_t.to_vec(), &leaf_index_bits, &cap_t, &proof_t,
        );
        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();

        Ok((data, proof))
    }

    pub fn verify(
        &self,
        verifier_data: &VerifierCircuitData<F, C, D>,
        public_inputs: Vec<F>,
        proof: Proof<F, C, D>
    ) -> Result<()> {
        verifier_data.verify(ProofWithPublicInputs {
            proof,
            public_inputs,
        })
    }
}

impl<F: RichField + Extendable<D> + Poseidon2, const D: usize, C: GenericConfig<D, F = F>, H: Hasher<F> + AlgebraicHasher<F>,> MerkleTreeCircuit<F, C, D, H> {

    pub fn verify_merkle_proof_circuit(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
        leaf_data: Vec<Target>,
        leaf_index_bits: &[BoolTarget],
        merkle_root: HashOutTarget,
        proof: &MerkleProofTarget,
    ) {
        let merkle_cap = MerkleCapTarget(vec![merkle_root]);
        self.verify_merkle_proof_to_cap_circuit(builder, leaf_data, leaf_index_bits, &merkle_cap, proof);
    }

    pub fn verify_merkle_proof_to_cap_circuit(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
        leaf_data: Vec<Target>,
        leaf_index_bits: &[BoolTarget],
        merkle_cap: &MerkleCapTarget,
        proof: &MerkleProofTarget,
    ) {
        let cap_index = builder.le_sum(leaf_index_bits[proof.siblings.len()..].iter().copied());
        self.verify_merkle_proof_to_cap_with_cap_index_circuit(
            builder,
            leaf_data,
            leaf_index_bits,
            cap_index,
            merkle_cap,
            proof,
        );
    }

    pub fn verify_merkle_proof_to_cap_with_cap_index_circuit(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
        leaf_data: Vec<Target>,
        leaf_index_bits: &[BoolTarget],
        cap_index: Target,
        merkle_cap: &MerkleCapTarget,
        proof: &MerkleProofTarget,
    ) {
        debug_assert!(H::AlgebraicPermutation::RATE >= NUM_HASH_OUT_ELTS);

        let zero = builder.zero();
        let mut state: HashOutTarget = builder.hash_or_noop::<H>(leaf_data);
        debug_assert_eq!(state.elements.len(), NUM_HASH_OUT_ELTS);

        for (&bit, &sibling) in leaf_index_bits.iter().zip(&proof.siblings) {
            debug_assert_eq!(sibling.elements.len(), NUM_HASH_OUT_ELTS);

            let mut perm_inputs = H::AlgebraicPermutation::default();
            perm_inputs.set_from_slice(&state.elements, 0);
            perm_inputs.set_from_slice(&sibling.elements, NUM_HASH_OUT_ELTS);
            // Ensure the rest of the state, if any, is zero:
            perm_inputs.set_from_iter(core::iter::repeat(zero), 2 * NUM_HASH_OUT_ELTS);
            // let perm_outs = builder.permute_swapped::<H>(perm_inputs, bit);
            let perm_outs = H::permute_swapped(perm_inputs, bit, builder);
            let hash_outs = perm_outs.squeeze()[0..NUM_HASH_OUT_ELTS]
                .try_into()
                .unwrap();
            state = HashOutTarget {
                elements: hash_outs,
            };
        }

        for i in 0..NUM_HASH_OUT_ELTS {
            let result = builder.random_access(
                cap_index,
                merkle_cap.0.iter().map(|h| h.elements[i]).collect(),
            );
            builder.connect(result, state.elements[i]);
        }
    }

    pub fn verify_batch_merkle_proof_to_cap_with_cap_index_circuit(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
        leaf_data: &[Vec<Target>],
        leaf_heights: &[usize],
        leaf_index_bits: &[BoolTarget],
        cap_index: Target,
        merkle_cap: &MerkleCapTarget,
        proof: &MerkleProofTarget,
    ) {
        debug_assert!(H::AlgebraicPermutation::RATE >= NUM_HASH_OUT_ELTS);

        let zero = builder.zero();
        let mut state: HashOutTarget = builder.hash_or_noop::<H>(leaf_data[0].clone());
        debug_assert_eq!(state.elements.len(), NUM_HASH_OUT_ELTS);

        let mut current_height = leaf_heights[0];
        let mut leaf_data_index = 1;
        for (&bit, &sibling) in leaf_index_bits.iter().zip(&proof.siblings) {
            debug_assert_eq!(sibling.elements.len(), NUM_HASH_OUT_ELTS);

            let mut perm_inputs = H::AlgebraicPermutation::default();
            perm_inputs.set_from_slice(&state.elements, 0);
            perm_inputs.set_from_slice(&sibling.elements, NUM_HASH_OUT_ELTS);
            // Ensure the rest of the state, if any, is zero:
            perm_inputs.set_from_iter(core::iter::repeat(zero), 2 * NUM_HASH_OUT_ELTS);
            // let perm_outs = builder.permute_swapped::<H>(perm_inputs, bit);
            let perm_outs = H::permute_swapped(perm_inputs, bit, builder);
            let hash_outs = perm_outs.squeeze()[0..NUM_HASH_OUT_ELTS]
                .try_into()
                .unwrap();
            state = HashOutTarget {
                elements: hash_outs,
            };
            current_height -= 1;

            if leaf_data_index < leaf_heights.len()
                && current_height == leaf_heights[leaf_data_index]
            {
                let mut new_leaves = state.elements.to_vec();
                new_leaves.extend_from_slice(&leaf_data[leaf_data_index]);
                state = builder.hash_or_noop::<H>(new_leaves);

                leaf_data_index += 1;
            }
        }

        for i in 0..NUM_HASH_OUT_ELTS {
            let result = builder.random_access(
                cap_index,
                merkle_cap.0.iter().map(|h| h.elements[i]).collect(),
            );
            builder.connect(result, state.elements[i]);
        }
    }

    pub fn connect_hashes(&mut self, builder: &mut CircuitBuilder<F, D>, x: HashOutTarget, y: HashOutTarget) {
        for i in 0..NUM_HASH_OUT_ELTS {
            builder.connect(x.elements[i], y.elements[i]);
        }
    }

    pub fn connect_merkle_caps(&mut self, builder: &mut CircuitBuilder<F, D>, x: &MerkleCapTarget, y: &MerkleCapTarget) {
        for (h0, h1) in x.0.iter().zip_eq(&y.0) {
            self.connect_hashes(builder, *h0, *h1);
        }
    }

    pub fn connect_verifier_data(&mut self, builder: &mut CircuitBuilder<F, D>, x: &VerifierCircuitTarget, y: &VerifierCircuitTarget) {
        self.connect_merkle_caps(builder, &x.constants_sigmas_cap, &y.constants_sigmas_cap);
        self.connect_hashes(builder, x.circuit_digest, y.circuit_digest);
    }
}

#[cfg(test)]
pub mod tests {
    use std::time::Instant;
    use rand::rngs::OsRng;
    use rand::Rng;

    use super::*;
    use plonky2::field::types::Field;
    use crate::merkle_tree::capped_tree::MerkleTree;
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

    pub fn random_data<F: Field>(n: usize, k: usize) -> Vec<Vec<F>> {
        (0..n).map(|_| F::rand_vec(k)).collect()
    }

    #[test]
    fn test_merkle_circuit() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        type H = PoseidonHash;

        // create Merkle tree
        let log_n = 8;
        let n = 1 << log_n;
        let cap_height = 1;
        let leaves = random_data::<F>(n, LEAF_LEN);
        let tree = MerkleTree::<F, <C as GenericConfig<D>>::Hasher>::new(leaves, cap_height);

        // ---- prover zone ----
        // Build and prove
        let start_build = Instant::now();
        let mut mt_circuit = MerkleTreeCircuit::<F,C,D,H>{ tree: tree.clone(), _phantom: Default::default() };
        let leaf_index: usize = OsRng.gen_range(0..n);
        let config = CircuitConfig::standard_recursion_config();
        let (data, proof_with_pub_input) = mt_circuit.build_and_prove(config,leaf_index).unwrap();
        println!("build and prove time is: {:?}", start_build.elapsed());

        let vd = data.verifier_data();
        let pub_input = proof_with_pub_input.public_inputs;
        let proof = proof_with_pub_input.proof;

        // ---- verifier zone ----
        let start_verifier = Instant::now();
        assert!(mt_circuit.verify(&vd,pub_input,proof).is_ok());
        println!("verify time is: {:?}", start_verifier.elapsed());

        Ok(())
    }

    #[test]
    fn mod_test_merkle_circuit() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        // create Merkle tree
        let log_n = 8;
        let n = 1 << log_n;
        let cap_height = 0;
        let leaves = random_data::<F>(n, LEAF_LEN);
        let tree = MerkleTree::<F, <C as GenericConfig<D>>::Hasher>::new(leaves, cap_height);

        // Build circuit
        let start_build = Instant::now();
        let mut mt_circuit = MerkleTreeCircuit{ tree: tree.clone(), _phantom: Default::default() };
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let targets = mt_circuit.build_circuit(&mut builder);
        let data = builder.build::<C>();
        let vd = data.verifier_data();
        println!("build time is: {:?}", start_build.elapsed());

        // Prover Zone
        let start_prover = Instant::now();
        let mut pw = PartialWitness::new();
        let leaf_index: usize = OsRng.gen_range(0..n);
        let proof = tree.prove(leaf_index);
        mt_circuit.fill_targets(&mut pw, leaf_index, targets);
        let proof_with_pub_input = mt_circuit.prove(data,pw).unwrap();
        let pub_input = proof_with_pub_input.public_inputs;
        let proof = proof_with_pub_input.proof;
        println!("prove time is: {:?}", start_prover.elapsed());

        // Verifier zone
        let start_verifier = Instant::now();
        assert!(mt_circuit.verify(&vd,pub_input,proof).is_ok());
        println!("verify time is: {:?}", start_verifier.elapsed());

        Ok(())
    }
}