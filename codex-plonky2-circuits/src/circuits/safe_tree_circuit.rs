// Plonky2 Circuit implementation of "safe" merkle tree
// consistent with the one in codex:
// https://github.com/codex-storage/codex-storage-proofs-circuits/blob/master/circuit/codex/merkle.circom

use anyhow::Result;
use plonky2::field::extension::Extendable;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::{HashOut, HashOutTarget, RichField, NUM_HASH_OUT_ELTS};
use plonky2::hash::hashing::PlonkyPermutation;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::{PartialWitness, Witness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, VerifierCircuitData};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig, GenericHashOut, Hasher, PoseidonGoldilocksConfig};
use plonky2::plonk::proof::{Proof, ProofWithPublicInputs};
use std::marker::PhantomData;
use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2;
use serde::Serialize;
use crate::circuits::utils::usize_to_bits_le_padded;

use crate::merkle_tree::merkle_safe::{MerkleTree, MerkleProofTarget};
use crate::merkle_tree::merkle_safe::{KEY_NONE,KEY_BOTTOM_LAYER};


/// Merkle tree targets representing the input to the circuit
// note: this omits the mask bits since in plonky2 we can
// uses the Plonk's permutation argument to check that two elements are equal.
// TODO: double check the need for mask
#[derive(Clone)]
pub struct MerkleTreeTargets<
    F: RichField + Extendable<D> + Poseidon2,
    C: GenericConfig<D, F = F>,
    const D: usize,
    H: Hasher<F> + AlgebraicHasher<F>,
> {
    pub leaf: HashOutTarget,
    pub path_bits: Vec<BoolTarget>,
    pub last_bits: Vec<BoolTarget>,
    pub merkle_path: MerkleProofTarget,
    pub _phantom: PhantomData<(C, H)>,
}

/// Merkle tree circuit contains the tree and functions for
/// building, proving and verifying the circuit.
#[derive(Clone)]
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
    C: GenericConfig<D, F=F>,
    const D: usize,
    H: Hasher<F> + AlgebraicHasher<F>,
> MerkleTreeCircuit<F, C, D, H> {

    /// defines the computations inside the circuit and returns the targets used
    pub fn build_circuit(
        &mut self,
        builder: &mut CircuitBuilder::<F, D>
    ) -> (MerkleTreeTargets<F, C, { D }, H>, HashOutTarget) {
        // Retrieve tree depth
        let depth = self.tree.depth();

        // Create virtual targets
        let leaf = builder.add_virtual_hash();

        // path bits (binary decomposition of leaf_index)
        let path_bits = (0..depth).map(|_| builder.add_virtual_bool_target_safe()).collect::<Vec<_>>();

        // last bits (binary decomposition of last_index = nleaves - 1)
        let last_bits = (0..depth).map(|_| builder.add_virtual_bool_target_safe()).collect::<Vec<_>>();

        // Merkle path (sibling hashes from leaf to root)
        let merkle_path = MerkleProofTarget {
            path: (0..depth).map(|_| builder.add_virtual_hash()).collect(),
        };

        // create MerkleTreeTargets struct
        let mut targets = MerkleTreeTargets {
            leaf,
            path_bits,
            last_bits,
            merkle_path,
            _phantom: PhantomData,
        };

        // Add Merkle proof verification constraints to the circuit
        let expected_root_target = Self::reconstruct_merkle_root_circuit(builder, &mut targets);

        // Return MerkleTreeTargets
        (targets, expected_root_target)
    }

    /// assign the witness values in the circuit targets
    /// this takes leaf_index and fills all required circuit targets(inputs)
    pub fn assign_witness(
        &mut self,
        pw: &mut PartialWitness<F>,
        targets: &mut MerkleTreeTargets<F, C, D, H>,
        leaf_index: usize,
    )-> Result<()> {
        // Get the total number of leaves and tree depth
        let nleaves = self.tree.leaves_count();
        let depth = self.tree.depth();

        // get the Merkle proof for the specified leaf index
        let proof = self.tree.get_proof(leaf_index)?;

        // get the leaf hash from the Merkle tree
        let leaf_hash = self.tree.layers[0][leaf_index].clone();

        // Assign the leaf hash to the leaf target
        pw.set_hash_target(targets.leaf, leaf_hash);

        // Convert `leaf_index` to binary bits and assign as path_bits
        let path_bits = usize_to_bits_le_padded(leaf_index, depth);
        for (i, bit) in path_bits.iter().enumerate() {
            pw.set_bool_target(targets.path_bits[i], *bit);
        }

        // get `last_index` (nleaves - 1) in binary bits and assign
        let last_index = nleaves - 1;
        let last_bits = usize_to_bits_le_padded(last_index, depth);
        for (i, bit) in last_bits.iter().enumerate() {
            pw.set_bool_target(targets.last_bits[i], *bit);
        }

        // assign the Merkle path (sibling hashes) to the targets
        for (i, sibling_hash) in proof.path.iter().enumerate() {
            // This is a bit hacky because it should be HashOutTarget, but it is H:Hash
            // pw.set_hash_target(targets.merkle_path.path[i],sibling_hash);
            // TODO: fix this HashOutTarget later
            let sibling_hash_out = sibling_hash.to_vec();
            for j in 0..sibling_hash_out.len() {
                pw.set_target(targets.merkle_path.path[i].elements[j], sibling_hash_out[j]);
            }
        }

        Ok(())
    }

    /// takes the params from the targets struct
    /// outputs the reconstructed merkle root
    pub fn reconstruct_merkle_root_circuit(
        // &self,
        builder: &mut CircuitBuilder<F, D>,
        targets: &mut MerkleTreeTargets<F, C, D, H>,
    ) -> HashOutTarget {
        let max_depth = targets.path_bits.len();
        let mut state: HashOutTarget = targets.leaf;
        let zero = builder.zero();
        let one = builder.one();
        let two = builder.two();
        debug_assert_eq!(targets.path_bits.len(), targets.merkle_path.path.len());

        // compute is_last
        let mut is_last = vec![BoolTarget::new_unsafe(zero); max_depth + 1];
        is_last[max_depth] = BoolTarget::new_unsafe(one); // set isLast[max_depth] to 1 (true)
        for i in (0..max_depth).rev() {
            let eq_out = builder.is_equal(targets.path_bits[i].target , targets.last_bits[i].target);
            is_last[i] = builder.and( is_last[i + 1] , eq_out);
        }

        let mut i: usize = 0;
        for (&bit, &sibling) in targets.path_bits.iter().zip(&targets.merkle_path.path) {
            debug_assert_eq!(sibling.elements.len(), NUM_HASH_OUT_ELTS);

            let bottom = if i == 0 {
                builder.constant(F::from_canonical_u64(KEY_BOTTOM_LAYER))
            } else {
                builder.constant(F::from_canonical_u64(KEY_NONE))
            };

            // compute: odd = isLast[i] * (1-pathBits[i]);
            // compute: key = bottom + 2*odd
            let mut odd = builder.sub(one, targets.path_bits[i].target);
            odd = builder.mul(is_last[i].target, odd);
            odd = builder.mul(two, odd);
            let key = builder.add(bottom,odd);

            // select left and right based on path_bit
            let mut left = vec![];
            let mut right = vec![];
            for i in 0..NUM_HASH_OUT_ELTS {
                left.push( builder.select(bit, sibling.elements[i], state.elements[i]));
                right.push( builder.select(bit, state.elements[i], sibling.elements[i]));
            }

            // hash left, right, and key
            let mut perm_inputs:Vec<Target>= Vec::new();
            perm_inputs.extend_from_slice(&left);
            perm_inputs.extend_from_slice(&right);
            perm_inputs.push(key);
            state = builder.hash_n_to_hash_no_pad::<H>(perm_inputs);

            i += 1;
        }

        return state;
    }
}

// NOTE: for now these tests don't check the reconstructed root is equal to expected_root
// will be fixed later, but for that test check the prove_single_cell tests
#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::field::types::Field;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use plonky2::iop::witness::PartialWitness;

    #[test]
    fn test_build_circuit() -> Result<()> {
        // circuit params
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type H = PoseidonHash;

        // Generate random leaf data
        let nleaves = 10; // Number of leaves
        let data = (0..nleaves)
            .map(|i| GoldilocksField::from_canonical_u64(i))
            .collect::<Vec<_>>();
        // Hash the data to obtain leaf hashes
        let leaves: Vec<HashOut<GoldilocksField>> = data
            .iter()
            .map(|&element| {
                // Hash each field element to get the leaf hash
                PoseidonHash::hash_no_pad(&[element])
            })
            .collect();

        //initialize the Merkle tree
        let zero_hash = HashOut {
            elements: [GoldilocksField::ZERO; 4],
        };
        let tree = MerkleTree::<F, H>::new(&leaves, zero_hash)?;

        // select leaf index to prove
        let leaf_index: usize = 8;

        // get the Merkle proof for the selected leaf
        let proof = tree.get_proof(leaf_index)?;
        // sanity check:
        let check = proof.verify(tree.layers[0][leaf_index],tree.root().unwrap()).unwrap();
        assert_eq!(check, true);

        // get the expected Merkle root
        let expected_root = tree.root()?;

        // create the circuit
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let mut circuit_instance = MerkleTreeCircuit::<F, C, D, H> {
            tree: tree.clone(),
            _phantom: PhantomData,
        };
        let (mut targets, expected_root_target) = circuit_instance.build_circuit(&mut builder);

        // create a PartialWitness and assign
        let mut pw = PartialWitness::new();
        circuit_instance.assign_witness(&mut pw, &mut targets, leaf_index)?;

        // build the circuit
        let data = builder.build::<C>();

        // Prove the circuit with the assigned witness
        let proof_with_pis = data.prove(pw)?;

        // verify the proof
        let verifier_data = data.verifier_data();
        assert!(
            verifier_data.verify(proof_with_pis).is_ok(),
            "Merkle proof verification failed"
        );

        Ok(())
    }

    // same as test above but for all leaves
    #[test]
    fn test_verify_all_leaves() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type H = PoseidonHash;

        let nleaves = 10; // Number of leaves
        let data = (0..nleaves)
            .map(|i| GoldilocksField::from_canonical_u64(i as u64))
            .collect::<Vec<_>>();
        // Hash the data to obtain leaf hashes
        let leaves: Vec<HashOut<GoldilocksField>> = data
            .iter()
            .map(|&element| {
                // Hash each field element to get the leaf hash
                PoseidonHash::hash_no_pad(&[element])
            })
            .collect();

        let zero_hash = HashOut {
            elements: [GoldilocksField::ZERO; 4],
        };
        let tree = MerkleTree::<F, H>::new(&leaves, zero_hash)?;

        let expected_root = tree.root()?;

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let mut circuit_instance = MerkleTreeCircuit::<F, C, D, H> {
            tree: tree.clone(),
            _phantom: PhantomData,
        };
        let (mut targets, expected_root_target) = circuit_instance.build_circuit(&mut builder);

        let data = builder.build::<C>();

        for leaf_index in 0..nleaves {
            let proof = tree.get_proof(leaf_index)?;
            let check = proof.verify(tree.layers[0][leaf_index], expected_root)?;
            assert!(
                check,
                "Merkle proof verification failed for leaf index {}",
                leaf_index
            );

            let mut pw = PartialWitness::new();

            circuit_instance.assign_witness(&mut pw, &mut targets, leaf_index)?;

            let proof_with_pis = data.prove(pw)?;

            let verifier_data = data.verifier_data();
            assert!(
                verifier_data.verify(proof_with_pis).is_ok(),
                "Merkle proof verification failed in circuit for leaf index {}",
                leaf_index
            );
        }

        Ok(())
    }
}