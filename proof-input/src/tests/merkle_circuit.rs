use anyhow::Result;
use plonky2::field::extension::Extendable;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::{HashOut, HashOutTarget, NUM_HASH_OUT_ELTS, RichField};
use plonky2::hash::hashing::PlonkyPermutation;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::witness::{PartialWitness, Witness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig, GenericHashOut, Hasher, PoseidonGoldilocksConfig};
use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2;
use serde::Serialize;
use codex_plonky2_circuits::circuits::merkle_circuit::{MerkleProofTarget, MerkleTreeCircuit, MerkleTreeTargets};
use codex_plonky2_circuits::circuits::utils::{assign_bool_targets, assign_hash_out_targets};
use crate::utils::usize_to_bits_le;

use codex_plonky2_circuits::merkle_tree::merkle_safe::MerkleTree;

/// the input to the merkle tree circuit
#[derive(Clone)]
pub struct MerkleTreeCircuitInput<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
>{
    pub leaf: HashOut<F>,
    pub path_bits: Vec<bool>,
    pub last_bits: Vec<bool>,
    pub mask_bits: Vec<bool>,
    pub merkle_path: Vec<HashOut<F>>,
}

/// defines the computations inside the circuit and returns the targets used
/// NOTE: this is not used in the sampling circuit, see reconstruct_merkle_root_circuit_with_mask
pub fn build_circuit<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
>(
    builder: &mut CircuitBuilder::<F, D>,
    depth: usize,
) -> (MerkleTreeTargets, HashOutTarget) {

    // Create virtual targets
    let leaf = builder.add_virtual_hash();

    // path bits (binary decomposition of leaf_index)
    let path_bits = (0..depth).map(|_| builder.add_virtual_bool_target_safe()).collect::<Vec<_>>();

    // last bits (binary decomposition of last_index = nleaves - 1)
    let last_bits = (0..depth).map(|_| builder.add_virtual_bool_target_safe()).collect::<Vec<_>>();

    // last bits (binary decomposition of last_index = nleaves - 1)
    let mask_bits = (0..depth+1).map(|_| builder.add_virtual_bool_target_safe()).collect::<Vec<_>>();

    // Merkle path (sibling hashes from leaf to root)
    let merkle_path = MerkleProofTarget {
        path: (0..depth).map(|_| builder.add_virtual_hash()).collect(),
    };

    // create MerkleTreeTargets struct
    let mut targets = MerkleTreeTargets{
        leaf,
        path_bits,
        last_bits,
        mask_bits,
        merkle_path,
    };

    // Add Merkle proof verification constraints to the circuit
    let reconstructed_root_target = MerkleTreeCircuit::reconstruct_merkle_root_circuit_with_mask(builder, &mut targets, depth);

    // Return MerkleTreeTargets
    (targets, reconstructed_root_target)
}

/// assign the witness values in the circuit targets
/// this takes MerkleTreeCircuitInput and fills all required circuit targets
pub fn assign_witness<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
>(
    pw: &mut PartialWitness<F>,
    targets: &mut MerkleTreeTargets,
    witnesses: MerkleTreeCircuitInput<F, D>
)-> Result<()> {
    // Assign the leaf hash to the leaf target
    pw.set_hash_target(targets.leaf, witnesses.leaf);

    // Assign path bits
    assign_bool_targets(pw, &targets.path_bits, witnesses.path_bits);

    // Assign last bits
    assign_bool_targets(pw, &targets.last_bits, witnesses.last_bits);

    // Assign mask bits
    assign_bool_targets(pw, &targets.mask_bits, witnesses.mask_bits);

    // assign the Merkle path (sibling hashes) to the targets
    for i in 0..targets.merkle_path.path.len() {
        if i>=witnesses.merkle_path.len() { // pad with zeros
            assign_hash_out_targets(pw, &targets.merkle_path.path[i].elements, &[F::ZERO; NUM_HASH_OUT_ELTS]);
            continue
        }
        assign_hash_out_targets(pw, &targets.merkle_path.path[i].elements, &witnesses.merkle_path[i].elements)
    }
    Ok(())
}


#[cfg(test)]
mod tests {
    use plonky2::hash::hash_types::HashOut;
    use plonky2::hash::poseidon::PoseidonHash;
    use super::*;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use plonky2::iop::witness::PartialWitness;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2_field::goldilocks_field::GoldilocksField;
    // use crate::merkle_tree::merkle_safe::MerkleTree;

    // NOTE: for now these tests don't check the reconstructed root is equal to expected_root
    // will be fixed later, but for that test check the other tests in this crate
    #[test]
    fn test_build_circuit() -> anyhow::Result<()> {
        // circuit params
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type H = PoseidonHash;

        // Generate random leaf data
        let nleaves = 16; // Number of leaves
        let max_depth = 4;
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
        let tree = MerkleTree::<F, D>::new(&leaves, zero_hash)?;

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
        let (mut targets, reconstructed_root_target) = build_circuit(&mut builder, max_depth);

        // expected Merkle root
        let expected_root = builder.add_virtual_hash();

        // check equality with expected root
        for i in 0..NUM_HASH_OUT_ELTS {
            builder.connect(expected_root.elements[i], reconstructed_root_target.elements[i]);
        }

        let path_bits = usize_to_bits_le(leaf_index, max_depth);
        let last_index = (nleaves - 1) as usize;
        let last_bits = usize_to_bits_le(last_index, max_depth);
        let mask_bits = usize_to_bits_le(last_index, max_depth+1);

        // circuit input
        let circuit_input = MerkleTreeCircuitInput::<F, D>{
            leaf: tree.layers[0][leaf_index],
            path_bits,
            last_bits,
            mask_bits,
            merkle_path: proof.path,
        };

        // create a PartialWitness and assign
        let mut pw = PartialWitness::new();
        assign_witness(&mut pw, &mut targets, circuit_input)?;
        pw.set_hash_target(expected_root, tree.root().unwrap());

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
    fn test_verify_all_leaves() -> anyhow::Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type H = PoseidonHash;

        let nleaves = 16; // Number of leaves
        let max_depth = 4;
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
        let tree = MerkleTree::<F, D>::new(&leaves, zero_hash)?;

        let expected_root = tree.root()?;

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let (mut targets, reconstructed_root_target) = build_circuit(&mut builder, max_depth);

        // expected Merkle root
        let expected_root_target = builder.add_virtual_hash();

        // check equality with expected root
        for i in 0..NUM_HASH_OUT_ELTS {
            builder.connect(expected_root_target.elements[i], reconstructed_root_target.elements[i]);
        }

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

            let path_bits = usize_to_bits_le(leaf_index, max_depth);
            let last_index = (nleaves - 1) as usize;
            let last_bits = usize_to_bits_le(last_index, max_depth);
            let mask_bits = usize_to_bits_le(last_index, max_depth+1);

            // circuit input
            let circuit_input = MerkleTreeCircuitInput::<F, D>{
                leaf: tree.layers[0][leaf_index],
                path_bits,
                last_bits,
                mask_bits,
                merkle_path: proof.path,
            };

            assign_witness(&mut pw, &mut targets, circuit_input)?;
            pw.set_hash_target(expected_root_target, expected_root);

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