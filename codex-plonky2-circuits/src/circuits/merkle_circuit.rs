// Plonky2 Circuit implementation of "safe" merkle tree
// consistent with the one in codex:
// https://github.com/codex-storage/codex-storage-proofs-circuits/blob/master/circuit/codex/merkle.circom

use anyhow::Result;
use plonky2::field::extension::Extendable;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::{HashOutTarget, RichField, NUM_HASH_OUT_ELTS};
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig, GenericHashOut, Hasher, PoseidonGoldilocksConfig};
use std::marker::PhantomData;
use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2;
use crate::circuits::keyed_compress::key_compress_circuit;
use crate::circuits::params::HF;
use crate::circuits::utils::{add_assign_hash_out_target, assign_bool_targets, assign_hash_out_targets, mul_hash_out_target, usize_to_bits_le_padded};
use crate::merkle_tree::merkle_safe::{KEY_NONE,KEY_BOTTOM_LAYER};

/// Merkle tree targets representing the input to the circuit
#[derive(Clone)]
pub struct MerkleTreeTargets{
    pub leaf: HashOutTarget,
    pub path_bits: Vec<BoolTarget>,
    pub last_bits: Vec<BoolTarget>,
    pub mask_bits: Vec<BoolTarget>,
    pub merkle_path: MerkleProofTarget,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MerkleProofTarget {
    /// The Merkle digest of each sibling subtree, staying from the bottommost layer.
    pub path: Vec<HashOutTarget>,
}

/// Merkle tree circuit contains the functions for
/// building, proving and verifying the circuit.
#[derive(Clone)]
pub struct MerkleTreeCircuit<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
> {
    pub phantom_data: PhantomData<F>,
}

impl<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
> MerkleTreeCircuit<F, D> {


    pub fn new() -> Self{
        Self{
            phantom_data: Default::default(),
        }
    }

    /// takes the params from the targets struct
    /// outputs the reconstructed merkle root
    pub fn reconstruct_merkle_root_circuit(
        builder: &mut CircuitBuilder<F, D>,
        targets: &mut MerkleTreeTargets,
        max_depth: usize,
    ) -> HashOutTarget {
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

            state = key_compress_circuit::<F,D,HF>(builder,left,right,key);

            i += 1;
        }

        return state;
    }

    /// takes the params from the targets struct
    /// outputs the reconstructed merkle root
    /// this one uses the mask bits to select the right layer
    pub fn reconstruct_merkle_root_circuit_with_mask(
        builder: &mut CircuitBuilder<F, D>,
        targets: &mut MerkleTreeTargets,
        max_depth: usize,
    ) -> HashOutTarget {
        let mut state: Vec<HashOutTarget> = Vec::with_capacity(max_depth+1);
        state.push(targets.leaf);
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
            for j in 0..NUM_HASH_OUT_ELTS {
                left.push( builder.select(bit, sibling.elements[j], state[i].elements[j]));
                right.push( builder.select(bit, state[i].elements[j], sibling.elements[j]));
            }

            state.push(key_compress_circuit::<F,D,HF>(builder,left,right,key));

            i += 1;
        }

        // select the right layer using the mask bits
        // another way to do this is to use builder.select
        // but that might be less efficient & more constraints
        let mut reconstructed_root  = HashOutTarget::from_vec([builder.zero();4].to_vec());
        for k in 0..max_depth {
            let diff = builder.sub(targets.mask_bits[k].target, targets.mask_bits[k+1].target);
            let mul_result = mul_hash_out_target(builder,&diff,&mut state[k+1]);
            add_assign_hash_out_target(builder,&mut reconstructed_root, &mul_result);
        }

        reconstructed_root

    }
}
