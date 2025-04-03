// Plonky2 Circuit implementation of "safe" merkle tree
// consistent with the one in codex:
// https://github.com/codex-storage/codex-storage-proofs-circuits/blob/master/circuit/codex/merkle.circom

use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField, NUM_HASH_OUT_ELTS},
    iop::target::BoolTarget,
    plonk::{
        circuit_builder::CircuitBuilder,
    },
};
use std::marker::PhantomData;
use plonky2::plonk::config::AlgebraicHasher;
use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2;
use crate::circuits::keyed_compress::key_compress_circuit;
use crate::circuits::utils::{add_assign_hash_out_target, mul_hash_out_target};
use crate::Result;
use crate::error::CircuitError;

// Constants for the keys used in compression
pub const KEY_NONE: u64 = 0x0;
pub const KEY_BOTTOM_LAYER: u64 = 0x1;
pub const KEY_ODD: u64 = 0x2;
pub const KEY_ODD_AND_BOTTOM_LAYER: u64 = 0x3;

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
    H: AlgebraicHasher<F>,
> {
    pub phantom_data: PhantomData<(F,H)>,
}

impl<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    H: AlgebraicHasher<F>,
> MerkleTreeCircuit<F, D, H> {


    pub fn new() -> Self{
        Self{
            phantom_data: Default::default(),
        }
    }

    /// Reconstructs the Merkle root from a leaf and Merkle path using a “mask” approach.
    ///
    /// # input
    ///
    /// * `builder`   - A circuit builder.
    /// * `targets`   - The Merkle targets.
    /// * `max_depth` - The maximum depth of the tree.
    ///
    /// # Returns
    ///
    /// A `HashOutTarget` representing the reconstructed Merkle root in-circuit.
    ///
    pub fn reconstruct_merkle_root_circuit_with_mask(
        builder: &mut CircuitBuilder<F, D>,
        targets: &mut MerkleTreeTargets,
        max_depth: usize,
    ) -> Result<HashOutTarget> {
        let mut state: Vec<HashOutTarget> = Vec::with_capacity(max_depth+1);
        state.push(targets.leaf);
        let zero = builder.zero();
        let one = builder.one();
        let two = builder.two();

        // --- Basic checks on input sizes.
        let path_len = targets.path_bits.len();
        let proof_len = targets.merkle_path.path.len();
        let mask_len = targets.mask_bits.len();
        let last_len = targets.last_bits.len();

        if path_len != proof_len {
            return Err(CircuitError::PathBitsLengthMismatch(path_len, proof_len));
        }

        if mask_len != path_len + 1 {
            return Err(CircuitError::MaskBitsLengthMismatch(mask_len, path_len+1));
        }

        if last_len != path_len {
            return Err(CircuitError::LastBitsLengthMismatch(last_len, path_len));
        }

        if path_len != max_depth {
            return Err(CircuitError::PathBitsMaxDepthMismatch(path_len, max_depth));
        }

        // compute is_last
        let mut is_last = vec![BoolTarget::new_unsafe(zero); max_depth + 1];
        is_last[max_depth] = BoolTarget::new_unsafe(one); // set isLast[max_depth] to 1 (true)
        for i in (0..max_depth).rev() {
            let eq_out = builder.is_equal(targets.path_bits[i].target , targets.last_bits[i].target);
            is_last[i] = builder.and( is_last[i + 1] , eq_out);
        }

        let mut i: usize = 0;
        for (&bit, &sibling) in targets.path_bits.iter().zip(&targets.merkle_path.path) {

            // logic: we add KEY_BOTTOM_LAYER if i == 0, otherwise KEY_NONE.
            let bottom_key_val = if i == 0 {
                KEY_BOTTOM_LAYER
            } else {
                KEY_NONE
            };
            let bottom = builder.constant(F::from_canonical_u64(bottom_key_val));

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

            // Compress them with a keyed-hash function
            let combined_hash = key_compress_circuit::<F, D, H>
                (builder,
                HashOutTarget::from_vec(left),
                HashOutTarget::from_vec(right),
                key);
            state.push(combined_hash);

            i += 1;
        }

        // select the right layer using the mask bits
        let mut reconstructed_root  = HashOutTarget::from_vec([builder.zero();4].to_vec());
        for k in 0..max_depth {
            let diff = builder.sub(targets.mask_bits[k].target, targets.mask_bits[k+1].target);
            let mul_result = mul_hash_out_target(builder,&diff,&mut state[k+1]);
            add_assign_hash_out_target(builder,&mut reconstructed_root, &mul_result);
        }

        Ok(reconstructed_root)

    }
}
