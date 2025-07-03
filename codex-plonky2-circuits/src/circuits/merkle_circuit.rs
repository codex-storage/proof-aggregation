// Plonky2 Circuit implementation of the Codex-specific "safe" merkle tree
// consistent with the one in codex:
// https://github.com/codex-storage/codex-storage-proofs-circuits/blob/master/circuit/codex/merkle.circom

use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    iop::target::BoolTarget,
    plonk::{
        circuit_builder::CircuitBuilder,
    },
};
use std::marker::PhantomData;
use plonky2::plonk::config::AlgebraicHasher;
use serde::{Deserialize, Serialize};
use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2;
use crate::circuits::keyed_compress::key_compress_circuit;
use crate::circuits::serialization::SerializableHashOutTarget;
use crate::circuits::utils::{add_assign_hash_out_target, mul_hash_out_target, select_hash};
use crate::Result;
use crate::error::CircuitError;

// Constants for the keys used in compression
pub const KEY_NONE: u64 = 0x0;
pub const KEY_BOTTOM_LAYER: u64 = 0x1;
pub const KEY_ODD: u64 = 0x2;
pub const KEY_ODD_AND_BOTTOM_LAYER: u64 = 0x3;

/// Merkle tree targets representing the input to the circuit
///  * `leaf`:        the leaf hash
///  * `path_bits`:    the linear index of the leaf, in binary decomposition (least significant bit first)
///  * `last_bits`:    the index of the last leaf (= nLeaves-1), in binary decomposition
///  * `mask_bits`:    the bits of the mask `2^ceilingLog2(size) - 1`
///  * `merkle_path`:  the Merkle inclusion proof (required hashes, starting from the leaf and ending near the root)
#[derive(Clone)]
pub struct MerkleTreeTargets{
    pub leaf: HashOutTarget,
    pub path_bits: Vec<BoolTarget>,
    pub last_bits: Vec<BoolTarget>,
    pub mask_bits: Vec<BoolTarget>,
    pub merkle_path: MerkleProofTarget,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MerkleProofTarget {
    /// The Merkle digest of each sibling subtree, staying from the bottommost layer.
    pub path: Vec<SerializableHashOutTarget>,
}

/// contains the functions for reconstructing the Merkle root and returns it.
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

        // --- Basic checks on input sizes -------
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

        // in case of a singleton tree, we receive maskBits = [0,0,0,...,0]
        // but what we really need is [1,0,0,0,...,0]
        // because we always expect [1,1,...,1,0,0,...,0],
        // we can just set the first entry to 1 and that should fix this issue.
        let mut mask_bit_corrected: Vec<BoolTarget> = targets.mask_bits.clone();
        mask_bit_corrected[0] = builder.constant_bool(true);

        // ------ Compute is_last --------
        // Determine whether nodes from the path are last in their row and are odd,
        // by computing which binary prefixes of the index are the same as the
        // corresponding prefix of the last index.
        // This is done in reverse bit order, because pathBits and lastBits have the
        // least significant bit first.
        let mut is_last: Vec<BoolTarget> = vec![builder.constant_bool(false); max_depth + 1];
        is_last[max_depth] = builder.constant_bool(true);
        for i in (0..max_depth).rev() {
            let eq_out = builder.is_equal(targets.path_bits[i].target , targets.last_bits[i].target);
            is_last[i] = builder.and( is_last[i + 1] , eq_out);
        }

        // ------ Compute the sequence of hashes --------
        for i in 0..path_len {

            let bit = targets.path_bits[i];
            let sibling = targets.merkle_path.path[i];

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
            let left = select_hash(builder, bit, sibling.0, state[i]);
            let right = select_hash(builder, bit,state[i], sibling.0);

            // Compress them with a keyed-hash function
            let combined_hash = key_compress_circuit::<F, D, H>
                (builder,
                left,
                right,
                key);
            state.push(combined_hash);

        }

        // select the right layer using the corrected mask bits
        let mut reconstructed_root  = HashOutTarget::from_vec([zero;4].to_vec());
        for k in 0..max_depth {
            let diff = builder.sub(mask_bit_corrected[k].target, mask_bit_corrected[k+1].target);
            let mul_result = mul_hash_out_target(builder,&diff,&mut state[k+1]);
            add_assign_hash_out_target(builder,&mut reconstructed_root, &mul_result);
        }

        Ok(reconstructed_root)

    }
}

