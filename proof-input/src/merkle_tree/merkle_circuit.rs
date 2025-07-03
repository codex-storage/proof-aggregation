use codex_plonky2_circuits::Result;
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::{HashOut, HashOutTarget, NUM_HASH_OUT_ELTS, RichField};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::config::AlgebraicHasher;
use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2;
use codex_plonky2_circuits::circuits::merkle_circuit::{MerkleProofTarget, MerkleTreeCircuit, MerkleTreeTargets};
use codex_plonky2_circuits::circuits::serialization::SerializableHashOutTarget;
use codex_plonky2_circuits::circuits::utils::{assign_bool_targets, assign_hash_out_targets};
use codex_plonky2_circuits::error::CircuitError;

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
    H: AlgebraicHasher<F>,
>(
    builder: &mut CircuitBuilder<F, D>,
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
        path: (0..depth).map(|_| builder.add_virtual_hash()).map(SerializableHashOutTarget::from).collect(),
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
    let reconstructed_root_target = MerkleTreeCircuit::<F,D,H>::reconstruct_merkle_root_circuit_with_mask(builder, &mut targets, depth).unwrap();

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
    pw.set_hash_target(targets.leaf, witnesses.leaf)
        .map_err(|e| {
            CircuitError::HashTargetAssignmentError("leaf".to_string(), e.to_string())
        })?;

    // Assign path bits
    assign_bool_targets(pw, &targets.path_bits, witnesses.path_bits)
        .map_err(|e| {
            CircuitError::BoolTargetAssignmentError("path_bits".to_string(), e.to_string())
        })?;

    // Assign last bits
    assign_bool_targets(pw, &targets.last_bits, witnesses.last_bits)
        .map_err(|e| {
            CircuitError::BoolTargetAssignmentError("last_bits".to_string(), e.to_string())
        })?;

    // Assign mask bits
    assign_bool_targets(pw, &targets.mask_bits, witnesses.mask_bits)
        .map_err(|e| {
            CircuitError::BoolTargetAssignmentError("mask_bits".to_string(), e.to_string())
        })?;

    // assign the Merkle path (sibling hashes) to the targets
    for i in 0..targets.merkle_path.path.len() {
        if i>=witnesses.merkle_path.len() { // pad with zeros
            assign_hash_out_targets(pw, &targets.merkle_path.path[i].0, &HashOut::from_vec([F::ZERO; NUM_HASH_OUT_ELTS].to_vec()))?;
            continue
        }
        assign_hash_out_targets(pw, &targets.merkle_path.path[i].0, &witnesses.merkle_path[i])?;
    }
    Ok(())
}