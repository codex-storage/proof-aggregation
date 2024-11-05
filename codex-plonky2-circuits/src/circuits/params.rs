// global params for the circuits

use plonky2::hash::poseidon::PoseidonHash;
use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2Hash;

// hash function used. this is hackish way of doing it because
// H::Hash is not consistent with HashOut<F> and causing a lot of headache
// will look into this later.
pub type HF = PoseidonHash;

