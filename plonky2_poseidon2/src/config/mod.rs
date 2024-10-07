use plonky2::plonk::config::GenericConfig;
use plonky2_field::extension::quadratic::QuadraticExtension;
use plonky2_field::goldilocks_field::GoldilocksField;
use serde::{Deserialize, Serialize};
use crate::poseidon2_hash::poseidon2::Poseidon2Hash;

/// Configuration using Poseidon2 over the Goldilocks field.
#[derive(Debug, Copy, Clone, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct Poseidon2GoldilocksConfig;
impl GenericConfig<2> for Poseidon2GoldilocksConfig {
    type F = GoldilocksField;
    type FE = QuadraticExtension<Self::F>;
    type Hasher = Poseidon2Hash;
    type InnerHasher = Poseidon2Hash;
}