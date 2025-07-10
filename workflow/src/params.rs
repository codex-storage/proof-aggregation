use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use plonky2_field::goldilocks_field::GoldilocksField;

// test types
// TODO: take these from cli args
pub const D: usize = 2;
pub type F = GoldilocksField;
pub type C = PoseidonGoldilocksConfig;
pub type H = PoseidonHash;