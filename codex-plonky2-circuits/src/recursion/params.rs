use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2_field::goldilocks_field::GoldilocksField;
use plonky2_poseidon2::config::Poseidon2GoldilocksConfig;

// recursion param
// TODO: make it more generic or use global params
pub type F = GoldilocksField;
pub const D: usize = 2;
pub type C = PoseidonGoldilocksConfig;
pub type H = PoseidonHash;
pub type Plonky2Proof = ProofWithPublicInputs<F, C, D>;


pub struct RecursionTreeParams{
    pub tree_width: usize,
}

impl RecursionTreeParams {
    pub fn new(tree_width: usize) -> Self{
        Self{
            tree_width
        }
    }
}
