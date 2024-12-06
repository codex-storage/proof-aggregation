use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2_field::goldilocks_field::GoldilocksField;
use plonky2_poseidon2::config::Poseidon2GoldilocksConfig;

// recursion param
pub type F = GoldilocksField;
pub const D: usize = 2;
pub type C = Poseidon2GoldilocksConfig;
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
