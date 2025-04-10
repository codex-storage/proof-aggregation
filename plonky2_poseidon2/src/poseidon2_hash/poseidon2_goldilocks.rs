//! Implementations for Poseidon over Goldilocks field of width 12.
//!
//! These contents of the implementations is consistent with that in:
//! https://github.com/HorizenLabs/poseidon2

use plonky2_field::goldilocks_field::GoldilocksField;
use crate::poseidon2_hash::poseidon2::{Poseidon2, FULL_ROUND_END, PARTIAL_ROUNDS, SPONGE_WIDTH};

impl Poseidon2 for GoldilocksField {
    const MAT_DIAG12_M_1: [u64; SPONGE_WIDTH] = [
        0xc3b6c08e23ba9300,
        0xd84b5de94a324fb6,
        0x0d0c371c5b35b84f,
        0x7964f570e7188037,
        0x5daf18bbd996604b,
        0x6743bc47b9595257,
        0x5528b9362c59bb70,
        0xac45e25b7127b68b,
        0xa2077d7dfbb606b5,
        0xf3faac6faee378ae,
        0x0c6388b51545e883,
        0xd27dbb6944917b60,
    ];

    const RC12: [u64; SPONGE_WIDTH * FULL_ROUND_END] = [
        0x13dcf33aba214f46,
        0x30b3b654a1da6d83,
        0x1fc634ada6159b56,
        0x937459964dc03466,
        0xedd2ef2ca7949924,
        0xede9affde0e22f68,
        0x8515b9d6bac9282d,
        0x6b5c07b4e9e900d8,
        0x1ec66368838c8a08,
        0x9042367d80d1fbab,
        0x400283564a3c3799,
        0x4a00be0466bca75e,
        0x7913beee58e3817f,
        0xf545e88532237d90,
        0x22f8cb8736042005,
        0x6f04990e247a2623,
        0xfe22e87ba37c38cd,
        0xd20e32c85ffe2815,
        0x117227674048fe73,
        0x4e9fb7ea98a6b145,
        0xe0866c232b8af08b,
        0x00bbc77916884964,
        0x7031c0fb990d7116,
        0x240a9e87cf35108f,
        0x2e6363a5a12244b3,
        0x5e1c3787d1b5011c,
        0x4132660e2a196e8b,
        0x3a013b648d3d4327,
        0xf79839f49888ea43,
        0xfe85658ebafe1439,
        0xb6889825a14240bd,
        0x578453605541382b,
        0x4508cda8f6b63ce9,
        0x9c3ef35848684c91,
        0x0812bde23c87178c,
        0xfe49638f7f722c14,
        0x8e3f688ce885cbf5,
        0xb8e110acf746a87d,
        0xb4b2e8973a6dabef,
        0x9e714c5da3d462ec,
        0x6438f9033d3d0c15,
        0x24312f7cf1a27199,
        0x23f843bb47acbf71,
        0x9183f11a34be9f01,
        0x839062fbb9d45dbf,
        0x24b56e7e6c2e43fa,
        0xe1683da61c962a72,
        0xa95c63971a19bfa7,
        0xc68be7c94882a24d,
        0xaf996d5d5cdaedd9,
        0x9717f025e7daf6a5,
        0x6436679e6e7216f4,
        0x8a223d99047af267,
        0xbb512e35a133ba9a,
        0xfbbf44097671aa03,
        0xf04058ebf6811e61,
        0x5cca84703fac7ffb,
        0x9b55c7945de6469f,
        0x8e05bf09808e934f,
        0x2ea900de876307d7,
        0x7748fff2b38dfb89,
        0x6b99a676dd3b5d81,
        0xac4bb7c627cf7c13,
        0xadb6ebe5e9e2f5ba,
        0x2d33378cafa24ae3,
        0x1e5b73807543f8c2,
        0x09208814bfebb10f,
        0x782e64b6bb5b93dd,
        0xadd5a48eac90b50f,
        0xadd4c54c736ea4b1,
        0xd58dbb86ed817fd8,
        0x6d5ed1a533f34ddd,
        0x28686aa3e36b7cb9,
        0x591abd3476689f36,
        0x047d766678f13875,
        0xa2a11112625f5b49,
        0x21fd10a3f8304958,
        0xf9b40711443b0280,
        0xd2697eb8b2bde88e,
        0x3493790b51731b3f,
        0x11caf9dd73764023,
        0x7acfb8f72878164e,
        0x744ec4db23cefc26,
        0x1e00e58f422c6340,
        0x21dd28d906a62dda,
        0xf32a46ab5f465b5f,
        0xbfce13201f3f7e6b,
        0xf30d2e7adb5304e2,
        0xecdf4ee4abad48e9,
        0xf94e82182d395019,
        0x4ee52e3744d887c5,
        0xa1341c7cac0083b2,
        0x2302fb26c30c834a,
        0xaea3c587273bf7d3,
        0xf798e24961823ec7,
        0x962deba3e9a2cd94,
    ];

    const RC12_MID: [u64; PARTIAL_ROUNDS] = [
        0x4adf842aa75d4316,
        0xf8fbb871aa4ab4eb,
        0x68e85b6eb2dd6aeb,
        0x07a0b06b2d270380,
        0xd94e0228bd282de4,
        0x8bdd91d3250c5278,
        0x209c68b88bba778f,
        0xb5e18cdab77f3877,
        0xb296a3e808da93fa,
        0x8370ecbda11a327e,
        0x3f9075283775dad8,
        0xb78095bb23c6aa84,
        0x3f36b9fe72ad4e5f,
        0x69bc96780b10b553,
        0x3f1d341f2eb7b881,
        0x4e939e9815838818,
        0xda366b3ae2a31604,
        0xbc89db1e7287d509,
        0x6102f411f9ef5659,
        0x58725c5e7ac1f0ab,
        0x0df5856c798883e7,
        0xf7bb62a8da4c961b,
    ];
}

#[cfg(test)]
mod tests {

    use plonky2_field::goldilocks_field::GoldilocksField as F;
    use crate::poseidon2_hash::poseidon2::test_helpers::check_test_vectors;

    #[test]
    fn test_vectors() {
        // Test inputs are:
        // 1. range 0..WIDTH
        // expected output calculated with reference implementation here:
        // https://github.com/HorizenLabs/poseidon2

        #[rustfmt::skip]
        let test_vectors12: Vec<([u64; 12], [u64; 12])> = vec![
             ([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, ],
              [0x01eaef96bdf1c0c1, 0x1f0d2cc525b2540c, 0x6282c1dfe1e0358d, 0xe780d721f698e1e6,
                  0x280c0b6f753d833b, 0x1b942dd5023156ab, 0x43f0df3fcccb8398, 0xe8e8190585489025,
                  0x56bdbf72f77ada22, 0x7911c32bf9dcd705, 0xec467926508fbe67, 0x6a50450ddf85a6ed,]),
        ];

        check_test_vectors::<F>(test_vectors12);
    }
}
