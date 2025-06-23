use plonky2::hash::hash_types::{HashOut, NUM_HASH_OUT_ELTS, RichField};
use plonky2_field::extension::Extendable;
use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2;
use plonky2::plonk::config::Hasher;
use plonky2::hash::hashing::PlonkyPermutation;

/// sponge function similar to the in-circuit one
/// used here for testing / sanity check
pub fn hash_n_with_padding<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    H: Hasher<F>
>(
    inputs: &[F],
) -> HashOut<F>{
    HashOut::<F>::from_vec(hash_n_to_m_with_padding::<F,D,H::Permutation>(inputs, NUM_HASH_OUT_ELTS))
}

pub fn hash_n_to_m_with_padding<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    P: PlonkyPermutation<F>
>(
    inputs: &[F],
    num_outputs: usize,
) -> Vec<F> {
    let rate = P::RATE;
    let width = P::WIDTH; // rate + capacity
    let zero = F::ZERO;
    let one = F::ONE;
    let mut perm = P::new(core::iter::repeat(zero).take(width));

    // Set the domain separator at index 8
    let domsep_value = F::from_canonical_u64(rate as u64 + 256 * 12 + 65536 * 63);
    perm.set_elt(domsep_value, 8);

    let input_n = inputs.len();
    let num_chunks = (input_n + rate) / rate; // Calculate number of chunks with 10* padding
    let mut input_iter = inputs.iter();

    // Process all chunks except the last one
    for _ in 0..(num_chunks - 1) {
        let mut chunk = Vec::with_capacity(rate);
        for _ in 0..rate {
            if let Some(&input) = input_iter.next() {
                chunk.push(input);
            } else {
                // should not happen here
                panic!("Insufficient input elements for chunk; expected more elements.");
            }
        }
        // Add the chunk to the state
        for j in 0..rate {
            perm.set_elt(perm.as_ref()[j] + chunk[j],j);
        }
        // Apply permutation
        perm.permute();
    }

    // Process the last chunk with 10* padding
    let rem = num_chunks * rate - input_n; // Number of padding elements (0 < rem <= rate)
    let ofs = rate - rem;            // Offset where padding starts

    let mut last_chunk = Vec::with_capacity(rate);
    // Absorb remaining inputs
    for _ in 0..ofs {
        if let Some(&input) = input_iter.next() {
            last_chunk.push(input);
        } else {
            last_chunk.push(zero);
        }
    }
    // Add the '1' padding bit
    last_chunk.push(one);
    // Pad with zeros to reach the full rate
    while last_chunk.len() < rate {
        last_chunk.push(zero);
    }

    // Add the last chunk to the state
    for j in 0..rate {
        perm.set_elt(perm.as_ref()[j] + last_chunk[j],j);
    }
    // Apply permutation
    perm.permute();

    // Squeeze outputs until we have the desired number
    let mut outputs = Vec::with_capacity(num_outputs);
    loop {
        for &item in perm.squeeze() {
            outputs.push(item);
            if outputs.len() == num_outputs {
                return outputs;
            }
        }
        perm.permute();
    }
}

/// sponge function for bytes with no padding
/// expects the input to be divisible by rate
/// note: rate is fixed at 8 for now
/// used here for testing / sanity check
pub fn hash_bytes_no_padding<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    H: Hasher<F>
>(
    inputs: &[F],
) -> HashOut<F>{
    HashOut::<F>::from_vec(hash_bytes_to_m_no_padding::<F, D, H::Permutation>(inputs, NUM_HASH_OUT_ELTS))
}

pub fn hash_bytes_to_m_no_padding<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    P: PlonkyPermutation<F>
>(
    inputs: &[F],
    num_outputs: usize,
) -> Vec<F> {
    let rate = P::RATE;
    let width = P::WIDTH; // rate + capacity
    let zero = F::ZERO;
    let mut perm = P::new(core::iter::repeat(zero).take(width));

    // Set the domain separator at index 8
    let domsep_value = F::from_canonical_u64(rate as u64 + 256 * 12 + 65536 * 8);
    perm.set_elt(domsep_value, 8);

    let n = inputs.len();
    assert_eq!(n % rate, 0, "Input length ({}) must be divisible by rate ({})", n, rate);
    let num_chunks = n / rate; // Calculate number of chunks
    let mut input_iter = inputs.iter();

    // Process all chunks
    for _ in 0..num_chunks {
        let mut chunk = Vec::with_capacity(rate);
        for _ in 0..rate {
            if let Some(&input) = input_iter.next() {
                chunk.push(input);
            } else {
                // should not happen here
                panic!("Insufficient input elements for chunk; expected more elements.");
            }
        }
        // Add the chunk to the state
        for j in 0..rate {
            perm.set_elt(perm.as_ref()[j] + chunk[j],j);
        }
        // Apply permutation
        perm.permute();
    }

    // Squeeze outputs until we have the desired number
    let mut outputs = Vec::with_capacity(num_outputs);
    loop {
        for &item in perm.squeeze() {
            outputs.push(item);
            if outputs.len() == num_outputs {
                return outputs;
            }
        }
        perm.permute();
    }
}

#[cfg(test)]
mod tests {
    use plonky2::field::types::Field;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2Hash;
    use crate::sponge::hash_n_with_padding;

    // test types
    pub const D: usize = 2;
    pub type C = PoseidonGoldilocksConfig;
    pub type F = <C as GenericConfig<D>>::F;
    pub type H = Poseidon2Hash;

    #[test]
    fn test_sponge_hash_rate_8() {

        struct TestCase {
            n: usize,
            digest: [u64; 4],
        }

        let test_cases: Vec<TestCase> = vec![
            TestCase { n: 0, digest: [0x509f3a747e4a6fca, 0xd6f21d91afb92eb3, 0xf65ef4075dcfb169, 0xbceaf22e0cd21b3d] },
            TestCase { n: 1, digest: [0xfa286adad207c7ea, 0x97d864ff2e89415e, 0xcf002b28585bd945, 0x95ec163fbdd0792e] },
            TestCase { n: 2, digest: [0xe4b779622cbb574f, 0x1fe4b1bc9a0c9fc7, 0x40051ada5252de9b, 0xb351345b1894a59f] },
            TestCase { n: 3, digest: [0x133a5a2fd0cae006, 0x072a7769ca9a550d, 0x92134dad95d394c6, 0x22234de7d7270aab] },
            TestCase { n: 4, digest: [0x78269e830f2a824a, 0x76f8b00469a8fa81, 0x6793369b1d75ebf5, 0xfba1a89dc21d9b30] },
            TestCase { n: 5, digest: [0x263994efd2cd5c57, 0x7c37a93fd48fc98b, 0xa081b26a68767d13, 0x16af92d6e1e4d7f8] },
            TestCase { n: 6, digest: [0x0b0b0f1d64f8d58c, 0x2946089b2eb949fc, 0xf68bcf08b69a95e7, 0x814d6eb4b2df848c] },
            TestCase { n: 7, digest: [0xae0c900a194ee051, 0x4555257fba7a500b, 0x1713fd448cc82c3a, 0xaf8f2e895e2136f3] },
            TestCase { n: 8, digest: [0x100351f04fc470b7, 0x79d3c3c416087158, 0x113bb1c70a6e84ee, 0x3eab2507cdc254d3] },
            TestCase { n: 9, digest: [0xbab284d7f11855d6, 0xe1b53d108f308a1c, 0x971fea7184337830, 0x6d674ae321cfb9ba] },
            TestCase { n: 10, digest: [0x68c00dbe0ed03a8f, 0xab5ba3617eb6f76b, 0x5d735bb89418cc0b, 0xff4101076f3f3c70] },
            TestCase { n: 11, digest: [0xaecce2fa7de4f97d, 0x07cee3dc720812e0, 0x4155bf667391a9e8, 0xbf8a49a12f40e746] },
            TestCase { n: 12, digest: [0xd3f43f06fc7affd2, 0xee9a8ac5ef44071a, 0xe00ec9e7f468d0e2, 0x944e34913a974233] },
            TestCase { n: 13, digest: [0xcd50fe6ab5e3de54, 0x9b2093adaeac949c, 0xa176a2a9e2c82787, 0xd35f0635a1ec333f] },
            TestCase { n: 14, digest: [0x8f5188d26ca0368c, 0x0116bf587e5cc970, 0x30654ee52a3c66d8, 0xe8ded60382c44b04] },
            TestCase { n: 15, digest: [0xc7f020f910327951, 0x13a468945463870d, 0xbcf8ca584edb30f3, 0x7e7234f0b8954e7e] },
            TestCase { n: 16, digest: [0xf8a9aef7392048e7, 0x6124715a2c5343eb, 0x1b7f17ebec4a5b13, 0xdf61d868051dad75] },
            TestCase { n: 17, digest: [0x44d1fb6822c7f3fa, 0x2623cc2240022e42, 0xc90ce9259c9e1160, 0x7a42bc611acacc12] },
            TestCase { n: 18, digest: [0x85dab5b06ef2d176, 0x24a587b13a4e3b30, 0xf547a00373299873, 0xb298a6ef846d64a1] },
            TestCase { n: 19, digest: [0x7cc060a3f2a74260, 0xa07dc76e73335eb0, 0xf8ed9acbcf8a242e, 0xd32eaf3150005e49] },
            TestCase { n: 20, digest: [0x3e961c84e53106f9, 0x63d9a807f9cfd88c, 0x7031e8834a17821a, 0xf2e1c79698798fa9] },
            TestCase { n: 21, digest: [0x8a0ab00081c9828f, 0xa5f7aadaf3af046e, 0xada8b4c6220b3420, 0x80ebc8c91a65518c] },
            TestCase { n: 22, digest: [0x39505fc00f052122, 0xb13edc24a35665c7, 0xa7b164fffe37ec64, 0x8f7eeb42c068e19f] },
            TestCase { n: 23, digest: [0x1f49d6f25f39522b, 0x879377d8df727784, 0x00f1461600d09cdd, 0xd2c7946a44e1aa66] },
            TestCase { n: 24, digest: [0x1c6f7a68537f7dc7, 0x64e6e09714dc0854, 0x9abfed111e51bd96, 0x65061b2bc484ed8b] },
            TestCase { n: 25, digest: [0x95fd5cc6bc02ab29, 0xe2e3c96d9b1b8b5d, 0xadcf491caa16549e, 0x97d91e370da3c0b4] },
            TestCase { n: 26, digest: [0x7599c5052ba67767, 0x3fe4a05f44e96ed6, 0xbbfe6874aa53808c, 0xd6771e162cc9f0ff] },
            TestCase { n: 27, digest: [0xdff28121d822093c, 0x7313ea03b57bb436, 0x10ed29b28a77d8c3, 0x6ee304be541fe36f] },
            TestCase { n: 28, digest: [0xce2b7f232b504b48, 0x02c638c398c12cb0, 0x4f1d416215377a86, 0x2d43ff6c5dd88f8c] },
            TestCase { n: 29, digest: [0xa60cb008de647e9a, 0x502e2e740f68e2d1, 0xe983eb54e4052013, 0xe76e59c5e5dbcca2] },
            TestCase { n: 30, digest: [0x7735e3ac5e08fa00, 0x211a86449207c30d, 0x9d80ddd40e7760b2, 0xe60f32f28597a188] },
            TestCase { n: 31, digest: [0x6fab3f12496f0691, 0x5116ad81bedd7d84, 0xaa8a7713a80b323b, 0xce6d94533fc40b88] },
            TestCase { n: 32, digest: [0xce51cdbd641d57c0, 0xf638202a88ee7f9c, 0x26c291ecc5162b45, 0x04a0a62b949c236f] },
            TestCase { n: 33, digest: [0x923391e4a4cde9e2, 0xdcb3acccba80597d, 0x247bb4b67044a0e1, 0x65bbac92e096d1ec] },
            TestCase { n: 34, digest: [0x1550d0234ae35f05, 0x16f4d1708923d4f1, 0x232319cb4090ea4e, 0x8354e1aed093070c] },
            TestCase { n: 35, digest: [0xc7dd24e6db4ea70f, 0x80bc3d2aac952cb1, 0xabbd1a878bc50565, 0xf1ebc3b8d513c591] },
            TestCase { n: 36, digest: [0xba9c4b1ce906efb1, 0xa332d0daccc62979, 0xfb658fcad0b5fbbd, 0x62d21407f34a35ee] },
            TestCase { n: 37, digest: [0xcb2973d44f2b589d, 0x01708b32c4556317, 0x3ad51597c12b8564, 0x28d3a5d7de72cfd5] },
            TestCase { n: 38, digest: [0x1dcf1f4ab7338296, 0xb88c661141b5aabb, 0x7e546b6e9b31bc90, 0xf26f7e6ffabb4e69] },
            TestCase { n: 39, digest: [0x2e139ff910c0f410, 0xba3d2c0a92ec3845, 0x2860e475933a7108, 0x8f2a6c6d13bedc7a] },
            TestCase { n: 40, digest: [0xc18a53c17c360ef4, 0x5e56ea9228988c68, 0xee0bd138436e996d, 0x06afd46a753f8257] },
            TestCase { n: 41, digest: [0x2c992403c5277dc5, 0xba8770bc3a54b043, 0x51b882882a7b7864, 0xf75e179a53e7948e] },
            TestCase { n: 42, digest: [0xde855183965741c3, 0x93520eac77a8f98d, 0x6412ae8cf0522d78, 0x9db49c6b455a83b4] },
            TestCase { n: 43, digest: [0x552e357ddb7e1ef6, 0x5fa779e9c7373b56, 0x18f7c445e27e5dcf, 0x2664ecee5e7bc6c2] },
            TestCase { n: 44, digest: [0x37b8a716c87e5489, 0x1201fcd31e407152, 0x0979d7887c42e1ca, 0x902e8b2bf748b356] },
            TestCase { n: 45, digest: [0xa48bdd1d464960ed, 0x8e92c1af0cf258bc, 0x7c5b447524b92ba9, 0xac63902e613e4ef0] },
            TestCase { n: 46, digest: [0x542e62f9317fe11d, 0xc23ba113a3f3c810, 0x2bda30c42a89cc7e, 0x35616e9f1a00aa8f] },
            TestCase { n: 47, digest: [0x1c9194a0acfa97d7, 0x60d536ac106dd774, 0x8855b4a40e110080, 0xc2c408114e8c20d6] },
            TestCase { n: 48, digest: [0x0e90b1cc3ac49e0c, 0x1b73aa8e0decbf88, 0x0ca9ef7070e0513f, 0x25cfb975571b6139] },
            TestCase { n: 49, digest: [0xba6d6f7aa664f2e7, 0x4b9af896093937b9, 0x115b9aeb6c5f563e, 0x41cb5f42c6d3b115] },
            TestCase { n: 50, digest: [0xdc3bdc491154caf6, 0xb95159bae61b2035, 0x98bd384fb3d0100b, 0xd70226f2b71ea465] },
            TestCase { n: 51, digest: [0x57f31da51bcd2eab, 0x4a3b3945a8662b5c, 0x44dffaa325530b19, 0x47f4e41c2c1474cf] },
            TestCase { n: 52, digest: [0xc3f518f6cf3b43bf, 0x1214790ff48554e4, 0x99c1eabc61b218fd, 0xf90b03954d7937f8] },
            TestCase { n: 53, digest: [0x6357b3cdcbc1283a, 0x6acc0c2d5aac9261, 0xdf11e7ad14d432d1, 0x2242b26bdcc8a380] },
            TestCase { n: 54, digest: [0x1946dc4471f8c502, 0x6be7d72499e0b4a5, 0x6e11de349239ff90, 0xfca78044256b8b54] },
            TestCase { n: 55, digest: [0x302b38fb3df623dd, 0x69b362f7932fd7af, 0x2b47156f9135508b, 0xfe6c574f0a102e92] },
            TestCase { n: 56, digest: [0xfdc9bd08a0416122, 0x063ebf4767fc7914, 0x330f36279d94050e, 0x79c61f80746893ec] },
            TestCase { n: 57, digest: [0x7b5d8384b67af5c0, 0xa705e0163fa4d839, 0x1e203432e872104e, 0xe0e7699f20a291f4] },
            TestCase { n: 58, digest: [0xb0aa74a52fe04366, 0x194b0d4afcdc03d9, 0x5134dc604b5d9f2a, 0x53c6bf9d5a1d502b] },
            TestCase { n: 59, digest: [0xd5c8258f6fc80e2b, 0x82bac373eb051b48, 0x5ef620241420462d, 0x58635db0134fb97a] },
            TestCase { n: 60, digest: [0x42ebb974ac5dd0ef, 0x676d0c6b3dde78c3, 0x14ed5eda2c9cb9de, 0x0f78a26badaa447c] },
            TestCase { n: 61, digest: [0x2b3ca7711db999d5, 0xb74bd29abcb6179a, 0x8ba196525e6adb25, 0x86cb9464ae269a43] },
            TestCase { n: 62, digest: [0x3d0e61a2ca7a65a2, 0x31f77852d41a6c8d, 0x2e4ceaa39763a53d, 0x5232ff5a3d78755e] },
            TestCase { n: 63, digest: [0xb2ed789e88c1f525, 0x1592c1a1eafd2a9b, 0x98700c512f8c9a5d, 0xf96837b5d99a4eb4] },
            TestCase { n: 64, digest: [0xe4b7d14e11de2fa9, 0xe81afff2cee68e14, 0xc58abb080bf37dd3, 0x36ae8b2196b5ae88] },
            TestCase { n: 65, digest: [0xa1df9ff199c41d63, 0xd02c067d3d12edc1, 0xc9b598130fa60794, 0x5afe82d34c3fc8fa] },
            TestCase { n: 66, digest: [0x0bc0094a1f07256d, 0x33c5b4c2a171d5bd, 0x1f38f1b1dc92aa54, 0x4610d21f276faa11] },
            TestCase { n: 67, digest: [0x8072f00df8f7e44f, 0x42f0c2b8fe81d8a0, 0x2b5caf9e7c0ff611, 0x92b0b3a4a4bebe1a] },
            TestCase { n: 68, digest: [0x6539f06fab064b57, 0xdb298b91f6c4f44f, 0x5d8f8eec6b7e8c86, 0x848a447123f39006] },
            TestCase { n: 69, digest: [0x87f32efc9eaa65f6, 0xc5699d4ab6443852, 0x61008286bc651f4a, 0xcbcf714354843da3] },
            TestCase { n: 70, digest: [0xffb8ad2258107315, 0xf7d6a58eb54f2745, 0xaecf888211821114, 0x7e0ea33b4d56976e] },
            TestCase { n: 71, digest: [0xa9e5b6d70f67db2b, 0x072fd05840040322, 0x40ffcc86e3909dec, 0x3d80f61616a9e6d7] },
            TestCase { n: 72, digest: [0xa77dd95d9ff4d7b8, 0x3a0e0502f74c091a, 0x1fa83de1e7dc716d, 0xe01ae447cc3a0e40] },
            TestCase { n: 73, digest: [0xc4a29dc875a308eb, 0xd2ed0da7aab24b0c, 0x4c2aaaed0bc4f059, 0xaea772c635ea901a] },
            TestCase { n: 74, digest: [0xaad59bf06c151ecf, 0x5e0f45e55df36692, 0x4798afb8b944a01e, 0xd7152cd819bbd7f8] },
            TestCase { n: 75, digest: [0x89ae5b2b35ba07c7, 0x129f4ff59afaa1a3, 0x4275f3f797112650, 0xea3b4baaf7190a19] },
            TestCase { n: 76, digest: [0xab068e43be297604, 0x17bd1c3cf4afec96, 0xaa84a8098dba4516, 0xa6e487ceafb02c49] },
            TestCase { n: 77, digest: [0x2c85080ef895bb4a, 0xbd280690a789c124, 0xca4f8423b50de8a5, 0xec809bb8c30de95b] },
            TestCase { n: 78, digest: [0x51c3d13543e4922b, 0xff9c11d5b93268db, 0xd9cf911cc5326948, 0x4b7bb11eafe7fd44] },
            TestCase { n: 79, digest: [0xb435274d75678586, 0x8600e7f2db687493, 0x282873a3600a38da, 0x727791507d1b600e] },
            TestCase { n: 80, digest: [0x23ae45602324f628, 0x0dc16b33f43209c5, 0x2455376f83b1aeff, 0xd5470f22ec2113bc] },
        ];

        for test_case in test_cases {
            let n = test_case.n;
            let expected_digest = test_case.digest;

            // Generate inputs
            let inputs: Vec<F> = (0..n)
                .map(|i| F::from_canonical_u64(i as u64 + 1))
                .collect();

            // Call the sponge function
            let output = hash_n_with_padding::<F,D,H>(&inputs);

            // Compare the outputs
            for (i, &out_elem) in output.elements.iter().enumerate() {
                let expected_elem = F::from_canonical_u64(expected_digest[i]);
                assert_eq!(
                    out_elem,
                    expected_elem,
                    "Mismatch at test case n={}, output element {}",
                    n,
                    i
                );
            }
        }
    }
}
