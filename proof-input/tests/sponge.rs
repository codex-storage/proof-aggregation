use plonky2::field::types::Field;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2Hash;

// test types
pub const D: usize = 2;
pub type C = PoseidonGoldilocksConfig;
pub type F = <C as GenericConfig<D>>::F;
pub type H = Poseidon2Hash;

struct TestCase {
    n: usize,
    digest: [u64; 4],
}


// test cases from https://github.com/codex-storage/nim-goldilocks-hash/blob/main/tests/goldilocks_hash/poseidon2/spongeTestCases.nim
static FIELD_TEST_CASES: &[TestCase] = &[
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
    TestCase { n: 80, digest: [0x23ae45602324f628, 0x0dc16b33f43209c5, 0x2455376f83b1aeff, 0xd5470f22ec2113bc] },
];

static BYTES_TEST_CASES: &[TestCase] = &[
    TestCase { n: 0, digest: [0xa71efb792775af71, 0x2064465f503cb64b, 0xaaf2462603add4e4, 0x624af691db1f31b4] },
    TestCase { n: 1, digest: [0x1460da7415280afd, 0x52839224731ae02d, 0xffe03215cd2aeb33, 0x763f0e72ce5a0540] },
    TestCase { n: 2, digest: [0x467db61976fa1ae6, 0xbf2ade5297a35d4c, 0x169ac5af6fd80e9c, 0xcdd2fa4b14069298] },
    TestCase { n: 3, digest: [0x35a8fd00f2bd772e, 0x1e0dadfe3b0864e2, 0x3f4fb72335ecee53, 0xf490a8eadd145834] },
    TestCase { n: 4, digest: [0xd591bef16061a09a, 0x89dcf554a816c403, 0x80af50d64f525b7c, 0xcd0e5915dfcb61fb] },
    TestCase { n: 5, digest: [0x57db3723046c90a2, 0xc9a83418c4e11db5, 0x4d3f878d99880748, 0x59fad57980c6608e] },
    TestCase { n: 6, digest: [0x220cd4f315b3186d, 0x87cf82260c9feca1, 0x53dbd246c735a5d8, 0xa0897aae20fafb3f] },
    TestCase { n: 7, digest: [0xa906648ef48d6416, 0xd6534a5d7e9f1aa0, 0xb58fa22d55a0b463, 0x2854310f3f51a1fe] },
    TestCase { n: 8, digest: [0x6e73442f9b52e8da, 0xe4da1f14442a2a53, 0x06947604cda62fc0, 0xdbef3462252de7dc] },
    TestCase { n: 9, digest: [0x2a2b887fe834a472, 0x2b7969e577e4115a, 0x44b38c320dba5241, 0xa1abdbf31feda23f] },
    TestCase { n: 10, digest: [0x53ce0cab3fc41069, 0xd847f0de465202ba, 0x555bdfb6097511b3, 0x58ea282d28c822c7] },
    TestCase { n: 11, digest: [0xb071c390b91267b6, 0x3fe35629994405bf, 0xd1afa127d85e5fa8, 0xd130f37093575727] },
    TestCase { n: 12, digest: [0x66f623b92bff1cb2, 0xe66cc1f0c2c792a2, 0x3bf9cf257506afba, 0x99c039e2540e6aa5] },
    TestCase { n: 13, digest: [0x808d118d154cf44d, 0x93b798658539aa1c, 0x08c9e86831c2a94b, 0x5c2d3fbf7e20fca1] },
    TestCase { n: 14, digest: [0x07951b722679dff1, 0xc3c6e8106ec95bc7, 0x94705df3c4f51ca5, 0x1bdd3fea0a5126d9] },
    TestCase { n: 15, digest: [0x329a1b245154d51d, 0xdd3ff7dc8978de53, 0x9421598ed5e51874, 0x66f40e3e1dd97a3a] },
    TestCase { n: 16, digest: [0x26bd29f3ce46fa9a, 0x72da3a824eeba107, 0xc987661b52f625d4, 0x5a46c6f1682937dd] },
    TestCase { n: 17, digest: [0xcb743ec8fbbf15e0, 0x5e14d219b6e9002b, 0xdb2fb3dad1af6948, 0x8f2ac2f9753e5444] },
    TestCase { n: 18, digest: [0x772bb07471115059, 0x4eb041547083f5d9, 0x60d7be342de7c869, 0x8d1ec1ec89827b8a] },
    TestCase { n: 19, digest: [0xe113b37d0f2916c6, 0x516eec61cacb3270, 0xac4bfbc822139edf, 0x329f015c18355e46] },
    TestCase { n: 20, digest: [0xb9a58e3105561e8e, 0xe79ad7f7d8d338c7, 0xfcb9969924b3205b, 0x25efee535ca286ac] },
    TestCase { n: 21, digest: [0x5fd1ccec816c941c, 0x808f1ad2301fc501, 0x50cb3ef96bb86d2c, 0x38d3ae5b11ed1313] },
    TestCase { n: 22, digest: [0x530a9bbdd47c2be9, 0xda716467ec093518, 0x4af4d26288834ec5, 0xd71bcc854e2dd489] },
    TestCase { n: 23, digest: [0xab70c0430576d365, 0xb163bb09b237c9d6, 0x2efa5bdc67e2383d, 0x69587492876ae89c] },
    TestCase { n: 24, digest: [0x4a5ca1b0b5e6b286, 0x7cf3f90c4081cadd, 0x4c67ba82341ab9c0, 0x22a4e8b0c141d826] },
    TestCase { n: 25, digest: [0xd08fa35f3d3d4cf6, 0x8c47f3976394772d, 0x08620c484f494b58, 0x16fcf057175d7e9f] },
    TestCase { n: 80, digest: [0xafd9328d3ee58953, 0x9daeb0e58fb7b0fc, 0x5f77e81b398edb3e, 0xb1a0dc7115ec3789] },
];

#[cfg(test)]
mod sponge_tests {
    use super::*;
    use proof_input::hash::sponge::{hash_n_with_padding, hash_bytes};

    /// Generate a byte sequence [1, 2, ..., n], wrapping at 256.
    fn byte_seq(n: usize) -> Vec<u8> {
        let mut seq = Vec::with_capacity(n);
        for i in 0..n {
            seq.push((i + 1) as u8);
        }
        seq
    }

    #[test]
    fn test_sponge_field_hash_rate_8() {

        for test_case in FIELD_TEST_CASES {
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

    #[test]
    fn test_sponge_bytes_hash_rate_8() {

        for test_case in BYTES_TEST_CASES {
            let n = test_case.n;
            let expected_digest = test_case.digest;

            // Generate inputs
            let inputs = byte_seq(n);

            // Call the sponge function
            let output = hash_bytes::<F,D,H>(&inputs);
            println!("n = {}", n);

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

#[cfg(test)]
mod sponge_circuit_tests {
    use super::*;
    use plonky2::hash::hash_types::NUM_HASH_OUT_ELTS;
    use plonky2::iop::target::Target;
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::{CircuitConfig};
    use codex_plonky2_circuits::circuits::sponge::hash_n_with_padding;

    #[test]
    fn test_sponge_field_hash_rate_8_circuit() {

        // if more tests are added, update this, but it would be slow
        let number_of_tests = 3;
        for test in FIELD_TEST_CASES {
            if test.n > number_of_tests {
                return;
            }
            let config = CircuitConfig::standard_recursion_config();
            let mut builder = CircuitBuilder::<F, D>::new(config);
            let inputs: Vec<Target> = (0..test.n).map(|_| builder.add_virtual_target()).collect();
            let hash = hash_n_with_padding::<F, D, H>(&mut builder, inputs.clone()).unwrap();
            builder.register_public_inputs(&hash.elements);

            let mut pw = PartialWitness::<F>::new();
            for (i, input) in inputs.iter().enumerate() {
                pw.set_target(*input, F::from_canonical_u64(i as u64 + 1)).expect("set_target");
            }

            let data = builder.build::<C>();
            let proof = data.prove(pw).unwrap();
            assert!(data.verify(proof.clone()).is_ok());

            // Construct the expected digest
            let expected_digest =
                [
                    F::from_canonical_u64(test.digest[0]),
                    F::from_canonical_u64(test.digest[1]),
                    F::from_canonical_u64(test.digest[2]),
                    F::from_canonical_u64(test.digest[3]),
                ];

            let output_vals = proof.public_inputs;
            assert_eq!(output_vals.len(), NUM_HASH_OUT_ELTS);
            for (i, &val) in output_vals.iter().enumerate() {
                assert_eq!(val, expected_digest[i]);
            }
        }
    }
}
