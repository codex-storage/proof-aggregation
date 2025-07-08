use plonky2::field::types::Field;
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig, Hasher, PoseidonGoldilocksConfig};
use plonky2_field::goldilocks_field::GoldilocksField;
use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2Hash;
use plonky2::hash::hash_types::NUM_HASH_OUT_ELTS;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use proof_input::hash::sponge::{hash_n_with_padding, hash_bytes};

// test types
pub const D: usize = 2;
pub type F = GoldilocksField;

struct TestCase {
    n: usize,
    digest: [u64; 4],
}

/// Generate a byte sequence [1, 2, ..., n]
fn byte_seq(n: usize) -> Vec<u8> {
    let mut seq = Vec::with_capacity(n);
    for i in 0..n {
        seq.push((i + 1) as u8);
    }
    seq
}

// test cases from https://github.com/codex-storage/nim-goldilocks-hash/blob/main/tests/goldilocks_hash/poseidon2/spongeTestCases.nim
static POSEIDON2_FIELD_TEST_CASES: &[TestCase] = &[
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

static MONOLITH_FIELD_TEST_CASES: &[TestCase] = &[
    TestCase { n: 0,  digest: [0xd47c5fbae9096559u64, 0xee882b9337378620u64, 0xc392c8614fc3aa09u64, 0x28fa56b792eb577cu64] },
    TestCase { n: 1,  digest: [0xbd2b3a8a876c057bu64, 0x571f86d703ab22d3u64, 0xd3800a8192720938u64, 0xff4e91ae72e439cau64] },
    TestCase { n: 2,  digest: [0x734df0e5728ce6b3u64, 0x99aced42682b5a2au64, 0xe8b66ad078279825u64, 0x9941b88ae257f341u64] },
    TestCase { n: 3,  digest: [0xa6433cb12ba62d52u64, 0x1629e21393900ebfu64, 0x4476301fc4f47f81u64, 0x000e9e55ae70c696u64] },
    TestCase { n: 4,  digest: [0x884602191b4a865fu64, 0xb77eb3239a710d56u64, 0x61eeb379d3cde9f1u64, 0xf2ee5db1c5183c06u64] },
    TestCase { n: 5,  digest: [0x13464401497bc0d6u64, 0x8ce82497cc9a4b2eu64, 0xf2fd40929bb97a7bu64, 0x881c1c52cbfd9f9bu64] },
    TestCase { n: 6,  digest: [0xb19b615bb7a98de4u64, 0x75c00a67ab6ff17au64, 0xc05f61c793da97fdu64, 0x0e447f619a0eaf07u64] },
    TestCase { n: 7,  digest: [0x765b2887f8537171u64, 0x50b4dfeffd4d49d5u64, 0xb50b5c206a05fd2au64, 0x77228853b07f9b3fu64] },
    TestCase { n: 8,  digest: [0x73d29f1b00757d2bu64, 0x03e6160b3f7ed271u64, 0x5ff50af82978c93bu64, 0x1507a55e93e53fd0u64] },
    TestCase { n: 9,  digest: [0x6b6639736cc33412u64, 0x13c3223859d2ec55u64, 0xa598be339d131a5eu64, 0x5248819c0cc46c59u64] },
    TestCase { n: 10, digest: [0x751f4254110c0e68u64, 0xc675b0209833e442u64, 0x71ae9952b81f4b25u64, 0xf93d2e2ed2ea41fdu64] },
    TestCase { n: 11, digest: [0x996a2bc62c21e532u64, 0x38271bd59cd6933du64, 0x26090c447278edb4u64, 0xec57edebfdc5a78eu64] },
    TestCase { n: 12, digest: [0x01e4744707a0de6au64, 0xbb28342b330ad160u64, 0x323a772ab3258cedu64, 0x23fa246d8fb1a32du64] },
    TestCase { n: 13, digest: [0xb0826250221ac267u64, 0xba2943c78fe7b327u64, 0x79dbde0324103615u64, 0xa321a157a35651c1u64] },
    TestCase { n: 14, digest: [0x21861f0f8f3613cfu64, 0xa81565899d61ba44u64, 0x32e974dd9a68ceccu64, 0x9770cb4f04d59d56u64] },
    TestCase { n: 15, digest: [0x56b40e590d508a8eu64, 0xed203ebcb5827ee1u64, 0x87028b8115caabe9u64, 0xb0c3625d8ce2d87cu64] },
    TestCase { n: 16, digest: [0x31a5cba06f373379u64, 0xd105f5a4db31aa39u64, 0xcfcb6d7ad0ac35bfu64, 0xb27c9fbe10785cd7u64] },
    TestCase { n: 17, digest: [0x168dc7f64443bb42u64, 0xa43b954af0438342u64, 0x9ee5475ec0b42203u64, 0x3d7f53b6355bd5ffu64] },
    TestCase { n: 18, digest: [0x51348a77a8dc0bc2u64, 0x7388a29f8156fd8eu64, 0x5ae41ca4b7826796u64, 0x5bb858d7460f9b59u64] },
    TestCase { n: 19, digest: [0xa5b7420df52838c1u64, 0x533e1509647c9fa1u64, 0x9651947c57cf4dcfu64, 0x103f08964038b9f9u64] },
    TestCase { n: 20, digest: [0x55a717e33b97b557u64, 0x7b4026e2d656a6ebu64, 0x18c401420a0242d4u64, 0x7186b16167404ba3u64] },
    TestCase { n: 21, digest: [0xff93bf59fc306d6du64, 0x5ab6423e9993bfe1u64, 0xa91c4da9b2734002u64, 0x4d05843fb1884c0eu64] },
    TestCase { n: 22, digest: [0xbcb54583ec543ca1u64, 0x4c9ef6b0d21178fcu64, 0x8fa173cf5b146e4eu64, 0xf1ff0fc009c96625u64] },
    TestCase { n: 23, digest: [0x987da4c2b745c0afu64, 0xaa95bfa45db48494u64, 0x936e1442355c708bu64, 0xa74c3dfd4b0e9e0cu64] },
    TestCase { n: 24, digest: [0xe9f92f57a196aeb5u64, 0xf3fa8aaa35362bc4u64, 0x6d529e2243620d8du64, 0xbe6f05be1de9d92du64] },
    TestCase { n: 25, digest: [0xfaf815dd45b7ff2au64, 0x8f618b4bf8674be9u64, 0x25ce53df6ff85ba6u64, 0xa4c870702e47d0ebu64] },
    TestCase { n: 80, digest: [0x2f610bed75395897u64, 0x9ae07b486f21fcf5u64, 0xc506265e839283a4u64, 0x619636360bbecda5u64] },
];

static POSEIDON2_BYTES_TEST_CASES: &[TestCase] = &[
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

static MONOLITH_BYTE_TEST_CASES: &[TestCase] = &[
    TestCase { n: 0,  digest: [0x3443a96d7eaaf60du64, 0x14255b96f0092ab9u64, 0xcb64323ad7041011u64, 0x59f2ba0ebe02827du64] },
    TestCase { n: 1,  digest: [0x0521794b1f6be4ecu64, 0x80f548060fadef35u64, 0xa5f7e3ad50bc15feu64, 0x3a83615c39b58140u64] },
    TestCase { n: 2,  digest: [0xdb67947161e6705fu64, 0x02fd26a0d53d25a9u64, 0x2cf5c1f7a04b03c1u64, 0x1d78d66f44463dc5u64] },
    TestCase { n: 3,  digest: [0x9b0c81110b510ebbu64, 0xf58790e70f9eab04u64, 0x6d9870e90d3b75a8u64, 0xc4ac327fa437f68du64] },
    TestCase { n: 4,  digest: [0x3e949c46300b9c91u64, 0xb4634e57944cd5c7u64, 0x385c5c9455fc5c08u64, 0xf28ac62e0aa8c7acu64] },
    TestCase { n: 5,  digest: [0x2a95903729d63d09u64, 0xec003aa5a2a1f54eu64, 0x03d555c457c2b909u64, 0x0643510bcd8467e8u64] },
    TestCase { n: 6,  digest: [0x2a3c56e354f17defu64, 0xa9b18e3f30ca6450u64, 0x028373b89071f71fu64, 0x352be1798ee7de0eu64] },
    TestCase { n: 7,  digest: [0x6d3596df0e38e63bu64, 0x4bf577ccf370dfb4u64, 0xf76e5d89f1d1dd5eu64, 0xd94a6d6f389c90dbu64] },
    TestCase { n: 8,  digest: [0x4c7efa0715eb4ef9u64, 0x0952db0d01f64627u64, 0xd54b1e9eacb669eeu64, 0xecc7efd2174195ccu64] },
    TestCase { n: 9,  digest: [0x5be81d45ca944ca9u64, 0x0cda9df1f63875f5u64, 0x23fbd8b8e820b96au64, 0x45d73ef08942a623u64] },
    TestCase { n: 10, digest: [0x1c0424ebab41510au64, 0xbfb82e664aabc43fu64, 0x37064df8b8739f95u64, 0xbd3df9c8c6f3f8b6u64] },
    TestCase { n: 11, digest: [0x2ccbd3d34bd4cd90u64, 0x124f23b8dc3271fcu64, 0xe015995b5f806003u64, 0xe9d02abf7666fd78u64] },
    TestCase { n: 12, digest: [0x4d19df925c93d7c0u64, 0xee01d6c870835514u64, 0xd423d71aeb3fb1a1u64, 0xf1660868b7dcc6ddu64] },
    TestCase { n: 13, digest: [0xd5aead5da0f1efcdu64, 0xe18f585eb3e0ebe6u64, 0xa8688fd3b06c959du64, 0xbe3b39dc37e81461u64] },
    TestCase { n: 14, digest: [0xff436bb5bdf34d56u64, 0x0938d4fe67ffe812u64, 0xe55d07afc99e1e08u64, 0x24385333292f4c8cu64] },
    TestCase { n: 15, digest: [0x729276b36fd1e880u64, 0xc28ad09142788753u64, 0x5825a598f66ad284u64, 0x54390583aaf9227du64] },
    TestCase { n: 16, digest: [0x9cfcd49462643e31u64, 0x268f4ce0f742f78bu64, 0xc5df066c71df396du64, 0x2feee3d5121fb3c1u64] },
    TestCase { n: 17, digest: [0x9fc04357cc207311u64, 0x9e320b5216a755abu64, 0x8d6ebaa263f4cfffu64, 0x0282948c7b0473ccu64] },
    TestCase { n: 18, digest: [0xd71f3eaa3be0e871u64, 0x59bc2ad3c0f3e40eu64, 0x3b3f285302f6be26u64, 0xd42595778e4857c3u64] },
    TestCase { n: 19, digest: [0x3ad9e6eda7ed6385u64, 0x77dea4e2a0f50776u64, 0xd6dace6ece5103e2u64, 0x024637ecef939fa1u64] },
    TestCase { n: 20, digest: [0xf4d171927ea5541fu64, 0xe8f14721b29c6aa0u64, 0x8746284b085cbb1cu64, 0x327bb32b2e66ec9eu64] },
    TestCase { n: 21, digest: [0xe39ecb4ea44409f5u64, 0x0c2dfc7446b45c23u64, 0xaa7ab53ef3ccfd90u64, 0x2773da7bca69e59bu64] },
    TestCase { n: 22, digest: [0x31958113cd57dcc4u64, 0xf39ff7b43cc171e0u64, 0x53bd115071515ac9u64, 0xe55acd4246ddc18eu64] },
    TestCase { n: 23, digest: [0xa3676fff478bd925u64, 0xfae6f5cc63d811c2u64, 0x6aa0453077fe063fu64, 0x01796f7425d2ccf2u64] },
    TestCase { n: 24, digest: [0x90dea16ce1903980u64, 0x9ec4a3200922506fu64, 0xfd38dfa3000178c4u64, 0x9ca5a2a697ba83f5u64] },
    TestCase { n: 25, digest: [0xc1497219666e1679u64, 0xc1ee0a7f9783ca57u64, 0xaa18e5be9bae4620u64, 0x2ec6e94f451f687cu64] },
    TestCase { n: 80, digest: [0xfdac23be1db05688u64, 0x3500b25390dc35e8u64, 0x9c3c23f6bb99f87bu64, 0x403b038b4878c1c0u64] },
];

// ------------------------------------Generic test functions----------------------------------------

fn test_sponge_field_hash_rate_8<H: Hasher<F>>(test_cases: &[TestCase]) {
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

fn test_sponge_bytes_hash_rate_8<H: Hasher<F>>(test_cases: &[TestCase]) {
    for test_case in test_cases {
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

fn test_sponge_field_hash_rate_8_circuit<C: GenericConfig<D, F = F>, H: AlgebraicHasher<F>>(config: CircuitConfig, test_cases: &[TestCase]) {
    // if more tests are added, update this, but it would be slow
    let number_of_tests = 3;
    for test in test_cases {
        if test.n > number_of_tests {
            return;
        }
        let mut builder = CircuitBuilder::<F, D>::new(config.clone());
        let inputs: Vec<Target> = (0..test.n).map(|_| builder.add_virtual_target()).collect();
        let hash = codex_plonky2_circuits::circuits::sponge::hash_n_with_padding::<F, D, H>(&mut builder, inputs.clone()).unwrap();
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

//------------------------------------Poseidon2 tests--------------------------------------------
#[cfg(test)]
mod poseidon2_sponge_tests {
    use super::*;
    use plonky2::plonk::circuit_data::CircuitConfig;

    pub type C = PoseidonGoldilocksConfig;
    pub type H = Poseidon2Hash;

    #[test]
    fn test_poseidon2_sponge_field_hash_rate_8() {
        test_sponge_field_hash_rate_8::<H>(POSEIDON2_FIELD_TEST_CASES);
    }

    #[test]
    fn test_poseidon2_sponge_bytes_hash_rate_8() {
        test_sponge_bytes_hash_rate_8::<H>(POSEIDON2_BYTES_TEST_CASES);
    }

    #[test]
    fn test_poseidon2_sponge_field_hash_rate_8_circuit() {
        let config = CircuitConfig::standard_recursion_config();
        test_sponge_field_hash_rate_8_circuit::<C, H>(config, POSEIDON2_FIELD_TEST_CASES);
    }
}

// ------------------------------------Monolith tests--------------------------------------------
#[cfg(test)]
mod monolith_sponge_tests {
    use super::*;
    use plonky2_monolith::gates::generate_config_for_monolith_gate;
    use plonky2_monolith::monolith_hash::MonolithHash;

    pub type C = PoseidonGoldilocksConfig;
    pub type H = MonolithHash;

    #[test]
    fn test_monolith_sponge_field_hash_rate_8() {
        test_sponge_field_hash_rate_8::<H>(MONOLITH_FIELD_TEST_CASES);
    }

    #[test]
    fn test_monolith_sponge_bytes_hash_rate_8() {
        test_sponge_bytes_hash_rate_8::<H>(MONOLITH_BYTE_TEST_CASES);
    }

    #[test]
    fn test_monolith_sponge_field_hash_rate_8_circuit() {
        let config = generate_config_for_monolith_gate::<F, D>();
        test_sponge_field_hash_rate_8_circuit::<C, H>(config, MONOLITH_FIELD_TEST_CASES);
    }
}