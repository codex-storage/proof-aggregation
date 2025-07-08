use plonky2::hash::hash_types::{HashOut, HashOutTarget};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig, Hasher, PoseidonGoldilocksConfig};
use plonky2_field::goldilocks_field::GoldilocksField;
use plonky2_field::types::Field;
use codex_plonky2_circuits::circuits::keyed_compress::key_compress_circuit;
use plonky2_monolith::monolith_hash::MonolithHash;
use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2Hash;
use proof_input::hash::key_compress::key_compress;

// test types
pub const D: usize = 2;
pub type F = GoldilocksField;
pub type C = PoseidonGoldilocksConfig;

// Test vectors as raw u64 limbs
const TEST_INPUTS_U64: [[u64; 4]; 2] = [
    [0x0000000000000001, 0x0000000000000002, 0x0000000000000003, 0x0000000000000004],
    [0x0000000000000005, 0x0000000000000006, 0x0000000000000007, 0x0000000000000008],
];

const EXPECTED_POSEIDON2_COMPRESS_OUTPUTS_U64: [[u64; 4]; 4] = [
    [0xc4a4082f411ba790, 0x98c2ed7546c44cce, 0xc9404f373b78c979, 0x65d6b3c998920f59],
    [0xca47449a05283778, 0x08d3ced2020391ac, 0xda461ea45670fb12, 0x57f2c0b6c98a05c5],
    [0xe6fcec96a7a7f4b0, 0x3002a22356daa551, 0x899e2c1075a45f3f, 0xf07e38ccb3ade312],
    [0x9930cff752b046fb, 0x41570687cadcea0b, 0x3ac093a5a92066c7, 0xc45c75a3911cde87],
];

const EXPECTED_MONOLITH_COMPRESS_OUTPUTS_U64: [[u64; 4]; 4] = [
    [0x794c4b4308cb8286, 0xe6ca7b9c49970427, 0x89b2e0614bc0af93, 0xd0f63984b0d43850],
    [0xe29e85f8f1782476, 0xd32a5179356e274f, 0x00fd4b778d2a019e, 0x060ca2a006f4815a],
    [0xd3b556e546fe9ea5, 0x5d99e5d70188e012, 0x6bd1f2c0940918f4, 0xe25b659a26b33f27],
    [0x12b810db565f56db, 0x25f66032a99e4e52, 0x3ceca3fb262075b4, 0x77602ef03231a802],
];

fn test_key_compress<H: Hasher<F>>(expected_outputs: &[[u64; 4]; 4]) {
    let ref_inp_1: HashOut<F> = HashOut {
        elements: TEST_INPUTS_U64[0].map(|x| F::from_canonical_u64(x)),
    };
    let ref_inp_2: HashOut<F> = HashOut {
        elements: TEST_INPUTS_U64[1].map(|x| F::from_canonical_u64(x)),
    };

    // Iterate over each key and test key_compress output
    for (key, &expected_u64s) in expected_outputs.iter().enumerate() {
        let expected: [F; 4] = expected_u64s.map(|x| F::from_canonical_u64(x));
        let output = key_compress::<F, D, H>(ref_inp_1, ref_inp_2, key as u64);

        // Assert that output matches the expected result
        assert_eq!(output.elements, expected, "Output mismatch for key: {}", key);

        println!("Test passed for key {}", key);
    }
}

fn test_key_compress_circuit<C: GenericConfig<D, F = F>, H: AlgebraicHasher<F>>(config: CircuitConfig, expected_outputs: &[[u64; 4]; 4]){
    // `HashOut` for inputs
    let inp1 = HashOut { elements: TEST_INPUTS_U64[0].map(|x| F::from_canonical_u64(x)) };
    let inp2 = HashOut { elements: TEST_INPUTS_U64[1].map(|x| F::from_canonical_u64(x)) };

    // Build circuit
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Create virtual targets
    let x_target: HashOutTarget = builder.add_virtual_hash();
    let y_target: HashOutTarget = builder.add_virtual_hash();
    let key_target = builder.add_virtual_target();

    // Build the key compression circuit
    let out_target = key_compress_circuit::<F, D, H>(&mut builder, x_target, y_target, key_target);

    // Register output elements as public inputs
    for &elt in &out_target.elements {
        builder.register_public_input(elt);
    }

    let data = builder.build::<C>();

    // Test for each key value
    for (i, &expected_u64s) in expected_outputs.iter().enumerate() {
        let expected: [F; 4] = expected_u64s.map(|x| F::from_canonical_u64(x));
        let mut pw = PartialWitness::new();
        pw.set_hash_target(x_target, inp1).expect("Failed to set hash target");
        pw.set_hash_target(y_target, inp2).expect("Failed to set hash target");
        pw.set_target(key_target, F::from_canonical_usize(i)).expect("Failed to set key target");

        let proof_with_pis = data.prove(pw).expect("Proof generation failed");
        data.verify(proof_with_pis.clone()).expect("Verification failed");

        assert_eq!(
            proof_with_pis.public_inputs,
            expected.to_vec(),
            "Key {} produced incorrect output",
            i
        );
    }
}

#[cfg(test)]
mod poseidon2_key_compress_tests {
    use super::*;
    pub type H = Poseidon2Hash;

    /// tests the non-circuit key_compress with concrete cases
    #[test]
    pub fn test_poseidon2_key_compress(){
        test_key_compress::<H>(&EXPECTED_POSEIDON2_COMPRESS_OUTPUTS_U64);
    }

    /// tests the in-circuit key_compress with concrete cases
    #[test]
    pub fn test_poseidon2_key_compress_circuit(){
        let config = CircuitConfig::standard_recursion_config();
        test_key_compress_circuit::<C, H>(config, &EXPECTED_POSEIDON2_COMPRESS_OUTPUTS_U64);
    }

}

#[cfg(test)]
mod monolith_key_compress_tests {
    use plonky2_monolith::gates::generate_config_for_monolith_gate;
    use super::*;
    type H = MonolithHash;

    /// tests the non-circuit key_compress with concrete cases
    #[test]
    pub fn test_monolith_key_compress(){
        test_key_compress::<H>(&EXPECTED_MONOLITH_COMPRESS_OUTPUTS_U64);
    }

    /// tests the in-circuit key_compress with concrete cases
    #[test]
    pub fn test_monolith_key_compress_circuit(){
        let config = generate_config_for_monolith_gate::<F, D>();
        test_key_compress_circuit::<C, H>(config, &EXPECTED_MONOLITH_COMPRESS_OUTPUTS_U64);
    }

}