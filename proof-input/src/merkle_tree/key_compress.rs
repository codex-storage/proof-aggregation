use plonky2::hash::hash_types::{HashOut, NUM_HASH_OUT_ELTS, RichField};
use plonky2::hash::hashing::PlonkyPermutation;
use plonky2::plonk::config::Hasher;
use plonky2_field::extension::Extendable;
use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2;

/// Compression function which takes two 256 bit inputs (HashOut) and u64 key (which is converted to field element in the function)
/// and returns a 256 bit output (HashOut /  4 Goldilocks field elems).
pub fn key_compress<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    H:Hasher<F>
>(x: HashOut<F>, y: HashOut<F>, key: u64) -> HashOut<F> {

    let key_field = F::from_canonical_u64(key);

    let mut perm = H::Permutation::new(core::iter::repeat(F::ZERO));
    perm.set_from_slice(&x.elements, 0);
    perm.set_from_slice(&y.elements, NUM_HASH_OUT_ELTS);
    perm.set_elt(key_field,NUM_HASH_OUT_ELTS*2);

    perm.permute();

    HashOut {
        elements: perm.squeeze()[..NUM_HASH_OUT_ELTS].try_into().unwrap(),
    }
}

#[cfg(test)]
mod tests {
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use plonky2_field::types::Field;
    use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2Hash;
    use super::*;
    // test types
    pub const D: usize = 2;
    pub type C = PoseidonGoldilocksConfig;
    pub type F = <C as GenericConfig<D>>::F;
    pub type H = Poseidon2Hash;

    /// tests the non-circuit key_compress with concrete cases
    #[test]
    pub fn test_key_compress(){
        let ref_inp_1: [F; 4] = [
            F::from_canonical_u64(0x0000000000000001),
            F::from_canonical_u64(0x0000000000000002),
            F::from_canonical_u64(0x0000000000000003),
            F::from_canonical_u64(0x0000000000000004),
        ];

        let ref_inp_2: [F; 4] = [
            F::from_canonical_u64(0x0000000000000005),
            F::from_canonical_u64(0x0000000000000006),
            F::from_canonical_u64(0x0000000000000007),
            F::from_canonical_u64(0x0000000000000008),
        ];

        let ref_out_key_0: [F; 4] = [
            F::from_canonical_u64(0xc4a4082f411ba790),
            F::from_canonical_u64(0x98c2ed7546c44cce),
            F::from_canonical_u64(0xc9404f373b78c979),
            F::from_canonical_u64(0x65d6b3c998920f59),
        ];

        let ref_out_key_1: [F; 4] = [
            F::from_canonical_u64(0xca47449a05283778),
            F::from_canonical_u64(0x08d3ced2020391ac),
            F::from_canonical_u64(0xda461ea45670fb12),
            F::from_canonical_u64(0x57f2c0b6c98a05c5),
        ];

        let ref_out_key_2: [F; 4] = [
            F::from_canonical_u64(0xe6fcec96a7a7f4b0),
            F::from_canonical_u64(0x3002a22356daa551),
            F::from_canonical_u64(0x899e2c1075a45f3f),
            F::from_canonical_u64(0xf07e38ccb3ade312),
        ];

        let ref_out_key_3: [F; 4] = [
            F::from_canonical_u64(0x9930cff752b046fb),
            F::from_canonical_u64(0x41570687cadcea0b),
            F::from_canonical_u64(0x3ac093a5a92066c7),
            F::from_canonical_u64(0xc45c75a3911cde87),
        ];

        // `HashOut` for inputs
        let inp1 = HashOut { elements: ref_inp_1 };
        let inp2 = HashOut { elements: ref_inp_2 };

        // Expected outputs
        let expected_outputs = [
            ref_out_key_0,
            ref_out_key_1,
            ref_out_key_2,
            ref_out_key_3,
        ];

        // Iterate over each key and test key_compress output
        for (key, &expected) in expected_outputs.iter().enumerate() {
            let output = key_compress::<F, D, H>(inp1, inp2, key as u64);

            // Assert that output matches the expected result
            assert_eq!(output.elements, expected, "Output mismatch for key: {}", key);

            println!("Test passed for key {}", key);
        }

    }
}