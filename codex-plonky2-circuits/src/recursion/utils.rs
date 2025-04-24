use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2_field::extension::Extendable;
use plonky2_poseidon2::Poseidon2;
use crate::recursion::leaf::{BUCKET_SIZE, LeafCircuit};

/// Splits a target `index` which is known to lie in the range [0, T)
/// where T = bucket_size * num_buckets
/// into two components (q, r) such that:
///
///     index = q * bucket_size + r,
///
/// where:
///   - `r` is in the range [0, bucket_size),
///   - `q` is in the range [0, num_buckets),
///
/// requires that the total range T = (bucket_size * num_buckets) is a power of 2.
pub fn split_index<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
    index: Target,
    bucket_size: usize,
    num_buckets: usize,
) -> crate::Result<(Target, Target)>
{
    // T = bucket_size * num_buckets
    let total = bucket_size * num_buckets;
    // check total is a power of two
    assert!(total.is_power_of_two(), "Total must be a power of two for split_index to work.");

    let total_bits = total.trailing_zeros() as usize;
    let log_bucket = bucket_size.trailing_zeros() as usize;

    // Decompose the index into total_bits bits (little-endian).
    let bits: Vec<BoolTarget> = builder.split_le(index, total_bits);

    // Recompose the remainder (r) from the lower log_bucket bits.
    let mut r_val = builder.zero();
    for i in 0..log_bucket {
        let bit_val = bits[i].target;
        let weight = builder.constant(F::from_canonical_u64(1 << i));
        let bit_mul_weight = builder.mul(bit_val, weight);
        r_val = builder.add(r_val, bit_mul_weight);
    }

    // Recompose the quotient (q) from the remaining log_q bits.
    let mut q_val = builder.zero();
    for i in log_bucket..total_bits {
        // The weight here is 2^(i - log_bucket).
        let bit_val = bits[i].target;
        let weight = builder.constant(F::from_canonical_u64(1 << (i - log_bucket)));
        let bit_mul_weight = builder.mul(bit_val, weight);
        q_val = builder.add(q_val, bit_mul_weight);
    }

    Ok((q_val, r_val))
}

/// A helper that computes 2^r for a target r in [0, 32) using selection over 32 constants.
pub fn compute_power_of_two<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
    r: Target,
) -> crate::Result<Target>
{
    // First range-check r so it is in [0, 32).
    builder.range_check(r, BUCKET_SIZE);
    let mut result = builder.zero();
    for i in 0..BUCKET_SIZE {
        let i_const = builder.constant(F::from_canonical_u64(i as u64));
        let eq_bool = builder.is_equal(r, i_const);
        let eq_val = eq_bool.target;
        let two_i = builder.constant(F::from_canonical_u64(1 << i));
        let eq_val_mul_two_i = builder.mul(eq_val, two_i);
        result = builder.add(result, eq_val_mul_two_i);
    }
    Ok(result)
}

/// Computes the flag buckets from a given index and flag.
///
/// Given:
///   - `index` is a Target representing a number in T = [0, bucket_size * num_buckets),
///   - `flag` is a BoolTarget (true if the proof is real, false if dummy),
///   - `bucket_size` (e.g. 32 for Goldilocks) and `num_buckets` (e.g. 4 to fit 128 proofs),
/// this function returns a vector of Targets representing the computed flag buckets.
/// For bucket i, the value is:
///   - flag * 2^(r) if i is the selected bucket (i.e. i == q), where (q, r) = split_index(index),
///   - 0 otherwise.
pub fn compute_flag_buckets<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
    index: Target,
    flag: BoolTarget,
    bucket_size: usize,
    num_buckets: usize,
) -> crate::Result<Vec<Target>>
{
    let total = bucket_size * num_buckets;
    // Range-check the index.
    builder.range_check(index, total);

    // Use your split_index helper to get (q, r)
    let (q, r) = split_index::<F,D>(builder, index, bucket_size, num_buckets)?;
    // Compute 2^(r)
    let power_of_two = compute_power_of_two::<F,D>(builder, r)?;
    // flag target from Boolean target.
    let flag_val = flag.target;
    // computed_value equals flag * 2^(r)
    let computed_value = builder.mul(flag_val, power_of_two);

    // For each bucket, if the bucket is the selected one (i.e. equals q), then its value is computed_value; otherwise 0.
    let mut buckets = Vec::with_capacity(num_buckets);
    for i in 0..num_buckets {
        let bucket_const = builder.constant(F::from_canonical_u64(i as u64));
        let is_selected = builder.is_equal(q, bucket_const);
        let is_selected_val = is_selected.target;
        // bucket value = is_selected * computed_value.
        let bucket_value = builder.mul(is_selected_val, computed_value);
        buckets.push(bucket_value);
    }
    Ok(buckets)
}

/// Returns the number of buckets required to hold `t` flags,
/// where each bucket can hold up to BUCKET_SIZE flags.
pub fn bucket_count(t: usize) -> usize {
    (t + BUCKET_SIZE -1) / BUCKET_SIZE
}


#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::config::GenericConfig;
    use plonky2_field::types::{Field, PrimeField64};
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2_poseidon2::poseidon2_hash::poseidon2::{Poseidon2, Poseidon2Hash};
    use plonky2::iop::witness::PartialWitness;

    // For our tests, we define:
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    type H = Poseidon2Hash;

    // Helper: Build, prove, and return public inputs ---
    fn build_and_prove(builder: CircuitBuilder<F, D>) -> Vec<F> {
        // Build the circuit.
        let circuit = builder.build::<C>();
        let pw = PartialWitness::new();
        // prove
        let p= circuit.prove(pw).expect("prove failed");

        p.public_inputs
    }

    #[test]
    fn test_split_index() -> anyhow::Result<()> {
        // Create a circuit where we register the outputs q and r of split_index.
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        // Let index = 45.
        let index_val: u64 = 45;
        let index_target = builder.constant(F::from_canonical_u64(index_val));
        // Call split_index with bucket_size=32 and num_buckets=4. We expect q = 1 and r = 13.
        let (q_target, r_target) =
            split_index::<F,D>(&mut builder, index_target, BUCKET_SIZE, 4)?;
        // Register outputs as public inputs.
        builder.register_public_input(q_target);
        builder.register_public_input(r_target);
        // Build and prove the circuit.
        let pub_inputs = build_and_prove(builder);
        // We expect the first public input to be q = 1 and the second r = 13.
        assert_eq!(pub_inputs[0].to_canonical_u64(), 1, "q should be 1");
        assert_eq!(pub_inputs[1].to_canonical_u64(), 13, "r should be 13");
        Ok(())
    }

    #[test]
    fn test_compute_power_of_two() -> anyhow::Result<()> {
        // Create a circuit to compute 2^r.
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        // Let r = 13.
        let r_val: u64 = 13;
        let r_target = builder.constant(F::from_canonical_u64(r_val));
        let pow_target =
            compute_power_of_two::<F,D>(&mut builder, r_target)?;
        builder.register_public_input(pow_target);
        let pub_inputs = build_and_prove(builder);
        // Expect 2^13 = 8192.
        assert_eq!(
            pub_inputs[0].to_canonical_u64(),
            1 << 13,
            "2^13 should be 8192"
        );
        Ok(())
    }

    #[test]
    fn test_compute_flag_buckets() -> anyhow::Result<()> {
        // Create a circuit to compute flag buckets.
        // Let index = 45 and flag = true.
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let index_val: u64 = 45;
        let index_target = builder.constant(F::from_canonical_u64(index_val));
        // Create a boolean constant target for flag = true.
        let flag_target = builder.constant_bool(true);
        // Compute the flag buckets with bucket_size = 32 and num_buckets = 4.
        let buckets = compute_flag_buckets::<F,D>(
            &mut builder,
            index_target,
            flag_target,
            BUCKET_SIZE,
            4,
        )?;
        // Register each bucket as a public input.
        for bucket in buckets.iter() {
            builder.register_public_input(*bucket);
        }
        let pub_inputs = build_and_prove(builder);
        // With index = 45, we expect:
        //   q = 45 / 32 = 1 and r = 45 % 32 = 13, so bucket 1 should be 2^13 = 8192 and the others 0.
        let expected = vec![0, 8192, 0, 0];
        for (i, &expected_val) in expected.iter().enumerate() {
            let computed = pub_inputs[i].to_canonical_u64();
            assert_eq!(
                computed, expected_val,
                "Bucket {}: expected {} but got {}",
                i, expected_val, computed
            );
        }
        Ok(())
    }
}


