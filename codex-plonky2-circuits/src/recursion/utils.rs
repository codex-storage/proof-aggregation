use plonky2::hash::hash_types::{HashOut, RichField};
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::VerifierCircuitData;
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2_field::extension::Extendable;
use plonky2_poseidon2::Poseidon2;
use crate::recursion::leaf::BUCKET_SIZE;

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
/// requires that the total range T = (bucket_size * num_buckets) is a power of 2 (and so is bucket_size and num_buckets).
/// Assumes that `index` is in the range [0, T), range-checks `index` before calling this function.
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

/// A helper that computes 2^r for a target r in [0, `BUCKET_SIZE`) using selection over `BUCKET_SIZE` constants.
/// assumes that r is in the range [0, `BUCKET_SIZE`), range-checks r before calling this function
/// if `r` is taken from `split_index` then it is already in the correct range
pub fn compute_power_of_two<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
    r: Target,
) -> crate::Result<Target>
{
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

/// Computes the flag buckets from a given index and flag (In-Circuit).
///
/// Given:
///   - `index` is a Target representing a number in T = [0, bucket_size * num_buckets),
///   - `flag` is a BoolTarget (true if the proof is real, false if dummy),
///   - `bucket_size` is the number of flags per bucket (e.g. 32 for Goldilocks)
///   - `num_buckets` is the number of buckets (e.g. 4 to fit 128 proofs)
/// this function returns a vector of `num_buckets` Targets representing the computed flag buckets.
/// the flag buckets should contain zeroes everywhere except for the bucket that contains the flag.
///
/// The logic of this mini-circuit is as follows:
/// For bucket i in [0, num_buckets), the value is:
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
/// bucket_count = ceil(t / BUCKET_SIZE)
pub fn bucket_count(t: usize) -> usize {
    (t + BUCKET_SIZE -1) / BUCKET_SIZE
}

/// helper fn to generate hash of verifier data (outside the circuit)
pub fn get_hash_of_verifier_data<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    C: GenericConfig<D, F = F>,
    H: AlgebraicHasher<F>,
>(verifier_data: &VerifierCircuitData<F, C, D>) -> HashOut<F> where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>
{
    let mut vd = vec![];
    let digest: &HashOut<F> = &verifier_data.verifier_only.circuit_digest;
    let caps = &verifier_data.verifier_only.constants_sigmas_cap;
    vd.extend_from_slice(&digest.elements);
    for i in 0..verifier_data.common.config.fri_config.num_cap_elements() {
        let cap_hash = caps.0[i] as HashOut<F>;
        vd.extend_from_slice(&cap_hash.elements);
    }

    H::hash_no_pad(&vd)
}


