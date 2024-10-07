//! Implementation of the Poseidon2 hash function, as described in
//! https://eprint.iacr.org/2023/323.pdf
//! The implementation is based on Poseidon hash in Plonky2:
//! https://github.com/0xPolygonZero/plonky2/blob/main/plonky2/src/hash/poseidon.rs

use core::fmt::Debug;
use plonky2_field::extension::{Extendable, FieldExtension};
use plonky2_field::types::{Field, PrimeField64};
use unroll::unroll_for_loops;
use crate::gate::poseidon2::Poseidon2Gate;
use plonky2::hash::hash_types::{HashOut, RichField};
use plonky2::hash::hashing::{compress, hash_n_to_hash_no_pad, PlonkyPermutation};
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::config::{AlgebraicHasher, Hasher};

// Constants defining the number of rounds and state width.
// Note: only state width 12 is currently supported.
pub const SPONGE_WIDTH: usize = 12; // state width
pub const DEGREE: usize = 7; // sbox degree
pub const FULL_ROUND_BEGIN: usize = 4;
pub const FULL_ROUND_END: usize = 2 * FULL_ROUND_BEGIN;
pub const PARTIAL_ROUNDS: usize = 22;
pub const ROUNDS: usize = FULL_ROUND_END + PARTIAL_ROUNDS;


pub trait Poseidon2: PrimeField64 {
    const MAT_DIAG12_M_1: [u64; SPONGE_WIDTH];
    const RC12: [u64; SPONGE_WIDTH * FULL_ROUND_END];
    const RC12_MID: [u64; PARTIAL_ROUNDS];

    // ------------- Poseidon2 Hash ------------
        #[inline]
    fn poseidon2(input: [Self; SPONGE_WIDTH]) -> [Self; SPONGE_WIDTH] {
        // state
        let mut current_state = input;

        // Linear layer at beginning
        Self::matmul_external(&mut current_state);

        // External Rounds 0 -> 4
        for round_ctr in 0..FULL_ROUND_BEGIN {
            Self::external_rounds(&mut current_state , round_ctr);
        }

        // Internal Rounds
        for round_ctr in 0..PARTIAL_ROUNDS {
            Self::internal_rounds(&mut current_state ,round_ctr);
        }

        // External Rounds 4 -> 8
        for round_ctr in FULL_ROUND_BEGIN..FULL_ROUND_END {
            Self::external_rounds(&mut current_state , round_ctr);
        }

        current_state
    }

    // ------------- matmul external and internal -------------------
    #[inline]
    #[unroll_for_loops]
    fn matmul_external(state: &mut [Self; SPONGE_WIDTH]){
        // Applying cheap 4x4 MDS matrix to each 4-element part of the state
        Self::matmul_m4(state);

        // Applying second cheap matrix for t > 4
        let t4: usize = SPONGE_WIDTH / 4;
        let mut stored = [Self::ZERO; 4];
        for l in 0..4 {
            stored[l] = state[l];
            for j in 1..t4 {
                stored[l] = stored[l].add(state[4 * j + l]);
            }
        }
        for i in 0..state.len() {
            state[i] = state[i].add(stored[i % 4]);
        }
    }

    fn matmul_m4 (state: &mut [Self; SPONGE_WIDTH]){
        let t4 = SPONGE_WIDTH / 4;

        for i in 0..t4 {
            let start_index = i * 4;
            let mut t_0 = state[start_index];

            t_0 = t_0.add(state[start_index + 1]);
            let mut t_1 = state[start_index + 2];

            t_1 = t_1.add(state[start_index + 3]);
            let mut t_2 = t_1;

            t_2 = t_2.multiply_accumulate(state[start_index + 1], Self::TWO);

            let mut t_3 = t_0;

            t_3 = t_3.multiply_accumulate(state[start_index + 3], Self::TWO);
            let mut t_4 = t_3;

            t_4 = t_4.multiply_accumulate(t_1, Self::TWO.double());

            let mut t_5 = t_2;

            t_5 = t_5.multiply_accumulate(t_0, Self::TWO.double());

            let t_6 = t_3.add(t_5);

            let t_7 = t_2.add(t_4);

            state[start_index] = t_6;
            state[start_index + 1] = t_5;
            state[start_index + 2] = t_7;
            state[start_index + 3] = t_4;
        }
    }

    #[inline]
    #[unroll_for_loops]
    fn matmul_internal(current_state: &mut [Self; SPONGE_WIDTH], mat_internal_diag_m_1: &[u64; SPONGE_WIDTH]){
        let sum: u128 = current_state
            .iter()
            .map(|&x| x.to_noncanonical_u64() as u128)
            .sum();

        current_state
            .iter_mut()
            .zip(mat_internal_diag_m_1.iter())
            .for_each(|(state_i, &diag_m1)| {
                let state_value = state_i.to_noncanonical_u64() as u128;
                let multi = (diag_m1 as u128) * state_value + sum;
                *state_i = Self::from_noncanonical_u128(multi);
        });
    }

    // ------------- external rounds -------------------
    fn external_rounds(state: &mut [Self; SPONGE_WIDTH], round_ctr: usize) {
        Self::constant_layer(state, round_ctr);
        Self::sbox_layer(state);
        Self::matmul_external(state);
    }

    // Constant Layer
    #[inline]
    #[unroll_for_loops]
    fn constant_layer(state: &mut [Self; SPONGE_WIDTH], round_ctr: usize) {
        let ofs = round_ctr * SPONGE_WIDTH;
        for i in 0..SPONGE_WIDTH {
            let round_constant = Self::RC12[ofs + i];
            unsafe {
                state[i] = state[i].add_canonical_u64(round_constant);
            }
        }
    }

    // sbox layer
    #[inline]
    #[unroll_for_loops]
    fn sbox_layer(state: &mut [Self; SPONGE_WIDTH]) {
        for i in 0..SPONGE_WIDTH {
            state[i] = Self::sbox_p(state[i]);
        }
    }
    #[inline(always)]
    fn sbox_p<F: FieldExtension<D, BaseField = Self>, const D: usize>(x: F) -> F {
        // x |--> x^7
        // only d=7 is supported for now
        if DEGREE != 7 { panic!("sbox degree not supported") }
        let x2 = x.square();
        let x4 = x2.square();
        let x3 = x * x2;
        x3 * x4
    }

    // ------------- internal rounds -------------------
    fn internal_rounds(state: &mut [Self; SPONGE_WIDTH], round_ctr: usize) {
        state[0] += Self::from_canonical_u64(Self::RC12_MID[round_ctr]);
        state[0] = Self::sbox_p(state[0]);
        Self::matmul_internal(state, &Self::MAT_DIAG12_M_1);
    }

    // ------------- Same functions as above but for field extensions of `Self`.
    #[inline]
    fn matmul_external_field<F: FieldExtension<D, BaseField = Self>, const D: usize>(
        state: &mut [F],
    ) {
        // Applying cheap 4x4 MDS matrix to each 4-element part of the state
        Self::matmul_m4_field(state);

        // Applying second cheap matrix for t > 4
        let t4: usize = SPONGE_WIDTH / 4;
        let mut stored = [F::ZERO; 4];
        for l in 0..4 {
            stored[l] = state[l];
            for j in 1..t4 {
                stored[l] += state[4 * j + l];
            }
        }
        for i in 0..state.len() {
            state[i] += stored[i % 4];
        }
    }
    fn matmul_m4_field<F: FieldExtension<D, BaseField = Self>, const D: usize>(state: &mut [F]) {
        let t4 = SPONGE_WIDTH / 4;

        for i in 0..t4 {
            let start_index = i * 4;
            let mut t_0 = state[start_index];

            t_0 = t_0.add(state[start_index + 1]);
            let mut t_1 = state[start_index + 2];

            t_1 = t_1.add(state[start_index + 3]);
            let mut t_2 = t_1;

            t_2 = t_2.multiply_accumulate(state[start_index + 1], F::TWO);

            let mut t_3 = t_0;

            t_3 = t_3.multiply_accumulate(state[start_index + 3], F::TWO);
            let mut t_4 = t_3;

            t_4 = t_4.multiply_accumulate(t_1, F::TWO.double());

            let mut t_5 = t_2;

            t_5 = t_5.multiply_accumulate(t_0, F::TWO.double());

            let t_6 = t_3.add(t_5);

            let t_7 = t_2.add(t_4);

            state[start_index] = t_6;
            state[start_index + 1] = t_5;
            state[start_index + 2] = t_7;
            state[start_index + 3] = t_4;
        }
    }
    #[inline]
    fn matmul_internal_field<F: FieldExtension<D, BaseField = Self>, const D: usize>(
        input: &mut [F],
        mat_internal_diag_m_1: &[u64],
    ) {
        let sum: F = input.iter().copied().sum();

        for (input_i, &diag_m1) in input.iter_mut().zip(mat_internal_diag_m_1.iter()) {
            let diag = F::from_canonical_u64(diag_m1);
            *input_i = *input_i * diag + sum;
        }
    }

    fn constant_layer_field<F: FieldExtension<D, BaseField = Self>, const D: usize>(
        state: &mut [F; SPONGE_WIDTH],
        round_ctr: usize,
    ) {
        let ofs = round_ctr * SPONGE_WIDTH;
        for i in 0..SPONGE_WIDTH {
            let round_constant = Self::RC12[ofs + i];
            state[i] += F::from_canonical_u64(round_constant);
        }
    }
    fn sbox_layer_field<F: FieldExtension<D, BaseField = Self>, const D: usize>(
        state: &mut [F; SPONGE_WIDTH],
    ) {
        for i in 0..SPONGE_WIDTH {
            state[i] = Self::sbox_p(state[i]);
        }
    }

    //---------- Same functions for circuit (recursion) -----------

    fn matmul_m4_circuit<const D: usize>(
        builder: &mut CircuitBuilder<Self, D>,
        state: &mut [ExtensionTarget<D>; SPONGE_WIDTH],
    ) where
        Self: RichField + Extendable<D>,
    {
        for i in 0..3 {
            let start_index = i * 4;
            let t_0 = builder.mul_const_add_extension(Self::ONE, state[start_index], state[start_index + 1]);
            let t_1 =
                builder.mul_const_add_extension(Self::ONE, state[start_index + 2], state[start_index + 3]);
            let t_2 = builder.mul_const_add_extension(Self::TWO, state[start_index + 1], t_1);
            let t_3 = builder.mul_const_add_extension(Self::TWO, state[start_index + 3], t_0);
            let t_4 = builder.mul_const_add_extension(Self::TWO.double(), t_1, t_3);
            let t_5 = builder.mul_const_add_extension(Self::TWO.double(), t_0, t_2);
            let t_6 = builder.mul_const_add_extension(Self::ONE, t_3, t_5);
            let t_7 = builder.mul_const_add_extension(Self::ONE, t_2, t_4);

            state[start_index] = t_6;
            state[start_index + 1] = t_5;
            state[start_index + 2] = t_7;
            state[start_index + 3] = t_4;
        }
    }

    fn matmul_external_circuit<const D: usize>(
        builder: &mut CircuitBuilder<Self, D>,
        state: &mut [ExtensionTarget<D>; SPONGE_WIDTH],
    ) -> [ExtensionTarget<D>; SPONGE_WIDTH]
    where
        Self: RichField + Extendable<D>,
    {
        Self::matmul_m4_circuit(builder, state);

        let t4: usize = SPONGE_WIDTH / 4;
        let mut stored = [builder.zero_extension(); 4];

        for l in 0..4 {
            let mut sum = state[l];
            for j in 1..t4 {
                let idx = 4 * j + l;
                sum = builder.add_extension(sum, state[idx]);
            }
            stored[l] = sum;
        }

        let result = state
            .iter()
            .enumerate()
            .map(|(i, &val)| {
                let stored_idx = i % 4;
                builder.add_extension(val, stored[stored_idx])
            })
            .collect::<Vec<_>>();

        result.try_into().unwrap_or_else(|v: Vec<ExtensionTarget<D>>| {
            panic!("Expected a Vec of length {}", SPONGE_WIDTH)
        })
    }

    fn constant_layer_circuit<const D: usize>(
        builder: &mut CircuitBuilder<Self, D>,
        state: &mut [ExtensionTarget<D>; SPONGE_WIDTH],
        rc_index: usize,
    ) where
        Self: RichField + Extendable<D>,
    {
        let ofs = rc_index * SPONGE_WIDTH;
        for i in 0..SPONGE_WIDTH {
            let round_constant = Self::Extension::from_canonical_u64(Self::RC12[ofs + i]);
            let round_constant = builder.constant_extension(round_constant);
            state[i] = builder.add_extension(state[i], round_constant);
        }
    }

    fn sbox_layer_circuit<const D: usize>(
        builder: &mut CircuitBuilder<Self, D>,
        state: &mut [ExtensionTarget<D>; SPONGE_WIDTH],
    ) where
        Self: RichField + Extendable<D>,
    {
        for i in 0..SPONGE_WIDTH {
            state[i] = builder.exp_u64_extension(state[i], DEGREE as u64);
        }
    }

    fn sbox_p_circuit<const D: usize>(
        builder: &mut CircuitBuilder<Self, D>,
        state: ExtensionTarget<D>,
    ) -> ExtensionTarget<D>
    where
        Self: RichField + Extendable<D>,
    {
        builder.exp_u64_extension(state, DEGREE as u64)
    }

    fn matmul_internal_circuit<const D: usize>(
        builder: &mut CircuitBuilder<Self, D>,
        state: &mut [ExtensionTarget<D>; SPONGE_WIDTH],
    ) where
        Self: RichField + Extendable<D>,
    {
        let sum = builder.add_many_extension(state.clone());

        for (i, input_i) in state.iter_mut().enumerate() {
            let constant = Self::from_canonical_u64(Self::MAT_DIAG12_M_1[i]);

            *input_i = builder.mul_const_add_extension(constant, *input_i, sum);
        }
    }

}

#[derive(Default, Clone, Copy, Debug, PartialEq)]
pub struct Poseidon2Permutation<T> {
    state: [T; SPONGE_WIDTH],
}

impl<T> AsRef<[T]> for Poseidon2Permutation<T> {
    fn as_ref(&self) -> &[T] {
        &self.state
    }
}

impl<T: Eq> Eq for Poseidon2Permutation<T> {}

trait Permuter: Sized {
    fn permute(input: [Self; SPONGE_WIDTH]) -> [Self; SPONGE_WIDTH];
}

impl<F: Poseidon2> Permuter for F {
    fn permute(input: [Self; SPONGE_WIDTH]) -> [Self; SPONGE_WIDTH] {
        <F as Poseidon2>::poseidon2(input)
    }
}

impl Permuter for Target {
    fn permute(_input: [Self; SPONGE_WIDTH]) -> [Self; SPONGE_WIDTH] {
        panic!("Call `permute_swapped()` instead of `permute()`");
    }
}

impl<T: Copy + Debug + Default + Eq + Permuter + Send + Sync> PlonkyPermutation<T>
    for Poseidon2Permutation<T>
{
    const RATE: usize = 8;
    const WIDTH: usize = SPONGE_WIDTH;

    fn new<I: IntoIterator<Item = T>>(elts: I) -> Self {
        let mut perm = Self {
            state: [T::default(); SPONGE_WIDTH],
        };
        perm.set_from_iter(elts, 0);
        perm
    }

    fn set_elt(&mut self, elt: T, idx: usize) {
        self.state[idx] = elt;
    }

    fn set_from_slice(&mut self, elts: &[T], start_idx: usize) {
        let begin = start_idx;
        let end = start_idx + elts.len();
        self.state[begin..end].copy_from_slice(elts);
    }

    fn set_from_iter<I: IntoIterator<Item = T>>(&mut self, elts: I, start_idx: usize) {
        for (s, e) in self.state[start_idx..].iter_mut().zip(elts) {
            *s = e;
        }
    }

    fn permute(&mut self) {
        self.state = T::permute(self.state);
    }

    fn squeeze(&self) -> &[T] {
        &self.state[..Self::RATE]
    }
}

/// Poseidon2 hash function.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Poseidon2Hash;
impl<F: RichField + Poseidon2> Hasher<F> for Poseidon2Hash {
    const HASH_SIZE: usize = 4 * 8;
    type Hash = HashOut<F>;
    type Permutation = Poseidon2Permutation<F>;

    fn hash_no_pad(input: &[F]) -> Self::Hash {
        hash_n_to_hash_no_pad::<F, Self::Permutation>(input)
    }

    fn two_to_one(left: Self::Hash, right: Self::Hash) -> Self::Hash {
        compress::<F, Self::Permutation>(left, right)
    }
}

impl<F: RichField + Poseidon2> AlgebraicHasher<F> for Poseidon2Hash {
    type AlgebraicPermutation = Poseidon2Permutation<Target>;

    fn permute_swapped<const D: usize>(
        inputs: Self::AlgebraicPermutation,
        swap: BoolTarget,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self::AlgebraicPermutation
    where
        F: RichField + Extendable<D>,
    {
        let gate_type = Poseidon2Gate::<F, D>::new();
        let gate = builder.add_gate(gate_type, vec![]);

        let swap_wire = Poseidon2Gate::<F, D>::WIRE_SWAP;
        let swap_wire = Target::wire(gate, swap_wire);
        builder.connect(swap.target, swap_wire);

        // Route input wires.
        let inputs = inputs.as_ref();
        for i in 0..SPONGE_WIDTH {
            let in_wire = Poseidon2Gate::<F, D>::wire_input(i);
            let in_wire = Target::wire(gate, in_wire);
            builder.connect(inputs[i], in_wire);
        }

        // Collect output wires.
        Self::AlgebraicPermutation::new(
            (0..SPONGE_WIDTH).map(|i| Target::wire(gate, Poseidon2Gate::<F, D>::wire_output(i))),
        )
    }
}

#[cfg(test)]
pub(crate) mod test_helpers {

    use crate::poseidon2_hash::poseidon2::{Poseidon2, SPONGE_WIDTH};

    pub(crate) fn check_test_vectors<F>(test_vectors: Vec<([u64; SPONGE_WIDTH], [u64; SPONGE_WIDTH])>)
    where
        F: Poseidon2,
    {
        for (input_, expected_output_) in test_vectors.into_iter() {
            let mut input = [F::ZERO; SPONGE_WIDTH];
            for i in 0..SPONGE_WIDTH {
                input[i] = F::from_canonical_u64(input_[i]);
            }
            let output = F::poseidon2(input);
            for i in 0..SPONGE_WIDTH {
                let ex_output = F::from_canonical_u64(expected_output_[i]);
                assert_eq!(output[i], ex_output);
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod test_consistency {
    use plonky2::hash::hashing::PlonkyPermutation;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use crate::poseidon2_hash::poseidon2::{Poseidon2, Poseidon2Permutation, SPONGE_WIDTH};
    use plonky2_field::goldilocks_field::GoldilocksField as F;
    use plonky2_field::types::Field;

    #[test]
    pub(crate) fn p2new_check_con()
    {
        let mut input = [F::ZERO; SPONGE_WIDTH];
        for i in 0..SPONGE_WIDTH {
            input[i] = F::from_canonical_u64(i as u64);
        }
        let output = F::poseidon2(input);
        for i in 0..SPONGE_WIDTH {
            println!("input {} = {}", i, input[i]);
        }
        for i in 0..SPONGE_WIDTH {
            println!("out {} = {}", i, output[i]);
        }
    }
}
