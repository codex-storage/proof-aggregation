use std::marker::PhantomData;
use plonky2_field::extension::Extendable;
use plonky2::gates::arithmetic_base::{ArithmeticBaseGenerator, ArithmeticGate};
use plonky2::gates::arithmetic_extension::{ArithmeticExtensionGate, ArithmeticExtensionGenerator};
use plonky2::gates::base_sum::{BaseSplitGenerator, BaseSumGate};
use plonky2::gates::constant::ConstantGate;
use plonky2::gates::coset_interpolation::{CosetInterpolationGate, InterpolationGenerator};
use plonky2::gates::exponentiation::{ExponentiationGate, ExponentiationGenerator};
use plonky2::gates::gate::{AnyGate, Gate, GateRef};
use plonky2::gates::lookup::{LookupGate, LookupGenerator};
use plonky2::gates::lookup_table::{LookupTableGate, LookupTableGenerator};
use plonky2::gates::multiplication_extension::{MulExtensionGate, MulExtensionGenerator};
use plonky2::gates::noop::NoopGate;
use plonky2::gates::poseidon::{PoseidonGate, PoseidonGenerator};
use crate::gate::poseidon2::{Poseidon2Gate, Poseidon2Generator};
use plonky2::gates::poseidon_mds::{PoseidonMdsGate, PoseidonMdsGenerator};
use plonky2::gates::public_input::PublicInputGate;
use plonky2::gates::random_access::{RandomAccessGate, RandomAccessGenerator};
use plonky2::gates::reducing::{ReducingGate, ReducingGenerator};
use plonky2::gates::reducing_extension::ReducingGenerator as ReducingExtensionGenerator;
use plonky2::gates::reducing_extension::ReducingExtensionGate;
use plonky2::hash::hash_types::RichField;
use plonky2::{impl_gate_serializer, impl_generator_serializer, get_generator_tag_impl, read_generator_impl};
use plonky2::read_gate_impl;
use plonky2::get_gate_tag_impl;
use plonky2::plonk::circuit_data::CommonCircuitData;
use plonky2::util::serialization::{Buffer, GateSerializer, IoError, IoResult, Read, WitnessGeneratorSerializer, Write};
use crate::poseidon2_hash::poseidon2::Poseidon2;
use std::vec::Vec;
use plonky2::gadgets::arithmetic::EqualityGenerator;
use plonky2::gadgets::arithmetic_extension::QuotientGeneratorExtension;
use plonky2::gadgets::range_check::LowHighGenerator;
use plonky2::gadgets::split_base::BaseSumGenerator;
use plonky2::gadgets::split_join::{SplitGenerator, WireSplitGenerator};
use plonky2::iop::generator::{ConstantGenerator, CopyGenerator, NonzeroTestGenerator, RandomValueGenerator, SimpleGenerator, WitnessGeneratorRef};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2::recursion::dummy_circuit::DummyProofGenerator;

#[derive(Debug, Default)]
pub struct DefaultGeneratorSerializer<C: GenericConfig<D>, const D: usize> {
    pub _phantom: PhantomData<C>,
}

/// A generator serializer that can be used to serialize all default generators supported
/// by the `plonky2` library with the added `Poseidon2Generator`
impl<F, C, const D: usize> WitnessGeneratorSerializer<F, D> for DefaultGeneratorSerializer<C, D>
    where
        F: RichField + Extendable<D> + Poseidon2,
        C: GenericConfig<D, F = F> + 'static,
        C::Hasher: AlgebraicHasher<F>,
{
    impl_generator_serializer! {
            DefaultGeneratorSerializer,
            ArithmeticBaseGenerator<F, D>,
            ArithmeticExtensionGenerator<F, D>,
            BaseSplitGenerator<2>,
            BaseSumGenerator<2>,
            ConstantGenerator<F>,
            CopyGenerator,
            DummyProofGenerator<F, C, D>,
            EqualityGenerator,
            ExponentiationGenerator<F, D>,
            InterpolationGenerator<F, D>,
            LookupGenerator,
            LookupTableGenerator,
            LowHighGenerator,
            MulExtensionGenerator<F, D>,
            NonzeroTestGenerator,
            PoseidonGenerator<F, D>,
            Poseidon2Generator<F, D>,
            PoseidonMdsGenerator<D>,
            QuotientGeneratorExtension<D>,
            RandomAccessGenerator<F, D>,
            RandomValueGenerator,
            ReducingGenerator<D>,
            ReducingExtensionGenerator<D>,
            SplitGenerator,
            WireSplitGenerator
        }
}