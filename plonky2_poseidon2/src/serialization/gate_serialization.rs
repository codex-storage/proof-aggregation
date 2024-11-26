use std::time::Instant;
use plonky2_field::extension::Extendable;
use plonky2::gates::arithmetic_base::ArithmeticGate;
use plonky2::gates::arithmetic_extension::ArithmeticExtensionGate;
use plonky2::gates::base_sum::BaseSumGate;
use plonky2::gates::constant::ConstantGate;
use plonky2::gates::coset_interpolation::CosetInterpolationGate;
use plonky2::gates::exponentiation::ExponentiationGate;
use plonky2::gates::gate::GateRef;
use plonky2::gates::lookup::LookupGate;
use plonky2::gates::lookup_table::LookupTableGate;
use plonky2::gates::multiplication_extension::MulExtensionGate;
use plonky2::gates::noop::NoopGate;
use plonky2::gates::poseidon::PoseidonGate;
use crate::gate::poseidon2::Poseidon2Gate;
use plonky2::gates::poseidon_mds::PoseidonMdsGate;
use plonky2::gates::public_input::PublicInputGate;
use plonky2::gates::random_access::RandomAccessGate;
use plonky2::gates::reducing::ReducingGate;
use plonky2::gates::reducing_extension::ReducingExtensionGate;
use plonky2::hash::hash_types::RichField;
use plonky2::{read_gate_impl, get_gate_tag_impl};
use plonky2::plonk::circuit_data::{CircuitConfig, CommonCircuitData};
use plonky2::util::serialization::{Buffer, GateSerializer, IoResult};
use crate::poseidon2_hash::poseidon2::Poseidon2;
use std::vec::Vec;
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2_field::goldilocks_field::GoldilocksField;

#[macro_export]
/// The macros are re-implemented here because of import issue with plonky2
/// in plonky2 `use std::vec::Vec;` // For macros was not set to public
/// so here these are re-implemented
macro_rules! impl_gate_serializer {
    ($target:ty, $($gate_types:ty),+) => {
        fn read_gate(
            &self,
            buf: &mut plonky2::util::serialization::Buffer,
            common: &plonky2::plonk::circuit_data::CommonCircuitData<F, D>,
        ) -> plonky2::util::serialization::IoResult<plonky2::gates::gate::GateRef<F, D>> {
            let tag = plonky2::util::serialization::Read::read_u32(buf)?;
            read_gate_impl!(buf, tag, common, $($gate_types),+)
        }

        fn write_gate(
            &self,
            buf: &mut Vec<u8>,
            gate: &plonky2::gates::gate::GateRef<F, D>,
            common: &plonky2::plonk::circuit_data::CommonCircuitData<F, D>,
        ) -> plonky2::util::serialization::IoResult<()> {
            let tag = get_gate_tag_impl!(gate, $($gate_types),+)?;

            plonky2::util::serialization::Write::write_u32(buf, tag)?;
            gate.0.serialize(buf, common)?;
            Ok(())
        }
    };
}

/// A gate serializer that can be used to serialize all default gates supported
/// by the `plonky2` library with the added Poseidon2 Gate
#[derive(Debug)]
pub struct DefaultGateSerializer;
impl<F: RichField + Extendable<D> + Poseidon2, const D: usize> GateSerializer<F, D> for DefaultGateSerializer {
    impl_gate_serializer! {
            DefaultGateSerializer,
            ArithmeticGate,
            ArithmeticExtensionGate<D>,
            BaseSumGate<2>,
            ConstantGate,
            CosetInterpolationGate<F, D>,
            ExponentiationGate<F, D>,
            LookupGate,
            LookupTableGate,
            MulExtensionGate<D>,
            NoopGate,
            PoseidonMdsGate<F, D>,
            PoseidonGate<F, D>,
            Poseidon2Gate<F, D>,
            PublicInputGate,
            RandomAccessGate<F, D>,
            ReducingExtensionGate<D>,
            ReducingGate<D>
        }
}


