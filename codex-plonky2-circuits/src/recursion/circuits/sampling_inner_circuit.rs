use std::marker::PhantomData;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CommonCircuitData};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2_field::extension::Extendable;
use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2;
use crate::circuits::params::CircuitParams;
use crate::circuits::sample_cells::{SampleCircuit, SampleCircuitInput, SampleTargets};
use crate::recursion::circuits::inner_circuit::InnerCircuit;
use crate::Result;

/// recursion Inner circuit for the sampling circuit
#[derive(Clone, Debug)]
pub struct SamplingRecursion<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    H: AlgebraicHasher<F>,
    C: GenericConfig<D, F = F>,
> {
    pub sampling_circ: SampleCircuit<F,D,H>,
    phantom_data: PhantomData<C>,
}

impl<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    H: AlgebraicHasher<F>,
    C: GenericConfig<D, F = F>,
> SamplingRecursion<F, D, H, C> {
    pub fn new(circ_params:CircuitParams) -> Self {
        Self{
            sampling_circ: SampleCircuit::new(circ_params),
            phantom_data: PhantomData::default(),
        }
    }
}


impl<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    H: AlgebraicHasher<F>,
    C: GenericConfig<D, F = F>,
> InnerCircuit<F, D> for SamplingRecursion<F, D, H, C> {
    type Targets = SampleTargets;
    type Input = SampleCircuitInput<F, D>;

    /// build the circuit
    fn build(&self, builder: &mut CircuitBuilder<F, D>, register_pi: bool) -> Result<Self::Targets> {
        if register_pi{
            self.sampling_circ.sample_slot_circuit_with_public_input(builder)
        }else {
            self.sampling_circ.sample_slot_circuit(builder)
        }
    }

    fn assign_targets(&self, pw: &mut PartialWitness<F>, targets: &Self::Targets, input: &Self::Input) -> Result<()> {
        self.sampling_circ.sample_slot_assign_witness(pw, targets, input)
    }

    /// returns the public input specific for this circuit which are:
    /// `[slot_index, dataset_root, entropy]`
    fn get_pub_input_targets(targets: &Self::Targets) -> Vec<Target> {
        let mut pub_targets = vec![];
        pub_targets.push(targets.slot_index.clone());
        pub_targets.extend_from_slice(&targets.dataset_root.elements);
        pub_targets.extend_from_slice(&targets.entropy.elements);

        pub_targets
    }

    /// return the common circuit data for the sampling circuit
    /// uses the `standard_recursion_config`
    /// TODO: make it generic for any config
    fn get_common_data(&self) -> Result<(CommonCircuitData<F, D>)> {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        // build the inner circuit
        self.sampling_circ.sample_slot_circuit_with_public_input(&mut builder)?;

        let circ_data = builder.build::<C>();

        Ok(circ_data.common)
    }
}