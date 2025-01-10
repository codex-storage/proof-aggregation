use plonky2::iop::target::Target;
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CommonCircuitData};
use crate::circuits::params::CircuitParams;
use crate::circuits::sample_cells::{SampleCircuit, SampleCircuitInput, SampleTargets};
use crate::params::{D, F, C};
use crate::recursion::circuits::inner_circuit::InnerCircuit;
use crate::Result;

/// recursion Inner circuit for the sampling circuit
#[derive(Clone, Debug)]
pub struct SamplingRecursion {
    pub sampling_circ: SampleCircuit<F,D>,
}

impl SamplingRecursion {
    pub fn new(circ_params: CircuitParams) -> Self{
        let sampling_circ = SampleCircuit::new(circ_params);
        Self{
            sampling_circ,
        }
    }
}

impl Default for SamplingRecursion {
    fn default() -> Self {
        Self{
            sampling_circ: SampleCircuit::new(CircuitParams::default())
        }
    }
}


impl InnerCircuit for SamplingRecursion{
    type Targets = SampleTargets;
    type Input = SampleCircuitInput<F, D>;

    /// build the circuit
    fn build(&self, builder: &mut CircuitBuilder<F, D>) -> Result<Self::Targets> {
        self.sampling_circ.sample_slot_circuit(builder)
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
    fn get_common_data(&self) -> Result<(CommonCircuitData<F, D>)> {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        // build the inner circuit
        self.sampling_circ.sample_slot_circuit_with_public_input(&mut builder)?;

        let circ_data = builder.build::<C>();

        Ok(circ_data.common)
    }
}