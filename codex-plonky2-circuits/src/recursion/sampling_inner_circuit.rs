use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use crate::circuits::params::CircuitParams;
use crate::circuits::sample_cells::{SampleCircuit, SampleCircuitInput, SampleTargets};
use crate::recursion::params::{D, F};
use crate::recursion::inner_circuit::InnerCircuit;
use crate::circuits::params;

/// recursion Inner circuit for the sampling circuit
#[derive(Clone, Debug)]
pub struct SamplingRecursion {
    pub sampling_circ: SampleCircuit<F,D>,
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
    fn build(&self, builder: &mut CircuitBuilder<F, D>) -> anyhow::Result<Self::Targets> {
        Ok(self.sampling_circ.sample_slot_circuit(builder))
    }

    fn assign_targets(&self, pw: &mut PartialWitness<F>, targets: &Self::Targets, input: &Self::Input) -> anyhow::Result<()> {
        Ok(self.sampling_circ.sample_slot_assign_witness(pw, targets, input))
    }

    /// returns the public input specific for this circuit which are:
    /// `[slot_index, dataset_root, entropy]`
    fn get_pub_input_targets(targets: &Self::Targets) -> anyhow::Result<(Vec<Target>)> {
        let mut pub_targets = vec![];
        pub_targets.push(targets.slot_index.clone());
        pub_targets.extend_from_slice(&targets.dataset_root.elements);
        pub_targets.extend_from_slice(&targets.entropy.elements);

        Ok(pub_targets)
    }
}