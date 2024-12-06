use plonky2::iop::target::BoolTarget;
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use crate::circuits::params::CircuitParams;
use crate::circuits::sample_cells::{SampleCircuit, SampleCircuitInput, SampleTargets};
use crate::recursion::params::{D, F};
use crate::recursion::traits::InnerCircuit;

pub struct SamplingRecursion {}

impl InnerCircuit for SamplingRecursion{
    type Targets = SampleTargets;
    type Input = SampleCircuitInput<F, D>;

    /// build the circuit
    /// TODO: this build the circuit with default circuit params -> make it generic
    fn build(builder: &mut CircuitBuilder<F, D>) -> anyhow::Result<Self::Targets> {
        let circ = SampleCircuit::new(CircuitParams::default());
        Ok(circ.sample_slot_circuit(builder))
    }

    fn assign_targets(pw: &mut PartialWitness<F>, targets: &Self::Targets, input: &Self::Input) -> anyhow::Result<()> {
        let circ = SampleCircuit::<F,D>::new(CircuitParams::default());
        // circ.sample_slot_assign_witness(pw,targets,input);
        todo!()
        // Ok(())
    }
}