use plonky2::iop::target::BoolTarget;
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use crate::recursion::params::{F,C,D};

/// InnerCircuit is the trait used to define the logic of the circuit and assign witnesses
/// to that circuit instance.
pub trait InnerCircuit<
    // TODO: make it generic for F and D ?
> {
    type Targets;
    type Input;

    /// build the circuit logic and return targets to be assigned later
    fn build(
        builder: &mut CircuitBuilder<F, D>,
    ) -> anyhow::Result<Self::Targets>;

    /// assign the actual witness values for the current instance of the circuit.
    fn assign_targets(
        pw: &mut PartialWitness<F>,
        targets: &Self::Targets,
        input: &Self::Input,
    ) -> anyhow::Result<()>;
}
