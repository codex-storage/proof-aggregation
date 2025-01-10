use plonky2::iop::target::Target;
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CommonCircuitData;
use crate::Result;
use crate::params::{F, D};

/// InnerCircuit is the trait used to define the logic of the circuit and assign witnesses
/// to that circuit instance.
pub trait InnerCircuit<
    // TODO: make it generic for F and D ?
> {
    type Targets;
    type Input:Clone;

    /// build the circuit logic and return targets to be assigned later
    fn build(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Result<Self::Targets>;

    /// assign the actual witness values for the current instance of the circuit.
    fn assign_targets(
        &self,
        pw: &mut PartialWitness<F>,
        targets: &Self::Targets,
        input: &Self::Input,
    ) -> Result<()>;

    /// from the set of the targets, return only the targets which are public
    /// TODO: this can probably be replaced with enum for Public/Private targets
    fn get_pub_input_targets(
        targets: &Self::Targets,
    ) -> Vec<Target>;

    /// from the set of the targets, return only the targets which are public
    /// TODO: this can probably be replaced with enum for Public/Private targets
    fn get_common_data(
        &self
    ) -> Result<(CommonCircuitData<F, D>)>;
}
