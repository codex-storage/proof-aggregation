use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CommonCircuitData;
use plonky2_field::extension::Extendable;
use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2;
use crate::Result;

/// InnerCircuit is the trait used to define the logic of the circuit and assign witnesses
/// to that circuit instance.
pub trait InnerCircuit<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
> {
    type Targets;
    type Input:Clone;

    /// build the circuit logic and return targets to be assigned later
    /// based on register_pi, registers the public input or not.
    fn build(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        register_pi: bool
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

    /// get the common data for the inner-circuit
    fn get_common_data(
        &self
    ) -> Result<(CommonCircuitData<F, D>)>;
}
