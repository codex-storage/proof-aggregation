use plonky2::hash::hash_types::RichField;
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, ProverCircuitData, VerifierCircuitData};
use plonky2::plonk::config::GenericConfig;
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2_field::extension::Extendable;
use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2;
use crate::error::CircuitError;
use crate::Result;

/// Plonky2Circuit is the trait used to define the logic of the circuit and assign witnesses
/// to that circuit instance.
pub trait Plonky2Circuit<
    F: RichField + Extendable<D> + Poseidon2,
    C: GenericConfig<D, F = F>,
    const D: usize,
> {
    type Targets;
    type Input:Clone;

    /// build the circuit with standard config
    fn build_with_standard_config(
        &self,
    ) -> Result<(Self::Targets,CircuitData<F, C, D>)>{
        self.build(CircuitConfig::standard_recursion_config())
    }

    /// build the circuit
    fn build(
        &self,
        circuit_config: CircuitConfig,
    ) -> Result<(Self::Targets,CircuitData<F, C, D>)>{
        let mut builder = CircuitBuilder::<F, D>::new(circuit_config);

        let targets = self.add_targets(&mut builder, true)?;

        Ok((targets,builder.build::<C>()))
    }

    /// build the circuit logic and return targets to be assigned later
    /// based on register_pi, registers the public input or not.
    fn add_targets(
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

    /// get the common data for the circuit with standard config
    fn get_common_data_standard_config(
        &self
    ) -> Result<CircuitData<F, C, D>>{
        self.get_common_data(CircuitConfig::standard_recursion_config())
    }

    /// get the common data for the circuit
    fn get_common_data(
        &self,
        circuit_config: CircuitConfig,
    ) -> Result<CircuitData<F, C, D>>{
        let mut builder = CircuitBuilder::<F, D>::new(circuit_config);

        self.add_targets(&mut builder, true)?;

        let circ_data = builder.build::<C>();

        Ok(circ_data)
    }

    /// generates a proof for the circuit using the given targets, input and prover circuit data
    fn prove(
        &self,
        targets: &Self::Targets,
        input: &Self::Input,
        prover_circuit_data: ProverCircuitData<F, C, D>
    )-> Result<ProofWithPublicInputs<F, C, D>>{
        let mut pw = PartialWitness::new();
        self.assign_targets(&mut pw, targets, input)?;

        let proof = prover_circuit_data.prove(pw).map_err(
            |e| CircuitError::ProofGenerationError(e.to_string())
        )?;

        Ok(proof)
    }

    /// verify the given proof with the verifier circuit data
    fn verify(
        proof_with_pi: ProofWithPublicInputs<F, C, D>,
        verifier_circuit_data: VerifierCircuitData<F, C, D>
    ) -> Result<()>{
        verifier_circuit_data.verify(proof_with_pi).map_err( |e|
            CircuitError::InvalidProofError(e.to_string())
        )
    }
}

