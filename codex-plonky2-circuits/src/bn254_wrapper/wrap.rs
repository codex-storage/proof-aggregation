use std::fs::{self, File};
use std::marker::PhantomData;
use std::path::Path;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CommonCircuitData, VerifierCircuitData, VerifierOnlyCircuitData};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2::plonk::proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget};
use plonky2_field::extension::Extendable;
use serde::Serialize;
use plonky2_poseidon2::Poseidon2;
use crate::circuit_helper::Plonky2Circuit;
use crate::error::CircuitError;

/// Wrap circuit - wraps the plonky2 proof with
/// InnerParameters: Config params for the inner proof - this is the default config
/// OuterParameters: Config params for the outer proof - this is the bn254 config
#[derive(Debug)]
pub struct WrapCircuit<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    InnerParameters: GenericConfig<D, F = F>,
    OuterParameters: GenericConfig<D, F = F>,
> {
    inner_verifier_data: VerifierCircuitData<F, InnerParameters, D>,
    phantom_data: PhantomData<OuterParameters>
}

#[derive(Clone, Debug)]
pub struct WrapTargets<
    const D: usize,
>{
    pub inner_proof: ProofWithPublicInputsTarget<D>,
}

#[derive(Clone, Debug)]
pub struct WrapInput<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    InnerParameters: GenericConfig<D, F = F>,
>{
    pub inner_proof: ProofWithPublicInputs<F, InnerParameters, D>
}

impl<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    InnerParameters: GenericConfig<D, F = F>,
    OuterParameters: GenericConfig<D, F = F>,
    > Plonky2Circuit<F,OuterParameters,D> for WrapCircuit<F, D, InnerParameters, OuterParameters>
    where
        <InnerParameters as GenericConfig<D>>::Hasher: AlgebraicHasher<F>
{
    type Targets = WrapTargets<D>;
    type Input = WrapInput<F, D, InnerParameters>;

    fn add_targets(&self, builder: &mut CircuitBuilder<F, D>, register_pi: bool) -> crate::Result<Self::Targets> {
        let inner_common = self.inner_verifier_data.common.clone();

        // the proof virtual targets
        let vir_proof = builder.add_virtual_proof_with_pis(&inner_common);
        // make inner public input into outer public input
        if register_pi {
            builder.register_public_inputs(&vir_proof.public_inputs);
        }

        // constant target for the verifier data
        let const_verifier_data = builder.constant_verifier_data(&self.inner_verifier_data.verifier_only);

        // verify the proofs in-circuit
        builder.verify_proof::<InnerParameters>(&vir_proof, &const_verifier_data, &inner_common);

        Ok(
            WrapTargets{
            inner_proof:vir_proof,
            }
        )
    }

    fn assign_targets(&self, pw: &mut PartialWitness<F>, targets: &Self::Targets, input: &Self::Input) -> crate::Result<()> where
        <InnerParameters as GenericConfig<D>>::Hasher: AlgebraicHasher<F> {
        // assign the proof
        pw.set_proof_with_pis_target(&targets.inner_proof, &input.inner_proof)
            .map_err(|e| {
                CircuitError::ProofTargetAssignmentError("inner-proof".to_string(), e.to_string())
            })?;

        Ok(())
    }
}

impl<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    InnerParameters: GenericConfig<D, F = F>,
    OuterParameters: GenericConfig<D, F = F>,
>  WrapCircuit<F, D, InnerParameters, OuterParameters>
{
    pub fn new(
        inner_verifier_data: VerifierCircuitData<F, InnerParameters, D>,
    ) -> Self {
        Self{
            inner_verifier_data,
            phantom_data: Default::default(),
        }
    }
}

#[derive(Debug)]
pub struct WrappedOutput<
    F: RichField + Extendable<D> + Poseidon2,
    C: GenericConfig<D, F = F>,
    const D: usize
> {
    pub proof: ProofWithPublicInputs<F, C, D>,
    pub common_data: CommonCircuitData<F, D>,
    pub verifier_data: VerifierOnlyCircuitData<C, D>,
}

impl<
    F: RichField + Extendable<D> + Poseidon2,
    C: GenericConfig<D, F = F>,
    const D: usize
> WrappedOutput<F,C,D> {
    pub fn save<P: AsRef<Path>>(&self, path: P) -> anyhow::Result<()>
    where
        C: Serialize,
    {
        if !path.as_ref().exists() {
            fs::create_dir_all(&path)?;
        }
        let common_data_file = File::create(path.as_ref().join("verifier_data/common_circuit_data.json"))?;
        serde_json::to_writer(&common_data_file, &self.common_data)?;
        println!("Succesfully wrote common circuit data to common_circuit_data.json");

        let verifier_data_file =
            File::create(path.as_ref().join("verifier_data/verifier_only_circuit_data.json"))?;
        serde_json::to_writer(&verifier_data_file, &self.verifier_data)?;
        println!("Succesfully wrote verifier data to verifier_only_circuit_data.json");

        let proof_file = File::create(path.as_ref().join("verifier_data/proof_with_public_inputs.json"))?;
        serde_json::to_writer(&proof_file, &self.proof)?;
        println!("Succesfully wrote proof to proof_with_public_inputs.json");

        Ok(())
    }
}


