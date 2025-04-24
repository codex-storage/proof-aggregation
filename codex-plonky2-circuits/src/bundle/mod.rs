use hashbrown::HashMap;
use plonky2::hash::hash_types::RichField;
use plonky2::plonk::circuit_data::{ProverCircuitData, VerifierCircuitData};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2_field::extension::Extendable;
use plonky2_poseidon2::Poseidon2;
use crate::circuit_helper::Plonky2Circuit;
use crate::circuits::params::CircuitParams;
use crate::circuits::sample_cells::{SampleCircuit, SampleCircuitInput, SampleTargets};
use crate::Result;

pub struct Bundle<
    F: RichField + Extendable<D> + Poseidon2,
    C: GenericConfig<D, F = F>,
    const D: usize,
    H: AlgebraicHasher<F>,
>{
    pub bundle_size: usize,
    pub circuit: SampleCircuit<F, D, H>,
    pub prover_data: ProverCircuitData<F, C, D>,
    pub verifier_data: VerifierCircuitData<F, C, D>,
    pub sample_targets: SampleTargets,
    pub bundle_proofs: HashMap<usize, ProofWithPublicInputs<F, C, D>>,
}

impl<
    F: RichField + Extendable<D> + Poseidon2,
    C: GenericConfig<D, F=F>,
    const D: usize,
    H: AlgebraicHasher<F>,
> Bundle<F, C, D, H> {
    pub fn new(bundle_size: usize, circuit_params: CircuitParams) -> Result<(Self)>{
        let samp_circ = SampleCircuit::<F, D, H>::new(circuit_params.clone());
        let (sample_targets, circuit_data) = samp_circ.build_with_standard_config()?;
        println!("sampling circuit built. Degree bits = {:?}", circuit_data.common.degree_bits());
        let verifier_data = circuit_data.verifier_data();
        let prover_data = circuit_data.prover_data();
        Ok(Self{
            bundle_size,
            circuit: samp_circ,
            prover_data,
            verifier_data,
            sample_targets,
            bundle_proofs: HashMap::new(),
        })
    }

    pub fn prove_all(&mut self, circ_inputs: Vec<SampleCircuitInput<F, D>>) -> Result<()>{
        assert_eq!(circ_inputs.len(), self.bundle_size, "not enough circuit input provided");
        for (i, input) in circ_inputs.into_iter().enumerate(){
            self.prove(i, input)?;
        }
        Ok(())
    }

    pub fn prove(&mut self, index: usize, circ_input: SampleCircuitInput<F, D>) -> Result<()>{
        let proof = self.circuit.prove(&self.sample_targets, &circ_input, &self.prover_data)?;
        self.bundle_proofs.insert(index, proof);
        Ok(())
    }

}

