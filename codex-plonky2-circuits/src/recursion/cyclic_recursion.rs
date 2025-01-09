// Cyclic approach to recursion where at each cycle you verify previous proof
// and run the inner circuit -> resulting in one proof that again can be fed
// into another cyclic circle.

use hashbrown::HashMap;
use plonky2::hash::hash_types::{HashOut, HashOutTarget, RichField};
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitData, VerifierCircuitTarget};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2::plonk::proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget};
use plonky2::recursion::dummy_circuit::cyclic_base_proof;
use plonky2_field::extension::Extendable;
use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2;
use crate::recursion::params::{F,D,C,Plonky2Proof,H};
use crate::recursion::inner_circuit::InnerCircuit;
use anyhow::Result;
use plonky2::gates::noop::NoopGate;
use plonky2::recursion::cyclic_recursion::check_cyclic_proof_verifier_data;
use crate::circuits::utils::select_hash;

/// cyclic circuit struct
/// contains necessary data
/// note: only keeps track of latest proof not all proofs.
pub struct CyclicCircuit<
    I: InnerCircuit,
>{
    pub layer: usize,
    pub circ: I,
    pub cyclic_target: Option<CyclicCircuitTargets<I>>,
    pub cyclic_circuit_data: Option<CircuitData<F, C, D>>,
    pub common_data: Option<CommonCircuitData<F, D>>,
    pub latest_proof: Option<ProofWithPublicInputs<F, C, D>>,
}

/// targets need to be assigned for the cyclic circuit
#[derive(Clone)]
pub struct CyclicCircuitTargets<
    I: InnerCircuit,
>{
    pub inner_targets: I::Targets,
    pub condition: BoolTarget,
    pub inner_cyclic_proof_with_pis: ProofWithPublicInputsTarget<D>,
    pub verifier_data: VerifierCircuitTarget,
}

impl<
    I: InnerCircuit,
> CyclicCircuit<I> {

    /// create a new cyclic circuit
    pub fn new(circ: I) -> Self{
        Self{
            layer: 0,
            circ,
            cyclic_target: None,
            cyclic_circuit_data: None,
            common_data: None,
            latest_proof: None,
        }
    }

    /// builds the cyclic recursion circuit using any inner circuit I
    /// returns the circuit data
    pub fn build_circuit(
        &mut self,
    ) -> Result<()>{
        // if the circuit data is already build then no need to rebuild
        if self.cyclic_circuit_data.is_some(){
            return Ok(());
        }

        // builder with standard recursion config
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        //build the inner circuit
        let inner_t = self.circ.build(& mut builder)?;

        // common data for recursion
        let mut common_data = common_data_for_recursion();
        // the hash of the public input
        let pub_input_hash = builder.add_virtual_hash_public_input();
        // verifier data for inner proofs
        let verifier_data_target = builder.add_verifier_data_public_inputs();
        // common data should have same num of public input as inner proofs
        common_data.num_public_inputs = builder.num_public_inputs();

        // condition
        let condition = builder.add_virtual_bool_target_safe();

        // inner proof with public input
        let inner_cyclic_proof_with_pis = builder.add_virtual_proof_with_pis(&common_data);
        // get the hash of the pub input
        let inner_cyclic_pis = &inner_cyclic_proof_with_pis.public_inputs;
        let inner_pub_input_hash = HashOutTarget::try_from(&inner_cyclic_pis[0..4]).unwrap();
        // now hash the current public input
        let outer_pis = I::get_pub_input_targets(&inner_t)?;
        let outer_pi_hash = builder.hash_n_to_hash_no_pad::<H>(outer_pis);
        let zero_hash = HashOutTarget::from_vec([builder.zero(); 4].to_vec());
        // if leaf pad with zeros
        let inner_pi_hash_or_zero_hash = select_hash(&mut builder, condition, inner_pub_input_hash, zero_hash);
        // hash current public input with previous hash
        let mut hash_input = vec![];
        hash_input.extend_from_slice(&outer_pi_hash.elements);
        hash_input.extend_from_slice(&inner_pi_hash_or_zero_hash.elements);
        let outer_pi_hash = builder.hash_n_to_hash_no_pad::<H>(hash_input);
        // connect this up one to `pub_input_hash`
        builder.connect_hashes(pub_input_hash,outer_pi_hash);

        // connect entropy?

        // verify proof in-circuit
        builder.conditionally_verify_cyclic_proof_or_dummy::<C>(
            condition,
            &inner_cyclic_proof_with_pis,
            &common_data,
        )?;

        // build the cyclic circuit
        let cyclic_circuit_data = builder.build::<C>();

        // assign targets
        let cyc_t = CyclicCircuitTargets::<I>{
            inner_targets: inner_t,
            condition,
            inner_cyclic_proof_with_pis,
            verifier_data: verifier_data_target
        };
        // assign the data
        self.cyclic_circuit_data = Some(cyclic_circuit_data);
        self.common_data = Some(common_data);
        self.cyclic_target = Some(cyc_t);
        Ok(())
    }

    /// generates a proof with only one recursion layer
    /// takes circuit input
    pub fn prove_one_layer(
        &mut self,
        circ_input: &I::Input,
    ) -> Result<ProofWithPublicInputs<F, C, D>>{

        if self.cyclic_circuit_data.is_none(){
            panic!("circuit data not found") // TODO: replace with err
        }

        let circ_data = self.cyclic_circuit_data.as_ref().unwrap();
        let cyc_targets = self.cyclic_target.as_ref().unwrap();
        let common_data = self.common_data.as_ref().unwrap();

        // assign targets
        let mut pw = PartialWitness::new();
        self.circ.assign_targets(&mut pw,&cyc_targets.inner_targets,&circ_input)?;

        // if leaf add dummy proof
        if(self.layer == 0) {
            pw.set_bool_target(cyc_targets.condition, false)?;
            pw.set_proof_with_pis_target::<C, D>(
                &cyc_targets.inner_cyclic_proof_with_pis,
                &cyclic_base_proof(
                    common_data,
                    &circ_data.verifier_only,
                    HashMap::new(),
                ),
            )?;
        }else{ // else add last proof
            pw.set_bool_target(cyc_targets.condition, true)?;
            let last_proof = self.latest_proof.as_ref().unwrap();
            pw.set_proof_with_pis_target(&cyc_targets.inner_cyclic_proof_with_pis, last_proof)?;
        }

        // assign verifier data
        pw.set_verifier_data_target(&cyc_targets.verifier_data, &circ_data.verifier_only)?;
        // prove
        let proof = circ_data.prove(pw)?;
        // check that the correct verifier data is consistent
        check_cyclic_proof_verifier_data(
            &proof,
            &circ_data.verifier_only,
            &circ_data.common,
        )?;

        self.latest_proof = Some(proof.clone());
        self.layer = self.layer + 1;
        Ok(proof)
    }

    /// prove n recursive layers
    /// the function takes
    /// - n: the number of layers and
    /// - circ_input:  vector of n inputs
    pub fn prove_n_layers(
        &mut self,
        n: usize,
        circ_input: Vec<I::Input>,
    ) -> Result<ProofWithPublicInputs<F, C, D>>{

        // asserts that n equals the number of input
        assert_eq!(n, circ_input.len());

        for i in 0..n {
            self.prove_one_layer(&circ_input[i])?;
        }

        Ok(self.latest_proof.clone().unwrap())
    }

    /// verifies the latest proof generated
    pub fn verify_latest_proof(
        &mut self,
    ) -> Result<()>{
        if(self.cyclic_circuit_data.is_none() || self.latest_proof.is_none()){
            panic!("no circuit data or proof found");
        }
        let circ_data = self.cyclic_circuit_data.as_ref().unwrap();
        let proof = self.latest_proof.clone().unwrap();

        circ_data.verify(proof)?;

        Ok(())
    }
}

/// Generates `CommonCircuitData` usable for recursion.
pub fn common_data_for_recursion() -> CommonCircuitData<F, D>
{
    // layer 1
    let config = CircuitConfig::standard_recursion_config();
    let builder = CircuitBuilder::<F, D>::new(config);
    let data = builder.build::<C>();
    // layer 2
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let proof = builder.add_virtual_proof_with_pis(&data.common);
    let verifier_data =
        builder.add_virtual_verifier_data(data.common.config.fri_config.cap_height);
    builder.verify_proof::<C>(&proof, &verifier_data, &data.common);
    let data = builder.build::<C>();
    // layer 3
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let proof = builder.add_virtual_proof_with_pis(&data.common);
    let verifier_data =
        builder.add_virtual_verifier_data(data.common.config.fri_config.cap_height);
    builder.verify_proof::<C>(&proof, &verifier_data, &data.common);
    // pad with noop gates
    while builder.num_gates() < 1 << 12 {
        builder.add_gate(NoopGate, vec![]);
    }
    builder.build::<C>().common
}