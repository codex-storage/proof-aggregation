use plonky2::hash::hash_types::{HashOutTarget, RichField};
use plonky2_field::extension::Extendable;
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitTarget};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::recursion::dummy_circuit::cyclic_base_proof;
use hashbrown::HashMap;
use plonky2::gates::noop::NoopGate;
use plonky2::iop::target::BoolTarget;
use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2;
use crate::circuits::utils::{select_hash, vec_to_array};
use crate::{error::CircuitError, Result};
use crate::recursion::circuits::inner_circuit::InnerCircuit;

/// Node circuit struct
/// contains necessary data
/// M: number of inner-circuits to run
/// N: number of proofs verified in-circuit (so num of child nodes)
pub struct NodeCircuit<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    I: InnerCircuit<F, D>,
    const M: usize,
    const N: usize,
    C: GenericConfig<D, F = F>,
>{
    pub circ: I,
    pub cyclic_target: NodeCircuitTargets<F, D, I,M,N>,
    pub cyclic_circuit_data: CircuitData<F, C, D>,
    pub common_data: CommonCircuitData<F, D>,
}

/// Node circuit targets
/// assumes that all inner proofs use the same verifier data
#[derive(Clone, Debug)]
pub struct NodeCircuitTargets<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    I: InnerCircuit<F, D>,
    const M: usize,
    const N: usize,
>{
    pub inner_targets: [I::Targets; M],
    pub condition: BoolTarget,
    pub inner_proofs_with_pis: [ProofWithPublicInputsTarget<D>; N],
    pub verifier_data: VerifierCircuitTarget,
}

impl<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    I: InnerCircuit<F, D>,
    const M: usize,
    const N: usize,
    C: GenericConfig<D, F = F> + 'static,
> NodeCircuit<F, D, I, M, N, C> where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>
{

    /// builds the cyclic recursion circuit using any inner circuit I
    /// return the Node circuit
    /// TODO: make generic recursion config
    pub fn build_circuit<
        H: AlgebraicHasher<F>,
    >(
        inner_circ: I,
    ) -> Result<(Self)>{

        // builder with standard recursion config
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        //build M inner circuits
        let inner_t: [I::Targets; M] =
            vec_to_array::<M, I::Targets>(
                (0..M)
                .map(|_| inner_circ.build(&mut builder, false))
                .collect::<Result<Vec<_>>>()?
            )?;

        // common data for recursion
        let mut common_data = Self::common_data_for_node()?;

        let pub_input_hash = builder.add_virtual_hash_public_input();
        let verifier_data_target = builder.add_verifier_data_public_inputs();
        common_data.num_public_inputs = builder.num_public_inputs();

        // condition
        let condition = builder.add_virtual_bool_target_safe();

        // inner proofs targets - N proof targets
        let inner_cyclic_proof_with_pis: [ProofWithPublicInputsTarget<D>; N] =
            vec_to_array::<N,ProofWithPublicInputsTarget<D>>(
                (0..N)
                .map(|_| builder.add_virtual_proof_with_pis(&common_data))
                .collect::<Vec<_>>()
            )?;

        // get the public input hash from all inner proof targets
        let mut inner_pub_input_hashes = vec![];
        for i in 0..N {
            let inner_cyclic_pis = &inner_cyclic_proof_with_pis[i].public_inputs;
            inner_pub_input_hashes.extend_from_slice(&inner_cyclic_pis[0..4]);
        }
        // hash all the inner public input h = H(h_1 | h_2 | ... | h_N)
        let inner_pub_input_hash = builder.hash_n_to_hash_no_pad::<H>(inner_pub_input_hashes);

        // get the public input of the inner circuit
        let mut outer_pis = vec![];
        for i in 0..M {
            outer_pis.push( I::get_pub_input_targets(&inner_t[i]));
        }
        // hash all the public input -> generate one HashOut at the end
        // this is not an optimal way to do it, verification might be ugly if M > 1
        // TODO: optimize this
        let mut outer_pi_hashes = vec![];
        for i in 0..M {
            let hash_res = builder.hash_n_to_hash_no_pad::<H>(outer_pis[i].clone());
            outer_pi_hashes.extend_from_slice(&hash_res.elements)
        }
        // the final public input hash
        let outer_pi_hash = builder.hash_n_to_hash_no_pad::<H>(outer_pi_hashes);
        // zero hash for leaves
        let zero_hash = HashOutTarget::from_vec([builder.zero(); 4].to_vec());
        // if the inner proofs are dummy then use zero hash for public input
        let inner_pi_hash_or_zero_hash = select_hash(&mut builder, condition, inner_pub_input_hash, zero_hash);

        // now hash the public input of the inner proofs and outer proof, so we have one public hash
        let mut hash_input = vec![];
        hash_input.extend_from_slice(&outer_pi_hash.elements);
        hash_input.extend_from_slice(&inner_pi_hash_or_zero_hash.elements);
        let outer_pi_hash = builder.hash_n_to_hash_no_pad::<H>(hash_input);
        // connect this up one to `pub_input_hash`
        builder.connect_hashes(pub_input_hash,outer_pi_hash);

        // verify all N proofs in-circuit
        for i in 0..N {
            builder.conditionally_verify_cyclic_proof_or_dummy::<C>(
                condition,
                &inner_cyclic_proof_with_pis[i],
                &common_data,
            ).map_err(|e| CircuitError::ConditionalVerificationError(e.to_string()))?;
        }

        // build the cyclic circuit
        let cyclic_circuit_data = builder.build::<C>();

        // assign targets
        let cyc_t = NodeCircuitTargets::<F, D, I, M, N>{
            inner_targets: inner_t,
            condition,
            inner_proofs_with_pis: inner_cyclic_proof_with_pis,
            verifier_data: verifier_data_target
        };

        // assign the data
        Ok(Self{
            circ: inner_circ,
            cyclic_target: cyc_t,
            cyclic_circuit_data,
            common_data,
        })
    }

    /// assigns the targets for the Node circuit
    /// takes circuit input
    pub fn assign_targets(
        &mut self,
        circ_input: &[I::Input; M],
        proof_options: Option<[ProofWithPublicInputs<F, C, D>; N]>,
        pw: &mut PartialWitness<F>,
        is_leaf: bool,
    ) -> Result<()>{

        let circ_data = &self.cyclic_circuit_data;
        let cyc_targets = &self.cyclic_target;
        let common_data = &self.common_data;

        for i in 0..M {
            self.circ.assign_targets(pw, &cyc_targets.inner_targets[i], &circ_input[i])?;
        }

        if is_leaf == true {
            pw.set_bool_target(cyc_targets.condition, false)
                .map_err(|e| CircuitError::BoolTargetAssignmentError("condition".to_string(),e.to_string()))?;
            for i in 0..N {
                pw.set_proof_with_pis_target::<C, D>(
                    &cyc_targets.inner_proofs_with_pis[i],
                    &cyclic_base_proof(
                        common_data,
                        &circ_data.verifier_only,
                        HashMap::new(),
                    ),
                ).map_err(|e| CircuitError::ProofTargetAssignmentError("inner proofs".to_string(),e.to_string()))?;
            }
        }else{
            pw.set_bool_target(cyc_targets.condition, true)
                .map_err(|e| CircuitError::BoolTargetAssignmentError("condition".to_string(),e.to_string()))?;

            let proofs = proof_options.ok_or(CircuitError::OptionError("inner proof not given".to_string()))?;
            for i in 0..N {
                pw.set_proof_with_pis_target(&cyc_targets.inner_proofs_with_pis[i], &proofs[i])
                    .map_err(|e| CircuitError::ProofTargetAssignmentError("inner proofs".to_string(),e.to_string()))?;
            }
        }

        pw.set_verifier_data_target(&cyc_targets.verifier_data, &circ_data.verifier_only)
            .map_err(|e| CircuitError::VerifierDataTargetAssignmentError(e.to_string()))?;

        Ok(())
    }

    /// Generates `CommonCircuitData` usable for node recursion.
    /// the circuit being built here depends on M and N so must be re-generated
    /// if the params change
    pub fn common_data_for_node() -> Result<CommonCircuitData<F, D>>
    {
        // layer 1
        let config = CircuitConfig::standard_recursion_config();
        let builder = CircuitBuilder::<F, D>::new(config);
        let data = builder.build::<C>();

        // layer 2
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config.clone());
        let verifier_data = builder.add_virtual_verifier_data(data.common.config.fri_config.cap_height);
        // generate and verify N number of proofs
        for _ in 0..N {
            let proof = builder.add_virtual_proof_with_pis(&data.common);
            builder.verify_proof::<C>(&proof, &verifier_data, &data.common);
        }
        let data = builder.build::<C>();

        // layer 3
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config.clone());

        // add a ConstantGate
        builder.add_gate(
            plonky2::gates::constant::ConstantGate::new(config.num_constants),
            vec![],
        );

        // generate and verify N number of proofs
        let verifier_data = builder.add_verifier_data_public_inputs();
        for _ in 0..N {
            let proof = builder.add_virtual_proof_with_pis(&data.common);
            builder.verify_proof::<C>(&proof, &verifier_data, &data.common);
        }
        // pad. TODO: optimize this padding to only needed number of gates
        while builder.num_gates() < 1 << 13 {
            builder.add_gate(NoopGate, vec![]);
        }
        Ok(builder.build::<C>().common)
    }

}
