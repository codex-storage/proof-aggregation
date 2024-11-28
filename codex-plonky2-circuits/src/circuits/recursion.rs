use plonky2::hash::hash_types::RichField;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{VerifierCircuitData, VerifierCircuitTarget};
use plonky2::plonk::config::GenericConfig;
use plonky2::plonk::proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget};
use plonky2_field::extension::Extendable;
use plonky2_field::goldilocks_field::GoldilocksField;
use plonky2_poseidon2::config::Poseidon2GoldilocksConfig;
use plonky2_poseidon2::poseidon2_hash::poseidon2::Poseidon2;

// recursion param

pub type F = GoldilocksField;
pub const D: usize = 2;
pub type C = Poseidon2GoldilocksConfig;
pub type Plonky2Proof = ProofWithPublicInputs<F, C, D>;

/// aggregate sampling proofs
pub fn aggregate_sampling_proofs<
>(
    proofs_with_pi: Vec<Plonky2Proof>,
    verifier_data: &VerifierCircuitData<F, C, D>,
    builder: &mut CircuitBuilder::<F, D>,
    pw: &mut PartialWitness<F>,
){
    // assert the number of proofs equals D
    assert_eq!(proofs_with_pi.len(), D, "Number of proofs to aggregate is not supported");

    // the proof virtual targets
    let mut proof_targets = vec![];
    for i in 0..D {
        let vir_proof = builder.add_virtual_proof_with_pis(&verifier_data.common);
        proof_targets.push(vir_proof);
    }
    // assign the proofs with public input
    for i in 0..D{
        pw.set_proof_with_pis_target(&proof_targets[i],&proofs_with_pi[i]);
    }

    let vd_target = VerifierCircuitTarget {
        constants_sigmas_cap: builder
            .add_virtual_cap(verifier_data.common.config.fri_config.cap_height),
        circuit_digest: builder.add_virtual_hash(),
    };
    pw.set_cap_target(
        &vd_target.constants_sigmas_cap,
        &verifier_data.verifier_only.constants_sigmas_cap,
    );
    pw.set_hash_target(
        vd_target.circuit_digest,
        verifier_data.verifier_only.circuit_digest,
    );

    // verify the proofs in-circuit
    for i in 0..D {
        builder.verify_proof::<C>(&proof_targets[i],&vd_target,&verifier_data.common);
    }

}