// some tests for approach 2 of the tree recursion

#[cfg(test)]
mod tests {
    use std::fs;
    use plonky2::iop::witness::{PartialWitness};
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::{CircuitConfig};
    use plonky2::plonk::config::{ GenericConfig};
    use plonky2::plonk::proof::{ProofWithPublicInputs};
    use codex_plonky2_circuits::circuits::sample_cells::SampleCircuit;
    use crate::params::{F, D, C, HF};
    use crate::gen_input::gen_testing_circuit_input;
    use crate::params::Params;
    use codex_plonky2_circuits::recursion::uniform::{tree::TreeRecursion};

    #[test]
    fn test_uniform_recursion() -> anyhow::Result<()> {

        let config = CircuitConfig::standard_recursion_config();
        let mut sampling_builder = CircuitBuilder::<F, D>::new(config);

        //------------ sampling inner circuit ----------------------
        // Circuit that does the sampling - 100 samples
        let mut params = Params::default();
        params.input_params.n_samples = 100;
        params.circuit_params.n_samples = 100;
        let one_circ_input = gen_testing_circuit_input::<F,D>(&params.input_params);
        let samp_circ = SampleCircuit::<F,D,HF>::new(params.circuit_params);
        let inner_tar = samp_circ.sample_slot_circuit_with_public_input(&mut sampling_builder)?;
        // get generate a sampling proof
        let mut pw = PartialWitness::<F>::new();
        samp_circ.sample_slot_assign_witness(&mut pw,&inner_tar,&one_circ_input)?;
        let inner_data = sampling_builder.build::<C>();
        println!("sampling circuit degree bits = {:?}", inner_data.common.degree_bits());
        let inner_proof = inner_data.prove(pw)?;

        let proofs: Vec<ProofWithPublicInputs<F, C, D>> = (0..16).map(|i| inner_proof.clone()).collect();

        // ------------------- tree --------------------
        const N: usize = 1;
        const M: usize = 4;

        let mut tree = TreeRecursion::<F,D,C,HF, N, M>::build(inner_data.common.clone())?;

        // serialize circuit into JSON
        let common_circuit_data_serialized        = serde_json::to_string(&tree.get_leaf_verifier_data().common       ).unwrap();
        fs::write("leaf_common.json" , common_circuit_data_serialized)       .expect("Unable to write file");

        // serialize circuit into JSON
        let common_circuit_data_serialized        = serde_json::to_string(&tree.get_node_verifier_data().common       ).unwrap();
        fs::write("node_common.json" , common_circuit_data_serialized)       .expect("Unable to write file");


        let root = tree.prove_tree(&proofs, &inner_data.verifier_only)?;
        println!("pub input size = {}", root.public_inputs.len());

        let inner_pi: Vec<Vec<F>> = proofs.iter().map(|p| p.public_inputs.clone()).collect();

        assert!(
            tree.verify_proof_and_public_input(root,inner_pi,&inner_data.verifier_data()).is_ok(),
            "proof verification failed"
        );

        Ok(())
    }
}