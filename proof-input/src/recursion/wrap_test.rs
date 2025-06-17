
#[cfg(test)]
mod tests {
    use plonky2::field::types::Field;
    use plonky2::gates::noop::NoopGate;
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::{CircuitConfig, VerifierCircuitData};
    use plonky2::plonk::proof::ProofWithPublicInputs;
    use codex_plonky2_circuits::bn254_wrapper::config::PoseidonBN254GoldilocksConfig;
    use codex_plonky2_circuits::bn254_wrapper::wrap::{WrapCircuit, WrapInput};
    use codex_plonky2_circuits::circuit_helper::Plonky2Circuit;
    use codex_plonky2_circuits::recursion::tree::TreeRecursion;
    use crate::params::{D, C, F, HF};
    use crate::recursion::run_sampling_circ;

    type OuterParameters = PoseidonBN254GoldilocksConfig;

    fn bn254_wrap(proof: ProofWithPublicInputs<F, C, D>, vd: VerifierCircuitData<F, C, D>) -> anyhow::Result<()>{
        // wrap this in the outer circuit.
        let wrapper = WrapCircuit::<F,D,C,OuterParameters>::new(vd);
        let (targ, data) = wrapper.build_with_standard_config().unwrap();
        println!(
            "wrapper circuit degree: {}",
            data.common.degree_bits()
        );
        let verifier_data = data.verifier_data();
        let prover_data = data.prover_data();
        let wrap_input = WrapInput{
            inner_proof: proof,
        };
        let proof = wrapper.prove(&targ, &wrap_input,&prover_data).unwrap();

        assert!(verifier_data.verify(proof).is_ok());

        Ok(())
    }

    #[test]
    fn test_dummy_wrap() -> anyhow::Result<()>{

        let conf = CircuitConfig::standard_recursion_config();
        let mut builder =  CircuitBuilder::<F, D>::new(conf);

        for _ in 0..(4096+10) {
            builder.add_gate(NoopGate, vec![]);
        }
        // Add one virtual public input so that the circuit has minimal structure.
        let t = builder.add_virtual_public_input();

        // Set up the dummy circuit and wrapper.
        let dummy_circuit = builder.build::<C>();
        let mut pw = PartialWitness::new();
        pw.set_target(t, F::ZERO).expect("faulty assign");
        println!(
            "dummy circuit degree: {}",
            dummy_circuit.common.degree_bits()
        );
        let dummy_inner_proof = dummy_circuit.prove(pw).unwrap();
        assert!(dummy_circuit.verify(dummy_inner_proof.clone()).is_ok());
        println!("Verified dummy_circuit");

        // wrap this in the outer circuit.
        bn254_wrap(dummy_inner_proof, dummy_circuit.verifier_data())?;
        Ok(())
    }

    fn run_tree_recursion<const N: usize, const T: usize>(compress: bool) -> anyhow::Result<()> {

        //------------ sampling inner circuit ----------------------
        // Circuit that does the sampling - 100 samples
        let (inner_proof, inner_prover_data, inner_verifier_data) = run_sampling_circ()?;

        let proofs: Vec<ProofWithPublicInputs<F, C, D>> = (0..T).map(|_i| inner_proof.clone()).collect();

        // ------------------- tree --------------------
        // N-to-1 tree aggregation

        let mut tree = TreeRecursion::<F, D,C,HF, N, T>::build_with_standard_config(inner_verifier_data.clone())?;

        // aggregate
        let root = if !compress {
            tree.prove_tree(&proofs)?
        } else {
            println!("Mode: tree with compression");
            tree.prove_tree_and_compress(&proofs)?
        };
        println!("pub input size = {}", root.public_inputs.len());
        println!("pub input = {:?}", root.public_inputs);
        println!("proof size = {:?} bytes", root.to_bytes().len());

        // sanity check
        let vd = if !compress {
            tree.get_node_verifier_data()}
            else{
                tree.get_compression_verifier_data()};
        assert!(vd.verify(root.clone()).is_ok());

        bn254_wrap(root, vd)?;

        Ok(())
    }

    #[test]
    fn test_wrap_tree_recursion() -> anyhow::Result<()> {
        // total number of proofs to aggregate
        const T:usize = 4;
        run_tree_recursion::<2, T>(false)
    }

    #[test]
    fn test_wrap_tree_recursion_with_compression() -> anyhow::Result<()> {
        // total number of proofs to aggregate
        const T:usize = 4;
        run_tree_recursion::<2, T>(true)
    }
}
