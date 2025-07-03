use plonky2::gates::noop::NoopGate;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, ProverCircuitData, VerifierCircuitData};
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2_field::goldilocks_field::GoldilocksField;
use plonky2_field::types::{Field, PrimeField64};
use codex_plonky2_circuits::circuit_helper::Plonky2Circuit;
use codex_plonky2_circuits::circuits::sample_cells::SampleCircuit;
use codex_plonky2_circuits::recursion::leaf::{LeafCircuit, LeafInput, BUCKET_SIZE};
use proof_input::input_generator::InputGenerator;
use proof_input::params::Params;

// types used in all tests
type F = GoldilocksField;
const D: usize = 2;
type H = PoseidonHash;
type C = PoseidonGoldilocksConfig;

// A helper to build a minimal circuit and returns T proofs & circuit data.
fn dummy_proofs<const T: usize>() -> (CircuitData<F, C, D>, Vec<ProofWithPublicInputs<F, C, D>>) {
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    for _ in 0..(4096+10) {
        builder.add_gate(NoopGate, vec![]);
    }
    // Add one virtual public input so that the circuit has minimal structure.
    let t = builder.add_virtual_public_input();
    let circuit = builder.build::<C>();
    println!("inner circuit size = {}", circuit.common.degree_bits());
    let mut pw = PartialWitness::<F>::new();
    pw.set_target(t, F::ZERO).expect("faulty assign");
    let proofs = (0..T).map(|_i| circuit.prove(pw.clone()).unwrap()).collect();
    (circuit, proofs)
}

pub fn run_sampling_circ() -> anyhow::Result<(ProofWithPublicInputs<F, C, D>, ProverCircuitData<F, C, D>, VerifierCircuitData<F, C, D>)> {
    //------------ sampling inner circuit ----------------------
    // Circuit that does the sampling - 100 samples
    let mut params = Params::default();
    params.set_n_samples(100);
    let input_gen = InputGenerator::<F,D,H>::new(params.input_params.clone());
    let one_circ_input = input_gen.gen_testing_circuit_input();
    let samp_circ = SampleCircuit::<F,D,H>::new(params.circuit_params);
    let (inner_tar, inner_data) = samp_circ.build_with_standard_config()?;

    let inner_verifier_data = inner_data.verifier_data();
    let inner_prover_data = inner_data.prover_data();

    println!("sampling circuit degree bits = {:?}", inner_verifier_data.common.degree_bits());
    let inner_proof = samp_circ.prove(&inner_tar, &one_circ_input, &inner_prover_data)?;

    Ok((inner_proof, inner_prover_data, inner_verifier_data))
}

pub fn run_leaf_circ<const T: usize>(inner_proof: ProofWithPublicInputs<F, C, D>, inner_verifier_data: VerifierCircuitData<F, C, D>, flag: bool, index: usize) -> anyhow::Result<(ProofWithPublicInputs<F, C, D>, ProverCircuitData<F, C, D>, VerifierCircuitData<F, C, D>)> {

    // ------------------- leaf --------------------
    let leaf = LeafCircuit::<F,D, C,H,T>::new(inner_verifier_data.clone());

    // build
    let (targets, data) = leaf.build_with_standard_config()?;
    let verifier_data: VerifierCircuitData<F, C,D> = data.verifier_data();
    let prover_data = data.prover_data();
    println!("leaf circuit degree bits = {:?}", prover_data.common.degree_bits());

    // prove
    let input = LeafInput{
        inner_proof,
        flag,
        index,
    };
    let proof = leaf.prove(&targets, &input, &prover_data)?;
    println!("pub input size = {}", proof.public_inputs.len());
    println!("proof size = {:?} bytes", proof.to_bytes().len());
    println!("pub input = {:?}", proof.public_inputs);

    // verify
    assert!(
        verifier_data.verify(proof.clone()).is_ok(),
        "proof verification failed"
    );

    let flag_buckets: Vec<F> = proof.public_inputs[9..13].to_vec();
    if flag {
        check_flag_buckets(index, flag_buckets);
    } else {
        for i in 0..flag_buckets.len() {
            assert_eq!(flag_buckets[i], F::ZERO, "bucket not valid");
        }
    }

    Ok((proof, prover_data, verifier_data))
}

/// A helper to build a minimal leaf circuit (with 9+B public inputs)
/// and return the circuit data and targets
fn dummy_leaf<const B: usize>() -> (CircuitData<F, C, D>, Vec<Target>) {
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let mut pub_input = vec![];
    for _i in 0..9+B {
        pub_input.push(builder.add_virtual_public_input());
    }
    let data = builder.build::<C>();
    (data, pub_input)
}

/// A helper to generate test leaf proofs with given data, targets, and indices.
fn dummy_leaf_proofs<const B: usize>(data: CircuitData<F, C, D>, pub_input: Vec<Target>, indices: Vec<usize>) -> Vec<ProofWithPublicInputs<F, C, D>> {
    let mut proofs = vec![];
    for k in 0..indices.len() {
        let mut pw = PartialWitness::new();
        for i in 0..8 {
            pw.set_target(pub_input[i], F::ZERO).expect("assign error");
        }
        pw.set_target(pub_input[8], F::from_canonical_u64(indices[k] as u64)).expect("assign error");
        let f_buckets = fill_buckets(indices[k], BUCKET_SIZE, B);
        for i in 0..f_buckets.len() {
            pw.set_target(pub_input[9 + i], f_buckets[i]).expect("assign error");
        }
        // Run all the generators. (This method is typically called in the proving process.)
        proofs.push(data.prove(pw).expect("prove failed"));
    }
    proofs
}

/// helper: returns the flag buckets with the single bit at given `index` set to true `1`
fn fill_buckets(index: usize, bucket_size: usize, num_buckets: usize) -> Vec<F>{
    assert!(index < bucket_size * num_buckets, "Index out of range");

    let q = index / bucket_size; // bucket index
    let r = index % bucket_size; // bucket bit

    let mut buckets = vec![F::ZERO; num_buckets];
    // Set the selected bucket to 2^r.
    buckets[q] = F::from_canonical_u64(1 << r);
    buckets
}

fn check_flag_buckets(index: usize, flag_buckets: Vec<F>) {
    // Compute the bucket and bit position from the input index.
    let bucket = index / 32;
    let bit = index % 32;
    // For each flag target (bucket), assign the appropriate 32-bit one-hot value.
    for (i, &flag_bucket) in flag_buckets.iter().enumerate() {
        let value: u64 = if i == bucket {
            1 << bit
        } else {
            0
        };
        assert_eq!(value, flag_bucket.to_canonical_u64(), "bucket value mismatch");
    }
}

/// some tests for the leaf in tree recursion
#[cfg(test)]
pub mod leaf_tests {
    use super::*;
    use codex_plonky2_circuits::recursion::dummy_gen::DummyProofGen;

    #[test]
    fn test_real_leaf_circ() -> anyhow::Result<()> {
        let (inner_proof, _, inner_verifier) = run_sampling_circ()?;

        run_leaf_circ::<128>(inner_proof, inner_verifier, true, 1)?;
        Ok(())
    }

    #[test]
    fn test_dummy_leaf_circuit() -> anyhow::Result<()> {
        // gen dummy inner common
        let common_data = DummyProofGen::<F, D, C>::gen_dummy_common_data();

        // Generate a dummy inner proof for the leaf using DummyProofGen
        let (dummy_proof, dummy_vd) = DummyProofGen::<F, D, C>::gen_dummy_proof_and_vd_zero_pi(&common_data)?;
        run_leaf_circ::<128>(dummy_proof, dummy_vd, true, 45)?;

        Ok(())
    }

    #[test]
    fn test_dummy_leaf_with_sampling_circ() -> anyhow::Result<()> {
        let (_, _, inner_verifier) = run_sampling_circ()?;
        let (dummy_proof, dummy_vd) = DummyProofGen::gen_dummy_proof_and_vd_zero_pi(&inner_verifier.common)?;
        run_leaf_circ::<128>(dummy_proof, dummy_vd, false, 0)?;
        Ok(())
    }

}

// some tests for the node in tree recursion
#[cfg(test)]
mod node_tests {
    use plonky2::plonk::circuit_data::VerifierCircuitData;
    use plonky2::plonk::proof::ProofWithPublicInputs;
    use codex_plonky2_circuits::circuit_helper::Plonky2Circuit;
    use codex_plonky2_circuits::recursion::node::{NodeCircuit, NodeInput};
    use super::*;

    fn run_node_circ<const N: usize, const T: usize>(leaf_proofs: Vec<ProofWithPublicInputs<F, C, D>>, leaf_verifier_data: VerifierCircuitData<F, C, D>, _flag: bool, index: usize) -> anyhow::Result<()> {

        // ------------------- Node --------------------
        // N leaf proofs
        assert_eq!(leaf_proofs.len(), N);
        let node = NodeCircuit::<F,D,C,H, N, T>::new(leaf_verifier_data.clone());

        // build
        let (targets, data) = node.build_with_standard_config()?;
        let verifier_data: VerifierCircuitData<F,C,D> = data.verifier_data();
        let prover_data = data.prover_data();
        println!("node circuit degree bits = {:?}", prover_data.common.degree_bits());

        // prove
        let input = NodeInput{
            inner_proofs: leaf_proofs,
            verifier_only_data: leaf_verifier_data.verifier_only,
            condition: false,
            flags: [true; N].to_vec(),
            index,
        };

        let proof = node.prove(&targets, &input, &prover_data)?;
        println!("pub input size = {}", proof.public_inputs.len());
        println!("proof size = {:?} bytes", proof.to_bytes().len());
        println!("pub input = {:?}", proof.public_inputs);

        // verify
        assert!(
            verifier_data.verify(proof.clone()).is_ok(),
            "proof verification failed"
        );

        // TODO: check flags

        Ok(())
    }


    #[test]
    fn test_real_node_circ() -> anyhow::Result<()> {
        let (inner_proof, _, inner_verifier) = run_sampling_circ()?;
        // this is a bit wasteful to build leaf twice, TODO: fix this
        let (leaf_proof_1, _, _leaf_verifier_1) = run_leaf_circ::<128>(inner_proof.clone(), inner_verifier.clone(), true, 0)?;
        let (leaf_proof_2, _, leaf_verifier_2) = run_leaf_circ::<128>(inner_proof, inner_verifier, true, 1)?;
        let leaf_proofs = vec![leaf_proof_1,leaf_proof_2];
        run_node_circ::<2,128>(leaf_proofs, leaf_verifier_2, true, 0)
    }

    #[test]
    fn test_dummy_node_circuit() -> anyhow::Result<()> {
        const N: usize = 2;
        const B: usize = 4; // bucket size
        const T: usize = 128;

        let (leaf_data, leaf_pi) = dummy_leaf::<B>();
        let leaf_vd = leaf_data.verifier_data();

        let indices = vec![0,1];
        let leaf_proofs = dummy_leaf_proofs::<B>(leaf_data,leaf_pi,indices);

        let node = NodeCircuit::<F, D, C, H, N, T>::new(leaf_vd.clone());

        // Build the node circuit.
        let (targets, circuit_data) = node.build_with_standard_config()?;
        let verifier_data = circuit_data.verifier_data();
        let prover_data = circuit_data.prover_data();

        // node input
        let input = NodeInput {
            inner_proofs: leaf_proofs,
            verifier_only_data: leaf_vd.verifier_only.clone(),
            condition: false,
            flags: vec![true, true],
            index: 0,
        };

        let proof = node.prove(&targets, &input, &prover_data)?;

        // Verify the proof.
        assert!(verifier_data.verify(proof.clone()).is_ok(), "Proof verification failed");

        println!("Public inputs: {:?}", proof.public_inputs);

        // the flag buckets appeared at positions 8..12.
        let flag_buckets: Vec<u64> = proof.public_inputs[9..(9+B)]
            .iter()
            .map(|f| f.to_canonical_u64())
            .collect();

        // With index = 45, we expect bucket 1 = 2^13 = 8192, and the rest 0.
        let expected = vec![3, 0, 0, 0];
        assert_eq!(flag_buckets, expected, "Flag bucket values mismatch");

        Ok(())
    }

}

// some tests for the tree recursion

#[cfg(test)]
mod tree_tests {
    use plonky2::plonk::proof::{ProofWithPublicInputs};
    use codex_plonky2_circuits::recursion::{tree::TreeRecursion};
    use super::*;

    fn run_tree_recursion<const N: usize, const T: usize>(compress: bool) -> anyhow::Result<()> {

        //------------ sampling inner circuit ----------------------
        // Circuit that does the sampling - 100 samples
        let (inner_proof, _inner_prover_data, inner_verifier_data) = run_sampling_circ()?;

        let proofs: Vec<ProofWithPublicInputs<F, C, D>> = (0..T).map(|_i| inner_proof.clone()).collect();

        // ------------------- tree --------------------
        // N-to-1 tree aggregation

        let mut tree = TreeRecursion::<F,D,C,H, N, T>::build_with_standard_config(inner_verifier_data.clone())?;

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

        let inner_pi: Vec<Vec<F>> = proofs.iter().map(|p| p.public_inputs.clone()).collect();

        assert!(
            tree.verify_proof_and_public_input(root,inner_pi.clone(), compress).is_ok(),
            "proof verification failed"
        );

        Ok(())
    }

    #[test]
    fn test_tree_recursion() -> anyhow::Result<()> {
        // total number of proofs to aggregate
        const T:usize = 4;
        run_tree_recursion::<2, T>(false)
    }

    #[test]
    fn test_tree_recursion_with_compression() -> anyhow::Result<()> {
        // total number of proofs to aggregate
        const T:usize = 4;
        run_tree_recursion::<2, T>(true)
    }

    #[test]
    fn test_dummy_tree_circuit() -> anyhow::Result<()> {
        const N: usize = 2;
        const T: usize = 128;

        let (data, proofs) = dummy_proofs::<T>();

        let mut tree = TreeRecursion::<F,D,C,H, N, T>::build_with_standard_config(data.verifier_data())?;

        // aggregate - no compression
        let root = tree.prove_tree(&proofs)?;
        println!("pub input size = {}", root.public_inputs.len());
        println!("proof size = {:?} bytes", root.to_bytes().len());

        assert!(
            tree.verify_proof(root, false).is_ok(),
            "proof verification failed"
        );

        Ok(())
    }

}


#[cfg(test)]
mod bn254wrap_tests {
    use plonky2::field::types::Field;
    use plonky2::gates::noop::NoopGate;
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::{CircuitConfig, VerifierCircuitData};
    use plonky2::plonk::proof::ProofWithPublicInputs;
    use codex_plonky2_circuits::bn254_wrapper::config::PoseidonBN254GoldilocksConfig;
    use codex_plonky2_circuits::bn254_wrapper::wrap::{WrapCircuit, WrapInput, WrappedOutput};
    use codex_plonky2_circuits::circuit_helper::Plonky2Circuit;
    use codex_plonky2_circuits::recursion::tree::TreeRecursion;
    use super::*;

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

    #[test]
    fn test_full_wrap() -> anyhow::Result<()>{
        const D: usize = 2;

        type F = GoldilocksField;
        type InnerParameters = PoseidonGoldilocksConfig;
        type OuterParameters = PoseidonBN254GoldilocksConfig;

        let build_path = "./verifier_data".to_string();
        let test_path = format!("{}/test_small/", build_path);

        let conf = CircuitConfig::standard_recursion_config();
        let mut builder =  CircuitBuilder::<F, D>::new(conf);

        for _ in 0..(4096+10) {
            builder.add_gate(NoopGate, vec![]);
        }
        // Add one virtual public input so that the circuit has minimal structure.
        let t = builder.add_virtual_public_input();

        // Set up the dummy circuit and wrapper.
        let dummy_circuit = builder.build::<InnerParameters>();
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
        let wrapper = WrapCircuit::<F,D,InnerParameters,OuterParameters>::new(dummy_circuit.verifier_data());
        let (targ, data) = wrapper.build_with_standard_config().unwrap();
        println!(
            "wrapper circuit degree: {}",
            data.common.degree_bits()
        );
        let verifier_data = data.verifier_data();
        let prover_data = data.prover_data();
        let wrap_input = WrapInput{
            inner_proof: dummy_inner_proof,
        };
        let proof = wrapper.prove(&targ, &wrap_input,&prover_data).unwrap();

        let wrap_circ = WrappedOutput::<F, OuterParameters,D>{
            proof,
            common_data: prover_data.common,
            verifier_data: verifier_data.verifier_only,
        };

        wrap_circ.save(test_path).unwrap();
        println!("Saved test wrapped circuit");
        Ok(())
    }

    fn run_tree_recursion<const N: usize, const T: usize>(compress: bool) -> anyhow::Result<()> {

        //------------ sampling inner circuit ----------------------
        // Circuit that does the sampling - 100 samples
        let (inner_proof, _inner_prover_data, inner_verifier_data) = run_sampling_circ()?;

        let proofs: Vec<ProofWithPublicInputs<F, C, D>> = (0..T).map(|_i| inner_proof.clone()).collect();

        // ------------------- tree --------------------
        // N-to-1 tree aggregation

        let mut tree = TreeRecursion::<F, D,C,H, N, T>::build_with_standard_config(inner_verifier_data.clone())?;

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

#[cfg(test)]
mod proof_tracking_tests {
    use super::*;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2_field::types::{Field, PrimeField64};
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::iop::witness::PartialWitness;
    use codex_plonky2_circuits::recursion::utils::{split_index, compute_flag_buckets, compute_power_of_two};

    // Helper: Build, prove, and return public inputs ---
    fn build_and_prove(builder: CircuitBuilder<F, D>) -> Vec<F> {
        // Build the circuit.
        let circuit = builder.build::<C>();
        let pw = PartialWitness::new();
        // prove
        let p= circuit.prove(pw).expect("prove failed");

        p.public_inputs
    }

    #[test]
    fn test_split_index() -> anyhow::Result<()> {
        // Create a circuit where we register the outputs q and r of split_index.
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        // Let index = 45.
        let index_val: u64 = 45;
        let index_target = builder.constant(F::from_canonical_u64(index_val));
        // Call split_index with bucket_size=32 and num_buckets=4. We expect q = 1 and r = 13.
        let (q_target, r_target) =
            split_index::<F,D>(&mut builder, index_target, BUCKET_SIZE, 4)?;
        // Register outputs as public inputs.
        builder.register_public_input(q_target);
        builder.register_public_input(r_target);
        // Build and prove the circuit.
        let pub_inputs = build_and_prove(builder);
        // We expect the first public input to be q = 1 and the second r = 13.
        assert_eq!(pub_inputs[0].to_canonical_u64(), 1, "q should be 1");
        assert_eq!(pub_inputs[1].to_canonical_u64(), 13, "r should be 13");
        Ok(())
    }

    #[test]
    fn test_compute_power_of_two() -> anyhow::Result<()> {
        // Create a circuit to compute 2^r.
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        // Let r = 13.
        let r_val: u64 = 13;
        let r_target = builder.constant(F::from_canonical_u64(r_val));
        let pow_target =
            compute_power_of_two::<F,D>(&mut builder, r_target)?;
        builder.register_public_input(pow_target);
        let pub_inputs = build_and_prove(builder);
        // Expect 2^13 = 8192.
        assert_eq!(
            pub_inputs[0].to_canonical_u64(),
            1 << 13,
            "2^13 should be 8192"
        );
        Ok(())
    }

    #[test]
    fn test_compute_flag_buckets() -> anyhow::Result<()> {
        // Create a circuit to compute flag buckets.
        // Let index = 45 and flag = true.
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let index_val: u64 = 45;
        let index_target = builder.constant(F::from_canonical_u64(index_val));
        // Create a boolean constant target for flag = true.
        let flag_target = builder.constant_bool(true);
        // Compute the flag buckets with bucket_size = 32 and num_buckets = 4.
        let buckets = compute_flag_buckets::<F,D>(
            &mut builder,
            index_target,
            flag_target,
            BUCKET_SIZE,
            4,
        )?;
        // Register each bucket as a public input.
        for bucket in buckets.iter() {
            builder.register_public_input(*bucket);
        }
        let pub_inputs = build_and_prove(builder);
        // With index = 45, we expect:
        //   q = 45 / 32 = 1 and r = 45 % 32 = 13, so bucket 1 should be 2^13 = 8192 and the others 0.
        let expected = vec![0, 8192, 0, 0];
        for (i, &expected_val) in expected.iter().enumerate() {
            let computed = pub_inputs[i].to_canonical_u64();
            assert_eq!(
                computed, expected_val,
                "Bucket {}: expected {} but got {}",
                i, expected_val, computed
            );
        }
        Ok(())
    }
}
