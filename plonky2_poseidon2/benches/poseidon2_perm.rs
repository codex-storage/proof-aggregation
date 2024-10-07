use std::fs;
use anyhow::Result;
use std::time::Instant;
use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use plonky2::field::extension::Extendable;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::hash::hash_types::RichField;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig, Hasher, PoseidonGoldilocksConfig};
use plonky2_poseidon2::config::Poseidon2GoldilocksConfig;
use tynm::type_name;
use plonky2::hash::hashing::PlonkyPermutation;
use plonky2_poseidon2::poseidon2_hash::poseidon2::{Poseidon2, Poseidon2Hash};
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use std::marker::PhantomData;
use plonky2::plonk::proof::ProofWithPublicInputs;

macro_rules! pretty_print {
    ($($arg:tt)*) => {
        print!("\x1b[0;36mINFO ===========>\x1b[0m ");
        println!($($arg)*);
    }
}

pub struct PoseidonCircuit<
    F: RichField + Extendable<D> + Poseidon2,
    C: GenericConfig<D, F = F>,
    const D: usize,
    H: Hasher<F> + AlgebraicHasher<F>,
> {
    public_input: Vec<Target>,
    circuit_data: CircuitData<F, C, D>,
    num_powers: usize,
    _hasher: PhantomData<H>,
}

impl<
    F: RichField + Extendable<D> + Poseidon2,
    C: GenericConfig<D, F = F>,
    const D: usize,
    H: Hasher<F> + AlgebraicHasher<F>,
> PoseidonCircuit<F, C, D, H>
{
    pub fn build_circuit(config: CircuitConfig, log_num_hashes: usize) -> Self {
        let num_hashes: usize = 1usize << log_num_hashes;
        const T: usize = 12;

        let mut builder = CircuitBuilder::<F, D>::new(config);
        let zero = builder.zero();
        let mut state = H::AlgebraicPermutation::new(core::iter::repeat(zero));

        let mut initial = Vec::new(); // vec![];
        for _ in 0..T {
            let x = builder.add_virtual_public_input();
            initial.push(x);
        }

        state.set_from_slice(&initial, 0);

        for k in 0..num_hashes {
            state = builder.permute::<H>(state);
        }

        let output = state.squeeze();
        for o in output{
            builder.register_public_input(*o);
        }

        let data = builder.build::<C>();

        Self {
            public_input: initial,
            circuit_data: data,
            num_powers: num_hashes,
            _hasher: PhantomData::<H>,
        }
    }

    pub fn generate_proof(&self, init: F) -> Result<ProofWithPublicInputs<F, C, D>> {
        const T: usize = 12;

        let mut pw = PartialWitness::<F>::new();
        for j in 0..T {
            pw.set_target(self.public_input[j], F::from_canonical_usize(j));
        }

        let proof = self.circuit_data.prove(pw).unwrap();

        Ok(proof)
    }

    pub fn get_circuit_data(&self) -> &CircuitData<F, C, D> {
        &self.circuit_data
    }
}

fn bench_poseidon2_perm<
    F: RichField + Extendable<D> + Poseidon2,
    const D: usize,
    C: GenericConfig<D, F = F>,
    H: Hasher<F> + AlgebraicHasher<F>,
>(
    c: &mut Criterion,
    config: CircuitConfig,
) {

    let mut group = c.benchmark_group(&format!(
        "poseidon-proof<{}, {}>",
        type_name::<C>(),
        type_name::<H>()
    ));

    for log_num_hashes in [ 10, 11, 12, 13 ] {
        group.bench_function(
            format!("build circuit for 2^{} permutations", log_num_hashes).as_str(),
            |b| {
                b.iter_with_large_drop(|| {
                    PoseidonCircuit::<F, C, D, H>::build_circuit(config.clone(), log_num_hashes);
                })
            },
        );

        let poseidon_circuit =
            PoseidonCircuit::<F, C, D, H>::build_circuit(config.clone(), log_num_hashes);

        pretty_print!(
            "circuit size: 2^{} gates",
            poseidon_circuit.get_circuit_data().common.degree_bits()
        );

        group.bench_function(
            format!("prove circuit with 2^{} permutations", log_num_hashes).as_str(),
            |b| {
                b.iter_batched(
                    || F::rand(),
                    |init| poseidon_circuit.generate_proof(init).unwrap(),
                    BatchSize::PerIteration,
                )
            },
        );

        let proof = poseidon_circuit.generate_proof(F::rand()).unwrap();

        pretty_print!("proof size: {}", proof.to_bytes().len());

        group.bench_function(
            format!("verify circuit with 2^{} permutations", log_num_hashes).as_str(),
            |b| {
                b.iter_batched(
                    || (poseidon_circuit.get_circuit_data(), proof.clone()),
                    |(data, proof)| data.verify(proof).unwrap(),
                    BatchSize::PerIteration,
                )
            },
        );
    }

    group.finish();
}

fn benchmark(c: &mut Criterion) {
    const D: usize = 2;
    type F = GoldilocksField;

    // bench poseidon hash
    bench_poseidon2_perm::<F, D, PoseidonGoldilocksConfig, PoseidonHash>(
        c,
        CircuitConfig::standard_recursion_config(),
    );

    // bench poseidon2 hash
    bench_poseidon2_perm::<F, D, Poseidon2GoldilocksConfig, Poseidon2Hash>(
        c,
        CircuitConfig::standard_recursion_config(),
    );
}

criterion_group!(name = benches;
    config = Criterion::default().sample_size(10);
    targets = benchmark);
criterion_main!(benches);
