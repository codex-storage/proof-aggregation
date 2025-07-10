use anyhow::Result;
use clap::{Parser, Subcommand};
use codex_plonky2_circuits::bn254_wrapper::config::PoseidonBN254GoldilocksConfig;
use crate::file_paths::{COMPRESS_CIRC_BASE_PATH, SAMPLING_CIRC_BASE_PATH, TREE_CIRC_BASE_PATH, WRAP_CIRC_BASE_PATH};
use crate::params::C;

type OuterParameters = PoseidonBN254GoldilocksConfig;

mod build_circ;
mod prove;
mod verify;
mod gen_input;
mod aggregate;
mod bn254_wrap;
mod file_paths;
mod params;

/// Codex_zk_cli: unified CLI for all zk operations
#[derive(Parser)]
#[command(name = "codex_zk_cli", version, about = "gen_input, build, prove, aggregate, wrap, verify")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate witness inputs
    GenInput,
    /// build the circuit
    Build,
    /// Run the prover
    Prove,
    /// Aggregate proofs
    Aggregate,
    /// Aggregate and compress proofs
    AggregateAndCompress,
    /// Wrap sampling proof
    Wrap,
    /// Wrap aggregated tree proof
    WrapTree,
    /// Wrap compressed proof
    WrapCompress,
    /// Verify a sampling proof
    Verify,
    /// Verify a tree proof
    VerifyTree,
    /// Verify a compressed tree proof
    VerifyCompressed,
    /// Verify a wrapped proof
    VerifyWrapped,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::GenInput   => gen_input::run()?,
        Commands::Build      => build_circ::run()?,
        Commands::Prove      => prove::run()?,
        Commands::Aggregate  => aggregate::run(false)?,
        Commands::AggregateAndCompress  => aggregate::run(true)?,
        Commands::Wrap       => bn254_wrap::run(SAMPLING_CIRC_BASE_PATH)?,
        Commands::WrapTree   => bn254_wrap::run(TREE_CIRC_BASE_PATH)?,
        Commands::WrapCompress => bn254_wrap::run(COMPRESS_CIRC_BASE_PATH)?,
        Commands::Verify     => verify::run::<C>(SAMPLING_CIRC_BASE_PATH)?,
        Commands::VerifyTree => verify::run::<C>(TREE_CIRC_BASE_PATH)?,
        Commands::VerifyCompressed => verify::run::<C>(COMPRESS_CIRC_BASE_PATH)?,
        Commands::VerifyWrapped => verify::run::<OuterParameters>(WRAP_CIRC_BASE_PATH)?,
    }

    Ok(())
}