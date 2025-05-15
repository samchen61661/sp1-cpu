use alloy_primitives::B256;
use anyhow::{anyhow, Result};
use bincode;
use clap::Parser;
use rsp_client_executor::{io::ClientExecutorInput, CHAIN_ID_ETH_MAINNET};
use sp1_prover::{components::DefaultProverComponents, RecursionInput, SP1Prover};
use sp1_sdk::{SP1Proof, SP1ProofCommonData, SP1ProofWithPublicValues};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::path::PathBuf;

use sp1_sdk::{include_elf, utils, ProverClient, SP1Stdin};

const PREFIX: &str = "./proofs/";

#[derive(Parser, Debug)]
struct Args {
    #[arg(long, default_value_t = false)]
    prove: bool,
    #[arg(long, default_value_t = false)]
    compress: bool,
}

fn load_input_from_cache(chain_id: u64, block_number: u64) -> ClientExecutorInput {
    let cache_path = PathBuf::from(format!("./input/{}/{}.bin", chain_id, block_number));
    let mut cache_file = std::fs::File::open(cache_path).unwrap();
    let client_input: ClientExecutorInput = bincode::deserialize_from(&mut cache_file).unwrap();

    client_input
}

fn load_shard_proofs() -> Result<SP1ProofWithPublicValues> {
    let common_path = Path::new(PREFIX).join("common_data.bin");
    let mut common_file = File::open(&common_path)?;
    let mut common_serialized = Vec::new();
    common_file.read_to_end(&mut common_serialized)?;
    let common_data: SP1ProofCommonData = bincode::deserialize(&common_serialized)?;
    // Load ShardProofs from proof_0.bin, proof_1.bin, etc.
    let mut shard_proofs = Vec::new();
    let mut index = 0;
    loop {
        let shard_path = Path::new(PREFIX).join(format!("proof_{}.bin", index));
        if !shard_path.exists() {
            break; // Stop when proof_{index}.bin is not found
        }
        let proof = RecursionInput::load(shard_path)?;
        let shard_proof = match proof {
            RecursionInput::Single { vk: _, proof, .. } => proof, // Extract proof, ignore vk
            RecursionInput::Double { .. } => {
                return Err(anyhow!("Expected Single RecursionInput, found Double"));
            }
        };
        shard_proofs.push(shard_proof);
        index += 1;
    }

    Ok(SP1ProofWithPublicValues {
        proof: SP1Proof::Core(shard_proofs),
        stdin: common_data.stdin,
        public_values: common_data.public_values,
        sp1_version: common_data.sp1_version,
    })
}

fn main() {
    // this is the total number of shard_proofs to be compressed
    let num_proofs = 21;

    // Initialize the logger.
    utils::setup_logger();

    // Parse the command line arguments.
    let args = Args::parse();

    // Load the input from the cache.
    let client_input = load_input_from_cache(CHAIN_ID_ETH_MAINNET, 20526624);

    // Generate the proof.
    let client = ProverClient::new();

    // Setup the proving key and verification key.
    let (pk, vk) = client.setup(include_elf!("rsp-program"));

    // Write the block to the program's stdin.
    let mut stdin = SP1Stdin::new();
    let buffer = bincode::serialize(&client_input).unwrap();
    stdin.write_vec(buffer);

    // Only execute the program.
    let (mut public_values, execution_report) =
        client.execute(&pk.elf, stdin.clone()).run().unwrap();
    println!(
        "Finished executing the block in {} cycles",
        execution_report.total_instruction_count()
    );

    // Read the block hash.
    let block_hash = public_values.read::<B256>();
    println!("success: block_hash={block_hash}");

    if args.prove {
        println!("Starting shard proof generation.");
        client.prove(&pk, stdin).run_shard_proof().expect("Proving should work.");
        println!("shard proof generation finished.");

        println!("loading proofs...");
        let proof = load_shard_proofs().unwrap();
        client.verify(&proof, &vk).unwrap();
        println!("shard proof verification finished.");
    } else if args.compress {
        println!("Starting compress proof generation.");
        // compress_all_proofs(num_proofs).unwrap();
        println!("Proof generation finished.");
        let prover = SP1Prover::<DefaultProverComponents>::new();

        let final_path = Path::new(PREFIX).join("reduced_final.bin");
        let input = RecursionInput::load(final_path).unwrap();
        let common_path = Path::new(PREFIX).join("common_data.bin");
        let mut common_file = File::open(&common_path).unwrap();
        let mut common_serialized = Vec::new();
        common_file.read_to_end(&mut common_serialized).unwrap();
        let common_data: SP1ProofCommonData = bincode::deserialize(&common_serialized).unwrap();
        prover.verify_final_compressed(vk, input, common_data.public_values).unwrap();
        println!("Verify final proof finished");
    } else {
        panic!("not supported");
    }

    println!("successfully generated and verified proof for the program!")
}
