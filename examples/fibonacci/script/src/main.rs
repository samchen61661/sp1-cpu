use anyhow::{anyhow, Result};
use bincode;
use clap::Parser;
use sp1_prover::{components::DefaultProverComponents, RecursionInput, SP1Prover};
use sp1_sdk::{
    include_elf, utils, ProverClient, SP1Proof, SP1ProofCommonData, SP1ProofWithPublicValues,
    SP1Stdin,
};
use std::fs::File;
use std::io::Read;
use std::path::Path;

/// The ELF we want to execute inside the zkVM.
const ELF: &[u8] = include_elf!("fibonacci-program");

const PREFIX: &str = "./proofs/";

#[derive(Parser, Debug)]
struct Args {
    /// Whether or not to generate a proof.
    #[arg(long, default_value_t = false)]
    prove: bool,
    #[arg(long, default_value_t = false)]
    compress: bool,
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
    // Setup logging.
    utils::setup_logger();

    let args = Args::parse();
    let n = 20000u32;

    // The input stream that the program will read from using `sp1_zkvm::io::read`. Note that the
    // types of the elements in the input stream must match the types being read in the program.
    let mut stdin = SP1Stdin::new();
    stdin.write(&n);

    // Create a `ProverClient` method.
    let client = ProverClient::new();

    // Execute the program using the `ProverClient.execute` method, without generating a proof.
    let (_, report) = client.execute(ELF, stdin.clone()).run().unwrap();
    println!("executed program with {} cycles", report.total_instruction_count());

    // Generate the proof for the given program and input.
    let (pk, vk) = client.setup(ELF);

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
        // compress_all_proofs(4).unwrap();
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
