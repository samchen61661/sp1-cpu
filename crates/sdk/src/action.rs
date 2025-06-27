use sp1_core_executor::{ExecutionReport, HookEnv, SP1ContextBuilder};
use sp1_core_machine::io::SP1Stdin;
use sp1_primitives::io::SP1PublicValues;
use sp1_prover::{
    components::DefaultProverComponents, RecursionCpuResult, RecursionInput, SP1Prover,
    SP1ProvingKey,
};

use anyhow::{anyhow, Ok, Result};
use bincode;
use sp1_stark::{baby_bear_poseidon2::BabyBearPoseidon2, SP1CoreOpts, SP1ProverOpts};
use std::time::Duration;

use crate::{provers::ProofOpts, Prover, SP1ProofKind, SP1ProofWithPublicValues};

pub type InnerSC = BabyBearPoseidon2;

/// Builder to prepare and configure execution of a program on an input.
/// May be run with [Self::run].
pub struct Execute<'a> {
    prover: &'a dyn Prover<DefaultProverComponents>,
    context_builder: SP1ContextBuilder<'a>,
    elf: &'a [u8],
    stdin: SP1Stdin,
}

impl<'a> Execute<'a> {
    /// Prepare to execute the given program on the given input (without generating a proof).
    ///
    /// Prefer using [ProverClient::execute](super::ProverClient::execute).
    /// See there for more documentation.
    pub fn new(
        prover: &'a dyn Prover<DefaultProverComponents>,
        elf: &'a [u8],
        stdin: SP1Stdin,
    ) -> Self {
        Self { prover, elf, stdin, context_builder: Default::default() }
    }

    /// Execute the program on the input, consuming the built action `self`.
    pub fn run(self) -> Result<(SP1PublicValues, ExecutionReport)> {
        let Self { prover, elf, stdin, mut context_builder } = self;
        let context = context_builder.build();
        Ok(prover.sp1_prover().execute(elf, &stdin, context)?)
    }

    /// Add a runtime [Hook](super::Hook) into the context.
    ///
    /// Hooks may be invoked from within SP1 by writing to the specified file descriptor `fd`
    /// with [`sp1_zkvm::io::write`], returning a list of arbitrary data that may be read
    /// with successive calls to [`sp1_zkvm::io::read`].
    pub fn with_hook(
        mut self,
        fd: u32,
        f: impl FnMut(HookEnv, &[u8]) -> Vec<Vec<u8>> + Send + Sync + 'a,
    ) -> Self {
        self.context_builder.hook(fd, f);
        self
    }

    /// Avoid registering the default hooks in the runtime.
    ///
    /// It is not necessary to call this to override hooks --- instead, simply
    /// register a hook with the same value of `fd` by calling [`Self::with_hook`].
    pub fn without_default_hooks(mut self) -> Self {
        self.context_builder.without_default_hooks();
        self
    }

    /// Set the maximum number of cpu cycles to use for execution.
    ///
    /// If the cycle limit is exceeded, execution will return
    /// [`sp1_core_executor::ExecutionError::ExceededCycleLimit`].
    pub fn max_cycles(mut self, max_cycles: u64) -> Self {
        self.context_builder.max_cycles(max_cycles);
        self
    }

    /// Skip deferred proof verification.
    pub fn set_skip_deferred_proof_verification(mut self, value: bool) -> Self {
        self.context_builder.set_skip_deferred_proof_verification(value);
        self
    }
}

/// Builder to prepare and configure proving execution of a program on an input.
/// May be run with [Self::run].
pub struct Prove<'a> {
    prover: &'a dyn Prover<DefaultProverComponents>,
    kind: SP1ProofKind,
    context_builder: SP1ContextBuilder<'a>,
    pk: &'a SP1ProvingKey,
    stdin: SP1Stdin,
    core_opts: SP1CoreOpts,
    recursion_opts: SP1CoreOpts,
    timeout: Option<Duration>,
}

impl<'a> Prove<'a> {
    /// Prepare to prove the execution of the given program with the given input.
    ///
    /// Prefer using [ProverClient::prove](super::ProverClient::prove).
    /// See there for more documentation.
    pub fn new(
        prover: &'a dyn Prover<DefaultProverComponents>,
        pk: &'a SP1ProvingKey,
        stdin: SP1Stdin,
    ) -> Self {
        Self {
            prover,
            kind: Default::default(),
            pk,
            stdin,
            context_builder: Default::default(),
            core_opts: SP1CoreOpts::default(),
            recursion_opts: SP1CoreOpts::recursion(),
            timeout: None,
        }
    }

    /// Prove the execution of the program on the input, consuming the built action `self`.
    pub fn run(self) -> Result<SP1ProofWithPublicValues> {
        let Self {
            prover,
            kind,
            pk,
            stdin,
            mut context_builder,
            core_opts,
            recursion_opts,
            timeout,
        } = self;
        let opts = SP1ProverOpts { core_opts, recursion_opts };
        let proof_opts = ProofOpts { sp1_prover_opts: opts, timeout };
        let context = context_builder.build();

        // Dump the program and stdin to files for debugging if `SP1_DUMP` is set.
        if std::env::var("SP1_DUMP")
            .map(|v| v == "1" || v.to_lowercase() == "true")
            .unwrap_or(false)
        {
            let program = pk.elf.clone();
            std::fs::write("program.bin", program).unwrap();
            let stdin = bincode::serialize(&stdin).unwrap();
            std::fs::write("stdin.bin", stdin.clone()).unwrap();
        }

        prover.prove(pk, stdin, proof_opts, context, kind)
    }

    // generate shard proofs
    pub fn run_shard_proof(self) -> Result<Vec<RecursionInput>> {
        let Self {
            prover,
            kind: _,
            pk,
            stdin,
            mut context_builder,
            core_opts,
            recursion_opts,
            timeout,
        } = self;
        let opts = SP1ProverOpts { core_opts, recursion_opts };
        let proof_opts = ProofOpts { sp1_prover_opts: opts, timeout };
        let context = context_builder.build();

        // Remove proofs folder and recreate it
        // fs::remove_dir_all(PREFIX).unwrap_or(()); // Ignore error if directory doesn't exist
        // fs::create_dir_all(PREFIX)?;
        let (common_data, proofs) = prover.prove_shard(pk, stdin, proof_opts, context)?;
        // let common_path = Path::new(PREFIX).join("common_data.bin");
        // let common_serialized = bincode::serialize(&common_data)?;
        // let mut common_file = File::create(common_path)?;
        // common_file.write_all(&common_serialized)?;
        let mut output: Vec<RecursionInput> = Vec::new();

        // Save each ShardProof to proof_0.bin, proof_1.bin, etc.
        for (index, shard_proof) in proofs.iter().enumerate() {
            let recursion_input = RecursionInput::Single {
                vk: common_data.vk.clone(),
                proof: shard_proof.clone(),
                is_first_shard: index == 0,
            };
            output.push(recursion_input);
            //let proof_path = Path::new(PREFIX).join(format!("proof_{}.bin", index));
            //recursion_input.save(proof_path)?;
        }
        Ok(output)
    }

    /// Set the proof kind to the core mode. This is the default.
    pub fn core(mut self) -> Self {
        self.kind = SP1ProofKind::Core;
        self
    }

    /// Set the proof kind to the compressed mode.
    pub fn compressed(mut self) -> Self {
        self.kind = SP1ProofKind::Compressed;
        self
    }

    /// Set the proof mode to the plonk bn254 mode.
    pub fn plonk(mut self) -> Self {
        self.kind = SP1ProofKind::Plonk;
        self
    }

    /// Set the proof mode to the groth16 bn254 mode.
    pub fn groth16(mut self) -> Self {
        self.kind = SP1ProofKind::Groth16;
        self
    }

    /// Add a runtime [Hook](super::Hook) into the context.
    ///
    /// Hooks may be invoked from within SP1 by writing to the specified file descriptor `fd`
    /// with [`sp1_zkvm::io::write`], returning a list of arbitrary data that may be read
    /// with successive calls to [`sp1_zkvm::io::read`].
    pub fn with_hook(
        mut self,
        fd: u32,
        f: impl FnMut(HookEnv, &[u8]) -> Vec<Vec<u8>> + Send + Sync + 'a,
    ) -> Self {
        self.context_builder.hook(fd, f);
        self
    }

    /// Avoid registering the default hooks in the runtime.
    ///
    /// It is not necessary to call this to override hooks --- instead, simply
    /// register a hook with the same value of `fd` by calling [`Self::with_hook`].
    pub fn without_default_hooks(mut self) -> Self {
        self.context_builder.without_default_hooks();
        self
    }

    /// Set the shard size for proving.
    pub fn shard_size(mut self, value: usize) -> Self {
        self.core_opts.shard_size = value;
        self
    }

    /// Set the shard batch size for proving.
    pub fn shard_batch_size(mut self, value: usize) -> Self {
        self.core_opts.shard_batch_size = value;
        self
    }

    /// Set whether we should reconstruct commitments while proving.
    pub fn reconstruct_commitments(mut self, value: bool) -> Self {
        self.core_opts.reconstruct_commitments = value;
        self
    }

    /// Set the maximum number of cpu cycles to use for execution.
    ///
    /// If the cycle limit is exceeded, execution will return
    /// [`sp1_core_executor::ExecutionError::ExceededCycleLimit`].
    pub fn cycle_limit(mut self, cycle_limit: u64) -> Self {
        self.context_builder.max_cycles(cycle_limit);
        self
    }

    /// Set the timeout for the proof's generation.
    ///
    /// This parameter is only used when the prover is run in network mode.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Set the skip deferred proof verification flag.
    pub fn set_skip_deferred_proof_verification(mut self, value: bool) -> Self {
        self.context_builder.set_skip_deferred_proof_verification(value);
        self
    }
}

// generate first layer recursion proof
pub fn run_recursion_first_layer(input: RecursionInput) -> Result<RecursionCpuResult> {
    // let proof_path = Path::new(PREFIX).join(format!("proof_{}.bin", index));
    // let input = RecursionInput::load(&proof_path)?;
    let recursion_input = match input {
        RecursionInput::Single { .. } => input,
        RecursionInput::Double { .. } => {
            return Err(anyhow!("Expected Single RecursionInput"));
        }
    };

    let prover = SP1Prover::<DefaultProverComponents>::new();
    Ok(prover.compress_proofs_trace(&recursion_input, false))
    /*
    let recursion_input = RecursionInput::Single {
        vk: reduced_proof.vk,
        proof: reduced_proof.proof,
        is_first_shard: false, // not used
    };
    */
    // let proof_path = Path::new(PREFIX).join(format!("reduced_0_{}.bin", index));
    // recursion_input.save(proof_path)?;
}

// combine two recursion proofs into one
pub fn run_recursion_two_to_one(
    input1: RecursionInput,
    input2: RecursionInput,
    is_complete: bool,
) -> Result<RecursionCpuResult> {
    // let path1 = path1.as_ref();
    // let path2 = path2.as_ref();

    // let input1 = RecursionInput::load(&path1)?;
    // let input2 = RecursionInput::load(&path2)?;

    // Ensure both inputs are Single (containing InnerSC proofs)
    let (vk1, proof1) = match input1 {
        RecursionInput::Single { vk, proof, .. } => (vk, proof),
        RecursionInput::Double { .. } => {
            return Err(anyhow!("Expected Single RecursionInput in input1"));
        }
    };
    let (vk2, proof2) = match input2 {
        RecursionInput::Single { vk, proof, .. } => (vk, proof),
        RecursionInput::Double { .. } => {
            return Err(anyhow!("Expected Single RecursionInput in input2"));
        }
    };

    // Construct RecursionInput::Double
    let recursion_input = RecursionInput::Double { vks_and_proofs: [(vk1, proof1), (vk2, proof2)] };

    // Compress the two proofs into one
    let prover = SP1Prover::<DefaultProverComponents>::new();
    Ok(prover.compress_proofs_trace(&recursion_input, is_complete))
    /*
    // Save the combined proof
    let recursion_input = RecursionInput::Single {
        vk: reduced_proof.vk,
        proof: reduced_proof.proof,
        is_first_shard: false,
    };
    // recursion_input.save(&out_path)?;
    Ok(recursion_input)
     */
}

/*
pub fn compress_all_proofs(num_proofs: usize) -> Result<()> {
    let prover = SP1Prover::<DefaultProverComponents>::new();
    for i in 0..num_proofs {
        run_recursion_first_layer(&prover, i)?;
    }

    let mut current_proofs: Vec<PathBuf> =
        (0..num_proofs).map(|i| Path::new(PREFIX).join(format!("reduced_0_{}.bin", i))).collect();
    let mut level = 0;

    while current_proofs.len() > 1 {
        let mut next_proofs = Vec::new();
        for idx in 0..(current_proofs.len() / 2) {
            let in1 = idx * 2;
            let in2 = idx * 2 + 1;
            let path1 = current_proofs[in1].clone();
            let path2 = current_proofs[in2].clone();
            let is_final = current_proofs.len() == 2 && idx == 0;
            let output_filename = if is_final {
                "reduced_final.bin".to_string()
            } else {
                format!("reduced_{}_{}.bin", level, idx)
            };
            let output_path = Path::new(PREFIX).join(&output_filename);

            // Run two-to-one compression
            run_recursion_two_to_one(&prover, &path1, &path2, &output_path, is_final)?;
            next_proofs.push(output_path);
        }
        // Carry over the last proof if odd
        if current_proofs.len() % 2 == 1 {
            next_proofs.push(current_proofs[current_proofs.len() - 1].clone());
        }
        current_proofs = next_proofs;
        level += 1;
    }

    Ok(())
}
*/
