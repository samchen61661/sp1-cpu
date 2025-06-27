use std::io::{Read, Write};

use super::serialize_primitives::SerializeProof;
use p3_baby_bear::BabyBear;
use p3_commit::TwoAdicMultiplicativeCoset;
use p3_matrix::Dimensions;
use sp1_prover::{CoreSC, SP1CircuitWitness};
use sp1_recursion_circuit::{
    machine::{
        SP1CompressWitnessValues, SP1DeferredWitnessValues, SP1MerkleProofWitnessValues,
        SP1RecursionWitnessValues,
    },
    merkle_tree::MerkleProof,
};
use sp1_stark::{baby_bear_poseidon2::BabyBearPoseidon2, StarkVerifyingKey, Word};

impl SerializeProof for SP1CircuitWitness {
    fn to_bytes<W: Write>(self, w: &mut W) -> std::io::Result<usize> {
        match self {
            SP1CircuitWitness::Core(sp1_recursion_witness_values) => {
                (0_u8, sp1_recursion_witness_values).to_bytes(w)
            }
            SP1CircuitWitness::Deferred(sp1_deferred_witness_values) => {
                (1_u8, sp1_deferred_witness_values).to_bytes(w)
            }
            SP1CircuitWitness::Compress(sp1_compress_witness_values) => {
                (2_u8, sp1_compress_witness_values).to_bytes(w)
            }
        }
    }

    fn from_bytes<R: Read>(buffer: &mut R) -> std::io::Result<Self> {
        let discriminant = u8::from_bytes(buffer)?;
        match discriminant {
            0 => {
                let values: SP1RecursionWitnessValues<CoreSC> = SerializeProof::from_bytes(buffer)?;
                Ok(Self::Core(values))
            }
            1 => {
                let values: SP1DeferredWitnessValues<CoreSC> = SerializeProof::from_bytes(buffer)?;
                Ok(Self::Deferred(values))
            }
            2 => {
                let values: SP1CompressWitnessValues<CoreSC> = SerializeProof::from_bytes(buffer)?;
                Ok(Self::Compress(values))
            }
            _ => panic!("unexpected discriminant"),
        }
    }
}

impl SerializeProof for SP1RecursionWitnessValues<CoreSC> {
    fn to_bytes<W: Write>(self, w: &mut W) -> std::io::Result<usize> {
        let Self {
            vk,
            shard_proofs,
            is_complete,
            is_first_shard,
            vk_root,
            reconstruct_deferred_digest,
        } = self;
        let a = (vk, shard_proofs, is_complete);
        let b = (is_first_shard, vk_root, reconstruct_deferred_digest);
        (a, b).to_bytes(w)
    }

    fn from_bytes<R: Read>(buffer: &mut R) -> std::io::Result<Self> {
        let (a, b) = SerializeProof::from_bytes(buffer)?;
        let (vk, shard_proofs, is_complete) = a;
        let (is_first_shard, vk_root, reconstruct_deferred_digest) = b;
        Ok(Self {
            vk,
            shard_proofs,
            is_complete,
            is_first_shard,
            vk_root,
            reconstruct_deferred_digest,
        })
    }
}

impl SerializeProof for Dimensions {
    fn to_bytes<W: Write>(self, w: &mut W) -> std::io::Result<usize> {
        let Self { width, height } = self;
        (width, height).to_bytes(w)
    }

    fn from_bytes<R: Read>(buffer: &mut R) -> std::io::Result<Self> {
        let (width, height) = SerializeProof::from_bytes(buffer)?;
        Ok(Self { width, height })
    }
}

impl SerializeProof for TwoAdicMultiplicativeCoset<BabyBear> {
    fn to_bytes<W: Write>(self, w: &mut W) -> std::io::Result<usize> {
        let Self { log_n, shift } = self;
        (log_n, shift).to_bytes(w)
    }

    fn from_bytes<R: Read>(buffer: &mut R) -> std::io::Result<Self> {
        let (log_n, shift) = SerializeProof::from_bytes(buffer)?;
        Ok(Self { log_n, shift })
    }
}

impl SerializeProof for StarkVerifyingKey<CoreSC> {
    fn to_bytes<W: Write>(self, w: &mut W) -> std::io::Result<usize> {
        let Self {
            commit,
            pc_start,
            initial_global_cumulative_sum,
            chip_information,
            chip_ordering,
        } = self;
        (commit, pc_start, initial_global_cumulative_sum, chip_information, chip_ordering)
            .to_bytes(w)
    }

    fn from_bytes<R: Read>(buffer: &mut R) -> std::io::Result<Self> {
        let (commit, pc_start, initial_global_cumulative_sum, chip_information, chip_ordering) =
            SerializeProof::from_bytes(buffer)?;
        Ok(Self {
            commit,
            pc_start,
            initial_global_cumulative_sum,
            chip_information,
            chip_ordering,
        })
    }
}

impl SerializeProof for SP1DeferredWitnessValues<CoreSC> {
    fn to_bytes<W: Write>(self, w: &mut W) -> std::io::Result<usize> {
        let Self {
            vks_and_proofs,
            vk_merkle_data,
            start_reconstruct_deferred_digest,
            sp1_vk_digest,
            committed_value_digest,
            deferred_proofs_digest,
            end_pc,
            end_shard,
            end_execution_shard,
            init_addr_bits,
            finalize_addr_bits,
            is_complete,
        } = self;
        let a = (vks_and_proofs, vk_merkle_data, start_reconstruct_deferred_digest);
        let b = (sp1_vk_digest, committed_value_digest, deferred_proofs_digest);
        let c = (end_pc, end_shard, end_execution_shard, init_addr_bits);
        let d = (finalize_addr_bits, is_complete);
        (a, b, c, d).to_bytes(w)
    }

    fn from_bytes<R: Read>(buffer: &mut R) -> std::io::Result<Self> {
        let (a, b, c, d) = SerializeProof::from_bytes(buffer)?;
        let (vks_and_proofs, vk_merkle_data, start_reconstruct_deferred_digest) = a;
        let (sp1_vk_digest, committed_value_digest, deferred_proofs_digest) = b;
        let (end_pc, end_shard, end_execution_shard, init_addr_bits) = c;
        let (finalize_addr_bits, is_complete) = d;
        Ok(Self {
            vks_and_proofs,
            vk_merkle_data,
            start_reconstruct_deferred_digest,
            sp1_vk_digest,
            committed_value_digest,
            deferred_proofs_digest,
            end_pc,
            end_shard,
            end_execution_shard,
            init_addr_bits,
            finalize_addr_bits,
            is_complete,
        })
    }
}

impl SerializeProof for SP1MerkleProofWitnessValues<BabyBearPoseidon2> {
    fn to_bytes<W: Write>(self, w: &mut W) -> std::io::Result<usize> {
        let Self { vk_merkle_proofs, values, root } = self;
        (vk_merkle_proofs, values, root).to_bytes(w)
    }

    fn from_bytes<R: Read>(buffer: &mut R) -> std::io::Result<Self> {
        let (vk_merkle_proofs, values, root) = SerializeProof::from_bytes(buffer)?;
        Ok(Self { vk_merkle_proofs, values, root })
    }
}

impl SerializeProof for MerkleProof<BabyBear, BabyBearPoseidon2> {
    fn to_bytes<W: Write>(self, w: &mut W) -> std::io::Result<usize> {
        let Self { index, path } = self;
        (index, path).to_bytes(w)
    }

    fn from_bytes<R: Read>(buffer: &mut R) -> std::io::Result<Self> {
        let (index, path) = SerializeProof::from_bytes(buffer)?;
        Ok(Self { index, path })
    }
}

impl<T: SerializeProof> SerializeProof for Word<T> {
    fn to_bytes<W: Write>(self, w: &mut W) -> std::io::Result<usize> {
        self.0.to_bytes(w)
    }

    fn from_bytes<R: Read>(buffer: &mut R) -> std::io::Result<Self> {
        SerializeProof::from_bytes(buffer).map(Word)
    }
}

impl SerializeProof for SP1CompressWitnessValues<CoreSC> {
    fn to_bytes<W: Write>(self, w: &mut W) -> std::io::Result<usize> {
        let Self { vks_and_proofs, is_complete } = self;
        (vks_and_proofs, is_complete).to_bytes(w)
    }

    fn from_bytes<R: Read>(buffer: &mut R) -> std::io::Result<Self> {
        let (vks_and_proofs, is_complete) = SerializeProof::from_bytes(buffer)?;
        Ok(Self { vks_and_proofs, is_complete })
    }
}