use super::serialize_primitives::SerializeProof;
use hashbrown::HashMap;
use p3_baby_bear::BabyBear;
use p3_field::{
    extension::BinomialExtensionField, AbstractExtensionField, AbstractField, PrimeField32,
};
use p3_fri::{BatchOpening, CommitPhaseProofStep, FriProof, QueryProof, TwoAdicFriPcsProof};
use sp1_core_machine::io::SP1Stdin;
use sp1_primitives::io::SP1PublicValues;
use sp1_prover::{CoreSC, SP1CoreProofData, SP1ProofWithMetadata};
use sp1_stark::{
    baby_bear_poseidon2::{ChallengeMmcs, ValMmcs},
    septic_curve::SepticCurve,
    septic_digest::SepticDigest,
    septic_extension::SepticExtension,
    AirOpenedValues, ChipOpenedValues, ShardCommitment, ShardOpenedValues, ShardProof,
};
use std::io::{self, Read, Write};

type Val = BabyBear;
type ExVal = BinomialExtensionField<Val, 4>;
type SepticVal = SepticExtension<Val>;
type Point = SepticCurve<Val>;
type Hash = p3_symmetric::Hash<Val, Val, 8>;

// SP1 types serialize as just combinations of std types and themselves, some notable types:
// Val serializes as u32.
// ExVal serializes as [Val; 4].
// SepticVal serializes as [Val; 7].
// Point as (SepticVal, SepticVal).
// Hash as [Val; 8]
// Buffer {data, ptr} ignores ptr as to be consistent wiht sp1, with default value on creation 0.
// AirOpenedValues<T> { local: Vec<T>, next: Vec<T>} uses Vec<T> like defined, but we can probably use [T;2] instead.
// SP1Stdin { buffer, ptr, proofs } ignores proofs and deserilizes an empty Vec<_>, it shouldn't be an issue for fibonacci2.

impl SerializeProof for Val {
    fn to_bytes<W: Write>(self, w: &mut W) -> io::Result<usize> {
        let as_u32 = self.as_canonical_u32();
        as_u32.to_bytes(w)
    }

    fn from_bytes<R: Read>(buffer: &mut R) -> io::Result<Self> {
        let as_u32 = u32::from_bytes(buffer)?;
        Ok(Val::from_canonical_u32(as_u32))
    }
}

impl SerializeProof for ExVal {
    fn to_bytes<W: Write>(self, w: &mut W) -> io::Result<usize> {
        let elems: &[Val] = self.as_base_slice();
        let elems: [Val; 4] = elems.try_into().unwrap();
        elems.to_bytes(w)
    }

    fn from_bytes<R: Read>(buffer: &mut R) -> io::Result<Self> {
        let elems: [Val; 4] = SerializeProof::from_bytes(buffer)?;
        Ok(ExVal::from_base_slice(&elems))
    }
}

impl SerializeProof for SepticVal {
    fn to_bytes<W: Write>(self, w: &mut W) -> io::Result<usize> {
        let elems: [Val; 7] = self.0;
        elems.to_bytes(w)
    }

    fn from_bytes<R: Read>(buffer: &mut R) -> io::Result<Self> {
        let elems: [Val; 7] = SerializeProof::from_bytes(buffer)?;
        Ok(SepticExtension(elems))
    }
}

impl SerializeProof for Point {
    fn to_bytes<W: Write>(self, w: &mut W) -> io::Result<usize> {
        let Self { x, y } = self;
        (x, y).to_bytes(w)
    }

    fn from_bytes<R: Read>(buffer: &mut R) -> io::Result<Self> {
        let (x, y) = SerializeProof::from_bytes(buffer)?;
        Ok(Point { x, y })
    }
}

impl SerializeProof for SP1PublicValues {
    fn to_bytes<W: Write>(self, w: &mut W) -> io::Result<usize> {
        // ignoring the ptr in the buffer seems fine
        let buffer: Vec<u8> = self.to_vec();
        buffer.to_bytes(w)
    }

    fn from_bytes<R: Read>(buffer: &mut R) -> io::Result<Self> {
        let buffer: Vec<u8> = SerializeProof::from_bytes(buffer)?;
        Ok(SP1PublicValues::from(&buffer))
    }
}

impl SerializeProof for SP1CoreProofData {
    fn to_bytes<W: Write>(self, w: &mut W) -> io::Result<usize> {
        self.0.to_bytes(w)
    }

    fn from_bytes<R: Read>(buffer: &mut R) -> io::Result<Self> {
        let proofs = SerializeProof::from_bytes(buffer)?;
        Ok(Self(proofs))
    }
}

impl SerializeProof for ShardProof<CoreSC> {
    fn to_bytes<W: Write>(self, w: &mut W) -> io::Result<usize> {
        let ShardProof { commitment, opened_values, opening_proof, chip_ordering, public_values } =
            self;
        let commitment: ShardCommitment<Hash> = commitment;
        let opened_values: ShardOpenedValues<Val, ExVal> = opened_values;
        let opening_proof: TwoAdicFriPcsProof<Val, ExVal, ValMmcs, ChallengeMmcs> = opening_proof;
        let chip_ordering: HashMap<String, usize> = chip_ordering;
        let mut written = 0;
        written += commitment.to_bytes(w)?;
        written += opened_values.to_bytes(w)?;
        written += opening_proof.to_bytes(w)?;
        let mut sorted_chip_ordering: Vec<_> = chip_ordering.into_iter().collect();
        sorted_chip_ordering.sort_by_key(|&(_, value)| value);
        written += (sorted_chip_ordering.len() as u32).to_bytes(w)?;
        for (key, value) in sorted_chip_ordering {
            written += key.to_bytes(w)?;
            written += value.to_bytes(w)?;
        }
        written += public_values.to_bytes(w)?;
        Ok(written)
    }

    fn from_bytes<R: Read>(buffer: &mut R) -> io::Result<Self> {
        let commitment = SerializeProof::from_bytes(buffer)?;
        let opened_values = SerializeProof::from_bytes(buffer)?;
        let opening_proof = SerializeProof::from_bytes(buffer)?;
        let chip_ordering = SerializeProof::from_bytes(buffer)?;
        let public_values = SerializeProof::from_bytes(buffer)?;
        Ok(Self { commitment, opened_values, opening_proof, chip_ordering, public_values })
    }
}

impl SerializeProof for Hash {
    fn to_bytes<W: Write>(self, w: &mut W) -> io::Result<usize> {
        let elems: &[Val; 8] = self.as_ref();
        elems.to_bytes(w)
    }

    fn from_bytes<R: Read>(buffer: &mut R) -> io::Result<Self> {
        let elems: [Val; 8] = SerializeProof::from_bytes(buffer)?;
        Ok(Hash::from(elems))
    }
}

impl SerializeProof for ShardCommitment<Hash> {
    fn to_bytes<W: Write>(self, w: &mut W) -> io::Result<usize> {
        let Self { main_commit, permutation_commit, quotient_commit } = self;
        (main_commit, permutation_commit, quotient_commit).to_bytes(w)
    }

    fn from_bytes<R: Read>(buffer: &mut R) -> io::Result<Self> {
        let (main_commit, permutation_commit, quotient_commit) =
            SerializeProof::from_bytes(buffer)?;
        Ok(Self { main_commit, permutation_commit, quotient_commit })
    }
}

impl SerializeProof for AirOpenedValues<ExVal> {
    fn to_bytes<W: Write>(self, w: &mut W) -> io::Result<usize> {
        let Self { local, next } = self;
        (local, next).to_bytes(w)
    }

    fn from_bytes<R: Read>(buffer: &mut R) -> io::Result<Self> {
        let (local, next) = SerializeProof::from_bytes(buffer)?;
        Ok(AirOpenedValues { local, next })
    }
}

impl SerializeProof for SepticDigest<Val> {
    fn to_bytes<W: Write>(self, w: &mut W) -> io::Result<usize> {
        self.0.to_bytes(w)
    }

    fn from_bytes<R: Read>(buffer: &mut R) -> io::Result<Self> {
        let point: Point = SerializeProof::from_bytes(buffer)?;
        Ok(SepticDigest(point))
    }
}

impl SerializeProof for ChipOpenedValues<Val, ExVal> {
    fn to_bytes<W: Write>(self, w: &mut W) -> io::Result<usize> {
        let Self {
            preprocessed,
            main,
            permutation,
            quotient,
            global_cumulative_sum,
            local_cumulative_sum,
            log_degree,
        } = self;
        let mut writen = preprocessed.to_bytes(w)?;
        writen += main.to_bytes(w)?;
        writen += permutation.to_bytes(w)?;
        writen += quotient.to_bytes(w)?;
        writen += global_cumulative_sum.to_bytes(w)?;
        writen += local_cumulative_sum.to_bytes(w)?;
        writen += log_degree.to_bytes(w)?;
        Ok(writen)
    }

    fn from_bytes<R: Read>(buffer: &mut R) -> io::Result<Self> {
        let preprocessed = SerializeProof::from_bytes(buffer)?;
        let main = SerializeProof::from_bytes(buffer)?;
        let permutation = SerializeProof::from_bytes(buffer)?;
        let quotient = SerializeProof::from_bytes(buffer)?;
        let global_cumulative_sum = SerializeProof::from_bytes(buffer)?;
        let local_cumulative_sum = SerializeProof::from_bytes(buffer)?;
        let log_degree = SerializeProof::from_bytes(buffer)?;

        Ok(Self {
            preprocessed,
            main,
            permutation,
            quotient,
            global_cumulative_sum,
            local_cumulative_sum,
            log_degree,
        })
    }
}

impl SerializeProof for ShardOpenedValues<Val, ExVal> {
    fn to_bytes<W: Write>(self, w: &mut W) -> io::Result<usize> {
        self.chips.to_bytes(w)
    }

    fn from_bytes<R: Read>(buffer: &mut R) -> io::Result<Self> {
        let chips = SerializeProof::from_bytes(buffer)?;
        Ok(ShardOpenedValues { chips })
    }
}

impl SerializeProof for CommitPhaseProofStep<ExVal, ChallengeMmcs> {
    fn to_bytes<W: Write>(self, w: &mut W) -> io::Result<usize> {
        let Self { sibling_value, opening_proof } = self;
        let opening_proof: Vec<[Val; 8]> = opening_proof;
        (sibling_value, opening_proof).to_bytes(w)
    }

    fn from_bytes<R: Read>(buffer: &mut R) -> io::Result<Self> {
        let (sibling_value, opening_proof) = SerializeProof::from_bytes(buffer)?;
        Ok(Self { sibling_value, opening_proof })
    }
}

impl SerializeProof for QueryProof<ExVal, ChallengeMmcs> {
    fn to_bytes<W: Write>(self, w: &mut W) -> io::Result<usize> {
        self.commit_phase_openings.to_bytes(w)
    }

    fn from_bytes<R: Read>(buffer: &mut R) -> io::Result<Self> {
        let commit_phase_openings = SerializeProof::from_bytes(buffer)?;
        Ok(Self { commit_phase_openings })
    }
}

impl SerializeProof for FriProof<ExVal, ChallengeMmcs, Val> {
    fn to_bytes<W: Write>(self, w: &mut W) -> io::Result<usize> {
        let Self { commit_phase_commits, query_proofs, final_poly, pow_witness } = self;
        let commit_phase_commits: Vec<Hash> = commit_phase_commits;
        let query_proofs: Vec<QueryProof<ExVal, ChallengeMmcs>> = query_proofs;
        let mut written = commit_phase_commits.to_bytes(w)?;
        written += query_proofs.to_bytes(w)?;
        written += final_poly.to_bytes(w)?;
        written += pow_witness.to_bytes(w)?;
        Ok(written)
    }

    fn from_bytes<R: Read>(buffer: &mut R) -> io::Result<Self> {
        let commit_phase_commits = SerializeProof::from_bytes(buffer)?;
        let query_proofs = SerializeProof::from_bytes(buffer)?;
        let final_poly = SerializeProof::from_bytes(buffer)?;
        let pow_witness = SerializeProof::from_bytes(buffer)?;
        Ok(Self { commit_phase_commits, query_proofs, final_poly, pow_witness })
    }
}

impl SerializeProof for BatchOpening<Val, ValMmcs> {
    fn to_bytes<W: Write>(self, w: &mut W) -> io::Result<usize> {
        let Self { opened_values, opening_proof } = self;
        (opened_values, opening_proof).to_bytes(w)
    }

    fn from_bytes<R: Read>(buffer: &mut R) -> io::Result<Self> {
        let opened_values = SerializeProof::from_bytes(buffer)?;
        let opening_proof = SerializeProof::from_bytes(buffer)?;
        Ok(Self { opened_values, opening_proof })
    }
}

impl SerializeProof for TwoAdicFriPcsProof<Val, ExVal, ValMmcs, ChallengeMmcs> {
    fn to_bytes<W: Write>(self, w: &mut W) -> io::Result<usize> {
        let Self { fri_proof, query_openings } = self;
        let fri_proof: FriProof<ExVal, ChallengeMmcs, Val> = fri_proof;
        let query_openings: Vec<Vec<BatchOpening<Val, ValMmcs>>> = query_openings;
        (fri_proof, query_openings).to_bytes(w)
    }

    fn from_bytes<R: Read>(buffer: &mut R) -> io::Result<Self> {
        let fri_proof = SerializeProof::from_bytes(buffer)?;
        let query_openings = SerializeProof::from_bytes(buffer)?;
        Ok(Self { fri_proof, query_openings })
    }
}

impl SerializeProof for SP1Stdin {
    fn to_bytes<W: Write>(self, w: &mut W) -> io::Result<usize> {
        let Self { buffer, ptr, proofs } = self;
        //TODO: ignoring proofs for now
        assert!(proofs.is_empty());
        (buffer, ptr).to_bytes(w)
    }

    fn from_bytes<R: Read>(buffer: &mut R) -> io::Result<Self> {
        let buffer_ = SerializeProof::from_bytes(buffer)?;
        let ptr = SerializeProof::from_bytes(buffer)?;
        let proofs = vec![];
        let buffer = buffer_;
        Ok(Self { buffer, ptr, proofs })
    }
}

impl SerializeProof for SP1ProofWithMetadata<SP1CoreProofData> {
    fn to_bytes<W: Write>(self, w: &mut W) -> io::Result<usize> {
        let Self { proof, stdin, public_values, cycles } = self;
        (proof, stdin, public_values, cycles).to_bytes(w)
    }

    fn from_bytes<R: Read>(buffer: &mut R) -> io::Result<Self> {
        let (proof, stdin, public_values, cycles) = SerializeProof::from_bytes(buffer)?;
        Ok(Self { proof, stdin, public_values, cycles })
    }
}