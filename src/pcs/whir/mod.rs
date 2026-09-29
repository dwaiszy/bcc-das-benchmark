//! Adapter from coefficient-form local polynomials to unchanged upstream WHIR.

use std::convert::TryInto;
use std::io::Read;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use ark_poly::DenseUVPolynomial;
use rayon::prelude::*;
use whir::algebra::embedding::Identity;
use whir::algebra::fields::Field64_2;
use whir::algebra::linear_form::{Evaluate, LinearForm, MultilinearExtension};
use whir::algebra::ntt::{NttEngine, ReedSolomon, NTT};
use whir::buffer::{Buffer, BufferOps};
use whir::hash::Hash as WhirHash;
use whir::parameters::ProtocolParameters;
use whir::protocols::whir::{Config, Witness};
#[cfg(debug_assertions)]
use whir::transcript::Interaction;
use whir::transcript::{
    codecs::Empty, DomainSeparator, Proof as TranscriptProof, ProverState, VerifierMessage,
    VerifierState,
};

use self::univariate_to_multilinear::{coeffs_to_hypercube_evals, multilinear_point};
use crate::pcs::{ArcPcs, OpeningPoint, PcsError, VerificationTiming};

mod univariate_to_multilinear;

/// Failures normalized at the boundary between DAS and upstream WHIR.
///
/// Prover-side methods normally receive trusted protocol data, but checked
/// variants keep unsupported dimensions and malformed claim vectors from
/// escaping as assertion panics. Verifier-side callers should use
/// [`WhirLocalCodeScheme::verify_checked`] when they need to distinguish a
/// malformed request from a cryptographically invalid proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum WhirAdapterError {
    #[error("WHIR setup parameters are unsupported")]
    UnsupportedSetup,
    #[error("polynomial has {coefficients} coefficients, but WHIR supports at most {maximum}")]
    UnsupportedPolynomial { coefficients: usize, maximum: usize },
    #[error("a WHIR opening must contain at least one evaluation claim")]
    EmptyClaims,
    #[error("WHIR point/value lengths differ: {points} points and {values} values")]
    ClaimLengthMismatch { points: usize, values: usize },
    #[error("WHIR opening transcript does not extend its commitment transcript")]
    TranscriptPrefixMismatch,
    #[error("upstream WHIR rejected the operation")]
    BackendFailure,
    #[error("WHIR evaluation proof is invalid")]
    InvalidProof,
}

/// Upstream WHIR Goldilocks1 base field (8-byte serialized elements).
/// WHIR Goldilocks2 quadratic extension field (16-byte serialized elements).
pub type WhirField = Field64_2;
type WhirUniPoly = ark_poly::univariate::DensePolynomial<WhirField>;

fn ensure_field_registered() {
    static REGISTERED: OnceLock<()> = OnceLock::new();
    REGISTERED.get_or_init(|| {
        NTT.insert::<WhirField>(Arc::new(NttEngine::<WhirField>::new_from_fftfield())
            as Arc<dyn ReedSolomon<WhirField>>);
    });
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct WhirCommitment {
    inner: whir::protocols::whir::Commitment<WhirField>,
    transcript: Arc<TranscriptProof>,
}

impl WhirCommitment {
    pub fn compressed_size(&self) -> usize {
        self.transcript.narg_string.len() + self.transcript.hints.len()
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct WhirProof {
    /// Compressed proof envelope. It is decompressed before WHIR sees it.
    serialized: Vec<u8>,
    uncompressed_len: usize,
    #[cfg(debug_assertions)]
    pattern_suffix: Vec<Interaction>,
}

/// Byte-exact boundaries of the adapter's WHIR wire envelope. `narg_suffix`
/// and `hint_suffix` are the two upstream transcript buffers after removing
/// the commitment prefix. Upstream WHIR does not expose semantic subranges
/// (for example, "Merkle" versus "sumcheck") within those buffers, so this
/// is the finest byte-exact decomposition available without changing WHIR.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WhirProofEnvelopeBytes {
    pub compressed: usize,
    pub uncompressed: usize,
    pub envelope_metadata: usize,
    pub narg_suffix: usize,
    pub hint_suffix: usize,
}

impl WhirProof {
    const PROOF_FORMAT_TAG: &'static [u8; 4] = b"WHR1";
    const MAX_DECOMPRESSED_BYTES: usize = 64 * 1024 * 1024;

    /// Higher compression is useful for the large WHIR proof envelopes.  It
    /// changes only the wire representation, not the cryptographic proof.
    /// Keep it configurable because levels above 3 trade proving time for
    /// smaller network objects.
    pub fn compression_level() -> i32 {
        std::env::var("DAS_WHIR_COMPRESSION_LEVEL")
            .ok()
            .and_then(|value| value.parse::<i32>().ok())
            .filter(|&level| (0..=22).contains(&level))
            .unwrap_or(9)
    }

    pub fn compressed_size(&self) -> usize {
        self.serialized.len()
    }

    pub fn uncompressed_size(&self) -> usize {
        self.uncompressed_len
    }

    /// Return the exact serialized proof bytes. The cryptographic verifier
    /// never authenticates this compressed representation directly.
    pub fn serialized_bytes(&self) -> &[u8] {
        &self.serialized
    }

    pub fn envelope_bytes(&self) -> Result<WhirProofEnvelopeBytes, WhirAdapterError> {
        let decoded = if self.serialized.starts_with(Self::PROOF_FORMAT_TAG) {
            self.serialized.clone()
        } else {
            Self::decompress_bounded(&self.serialized)?
        };
        if decoded.len() < 12 || &decoded[..4] != Self::PROOF_FORMAT_TAG {
            return Err(WhirAdapterError::InvalidProof);
        }
        let narg_suffix = u32::from_le_bytes(
            decoded[4..8].try_into().map_err(|_| WhirAdapterError::InvalidProof)?,
        ) as usize;
        let hint_suffix = u32::from_le_bytes(
            decoded[8..12].try_into().map_err(|_| WhirAdapterError::InvalidProof)?,
        ) as usize;
        if decoded.len() != 12 + narg_suffix + hint_suffix {
            return Err(WhirAdapterError::InvalidProof);
        }
        Ok(WhirProofEnvelopeBytes {
            compressed: self.compressed_size(),
            uncompressed: decoded.len(),
            envelope_metadata: 12,
            narg_suffix,
            hint_suffix,
        })
    }

    /// Decode a proof received from the network. Decompression is bounded by
    /// the envelope's declared lengths before the proof reaches WHIR.
    pub fn from_serialized_bytes(bytes: &[u8]) -> Result<Self, WhirAdapterError> {
        let decoded = if bytes.starts_with(Self::PROOF_FORMAT_TAG) {
            bytes.to_vec()
        } else {
            Self::decompress_bounded(bytes)?
        };
        Self::from_uncompressed_serialized(&decoded)
    }

    fn decompress_bounded(bytes: &[u8]) -> Result<Vec<u8>, WhirAdapterError> {
        let decoder =
            zstd::stream::read::Decoder::new(bytes).map_err(|_| WhirAdapterError::InvalidProof)?;
        let mut decoded = Vec::new();
        decoder
            .take((Self::MAX_DECOMPRESSED_BYTES + 1) as u64)
            .read_to_end(&mut decoded)
            .map_err(|_| WhirAdapterError::InvalidProof)?;
        if decoded.len() > Self::MAX_DECOMPRESSED_BYTES {
            return Err(WhirAdapterError::InvalidProof);
        }
        Ok(decoded)
    }

    fn from_uncompressed_serialized(bytes: &[u8]) -> Result<Self, WhirAdapterError> {
        if bytes.len() < 12 || &bytes[..4] != Self::PROOF_FORMAT_TAG {
            return Err(WhirAdapterError::InvalidProof);
        }
        let narg_len = u32::from_le_bytes(
            bytes[4..8]
                .try_into()
                .map_err(|_| WhirAdapterError::InvalidProof)?,
        ) as usize;
        let hints_len = u32::from_le_bytes(
            bytes[8..12]
                .try_into()
                .map_err(|_| WhirAdapterError::InvalidProof)?,
        ) as usize;
        let payload_len = narg_len
            .checked_add(hints_len)
            .ok_or(WhirAdapterError::InvalidProof)?;
        if bytes.len() != 12 + payload_len {
            return Err(WhirAdapterError::InvalidProof);
        }
        let serialized = if Self::compression_level() == 0 {
            bytes.to_vec()
        } else {
            zstd::stream::encode_all(bytes, Self::compression_level())
                .map_err(|_| WhirAdapterError::InvalidProof)?
        };
        Ok(Self {
            serialized,
            uncompressed_len: bytes.len(),
            #[cfg(debug_assertions)]
            pattern_suffix: Vec::new(),
        })
    }

    fn from_full_timed(
        full: TranscriptProof,
        prefix: &TranscriptProof,
    ) -> Result<(Self, Duration, Duration), WhirAdapterError> {
        let serialization_started = Instant::now();
        if !full.narg_string.starts_with(&prefix.narg_string)
            || !full.hints.starts_with(&prefix.hints)
        {
            return Err(WhirAdapterError::TranscriptPrefixMismatch);
        }
        #[cfg(debug_assertions)]
        if !full.pattern.starts_with(&prefix.pattern) {
            return Err(WhirAdapterError::TranscriptPrefixMismatch);
        }
        let narg_suffix = &full.narg_string[prefix.narg_string.len()..];
        let hints_suffix = &full.hints[prefix.hints.len()..];
        let mut uncompressed = Vec::with_capacity(12 + narg_suffix.len() + hints_suffix.len());
        uncompressed.extend_from_slice(Self::PROOF_FORMAT_TAG);
        uncompressed.extend_from_slice(&(narg_suffix.len() as u32).to_le_bytes());
        uncompressed.extend_from_slice(&(hints_suffix.len() as u32).to_le_bytes());
        uncompressed.extend_from_slice(narg_suffix);
        uncompressed.extend_from_slice(hints_suffix);
        let serialization = serialization_started.elapsed();
        let compression_started = Instant::now();
        let serialized = if Self::compression_level() == 0 {
            uncompressed.clone()
        } else {
            zstd::stream::encode_all(&uncompressed[..], Self::compression_level())
                .map_err(|_| WhirAdapterError::BackendFailure)?
        };
        let compression = if Self::compression_level() == 0 {
            Duration::ZERO
        } else {
            compression_started.elapsed()
        };
        Ok((
            Self {
                serialized,
                uncompressed_len: uncompressed.len(),
                #[cfg(debug_assertions)]
                pattern_suffix: full.pattern[prefix.pattern.len()..].to_vec(),
            },
            serialization,
            compression,
        ))
    }

    fn with_prefix(&self, prefix: &TranscriptProof) -> Option<TranscriptProof> {
        let decoded = if self.serialized.starts_with(Self::PROOF_FORMAT_TAG) {
            self.serialized.clone()
        } else {
            Self::decompress_bounded(self.serialized.as_slice()).ok()?
        };
        if decoded.len() < 12 || &decoded[..4] != Self::PROOF_FORMAT_TAG {
            return None;
        }
        let narg_len = u32::from_le_bytes(decoded[4..8].try_into().ok()?) as usize;
        let hints_len = u32::from_le_bytes(decoded[8..12].try_into().ok()?) as usize;
        if decoded.len() != 12usize.checked_add(narg_len)?.checked_add(hints_len)? {
            return None;
        }
        let narg_end = 12 + narg_len;
        let mut narg_string = prefix.narg_string.clone();
        narg_string.extend_from_slice(&decoded[12..narg_end]);
        let mut hints = prefix.hints.clone();
        hints.extend_from_slice(&decoded[narg_end..]);
        #[cfg(debug_assertions)]
        let pattern = prefix
            .pattern
            .iter()
            .cloned()
            .chain(self.pattern_suffix.iter().cloned())
            .collect();
        Some(TranscriptProof {
            narg_string,
            hints,
            #[cfg(debug_assertions)]
            pattern,
        })
    }
}

pub struct WhirState {
    /// The immutable evaluation vector is retained in backend storage so each
    /// scalar opening does not copy it before calling WHIR.
    vector: Buffer<WhirField>,
    /// Commitment witness (matrix, Merkle witness and OOD evaluations). WHIR's
    /// proving API borrows this witness, so it is safe to reuse for openings.
    witness: Witness<WhirField, Identity<WhirField>>,
    commitment_root: WhirHash,
    commitment_transcript: Arc<TranscriptProof>,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct WhirOpeningTiming {
    pub state_clone_or_rebuild: Duration,
    pub point_preparation: Duration,
    pub evaluation_check: Duration,
    pub whir_cryptographic_prove: Duration,
    pub proof_serialization: Duration,
    pub proof_compression: Duration,
}

pub struct WhirLocalCodeScheme {
    params: Config<Identity<WhirField>>,
    domain_separator: DomainSeparator<'static, Empty>,
    num_vars: usize,
}

const SESSION_LABEL: &str = "block-circulant-codes/pcs/whir";

fn whir_point(z: WhirField, num_vars: usize) -> Vec<WhirField> {
    let mut point = multilinear_point(z, num_vars);
    point.reverse();
    point
}

impl WhirLocalCodeScheme {
    pub fn setup(max_degree: usize, parameters: &ProtocolParameters) -> Self {
        Self::try_setup(max_degree, parameters).expect("valid WHIR setup parameters")
    }

    pub fn try_setup(
        max_degree: usize,
        parameters: &ProtocolParameters,
    ) -> Result<Self, WhirAdapterError> {
        ensure_field_registered();
        let vector_len = max_degree
            .checked_add(1)
            .and_then(usize::checked_next_power_of_two)
            .map(|length| length.max(2))
            .ok_or(WhirAdapterError::UnsupportedSetup)?;
        let num_vars = vector_len.trailing_zeros() as usize;
        catch_unwind(AssertUnwindSafe(|| {
            let params = Config::<Identity<WhirField>>::new(vector_len, parameters);
            let domain_separator = DomainSeparator::protocol(&params)
                .session(&SESSION_LABEL.to_string())
                .instance(&Empty);
            Self {
                params,
                domain_separator,
                num_vars,
            }
        }))
        .map_err(|_| WhirAdapterError::UnsupportedSetup)
    }

    pub fn commit(&self, polynomial: &WhirUniPoly) -> (WhirCommitment, WhirState) {
        self.commit_checked(polynomial)
            .expect("polynomial fits the configured WHIR dimension")
    }

    pub fn commit_checked(
        &self,
        polynomial: &WhirUniPoly,
    ) -> Result<(WhirCommitment, WhirState), WhirAdapterError> {
        let maximum = 1usize << self.num_vars;
        if polynomial.coeffs.len() > maximum {
            return Err(WhirAdapterError::UnsupportedPolynomial {
                coefficients: polynomial.coeffs.len(),
                maximum,
            });
        }
        catch_unwind(AssertUnwindSafe(|| self.commit_inner(polynomial)))
            .map_err(|_| WhirAdapterError::BackendFailure)
    }

    fn commit_inner(&self, polynomial: &WhirUniPoly) -> (WhirCommitment, WhirState) {
        let vector = Buffer::from(coeffs_to_hypercube_evals(&polynomial.coeffs, self.num_vars));
        let mut prover = ProverState::new_std(&self.domain_separator);
        let witness = self.params.commit(&mut prover, &[&vector]);
        let transcript = Arc::new(prover.proof());
        let mut verifier = VerifierState::new_std(&self.domain_separator, &transcript);
        let commitment_root: WhirHash = verifier
            .prover_message()
            .expect("WHIR commitment root must be present");
        let mut verifier = VerifierState::new_std(&self.domain_separator, &transcript);
        let inner = self
            .params
            .receive_commitment(&mut verifier)
            .expect("WHIR must parse its own commitment transcript");
        (
            WhirCommitment {
                inner,
                transcript: Arc::clone(&transcript),
            },
            WhirState {
                vector,
                witness,
                commitment_root,
                commitment_transcript: transcript,
            },
        )
    }

    /// Replays only the immutable commitment prefix. WHIR's public API does
    /// not expose a transcript snapshot, but the prefix consists of the root,
    /// OOD challenges and OOD evaluations emitted by `Config::commit`.
    fn replay_commitment_prefix(&self, state: &WhirState) -> ProverState {
        let mut prover = ProverState::new_std(&self.domain_separator);
        prover.prover_message(&state.commitment_root);
        for point in &state.witness.out_of_domain.points {
            let replayed: WhirField = prover.verifier_message();
            debug_assert_eq!(replayed, *point);
        }
        for row in state.witness.out_of_domain.rows() {
            for value in row {
                prover.prover_message(value);
            }
        }
        prover
    }

    pub fn open(&self, state: &WhirState, point: WhirField) -> WhirProof {
        self.open_checked(state, point)
            .expect("one-point WHIR opening is supported")
    }

    pub fn open_checked(
        &self,
        state: &WhirState,
        point: WhirField,
    ) -> Result<WhirProof, WhirAdapterError> {
        self.open_all_checked(state, &[point])
    }

    pub fn open_all(&self, state: &WhirState, points: &[WhirField]) -> WhirProof {
        self.open_all_checked(state, points)
            .expect("valid WHIR opening claims")
    }

    pub fn open_all_checked(
        &self,
        state: &WhirState,
        points: &[WhirField],
    ) -> Result<WhirProof, WhirAdapterError> {
        if points.is_empty() {
            return Err(WhirAdapterError::EmptyClaims);
        }
        let evaluations = points
            .iter()
            .map(|&point| {
                MultilinearExtension::new(whir_point(point, self.num_vars))
                    .evaluate(self.params.embedding(), state.vector.to_slice())
            })
            .collect::<Vec<_>>();
        self.prove_checked(state, points, &evaluations)
    }

    pub fn open_all_with_evaluations(
        &self,
        state: &WhirState,
        points: &[WhirField],
        evaluations: &[WhirField],
    ) -> WhirProof {
        self.open_all_with_evaluations_checked(state, points, evaluations)
            .expect("valid WHIR opening claims")
    }

    pub fn open_all_with_evaluations_checked(
        &self,
        state: &WhirState,
        points: &[WhirField],
        evaluations: &[WhirField],
    ) -> Result<WhirProof, WhirAdapterError> {
        self.open_all_with_evaluations_checked_timed(state, points, evaluations)
            .map(|(proof, _)| proof)
    }

    pub fn open_all_with_evaluations_checked_timed(
        &self,
        state: &WhirState,
        points: &[WhirField],
        evaluations: &[WhirField],
    ) -> Result<(WhirProof, WhirOpeningTiming), WhirAdapterError> {
        let evaluation_started = Instant::now();
        validate_claim_shape(points, evaluations)?;
        let evaluation_check = evaluation_started.elapsed();
        let (proof, mut timing) = self.prove_checked_timed(state, points, evaluations)?;
        timing.evaluation_check = evaluation_check;
        Ok((proof, timing))
    }

    fn prove_checked(
        &self,
        state: &WhirState,
        points: &[WhirField],
        evaluations: &[WhirField],
    ) -> Result<WhirProof, WhirAdapterError> {
        self.prove_checked_timed(state, points, evaluations)
            .map(|(proof, _)| proof)
    }

    fn prove_checked_timed(
        &self,
        state: &WhirState,
        points: &[WhirField],
        evaluations: &[WhirField],
    ) -> Result<(WhirProof, WhirOpeningTiming), WhirAdapterError> {
        catch_unwind(AssertUnwindSafe(|| {
            self.prove_inner_timed(state, points, evaluations)
        }))
        .map_err(|_| WhirAdapterError::BackendFailure)?
    }

    fn prove_inner_timed(
        &self,
        state: &WhirState,
        points: &[WhirField],
        evaluations: &[WhirField],
    ) -> Result<(WhirProof, WhirOpeningTiming), WhirAdapterError> {
        let state_started = Instant::now();
        let mut prover = self.replay_commitment_prefix(state);
        let state_clone_or_rebuild = state_started.elapsed();
        let point_started = Instant::now();
        let forms = points
            .iter()
            .map(|&point| {
                Box::new(MultilinearExtension::new(whir_point(point, self.num_vars)))
                    as Box<dyn LinearForm<WhirField>>
            })
            .collect();
        let point_preparation = point_started.elapsed();
        let prove_started = Instant::now();
        let _ = self.params.prove(
            &mut prover,
            &[&state.vector],
            vec![&state.witness],
            forms,
            Buffer::from(evaluations),
        );
        let whir_cryptographic_prove = prove_started.elapsed();
        let (proof, proof_serialization, proof_compression) =
            WhirProof::from_full_timed(prover.proof(), &state.commitment_transcript)?;
        Ok((
            proof,
            WhirOpeningTiming {
                state_clone_or_rebuild,
                point_preparation,
                whir_cryptographic_prove,
                proof_serialization,
                proof_compression,
                ..WhirOpeningTiming::default()
            },
        ))
    }

    pub fn verify(
        &self,
        commitment: &WhirCommitment,
        point: WhirField,
        value: WhirField,
        proof: &WhirProof,
    ) -> bool {
        self.verify_checked(commitment, point, value, proof).is_ok()
    }

    pub fn verify_checked(
        &self,
        commitment: &WhirCommitment,
        point: WhirField,
        value: WhirField,
        proof: &WhirProof,
    ) -> Result<(), WhirAdapterError> {
        self.verify_all_checked(commitment, &[point], &[value], proof)
    }

    fn verify_checked_timed(
        &self,
        commitment: &WhirCommitment,
        point: WhirField,
        value: WhirField,
        proof: &WhirProof,
    ) -> Result<std::time::Duration, WhirAdapterError> {
        let mut decompression = std::time::Duration::ZERO;
        self.verify_all_checked_inner(commitment, &[point], &[value], proof, &mut decompression)?;
        Ok(decompression)
    }

    fn verify_all_checked_inner(
        &self,
        commitment: &WhirCommitment,
        points: &[WhirField],
        values: &[WhirField],
        proof: &WhirProof,
        decompression: &mut std::time::Duration,
    ) -> Result<(), WhirAdapterError> {
        validate_claim_shape(points, values)?;
        catch_unwind(AssertUnwindSafe(|| {
            self.verify_all_inner_timed(commitment, points, values, proof, decompression)
        }))
        .map_err(|_| WhirAdapterError::InvalidProof)?
        .then_some(())
        .ok_or(WhirAdapterError::InvalidProof)
    }

    pub fn verify_all(
        &self,
        commitment: &WhirCommitment,
        points: &[WhirField],
        values: &[WhirField],
        proof: &WhirProof,
    ) -> bool {
        self.verify_all_checked(commitment, points, values, proof)
            .is_ok()
    }

    pub fn verify_all_checked(
        &self,
        commitment: &WhirCommitment,
        points: &[WhirField],
        values: &[WhirField],
        proof: &WhirProof,
    ) -> Result<(), WhirAdapterError> {
        validate_claim_shape(points, values)?;
        // WHIR's verifier contains assertion-style field division. Network
        // input must never let that panic escape the DAS verification seam.
        let mut decompression = std::time::Duration::ZERO;
        self.verify_all_checked_inner(commitment, points, values, proof, &mut decompression)
    }

    fn verify_all_inner_timed(
        &self,
        commitment: &WhirCommitment,
        points: &[WhirField],
        values: &[WhirField],
        proof: &WhirProof,
        decompression: &mut std::time::Duration,
    ) -> bool {
        let decompression_started = std::time::Instant::now();
        let transcript = match proof.with_prefix(&commitment.transcript) {
            Some(transcript) => transcript,
            None => return false,
        };
        *decompression += decompression_started.elapsed();
        let mut verifier = VerifierState::new_std(&self.domain_separator, &transcript);
        let parsed = match self.params.receive_commitment(&mut verifier) {
            Ok(parsed) if parsed == commitment.inner => parsed,
            _ => return false,
        };
        let claim = match self.params.verify(&mut verifier, &[&parsed], values) {
            Ok(claim) => claim,
            Err(_) => return false,
        };
        let forms = points
            .iter()
            .map(|&point| {
                Box::new(MultilinearExtension::new(whir_point(point, self.num_vars)))
                    as Box<dyn LinearForm<WhirField>>
            })
            .collect::<Vec<_>>();
        claim.verify(forms.iter().map(|form| form.as_ref())).is_ok()
    }
}

fn validate_claim_shape(
    points: &[WhirField],
    values: &[WhirField],
) -> Result<(), WhirAdapterError> {
    if points.is_empty() {
        return Err(WhirAdapterError::EmptyClaims);
    }
    if points.len() != values.len() {
        return Err(WhirAdapterError::ClaimLengthMismatch {
            points: points.len(),
            values: values.len(),
        });
    }
    Ok(())
}

impl ArcPcs<WhirField> for WhirLocalCodeScheme {
    type Commitment = WhirCommitment;
    type ProverState = WhirState;
    type Proof = WhirProof;

    fn commit(
        &self,
        coefficients: &[WhirField],
    ) -> Result<(Self::Commitment, Self::ProverState), PcsError> {
        let polynomial = WhirUniPoly::from_coefficients_vec(coefficients.to_vec());
        Ok(WhirLocalCodeScheme::commit(self, &polynomial))
    }

    fn precompute_openings(
        &self,
        state: &Self::ProverState,
        points: &[OpeningPoint<WhirField>],
    ) -> Result<Vec<Self::Proof>, PcsError> {
        Ok(points
            .par_iter()
            .map(|point| self.open(state, point.point()))
            .collect())
    }

    fn precompute_openings_with_values(
        &self,
        state: &Self::ProverState,
        points: &[OpeningPoint<WhirField>],
        values: &[WhirField],
    ) -> Result<Vec<Self::Proof>, PcsError> {
        if points.len() != values.len() {
            return Err(PcsError::Open);
        }
        points
            .par_iter()
            .zip(values.par_iter())
            .map(|(point, value)| {
                self.open_all_with_evaluations_checked(state, &[point.point()], &[*value])
                    .map_err(|_| PcsError::Open)
            })
            .collect()
    }

    fn verify(
        &self,
        commitment: &Self::Commitment,
        point: WhirField,
        value: WhirField,
        proof: &Self::Proof,
    ) -> Result<(), PcsError> {
        WhirLocalCodeScheme::verify(self, commitment, point, value, proof)
            .then_some(())
            .ok_or(PcsError::Verification)
    }

    fn verify_batch_timed(
        &self,
        entries: &[(&Self::Commitment, WhirField, WhirField, &Self::Proof)],
    ) -> Result<VerificationTiming, PcsError> {
        let started = std::time::Instant::now();
        let mut decompression = std::time::Duration::ZERO;
        for &(commitment, point, value, proof) in entries {
            decompression += self
                .verify_checked_timed(commitment, point, value, proof)
                .map_err(|_| PcsError::Verification)?;
        }
        let total = started.elapsed();
        Ok(VerificationTiming {
            commitment_selection: std::time::Duration::ZERO,
            evaluation_point: std::time::Duration::ZERO,
            batch_preparation: std::time::Duration::ZERO,
            proof_deserialization: std::time::Duration::ZERO,
            decompression,
            pcs_verification: total.saturating_sub(decompression),
            total,
        })
    }

    fn commitment_bytes(&self, commitment: &Self::Commitment) -> usize {
        commitment.compressed_size()
    }
    fn proof_bytes(&self, proof: &Self::Proof) -> usize {
        proof.compressed_size()
    }
}

#[cfg(test)]
mod tests {
    use ark_poly::{DenseUVPolynomial, Polynomial};
    use whir::cmdline_utils::AvailableHash;
    use whir::parameters::ProtocolParameters;
    use whir::protocols::params::DecodingRegime;

    use super::{WhirAdapterError, WhirField, WhirLocalCodeScheme, WhirUniPoly};

    fn parameters(security_level: usize) -> ProtocolParameters {
        ProtocolParameters {
            decoding_regime: DecodingRegime::Johnson,
            starting_log_inv_rate: 1,
            initial_folding_factor: 2,
            folding_factor: 2,
            security_level,
            pow_bits: 0,
            batch_size: 1,
            hash_id: AvailableHash::Blake3.hash_id(),
        }
    }

    #[test]
    fn adapter_authenticates_a_single_univariate_evaluation() {
        let parameters = parameters(40);
        let pcs = WhirLocalCodeScheme::setup(511, &parameters);
        let polynomial = WhirUniPoly::from_coefficients_vec(vec![
            WhirField::from(7_u64),
            WhirField::from(9_u64),
        ]);
        let point = WhirField::from(3_u64);
        let (commitment, state) = pcs.commit(&polynomial);
        let proof = pcs.open(&state, point);
        assert!(pcs.verify(&commitment, point, polynomial.evaluate(&point), &proof));
        assert!(pcs.verify(
            &commitment.clone(),
            point,
            polynomial.evaluate(&point),
            &proof.clone()
        ));

        let corner = WhirField::from(1_u64);
        let corner_proof = pcs.open(&state, corner);
        assert!(pcs.verify(
            &commitment,
            corner,
            polynomial.evaluate(&corner),
            &corner_proof
        ));

        let full_degree = WhirUniPoly::from_coefficients_vec(
            (0..512)
                .map(|coefficient| WhirField::from(coefficient as u64 + 1))
                .collect(),
        );
        let (full_commitment, full_state) = pcs.commit(&full_degree);
        let full_proof = pcs.open(&full_state, corner);
        assert!(pcs.verify(
            &full_commitment,
            corner,
            full_degree.evaluate(&corner),
            &full_proof
        ));

        let code = crate::FftBlockCirculantCode::<WhirField>::new(crate::BcParams {
            mu: 4,
            omega: 256,
            rho: 768,
        });
        let message = (0..code.params().k())
            .map(|value| WhirField::from(value as u64 + 41))
            .collect::<Vec<_>>();
        let (_, local_coefficients) = code.encode_with_local_polys(&message).unwrap();
        for (arc, coefficients) in local_coefficients.into_iter().enumerate() {
            let local = WhirUniPoly::from_coefficients_vec(coefficients);
            let local_point = code.eval_point(arc * code.params().period());
            let (local_commitment, local_state) = pcs.commit(&local);
            let local_proof = pcs.open(&local_state, local_point);
            assert!(pcs.verify(
                &local_commitment,
                local_point,
                local.evaluate(&local_point),
                &local_proof
            ));
        }
    }

    #[test]
    fn checked_boundary_rejects_unsupported_shapes_without_panicking() {
        let pcs = WhirLocalCodeScheme::try_setup(3, &parameters(40)).unwrap();
        let oversized = WhirUniPoly::from_coefficients_vec(vec![WhirField::from(1_u64); 5]);
        assert!(matches!(
            pcs.commit_checked(&oversized),
            Err(WhirAdapterError::UnsupportedPolynomial {
                coefficients: 5,
                maximum: 4,
            })
        ));

        let polynomial = WhirUniPoly::from_coefficients_vec(vec![
            WhirField::from(2_u64),
            WhirField::from(3_u64),
        ]);
        let (_, state) = pcs.commit_checked(&polynomial).unwrap();
        assert_eq!(
            pcs.open_all_checked(&state, &[]).unwrap_err(),
            WhirAdapterError::EmptyClaims
        );
        assert_eq!(
            pcs.open_all_with_evaluations_checked(
                &state,
                &[WhirField::from(1_u64)],
                &[WhirField::from(1_u64), WhirField::from(2_u64)],
            )
            .unwrap_err(),
            WhirAdapterError::ClaimLengthMismatch {
                points: 1,
                values: 2,
            }
        );
        assert!(matches!(
            WhirLocalCodeScheme::try_setup(usize::MAX, &parameters(40)),
            Err(WhirAdapterError::UnsupportedSetup)
        ));
    }

    #[test]
    fn a_zero_evaluation_uses_the_normal_whir_proof_path() {
        let pcs = WhirLocalCodeScheme::try_setup(3, &parameters(40)).unwrap();
        // This is a nonzero polynomial with an ordinary zero-valued symbol;
        // no polynomial mutation or synthetic proof is involved.
        let zero = WhirField::from(0_u64);
        let polynomial = WhirUniPoly::from_coefficients_vec(vec![zero, WhirField::from(7_u64)]);
        let point = zero;
        let (commitment, state) = pcs.commit_checked(&polynomial).unwrap();
        let proof = pcs.open_checked(&state, point).unwrap();
        assert_eq!(polynomial.evaluate(&point), zero);
        assert_eq!(pcs.verify_checked(&commitment, point, zero, &proof), Ok(()));
    }

    #[test]
    fn johnson_80_bit_profile_commits_opens_and_verifies() {
        let pcs = WhirLocalCodeScheme::try_setup(3, &parameters(80)).unwrap();
        let polynomial = WhirUniPoly::from_coefficients_vec(vec![
            WhirField::from(3_u64),
            WhirField::from(1_u64),
            WhirField::from(4_u64),
            WhirField::from(1_u64),
        ]);
        let point = WhirField::from(9_u64);
        let value = polynomial.evaluate(&point);
        let (commitment, state) = pcs.commit_checked(&polynomial).unwrap();
        let proof = pcs.open_checked(&state, point).unwrap();
        assert_eq!(
            pcs.verify_checked(&commitment, point, value, &proof),
            Ok(())
        );
    }

    #[test]
    fn native_multi_point_proof_binds_every_claimed_value() {
        let pcs = WhirLocalCodeScheme::try_setup(7, &parameters(40)).unwrap();
        let polynomial =
            WhirUniPoly::from_coefficients_vec((1_u64..=8).map(WhirField::from).collect());
        let points = (11_u64..=14).map(WhirField::from).collect::<Vec<_>>();
        let values = points
            .iter()
            .map(|point| polynomial.evaluate(point))
            .collect::<Vec<_>>();
        let (commitment, state) = pcs.commit_checked(&polynomial).unwrap();
        let proof = pcs
            .open_all_with_evaluations_checked(&state, &points, &values)
            .unwrap();

        assert_eq!(
            pcs.verify_all_checked(&commitment, &points, &values, &proof),
            Ok(())
        );
        let mut wrong_values = values;
        wrong_values[2] += WhirField::from(1_u64);
        assert_eq!(
            pcs.verify_all_checked(&commitment, &points, &wrong_values, &proof),
            Err(WhirAdapterError::InvalidProof)
        );
    }

    #[test]
    fn malformed_and_mismatched_claims_return_typed_errors() {
        let pcs = WhirLocalCodeScheme::try_setup(3, &parameters(40)).unwrap();
        let polynomial = WhirUniPoly::from_coefficients_vec(vec![
            WhirField::from(5_u64),
            WhirField::from(9_u64),
        ]);
        let point = WhirField::from(3_u64);
        let value = polynomial.evaluate(&point);
        let (commitment, state) = pcs.commit_checked(&polynomial).unwrap();
        let proof = pcs.open_checked(&state, point).unwrap();

        assert_eq!(
            pcs.verify_all_checked(&commitment, &[], &[], &proof),
            Err(WhirAdapterError::EmptyClaims)
        );
        assert_eq!(
            pcs.verify_all_checked(&commitment, &[point], &[value, value], &proof),
            Err(WhirAdapterError::ClaimLengthMismatch {
                points: 1,
                values: 2,
            })
        );
        assert_eq!(
            pcs.verify_checked(&commitment, point, value + WhirField::from(1_u64), &proof),
            Err(WhirAdapterError::InvalidProof)
        );

        let mut malformed = proof;
        if let Some(byte) = malformed.serialized.last_mut() {
            *byte ^= 0x80;
        } else {
            panic!("a WHIR opening proof must contain transport bytes");
        }
        assert_eq!(
            pcs.verify_checked(&commitment, point, value, &malformed),
            Err(WhirAdapterError::InvalidProof)
        );
    }
}
