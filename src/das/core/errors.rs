//! Error types for code construction, preparation, verification, and extraction.

use thiserror::Error;

use crate::BcError;
use crate::pcs::PcsError;

#[derive(Debug, Error)]
pub enum CodeError {
    #[error("erasure-code geometry is invalid")]
    InvalidGeometry,
    #[error("message length does not match the erasure-code dimension")]
    WrongMessageLength,
    #[error("encoded local-code shape is invalid")]
    InvalidEncodedShape,
    #[error("local polynomial shape is invalid")]
    InvalidPolynomialShape,
    #[error("a local polynomial does not evaluate to the encoded symbol")]
    InconsistentLocalPolynomial,
    #[error("global or local position is out of range")]
    PositionOutOfRange,
    #[error("erasure-code operation failed: {0}")]
    Codec(#[from] BcError),
}

#[derive(Debug, Error)]
pub enum SetupError {
    #[error("protocol configuration does not match the selected adapters")]
    ConfigMismatch,
    #[error("failed to construct the proposer Rayon pool")]
    ThreadPool,
    #[error(transparent)]
    Code(#[from] CodeError),
    #[error(transparent)]
    Pcs(#[from] PcsError),
}

#[derive(Debug, Error)]
pub enum PrepareError {
    #[error("message length {got} does not match {expected}")]
    WrongMessageLength { got: usize, expected: usize },
    #[error("PCS returned the wrong number of scalar proofs")]
    WrongProofCount,
    #[error(transparent)]
    Code(#[from] CodeError),
    #[error(transparent)]
    Pcs(#[from] PcsError),
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum VerificationError {
    #[error("header selects a different protocol configuration")]
    WrongConfig,
    #[error("header contains the wrong number of ordered commitments")]
    WrongCommitmentCount,
    #[error("sample count does not match the protocol configuration")]
    WrongSampleCount,
    #[error("one light client cannot sample the same index twice")]
    DuplicateSample,
    #[error("sample position is outside the encoded block")]
    PositionOutOfRange,
    #[error("sample plan or response order does not match the header")]
    PlanMismatch,
    #[error("a required dispersed response is missing")]
    MissingResponse,
    #[error("response does not match the canonical local-code claim")]
    NonCanonicalClaim,
    #[error("commitment is not the sampled position's owning local-code commitment")]
    WrongCommitment,
    #[error("PCS proof verification failed")]
    InvalidProof,
    #[error("authenticated BCC arcs disagree on an overlapping position")]
    InconsistentOverlap,
}

#[derive(Debug, Error)]
pub enum ExtractionError {
    #[error("header verification failed: {0}")]
    Verification(VerificationError),
    #[error("transcript belongs to another block or configuration")]
    WrongTranscript,
    #[error("verified transcripts conflict at one global index")]
    ConflictingValue,
    #[error("received {got} distinct symbols but require {required}")]
    InsufficientReception { got: usize, required: usize },
    #[error(transparent)]
    Code(CodeError),
}
