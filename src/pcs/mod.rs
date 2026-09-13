//! Common polynomial-commitment interface shared by KZG and WHIR adapters.

pub mod kzg;
pub mod whir;
pub use kzg::{KzgLocalCodeScheme, MultipointProof, UniPoly, local_message_polynomial};

use ark_ff::FftField;
use std::time::Duration;
use thiserror::Error;

/// Verification timing split for serialized-proof processing and cryptographic
/// checking. `total` includes `decompression`.
#[derive(Clone, Copy, Debug, Default)]
pub struct VerificationTiming {
    pub decompression: Duration,
    pub total: Duration,
}

/// One legal point in an erasure code's local evaluation domain.
#[derive(Clone, Copy, Debug)]
pub struct OpeningPoint<F> {
    point: F,
    domain_index: usize,
}

impl<F: Copy> OpeningPoint<F> {
    pub(crate) const fn new(point: F, domain_index: usize) -> Self {
        Self {
            point,
            domain_index,
        }
    }

    pub const fn point(&self) -> F {
        self.point
    }

    pub const fn domain_index(&self) -> usize {
        self.domain_index
    }
}

/// PCS failures normalized before they cross the DAS seam.
#[derive(Debug, Error)]
pub enum PcsError {
    #[error("PCS setup failed")]
    Setup,
    #[error("PCS commitment failed")]
    Commit,
    #[error("PCS opening failed")]
    Open,
    #[error("opening point is outside the configured structured domain")]
    UnsupportedPoint,
    #[error("PCS proof verification failed")]
    Verification,
}

/// Deep interface implemented by a PCS for one independently committed local code.
pub trait ArcPcs<F: FftField>: Send + Sync + 'static {
    type Commitment: Send + Sync + 'static;
    type ProverState: Send + Sync + 'static;
    type Proof: Clone + Send + Sync + 'static;

    fn commit(&self, coefficients: &[F])
    -> Result<(Self::Commitment, Self::ProverState), PcsError>;

    /// Generate the scalar oracle for one local polynomial in local-index order.
    fn precompute_openings(
        &self,
        state: &Self::ProverState,
        points: &[OpeningPoint<F>],
    ) -> Result<Vec<Self::Proof>, PcsError>;

    /// Generate scalar openings when the erasure-code layer already knows
    /// the evaluations at `points`. Backends that cannot use the values keep
    /// the existing path; this avoids redundant evaluation work in backends
    /// such as WHIR without changing the claims or proof equations.
    fn precompute_openings_with_values(
        &self,
        state: &Self::ProverState,
        points: &[OpeningPoint<F>],
        values: &[F],
    ) -> Result<Vec<Self::Proof>, PcsError> {
        if points.len() != values.len() {
            return Err(PcsError::Open);
        }
        self.precompute_openings(state, points)
    }

    fn verify(
        &self,
        commitment: &Self::Commitment,
        point: F,
        value: F,
        proof: &Self::Proof,
    ) -> Result<(), PcsError>;

    fn commitment_bytes(&self, commitment: &Self::Commitment) -> usize;

    /// Verify existing scalar proofs together. Backends may reuse a native
    /// batch verifier; the default preserves individual verification.
    fn verify_batch(
        &self,
        entries: &[(&Self::Commitment, F, F, &Self::Proof)],
    ) -> Result<(), PcsError> {
        for &(commitment, point, value, proof) in entries {
            self.verify(commitment, point, value, proof)?;
        }
        Ok(())
    }

    fn verify_batch_timed(
        &self,
        entries: &[(&Self::Commitment, F, F, &Self::Proof)],
    ) -> Result<VerificationTiming, PcsError> {
        let started = std::time::Instant::now();
        self.verify_batch(entries)?;
        Ok(VerificationTiming {
            decompression: Duration::ZERO,
            total: started.elapsed(),
        })
    }

    fn proof_bytes(&self, proof: &Self::Proof) -> usize;
}
