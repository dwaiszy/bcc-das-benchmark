//! Scalar opening generation for one encoded local polynomial.

use ark_ff::FftField;

use crate::das::core::das_workflow::EvaluationClaim;
use crate::pcs::{ArcPcs, PcsError};

pub(super) trait OpeningStrategy<F, P>
where
    F: FftField,
    P: ArcPcs<F>,
{
    fn precompute(
        pcs: &P,
        state: &P::ProverState,
        claims: &[EvaluationClaim<F>],
    ) -> Result<Vec<P::Proof>, PcsError>;
}

pub(super) struct ScalarOpening;

impl<F, P> OpeningStrategy<F, P> for ScalarOpening
where
    F: FftField,
    P: ArcPcs<F>,
{
    fn precompute(
        pcs: &P,
        state: &P::ProverState,
        claims: &[EvaluationClaim<F>],
    ) -> Result<Vec<P::Proof>, PcsError> {
        let points = claims
            .iter()
            .map(EvaluationClaim::opening_point)
            .collect::<Vec<_>>();
        let values = claims
            .iter()
            .map(EvaluationClaim::value)
            .collect::<Vec<_>>();
        pcs.precompute_openings_with_values(state, &points, &values)
    }
}
