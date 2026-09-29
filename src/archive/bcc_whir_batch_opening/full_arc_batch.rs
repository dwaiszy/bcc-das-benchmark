//! One WHIR multi-evaluation proof for every complete BCC arc.
//!
//! The proof for an arc authenticates its entire ordered local support. A
//! verifier therefore receives every value in each sampled arc, not only the
//! values at its sampled global positions.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

use crate::pcs::whir::WhirField;
use rayon::prelude::*;

use super::{parameters, SECURITY_BITS};
use crate::das::core::{
    BlockId, ErasureCode, FieldConfig, OpeningBreakdown, OpeningMode, PcsConfig,
    PreparationMetrics, PrepareError, ProtocolConfig, ProtocolConfigDigest, SetupError,
    VerificationError,
};
use crate::das::erasure_code::BccCode;
use crate::pcs::whir::{
    WhirCommitment, WhirLocalCodeScheme, WhirOpeningTiming, WhirProof, WhirState,
};
use crate::pcs::ArcPcs;
use crate::BcParams;

pub struct FullArcBatchWhir {
    code: BccCode<WhirField>,
    pcs: WhirLocalCodeScheme,
    profile: ProtocolConfig,
    pool: rayon::ThreadPool,
}

pub struct FullArcHeader {
    block_id: BlockId,
    profile_id: ProtocolConfigDigest,
    commitments: Vec<WhirCommitment>,
}

struct ArcOracle {
    values: Vec<WhirField>,
    proof: WhirProof,
}

pub struct PreparedFullArcBlock {
    pub header: FullArcHeader,
    arcs: Vec<ArcOracle>,
    pub metrics: PreparationMetrics,
}

pub struct FullArcSamplePlan {
    block_id: BlockId,
    profile_id: ProtocolConfigDigest,
    indices: Vec<usize>,
}

pub struct ArcResponse {
    arc_id: usize,
    values: Vec<WhirField>,
    proof: WhirProof,
}

pub struct FullArcResponses {
    arcs: Vec<ArcResponse>,
}

impl FullArcBatchWhir {
    pub fn setup(
        params: BcParams,
        sample_count: usize,
        proposer_threads: usize,
    ) -> Result<Self, SetupError> {
        let code = BccCode::new(params)?;
        if sample_count == 0 || sample_count > params.n() || proposer_threads == 0 {
            return Err(SetupError::ConfigMismatch);
        }
        let pcs = WhirLocalCodeScheme::try_setup(super::whir_max_degree(params), &parameters())
            .map_err(|_| SetupError::ConfigMismatch)?;
        let profile = ProtocolConfig::new_with_opening(
            code.profile(),
            FieldConfig::Goldilocks2,
            PcsConfig::WhirJohnson {
                security_bits: SECURITY_BITS as u16,
            },
            OpeningMode::FullArcBatch,
            sample_count,
            [0x58; 32],
            proposer_threads,
        );
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(proposer_threads)
            .stack_size(16 * 1024 * 1024)
            .thread_name(|i| format!("bcc-whir-arc-batch-{i}"))
            .build()
            .map_err(|_| SetupError::ThreadPool)?;
        Ok(Self {
            code,
            pcs,
            profile,
            pool,
        })
    }

    pub fn profile(&self) -> &ProtocolConfig {
        &self.profile
    }

    pub fn prepare(
        &self,
        block_id: BlockId,
        message: &[WhirField],
    ) -> Result<PreparedFullArcBlock, PrepareError> {
        if message.len() != self.code.message_len() {
            return Err(PrepareError::WrongMessageLength {
                got: message.len(),
                expected: self.code.message_len(),
            });
        }
        let polynomials = self.code.polynomialize(message)?;
        let encode_started = Instant::now();
        let encoded = self
            .pool
            .install(|| self.code.encode_polynomials(&polynomials))?;
        let encode = encode_started.elapsed();
        let commit_started = Instant::now();
        let committed = self.pool.install(|| {
            polynomials
                .local_polynomials()
                .par_iter()
                .map(|coefficients| ArcPcs::commit(&self.pcs, coefficients))
                .collect::<Result<Vec<_>, _>>()
        })?;
        let commit = commit_started.elapsed();
        let (commitments, states): (Vec<_>, Vec<WhirState>) = committed.into_iter().unzip();

        let started = Instant::now();
        let arcs = self.pool.install(|| {
            states
                .par_iter()
                .zip(encoded.local_codes().par_iter())
                .map(|(state, local)| {
                    let point_started = Instant::now();
                    let points = local
                        .claims()
                        .iter()
                        .map(|claim| claim.point())
                        .collect::<Vec<_>>();
                    let values = local
                        .claims()
                        .iter()
                        .map(|claim| claim.value())
                        .collect::<Vec<_>>();
                    let point_preparation = point_started.elapsed();
                    let (proof, timing) = self
                        .pcs
                        .open_all_with_evaluations_checked_timed(state, &points, &values)
                        .map_err(|_| crate::pcs::PcsError::Open)?;
                    Ok::<_, crate::pcs::PcsError>((
                        ArcOracle { values, proof },
                        point_preparation,
                        timing,
                    ))
                })
                .collect::<Result<Vec<_>, _>>()
        })?;
        let open = started.elapsed();
        let mut opening = OpeningBreakdown::default();
        let arcs = arcs
            .into_iter()
            .map(|(arc, point_preparation, timing)| {
                opening.point_preparation += point_preparation;
                add_whir_timing(&mut opening, timing);
                opening.uncompressed_proof_oracle_bytes += arc.proof.uncompressed_size();
                opening.compressed_proof_oracle_bytes += arc.proof.compressed_size();
                arc
            })
            .collect();
        opening.peak_or_estimated_working_memory_bytes = opening.compressed_proof_oracle_bytes
            + self.code.local_code_count() * self.code.local_code_len() * 16;
        Ok(PreparedFullArcBlock {
            header: FullArcHeader {
                block_id,
                profile_id: self.profile.id(),
                commitments,
            },
            arcs,
            metrics: PreparationMetrics {
                commit,
                encode,
                open,
                opening,
            },
        })
    }

    pub fn sample(
        &self,
        header: &FullArcHeader,
        indices: &[usize],
    ) -> Result<FullArcSamplePlan, VerificationError> {
        self.validate_header(header)?;
        if indices.len() != self.profile.sample_count() {
            return Err(VerificationError::WrongSampleCount);
        }
        let mut seen = BTreeSet::new();
        for &index in indices {
            if index >= self.code.codeword_len() {
                return Err(VerificationError::PositionOutOfRange);
            }
            if !seen.insert(index) {
                return Err(VerificationError::DuplicateSample);
            }
        }
        Ok(FullArcSamplePlan {
            block_id: header.block_id,
            profile_id: header.profile_id,
            indices: indices.to_vec(),
        })
    }

    pub fn respond(
        &self,
        prepared: &PreparedFullArcBlock,
        plan: &FullArcSamplePlan,
    ) -> Result<FullArcResponses, VerificationError> {
        self.validate_header(&prepared.header)?;
        if plan.block_id != prepared.header.block_id
            || plan.profile_id != prepared.header.profile_id
        {
            return Err(VerificationError::PlanMismatch);
        }
        let ids = self.sampled_arcs(&plan.indices)?;
        let arcs = ids
            .into_iter()
            .map(|arc_id| {
                let oracle = prepared
                    .arcs
                    .get(arc_id)
                    .ok_or(VerificationError::MissingResponse)?;
                Ok(ArcResponse {
                    arc_id,
                    values: oracle.values.clone(),
                    proof: oracle.proof.clone(),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(FullArcResponses { arcs })
    }

    pub fn verify(
        &self,
        header: &FullArcHeader,
        plan: &FullArcSamplePlan,
        responses: &FullArcResponses,
    ) -> Result<Vec<(usize, WhirField)>, VerificationError> {
        self.validate_header(header)?;
        if plan.block_id != header.block_id || plan.profile_id != header.profile_id {
            return Err(VerificationError::PlanMismatch);
        }
        let ids = self.sampled_arcs(&plan.indices)?;
        if ids.len() != responses.arcs.len() {
            return Err(VerificationError::PlanMismatch);
        }
        let params = self.code.params();
        let mut authenticated_values = BTreeMap::new();
        for (&arc_id, response) in ids.iter().zip(&responses.arcs) {
            if response.arc_id != arc_id || response.values.len() != params.n0() {
                return Err(VerificationError::NonCanonicalClaim);
            }
            let points = params
                .local_support(arc_id)
                .into_iter()
                .zip(&response.values)
                .map(|(index, &value)| {
                    self.code
                        .canonical_claim(index, value)
                        .map(|claim| claim.point())
                        .map_err(|_| VerificationError::PositionOutOfRange)
                })
                .collect::<Result<Vec<_>, _>>()?;
            self.pcs
                .verify_all_checked(
                    &header.commitments[arc_id],
                    &points,
                    &response.values,
                    &response.proof,
                )
                .map_err(|_| VerificationError::InvalidProof)?;
            for (global_index, &value) in params
                .local_support(arc_id)
                .into_iter()
                .zip(&response.values)
            {
                record_authenticated_value(&mut authenticated_values, global_index, value)?;
            }
        }
        plan.indices
            .iter()
            .map(|&index| {
                let arc_id = params.canonical_local_code(index);
                let response = responses
                    .arcs
                    .iter()
                    .find(|arc| arc.arc_id == arc_id)
                    .ok_or(VerificationError::MissingResponse)?;
                Ok((index, response.values[index % params.period()]))
            })
            .collect()
    }

    fn validate_header(&self, header: &FullArcHeader) -> Result<(), VerificationError> {
        if header.profile_id != self.profile.id() {
            return Err(VerificationError::WrongConfig);
        }
        if header.commitments.len() != self.code.local_code_count() {
            return Err(VerificationError::WrongCommitmentCount);
        }
        Ok(())
    }

    fn sampled_arcs(&self, indices: &[usize]) -> Result<Vec<usize>, VerificationError> {
        if indices.len() != self.profile.sample_count() {
            return Err(VerificationError::WrongSampleCount);
        }
        let mut seen = BTreeSet::new();
        let mut arcs = BTreeSet::new();
        for &index in indices {
            if index >= self.code.codeword_len() {
                return Err(VerificationError::PositionOutOfRange);
            }
            if !seen.insert(index) {
                return Err(VerificationError::DuplicateSample);
            }
            arcs.insert(self.code.params().canonical_local_code(index));
        }
        Ok(arcs.into_iter().collect())
    }
}

fn record_authenticated_value(
    values: &mut BTreeMap<usize, WhirField>,
    index: usize,
    value: WhirField,
) -> Result<(), VerificationError> {
    if values
        .insert(index, value)
        .is_some_and(|previous| previous != value)
    {
        Err(VerificationError::InconsistentOverlap)
    } else {
        Ok(())
    }
}

impl FullArcHeader {
    pub fn commitment_count(&self) -> usize {
        self.commitments.len()
    }

    pub fn serialized_size(&self) -> usize {
        // Match scalar benchmark accounting: profile digest plus commitments.
        32 + self
            .commitments
            .iter()
            .map(WhirCommitment::compressed_size)
            .sum::<usize>()
    }
}

impl PreparedFullArcBlock {
    pub fn proof_count(&self) -> usize {
        self.arcs.len()
    }
}

impl FullArcResponses {
    pub fn arc_count(&self) -> usize {
        self.arcs.len()
    }

    pub fn proof_bytes(&self) -> usize {
        self.arcs
            .iter()
            .map(|arc| arc.proof.serialized_bytes().len())
            .sum()
    }

    pub fn value_bytes(&self) -> usize {
        self.arcs.iter().map(|arc| arc.values.len() * 16).sum()
    }

    pub fn metadata_bytes(&self) -> usize {
        self.arcs.len() * 8
    }

    pub fn authenticated_values(&self, params: BcParams) -> Vec<(usize, WhirField)> {
        self.arcs
            .iter()
            .flat_map(|arc| {
                params
                    .local_support(arc.arc_id)
                    .into_iter()
                    .zip(arc.values.iter().copied())
            })
            .collect()
    }
}

fn add_whir_timing(breakdown: &mut OpeningBreakdown, timing: WhirOpeningTiming) {
    breakdown.state_clone_or_rebuild += timing.state_clone_or_rebuild;
    breakdown.point_preparation += timing.point_preparation;
    breakdown.evaluation_check += timing.evaluation_check;
    breakdown.whir_cryptographic_prove += timing.whir_cryptographic_prove;
    breakdown.proof_serialization += timing.proof_serialization;
    breakdown.proof_compression += timing.proof_compression;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_arc_proofs_verify_and_reject_tampered_value() {
        let params = BcParams {
            mu: 4,
            omega: 4,
            rho: 12,
        };
        let scheme = FullArcBatchWhir::setup(params, 2, 2).unwrap();
        let input = (1..=params.k())
            .map(|x| WhirField::from(x as u64))
            .collect::<Vec<_>>();
        let prepared = scheme.prepare(BlockId::new([3; 32]), &input).unwrap();
        assert_eq!(prepared.proof_count(), params.mu);
        let plan = scheme
            .sample(&prepared.header, &[0, params.period()])
            .unwrap();
        let mut responses = scheme.respond(&prepared, &plan).unwrap();
        assert_eq!(responses.arc_count(), 2);
        let transcript = scheme.verify(&prepared.header, &plan, &responses).unwrap();
        assert_eq!(transcript.len(), 2);
        // Even a value outside the sample set is bound by the full-arc proof.
        responses.arcs[0].values[1] += WhirField::from(1);
        assert_eq!(
            scheme.verify(&prepared.header, &plan, &responses),
            Err(VerificationError::InvalidProof)
        );
    }

    #[test]
    fn overlap_comparison_rejects_conflicting_authenticated_values() {
        let mut values = BTreeMap::new();
        let first = WhirField::from(1);
        let second = WhirField::from(2);
        assert_eq!(record_authenticated_value(&mut values, 7, first), Ok(()));
        assert_eq!(record_authenticated_value(&mut values, 7, first), Ok(()));
        assert_eq!(
            record_authenticated_value(&mut values, 7, second),
            Err(VerificationError::InconsistentOverlap)
        );
    }
}
