//! BCC + WHIR deterministic fixed-group openings.

use std::collections::BTreeSet;
use std::time::Instant;

use crate::pcs::whir::WhirField;
use rayon::prelude::*;

use super::{parameters, SECURITY_BITS};
use crate::das::core::grouped_opening::{
    contiguous_groups, group_for_local_index, GroupId, LocalGroup,
};
use crate::das::core::{
    BlockId, ErasureCode, FieldConfig, GroupLayout, OpeningBreakdown, OpeningMode, PcsConfig,
    PreparationMetrics, PrepareError, ProtocolConfig, ProtocolConfigDigest, SetupError,
    VerificationError,
};
use crate::das::erasure_code::BccCode;
use crate::pcs::whir::{WhirCommitment, WhirLocalCodeScheme, WhirOpeningTiming, WhirProof};
use crate::pcs::ArcPcs;
use crate::BcParams;

pub struct BccWhirFixedGroup {
    code: BccCode<WhirField>,
    pcs: WhirLocalCodeScheme,
    profile: ProtocolConfig,
    groups: Vec<Vec<LocalGroup>>,
    pool: rayon::ThreadPool,
    group_mapping: std::time::Duration,
}

struct PreparedGroup {
    values: Vec<WhirField>,
    proof: WhirProof,
}

pub struct PreparedBccWhirFixedGroup {
    pub header: FixedGroupHeader,
    groups: Vec<Vec<PreparedGroup>>,
    pub metrics: PreparationMetrics,
}

pub struct FixedGroupHeader {
    block_id: BlockId,
    profile_id: ProtocolConfigDigest,
    commitments: Vec<WhirCommitment>,
}

pub struct FixedGroupSamplePlan {
    block_id: BlockId,
    profile_id: ProtocolConfigDigest,
    indices: Vec<usize>,
}

pub struct GroupResponse {
    pub id: GroupId,
    pub values: Vec<WhirField>,
    pub proof: WhirProof,
}

pub struct FixedGroupResponses {
    pub groups: Vec<GroupResponse>,
}

impl BccWhirFixedGroup {
    pub fn setup(
        params: BcParams,
        sample_count: usize,
        group_size: usize,
        threads: usize,
    ) -> Result<Self, SetupError> {
        if group_size == 0 || threads == 0 || sample_count == 0 || sample_count > params.n() {
            return Err(SetupError::ConfigMismatch);
        }
        let code = BccCode::new(params)?;
        let pcs = WhirLocalCodeScheme::setup(super::whir_max_degree(params), &parameters());
        let profile = ProtocolConfig::new_with_opening(
            code.profile(),
            FieldConfig::Goldilocks2,
            PcsConfig::WhirJohnson {
                security_bits: SECURITY_BITS as u16,
            },
            OpeningMode::FixedGroup {
                group_size,
                layout: GroupLayout::ContiguousLocal,
            },
            sample_count,
            [0x47; 32],
            threads,
        );
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .thread_name(|i| format!("bcc-whir-fixed-group-{i}"))
            .build()
            .map_err(|_| SetupError::ThreadPool)?;
        let group_mapping_started = Instant::now();
        let groups = (0..params.mu)
            .map(|i| contiguous_groups(i, params.n0(), group_size))
            .collect();
        let group_mapping = group_mapping_started.elapsed();
        Ok(Self {
            code,
            pcs,
            profile,
            groups,
            pool,
            group_mapping,
        })
    }

    pub fn profile(&self) -> &ProtocolConfig {
        &self.profile
    }
    pub fn group_size(&self) -> usize {
        match self.profile.opening() {
            OpeningMode::FixedGroup { group_size, .. } => group_size,
            _ => unreachable!(),
        }
    }

    pub fn prepare(
        &self,
        block_id: BlockId,
        message: &[WhirField],
    ) -> Result<PreparedBccWhirFixedGroup, PrepareError> {
        if message.len() != self.code.message_len() {
            return Err(PrepareError::WrongMessageLength {
                got: message.len(),
                expected: self.code.message_len(),
            });
        }
        let polynomials = self.code.polynomialize(message)?;
        let encode_started = Instant::now();
        let encoded = self.code.encode_polynomials(&polynomials)?;
        let encode = encode_started.elapsed();
        let commit_started = Instant::now();
        let committed = self.pool.install(|| {
            polynomials
                .local_polynomials()
                .par_iter()
                .map(|c| ArcPcs::commit(&self.pcs, c))
                .collect::<Result<Vec<_>, _>>()
        })?;
        let (commitments, states): (Vec<_>, Vec<_>) = committed.into_iter().unzip();
        let commit = commit_started.elapsed();
        let started = Instant::now();
        let groups_parallel = std::env::var("DAS_WHIR_PARALLEL_LAYOUT")
            .map(|value| value.eq_ignore_ascii_case("groups"))
            .unwrap_or(false);
        let (groups, mut breakdowns) = if groups_parallel {
            let jobs = self
                .groups
                .iter()
                .enumerate()
                .flat_map(|(arc, groups)| (0..groups.len()).map(move |group| (arc, group)))
                .collect::<Vec<_>>();
            let mut prepared = self.pool.install(|| {
                jobs.into_par_iter()
                    .map(|(arc, group)| {
                        let (prepared, breakdown) = self.prepare_one_group(
                            &states[arc],
                            &encoded.local_codes()[arc],
                            &self.groups[arc][group],
                        )?;
                        Ok::<_, crate::pcs::PcsError>((arc, group, prepared, breakdown))
                    })
                    .collect::<Result<Vec<_>, _>>()
            })?;
            prepared.sort_by_key(|(arc, group, _, _)| (*arc, *group));
            let mut grouped = (0..self.groups.len())
                .map(|_| Vec::new())
                .collect::<Vec<Vec<PreparedGroup>>>();
            let mut breakdowns = Vec::new();
            for (arc, _, group, breakdown) in prepared {
                grouped[arc].push(group);
                breakdowns.push(breakdown);
            }
            (grouped, breakdowns)
        } else {
            let prepared = self.pool.install(|| {
                states
                    .par_iter()
                    .zip(encoded.local_codes().par_iter())
                    .zip(self.groups.par_iter())
                    .map(|((state, local), groups)| {
                        let mut breakdown = OpeningBreakdown::default();
                        let prepared = groups
                            .iter()
                            .map(|group| {
                                let (prepared, group_breakdown) =
                                    self.prepare_one_group(state, local, group)?;
                                accumulate_breakdown(&mut breakdown, group_breakdown);
                                Ok(prepared)
                            })
                            .collect::<Result<Vec<_>, crate::pcs::PcsError>>()?;
                        Ok::<_, crate::pcs::PcsError>((prepared, breakdown))
                    })
                    .collect::<Result<Vec<_>, _>>()
            })?;
            let (groups, breakdowns) = prepared.into_iter().unzip();
            (groups, breakdowns)
        };
        let mut breakdown = OpeningBreakdown {
            group_mapping: self.group_mapping,
            ..OpeningBreakdown::default()
        };
        for group_breakdown in breakdowns.drain(..) {
            accumulate_breakdown(&mut breakdown, group_breakdown);
        }
        breakdown.peak_or_estimated_working_memory_bytes = breakdown.compressed_proof_oracle_bytes
            + self.code.local_code_count() * self.code.local_code_len() * 16;
        Ok(PreparedBccWhirFixedGroup {
            header: FixedGroupHeader {
                block_id,
                profile_id: self.profile.id(),
                commitments,
            },
            groups,
            metrics: PreparationMetrics {
                commit,
                encode,
                open: started.elapsed(),
                opening: breakdown,
            },
        })
    }

    pub fn sample(
        &self,
        header: &FixedGroupHeader,
        indices: &[usize],
    ) -> Result<FixedGroupSamplePlan, VerificationError> {
        self.validate_header(header)?;
        if indices.len() != self.profile.sample_count() {
            return Err(VerificationError::WrongSampleCount);
        }
        let mut seen = BTreeSet::new();
        for &i in indices {
            if i >= self.code.codeword_len() {
                return Err(VerificationError::PositionOutOfRange);
            }
            if !seen.insert(i) {
                return Err(VerificationError::DuplicateSample);
            }
        }
        Ok(FixedGroupSamplePlan {
            block_id: header.block_id,
            profile_id: header.profile_id,
            indices: indices.to_vec(),
        })
    }

    pub fn respond(
        &self,
        prepared: &PreparedBccWhirFixedGroup,
        plan: &FixedGroupSamplePlan,
    ) -> Result<FixedGroupResponses, VerificationError> {
        if plan.block_id != prepared.header.block_id
            || plan.profile_id != prepared.header.profile_id
        {
            return Err(VerificationError::PlanMismatch);
        }
        let ids = self.group_ids(&plan.indices)?;
        let groups = ids
            .into_iter()
            .map(|id| {
                let prepared_group = prepared
                    .groups
                    .get(id.local_code_index)
                    .and_then(|groups| groups.get(id.local_group_index))
                    .ok_or(VerificationError::MissingResponse)?;
                Ok(GroupResponse {
                    id,
                    values: prepared_group.values.clone(),
                    proof: prepared_group.proof.clone(),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(FixedGroupResponses { groups })
    }

    pub fn verify(
        &self,
        header: &FixedGroupHeader,
        plan: &FixedGroupSamplePlan,
        response: &FixedGroupResponses,
    ) -> Result<(), VerificationError> {
        self.validate_header(header)?;
        if plan.block_id != header.block_id || plan.profile_id != header.profile_id {
            return Err(VerificationError::PlanMismatch);
        }
        let ids = self.group_ids(&plan.indices)?;
        if ids.len() != response.groups.len() {
            return Err(VerificationError::PlanMismatch);
        }
        for (expected, received) in ids.iter().zip(&response.groups) {
            if expected != &received.id {
                return Err(VerificationError::NonCanonicalClaim);
            }
            let local_group = self.groups[expected.local_code_index]
                .get(expected.local_group_index)
                .ok_or(VerificationError::MissingResponse)?;
            if received.values.len() != local_group.local_positions.len() {
                return Err(VerificationError::NonCanonicalClaim);
            }
            let global_positions = self.code.params().local_support(expected.local_code_index);
            let points: Vec<_> = local_group
                .local_positions
                .iter()
                .map(|&i| {
                    self.code
                        .canonical_claim(
                            global_positions[i],
                            received.values[i - local_group.local_positions[0]],
                        )
                        .map(|c| c.point())
                })
                .collect::<Result<_, _>>()
                .map_err(|_| VerificationError::NonCanonicalClaim)?;
            self.pcs
                .verify_all_checked(
                    &header.commitments[expected.local_code_index],
                    &points,
                    &received.values,
                    &received.proof,
                )
                .map_err(|_| VerificationError::InvalidProof)?;
        }
        for &global in &plan.indices {
            let local = self
                .code
                .canonical_position(global)
                .map_err(|_| VerificationError::PositionOutOfRange)?;
            let id = group_for_local_index(
                local.local_code().get(),
                local.local_index(),
                self.group_size(),
            );
            if !response.groups.iter().any(|group| group.id == id) {
                return Err(VerificationError::MissingResponse);
            }
        }
        Ok(())
    }

    fn group_ids(&self, indices: &[usize]) -> Result<Vec<GroupId>, VerificationError> {
        let mut ids = BTreeSet::new();
        for &global in indices {
            let local = self
                .code
                .canonical_position(global)
                .map_err(|_| VerificationError::PositionOutOfRange)?;
            ids.insert(group_for_local_index(
                local.local_code().get(),
                local.local_index(),
                self.group_size(),
            ));
        }
        Ok(ids.into_iter().collect())
    }
    fn validate_header(&self, header: &FixedGroupHeader) -> Result<(), VerificationError> {
        if header.profile_id != self.profile.id() {
            return Err(VerificationError::WrongConfig);
        }
        if header.commitments.len() != self.code.local_code_count() {
            return Err(VerificationError::WrongCommitmentCount);
        }
        Ok(())
    }

    fn prepare_one_group(
        &self,
        state: &crate::pcs::whir::WhirState,
        local: &crate::das::core::LocalCode<WhirField>,
        group: &LocalGroup,
    ) -> Result<(PreparedGroup, OpeningBreakdown), crate::pcs::PcsError> {
        let points_started = Instant::now();
        let points: Vec<_> = group
            .local_positions
            .iter()
            .map(|&i| local.claims()[i].point())
            .collect();
        let values: Vec<_> = group
            .local_positions
            .iter()
            .map(|&i| local.claims()[i].value())
            .collect();
        let mut breakdown = OpeningBreakdown {
            point_preparation: points_started.elapsed(),
            ..OpeningBreakdown::default()
        };
        let (proof, timing) = self
            .pcs
            .open_all_with_evaluations_checked_timed(state, &points, &values)
            .map_err(|_| crate::pcs::PcsError::Open)?;
        add_whir_timing(&mut breakdown, timing);
        breakdown.uncompressed_proof_oracle_bytes = proof.uncompressed_size();
        breakdown.compressed_proof_oracle_bytes = proof.compressed_size();
        Ok((PreparedGroup { values, proof }, breakdown))
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

fn accumulate_breakdown(total: &mut OpeningBreakdown, part: OpeningBreakdown) {
    total.point_preparation += part.point_preparation;
    total.state_clone_or_rebuild += part.state_clone_or_rebuild;
    total.evaluation_check += part.evaluation_check;
    total.whir_cryptographic_prove += part.whir_cryptographic_prove;
    total.proof_serialization += part.proof_serialization;
    total.proof_compression += part.proof_compression;
    total.uncompressed_proof_oracle_bytes += part.uncompressed_proof_oracle_bytes;
    total.compressed_proof_oracle_bytes += part.compressed_proof_oracle_bytes;
}

impl FixedGroupHeader {
    pub fn commitment_count(&self) -> usize {
        self.commitments.len()
    }
    pub fn serialized_size(&self) -> usize {
        32 + self
            .commitments
            .iter()
            .map(WhirCommitment::compressed_size)
            .sum::<usize>()
    }
}
impl PreparedBccWhirFixedGroup {
    pub fn proof_count(&self) -> usize {
        self.groups.iter().map(Vec::len).sum()
    }
}
impl PreparedBccWhirFixedGroup {
    pub fn proof_bytes(&self) -> usize {
        self.groups
            .iter()
            .flat_map(|gs| gs.iter())
            .map(|g| g.proof.serialized_bytes().len())
            .sum()
    }
}
impl FixedGroupResponses {
    pub fn group_count(&self) -> usize {
        self.groups.len()
    }
    pub fn local_code_count(&self) -> usize {
        self.groups
            .iter()
            .map(|g| g.id.local_code_index)
            .collect::<BTreeSet<_>>()
            .len()
    }
    pub fn value_bytes(&self) -> usize {
        self.groups.iter().map(|g| g.values.len() * 16).sum()
    }
    pub fn proof_bytes(&self) -> usize {
        self.groups
            .iter()
            .map(|g| g.proof.serialized_bytes().len())
            .sum()
    }
    pub fn metadata_bytes(&self) -> usize {
        self.groups.len() * 16
    }

    pub fn authenticated_values(
        &self,
        params: BcParams,
        group_size: usize,
    ) -> Vec<(usize, WhirField)> {
        assert!(group_size > 0);
        self.groups
            .iter()
            .flat_map(|group| {
                params
                    .local_support(group.id.local_code_index)
                    .into_iter()
                    .skip(group.id.local_group_index * group_size)
                    .take(group.values.len())
                    .zip(group.values.iter().copied())
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fixed_groups_prepare_one_proof_per_group() {
        let params = BcParams {
            mu: 4,
            omega: 4,
            rho: 12,
        };
        let scheme = BccWhirFixedGroup::setup(params, 2, 4, 2).unwrap();
        let message = (1..=params.k())
            .map(|x| WhirField::from(x as u64))
            .collect::<Vec<_>>();
        let prepared = scheme.prepare(BlockId::new([8; 32]), &message).unwrap();
        assert_eq!(prepared.proof_count(), params.mu * params.n0().div_ceil(4));
        let plan = scheme
            .sample(&prepared.header, &[0, params.period()])
            .unwrap();
        let response = scheme.respond(&prepared, &plan).unwrap();
        scheme.verify(&prepared.header, &plan, &response).unwrap();
    }

    #[test]
    fn mu4_group_counts_match_protocol_geometry() {
        let params = BcParams { mu: 4, omega: 256, rho: 768 };
        assert_eq!(params.mu * params.n0().div_ceil(1), 5120);
        assert_eq!(params.mu * params.n0().div_ceil(32), 160);
        assert_eq!(params.mu * params.n0().div_ceil(64), 80);
        assert_eq!(params.mu * params.n0().div_ceil(1280), 4);
    }
}
