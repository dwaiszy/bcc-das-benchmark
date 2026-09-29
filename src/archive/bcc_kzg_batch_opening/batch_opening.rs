//! BCC + KZG arbitrary fixed-group openings using SHPLONK.

use super::super::core::grouped_opening::{
    GroupId, LocalGroup, contiguous_groups, group_for_local_index,
};
use super::super::core::{
    BlockId, ErasureCode, FieldConfig, GroupLayout, OpeningBreakdown, OpeningMode, PcsConfig, PreparationMetrics,
    PrepareError, ProtocolConfig, ProtocolConfigDigest, SetupError, VerificationError,
};
use super::super::erasure_code::BccCode;
use crate::BcParams;
use crate::pcs::kzg::{KzgLocalCodeScheme, MultipointProof};
use ark_bls12_381::{Bls12_381, Fr};
use ark_poly::DenseUVPolynomial;
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::kzg10::Commitment;
use ark_serialize::CanonicalSerialize;
use rayon::prelude::*;
use std::collections::BTreeSet;
use std::time::Instant;

pub struct BccKzgFixedGroup {
    code: BccCode<Fr>,
    pcs: KzgLocalCodeScheme,
    profile: ProtocolConfig,
    groups: Vec<Vec<LocalGroup>>,
    pool: rayon::ThreadPool,
}
struct PreparedGroup {
    values: Vec<Fr>,
    proof: MultipointProof,
}
pub struct FixedGroupHeader {
    block_id: BlockId,
    profile_id: ProtocolConfigDigest,
    commitments: Vec<Commitment<Bls12_381>>,
}
pub struct PreparedBccKzgFixedGroup {
    pub header: FixedGroupHeader,
    groups: Vec<Vec<PreparedGroup>>,
    pub metrics: PreparationMetrics,
}
pub struct FixedGroupSamplePlan {
    block_id: BlockId,
    profile_id: ProtocolConfigDigest,
    indices: Vec<usize>,
}
pub struct GroupResponse {
    pub id: GroupId,
    pub values: Vec<Fr>,
    pub proof: MultipointProof,
}
pub struct FixedGroupResponses {
    pub groups: Vec<GroupResponse>,
}

impl BccKzgFixedGroup {
    pub fn setup(
        params: BcParams,
        sample_count: usize,
        group_size: usize,
        threads: usize,
    ) -> Result<Self, SetupError> {
        if group_size == 0 || threads == 0 || sample_count == 0 || sample_count > params.n() {
            return Err(SetupError::ConfigMismatch);
        }
        let mut rng = ark_std::test_rng();
        let pcs = KzgLocalCodeScheme::setup_peerdas(
            params.k0() - 1,
            1,
            params.num_eval_points(),
            &mut rng,
        )
        .map_err(|_| SetupError::ConfigMismatch)?;
        Self::setup_with_pcs(params, sample_count, group_size, threads, pcs)
    }

    pub fn setup_with_pcs(
        params: BcParams,
        sample_count: usize,
        group_size: usize,
        threads: usize,
        pcs: KzgLocalCodeScheme,
    ) -> Result<Self, SetupError> {
        if group_size == 0 || threads == 0 || sample_count == 0 || sample_count > params.n() {
            return Err(SetupError::ConfigMismatch);
        }
        let code = BccCode::new(params)?;
        let profile = ProtocolConfig::new_with_opening(
            code.profile(),
            FieldConfig::Bls12381Scalar,
            PcsConfig::Kzg {
                strategy: crate::pcs::kzg::KzgStrategy::Shplonk,
            },
            OpeningMode::FixedGroup {
                group_size,
                layout: GroupLayout::ContiguousLocal,
            },
            sample_count,
            [0x4c; 32],
            threads,
        );
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .map_err(|_| SetupError::ThreadPool)?;
        let groups = (0..params.mu)
            .map(|i| contiguous_groups(i, params.n0(), group_size))
            .collect();
        Ok(Self {
            code,
            pcs,
            profile,
            groups,
            pool,
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
        message: &[Fr],
    ) -> Result<PreparedBccKzgFixedGroup, PrepareError> {
        if message.len() != self.code.message_len() {
            return Err(PrepareError::WrongMessageLength {
                got: message.len(),
                expected: self.code.message_len(),
            });
        }
        let polys = self.code.polynomialize(message)?;
        let encode_started = Instant::now();
        let encoded = self.code.encode_polynomials(&polys)?;
        let encode = encode_started.elapsed();
        let commit_started = Instant::now();
        let committed = self.pool.install(|| {
            polys
                .local_polynomials()
                .par_iter()
                .map(|coeffs| {
                    let poly = DensePolynomial::from_coefficients_vec(coeffs.clone());
                    let (c, _) = self.pcs.commit(&poly);
                    Ok::<_, crate::pcs::PcsError>((c, poly))
                })
                .collect::<Result<Vec<_>, _>>()
        })?;
        let commit = commit_started.elapsed();
        let (commitments, committed_polys): (Vec<_>, Vec<_>) = committed.into_iter().unzip();
        let started = Instant::now();
        let groups = self.pool.install(|| {
            committed_polys
                .par_iter()
                .zip(encoded.local_codes().par_iter())
                .zip(self.groups.par_iter())
                .zip(commitments.par_iter())
                .map(|(((poly, local), groups), commitment)| {
                    groups
                        .iter()
                        .map(|group| {
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
                            Ok(PreparedGroup {
                                proof: self.pcs.open_multipoint(poly, commitment, &points),
                                values,
                            })
                        })
                        .collect::<Result<Vec<_>, crate::pcs::PcsError>>()
                })
                .collect::<Result<Vec<_>, _>>()
        })?;
        let proof_oracle_bytes = groups
            .iter()
            .flat_map(|groups| groups.iter())
            .map(|group| group.proof.serialized_bytes().len())
            .sum::<usize>();
        assert!(groups.iter().flatten().all(|group| {
            group.proof.serialized_bytes().len() == MultipointProof::expected_serialized_size()
        }));
        Ok(PreparedBccKzgFixedGroup {
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
                opening: OpeningBreakdown {
                    compressed_proof_oracle_bytes: proof_oracle_bytes,
                    peak_or_estimated_working_memory_bytes: proof_oracle_bytes
                        + self.code.local_code_count() * self.code.local_code_len() * 32,
                    ..OpeningBreakdown::default()
                },
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
        prepared: &PreparedBccKzgFixedGroup,
        plan: &FixedGroupSamplePlan,
    ) -> Result<FixedGroupResponses, VerificationError> {
        let ids = self.group_ids(&plan.indices)?;
        let groups = ids
            .into_iter()
            .map(|id| {
                let g = prepared
                    .groups
                    .get(id.local_code_index)
                    .and_then(|v| v.get(id.local_group_index))
                    .ok_or(VerificationError::MissingResponse)?;
                Ok(GroupResponse {
                    id,
                    values: g.values.clone(),
                    proof: g.proof.clone(),
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
        if plan.profile_id != header.profile_id || plan.block_id != header.block_id {
            return Err(VerificationError::PlanMismatch);
        }
        let ids = self.group_ids(&plan.indices)?;
        if ids.len() != response.groups.len() {
            return Err(VerificationError::PlanMismatch);
        }
        for (id, received) in ids.iter().zip(&response.groups) {
            if id != &received.id {
                return Err(VerificationError::NonCanonicalClaim);
            }
            let group = self.groups[id.local_code_index]
                .get(id.local_group_index)
                .ok_or(VerificationError::MissingResponse)?;
            if group.local_positions.len() != received.values.len() {
                return Err(VerificationError::NonCanonicalClaim);
            }
            let support = self.code.params().local_support(id.local_code_index);
            let points: Vec<_> = group
                .local_positions
                .iter()
                .map(|&i| {
                    self.code
                        .canonical_claim(support[i], received.values[i - group.local_positions[0]])
                        .map(|c| c.point())
                })
                .collect::<Result<_, _>>()
                .map_err(|_| VerificationError::NonCanonicalClaim)?;
            if !self.pcs.verify_multipoint(
                &header.commitments[id.local_code_index],
                &points,
                &received.values,
                &received.proof,
            ) {
                return Err(VerificationError::InvalidProof);
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
}
impl FixedGroupHeader {
    pub fn commitment_count(&self) -> usize {
        self.commitments.len()
    }
}
impl PreparedBccKzgFixedGroup {
    pub fn proof_count(&self) -> usize {
        self.groups.iter().map(Vec::len).sum()
    }
}
impl PreparedBccKzgFixedGroup {
    pub fn proof_bytes(&self) -> usize {
        self.groups
            .iter()
            .flat_map(|gs| gs.iter())
            .map(|g| g.proof.serialized_bytes().len())
            .sum()
    }
}
impl FixedGroupHeader {
    pub fn serialized_size(&self) -> usize {
        32 + self
            .commitments
            .iter()
            .map(|c| c.compressed_size())
            .sum::<usize>()
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
        self.groups.iter().map(|g| g.values.len() * 32).sum()
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_group_shplonk_authenticates_one_group() {
        let params = BcParams {
            mu: 4,
            omega: 4,
            rho: 12,
        };
        let scheme = BccKzgFixedGroup::setup(params, 1, 4, 2).unwrap();
        let message = (1..=params.k())
            .map(|x| Fr::from(x as u64))
            .collect::<Vec<_>>();
        let prepared = scheme.prepare(BlockId::new([9; 32]), &message).unwrap();
        assert_eq!(prepared.proof_count(), params.mu * params.n0().div_ceil(4));
        let plan = scheme.sample(&prepared.header, &[0]).unwrap();
        let mut response = scheme.respond(&prepared, &plan).unwrap();
        scheme.verify(&prepared.header, &plan, &response).unwrap();
        response.groups[0].values.swap(0, 1);
        assert_eq!(
            scheme.verify(&prepared.header, &plan, &response),
            Err(VerificationError::InvalidProof)
        );
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
