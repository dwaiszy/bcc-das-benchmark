//! 2D-RS + KZG fixed groups over the row evaluation domain.

use std::collections::BTreeSet;
use std::time::Instant;

use ark_bls12_381::{Bls12_381, Fr};
use ark_poly::{
    DenseUVPolynomial, EvaluationDomain, Radix2EvaluationDomain, univariate::DensePolynomial,
};
use ark_poly_commit::kzg10::{Commitment, Proof};
use ark_serialize::CanonicalSerialize;
use rayon::prelude::*;

use super::super::core::grouped_opening::{GroupId, LocalGroup};
use super::super::core::{
    BlockId, ErasureCode, FieldConfig, GroupLayout, OpeningBreakdown, OpeningMode, PcsConfig, PreparationMetrics,
    PrepareError, ProtocolConfig, ProtocolConfigDigest, SetupError, VerificationError,
};
use super::super::erasure_code::Rs2dCode;
use crate::pcs::kzg::{KzgLocalCodeScheme, KzgStrategy, MultipointProof};

pub struct Rs2dKzgCosetGroup {
    code: Rs2dCode<Fr>,
    pcs: KzgLocalCodeScheme,
    profile: ProtocolConfig,
    groups: Vec<Vec<LocalGroup>>,
    pool: rayon::ThreadPool,
    backend: GroupedKzgBackend,
}
#[derive(Clone)]
enum GroupedKzgBackend {
    Fk20,
    Shplonk,
}
struct PreparedGroup {
    values: Vec<Fr>,
    proof: GroupedKzgProof,
    start: Fr,
}
#[derive(Clone)]
pub enum GroupedKzgProof {
    Fk20(Proof<Bls12_381>),
    Shplonk(MultipointProof),
}
pub struct FixedGroupHeader {
    block_id: BlockId,
    profile_id: ProtocolConfigDigest,
    commitments: Vec<Commitment<Bls12_381>>,
}
pub struct PreparedRs2dKzgCosetGroup {
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
    pub proof: GroupedKzgProof,
    pub start: Fr,
}
pub struct FixedGroupResponses {
    pub groups: Vec<GroupResponse>,
}

impl Rs2dKzgCosetGroup {
    pub fn setup(
        n0: usize,
        k0: usize,
        sample_count: usize,
        group_size: usize,
        threads: usize,
    ) -> Result<Self, SetupError> {
        if group_size == 0
            || !group_size.is_power_of_two()
            || n0 < group_size
            || !n0.is_power_of_two()
            || n0 % group_size != 0
            || threads == 0
            || sample_count == 0
            || sample_count > n0 * n0
        {
            return Err(SetupError::ConfigMismatch);
        }
        let mut rng = ark_std::test_rng();
        let pcs = KzgLocalCodeScheme::setup_peerdas(k0 - 1, group_size, n0, &mut rng)
            .map_err(|_| SetupError::ConfigMismatch)?;
        Self::setup_with_pcs(n0, k0, sample_count, group_size, threads, pcs)
    }

    pub fn setup_with_pcs(
        n0: usize,
        k0: usize,
        sample_count: usize,
        group_size: usize,
        threads: usize,
        pcs: KzgLocalCodeScheme,
    ) -> Result<Self, SetupError> {
        if group_size == 0
            || !group_size.is_power_of_two()
            || n0 < group_size
            || !n0.is_power_of_two()
            || n0 % group_size != 0
            || threads == 0
            || sample_count == 0
            || sample_count > n0 * n0
        {
            return Err(SetupError::ConfigMismatch);
        }
        let code = Rs2dCode::new(n0, k0)?;
        let profile = ProtocolConfig::new_with_opening(
            code.profile(),
            FieldConfig::Bls12381Scalar,
            PcsConfig::Kzg {
                strategy: KzgStrategy::Fk20,
            },
            OpeningMode::FixedGroup {
                group_size,
                layout: GroupLayout::EvaluationCoset,
            },
            sample_count,
            [0x53; 32],
            threads,
        );
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .map_err(|_| SetupError::ThreadPool)?;
        let coset_count = n0 / group_size;
        let groups = (0..n0)
            .map(|row| {
                (0..coset_count)
                    .map(|group| LocalGroup {
                        id: GroupId {
                            local_code_index: row,
                            local_group_index: group,
                        },
                        local_positions: (group..n0).step_by(coset_count).collect(),
                    })
                    .collect()
            })
            .collect();
        Ok(Self {
            code,
            pcs,
            profile,
            groups,
            pool,
            backend: GroupedKzgBackend::Fk20,
        })
    }
    /// Build the same fixed groups as the coset profile, but prove them with
    /// arbitrary-point SHPLONK so this is directly comparable with BCC.
    pub fn setup_shplonk(
        n0: usize,
        k0: usize,
        sample_count: usize,
        group_size: usize,
        threads: usize,
    ) -> Result<Self, SetupError> {
        let mut scheme = Self::setup(n0, k0, sample_count, group_size, threads)?;
        scheme.profile = ProtocolConfig::new_with_opening(
            scheme.code.profile(),
            FieldConfig::Bls12381Scalar,
            PcsConfig::Kzg {
                strategy: KzgStrategy::Shplonk,
            },
            OpeningMode::FixedGroup {
                group_size,
                layout: GroupLayout::EvaluationCoset,
            },
            sample_count,
            [0x53; 32],
            threads,
        );
        scheme.backend = GroupedKzgBackend::Shplonk;
        Ok(scheme)
    }

    pub fn setup_shplonk_with_pcs(
        n0: usize,
        k0: usize,
        sample_count: usize,
        group_size: usize,
        threads: usize,
        pcs: KzgLocalCodeScheme,
    ) -> Result<Self, SetupError> {
        let mut scheme = Self::setup_with_pcs(n0, k0, sample_count, group_size, threads, pcs)?;
        scheme.profile = ProtocolConfig::new_with_opening(
            scheme.code.profile(),
            FieldConfig::Bls12381Scalar,
            PcsConfig::Kzg {
                strategy: KzgStrategy::Shplonk,
            },
            OpeningMode::FixedGroup {
                group_size,
                layout: GroupLayout::EvaluationCoset,
            },
            sample_count,
            [0x53; 32],
            threads,
        );
        scheme.backend = GroupedKzgBackend::Shplonk;
        Ok(scheme)
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
    ) -> Result<PreparedRs2dKzgCosetGroup, PrepareError> {
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
        let source_polys = self.code.source_row_polynomials(message)?;
        let committed = self.pool.install(|| {
            source_polys
                .par_iter()
                .map(|coeffs| {
                    let poly = DensePolynomial::from_coefficients_vec(coeffs.clone());
                    let (c, _) = self.pcs.commit(&poly);
                    Ok::<_, crate::pcs::PcsError>((c, poly))
                })
                .collect::<Result<Vec<_>, _>>()
        })?;
        let commit = commit_started.elapsed();
        let (source_commitments, _source_polys): (Vec<_>, Vec<_>) = committed.into_iter().unzip();
        let commitments = (0..self.code.n0())
            .map(|row| {
                self.pcs.linear_combination_commitment(
                    &source_commitments,
                    &self.code.source_row_weights(row),
                )
            })
            .collect::<Vec<_>>();
        let committed_polys = polynomials
            .local_polynomials()
            .iter()
            .map(|coeffs| DensePolynomial::from_coefficients_vec(coeffs.clone()))
            .collect::<Vec<_>>();
        let started = Instant::now();
        let groups = self.pool.install(|| {
            commitments
                .par_iter()
                .zip(committed_polys.par_iter())
                .zip(encoded.local_codes().par_iter())
                .map(|((commitment, poly), local)| {
                    let proofs = match self.backend {
                        GroupedKzgBackend::Fk20 => Some(self.pcs.open_coset_all(poly)),
                        GroupedKzgBackend::Shplonk => None,
                    };
                    let coset_count = self.code.n0() / self.group_size();
                    (0..coset_count)
                        .map(|group| {
                            let positions: Vec<_> =
                                (group..self.code.n0()).step_by(coset_count).collect();
                            let values = positions
                                .iter()
                                .map(|&i| local.claims()[i].value())
                                .collect();
                            let domain = Radix2EvaluationDomain::<Fr>::new(self.code.n0())
                                .expect("radix domain");
                            let proof = match &proofs {
                                Some(proofs) => GroupedKzgProof::Fk20(proofs[group].clone()),
                                None => {
                                    let domain = Radix2EvaluationDomain::<Fr>::new(self.code.n0())
                                        .expect("radix domain");
                                    let points = positions
                                        .iter()
                                        .map(|&i| domain.element(i))
                                        .collect::<Vec<_>>();
                                    GroupedKzgProof::Shplonk(
                                        self.pcs.open_multipoint(poly, commitment, &points),
                                    )
                                }
                            };
                            Ok::<_, crate::pcs::PcsError>(PreparedGroup {
                                values,
                                proof,
                                start: domain.element(group),
                            })
                        })
                        .collect::<Result<Vec<_>, _>>()
                })
                .collect::<Result<Vec<_>, _>>()
        })?;
        let proof_oracle_bytes = groups
            .iter()
            .flat_map(|groups| groups.iter())
            .map(|group| match &group.proof {
                GroupedKzgProof::Fk20(proof) => proof.w.compressed_size(),
                GroupedKzgProof::Shplonk(proof) => proof.compressed_size(),
            })
            .sum::<usize>();
        assert!(groups.iter().flatten().all(|group| {
            matches!(&group.proof, GroupedKzgProof::Shplonk(proof)
                if proof.serialized_bytes().len() == MultipointProof::expected_serialized_size())
                || matches!(&group.proof, GroupedKzgProof::Fk20(_))
        }));
        Ok(PreparedRs2dKzgCosetGroup {
            header: FixedGroupHeader {
                block_id,
                profile_id: self.profile.id(),
                commitments: source_commitments,
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
        prepared: &PreparedRs2dKzgCosetGroup,
        plan: &FixedGroupSamplePlan,
    ) -> Result<FixedGroupResponses, VerificationError> {
        let groups = self
            .group_ids(&plan.indices)?
            .into_iter()
            .map(|id| {
                let g = &prepared.groups[id.local_code_index][id.local_group_index];
                Ok(GroupResponse {
                    id,
                    values: g.values.clone(),
                    proof: g.proof.clone(),
                    start: g.start,
                })
            })
            .collect::<Result<Vec<_>, VerificationError>>()?;
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
        let domain = Radix2EvaluationDomain::<Fr>::new(self.code.n0()).expect("radix domain");
        let all_commitments = self.derived_commitments(&header.commitments);
        for (id, received) in ids.iter().zip(&response.groups) {
            if id != &received.id {
                return Err(VerificationError::NonCanonicalClaim);
            }
            let expected = &self.groups[id.local_code_index][id.local_group_index];
            if received.values.len() != expected.local_positions.len()
                || received.start != domain.element(id.local_group_index)
            {
                return Err(VerificationError::NonCanonicalClaim);
            }
            let valid = match &received.proof {
                GroupedKzgProof::Fk20(proof) => self.pcs.verify_coset(
                    &all_commitments[id.local_code_index],
                    received.start,
                    &received.values,
                    proof,
                ),
                GroupedKzgProof::Shplonk(proof) => {
                    let points = expected
                        .local_positions
                        .iter()
                        .map(|&i| domain.element(i))
                        .collect::<Vec<_>>();
                    self.pcs.verify_multipoint(
                        &all_commitments[id.local_code_index],
                        &points,
                        &received.values,
                        proof,
                    )
                }
            };
            if !valid {
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
            // The two size-64 groups in a 128-point row are multiplicative
            // cosets, so their encoded-array indices are strided.  Group
            // ownership is therefore index modulo the number of cosets,
            // rather than contiguous `index / group_size` ownership.
            ids.insert(GroupId {
                local_code_index: local.local_code().get(),
                local_group_index: local.local_index() % (self.code.n0() / self.group_size()),
            });
        }
        Ok(ids.into_iter().collect())
    }
    fn validate_header(&self, header: &FixedGroupHeader) -> Result<(), VerificationError> {
        if header.profile_id != self.profile.id() {
            return Err(VerificationError::WrongConfig);
        }
        if header.commitments.len() != self.code.k0() {
            return Err(VerificationError::WrongCommitmentCount);
        }
        Ok(())
    }
    fn derived_commitments(
        &self,
        source: &[Commitment<Bls12_381>],
    ) -> Vec<Commitment<Bls12_381>> {
        (0..self.code.n0())
            .map(|row| {
                self.pcs
                    .linear_combination_commitment(source, &self.code.source_row_weights(row))
            })
            .collect()
    }
}
impl FixedGroupHeader {
    pub fn local_commitments(&self) -> &[Commitment<Bls12_381>] {
        &self.commitments
    }
    pub fn serialized_size(&self) -> usize {
        32 + self
            .commitments
            .iter()
            .map(|c| c.compressed_size())
            .sum::<usize>()
    }
}
impl PreparedRs2dKzgCosetGroup {
    pub fn proof_count(&self) -> usize {
        self.groups.iter().map(Vec::len).sum()
    }
}
impl PreparedRs2dKzgCosetGroup {
    pub fn proof_bytes(&self) -> usize {
        self.groups
            .iter()
            .flat_map(|gs| gs.iter())
            .map(|g| match &g.proof {
                GroupedKzgProof::Fk20(proof) => proof.w.compressed_size(),
                GroupedKzgProof::Shplonk(proof) => proof.compressed_size(),
            })
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
        self.groups.iter().map(|g| g.values.len() * 32).sum()
    }
    pub fn proof_bytes(&self) -> usize {
        self.groups
            .iter()
            .map(|g| match &g.proof {
                GroupedKzgProof::Fk20(proof) => proof.w.compressed_size(),
                GroupedKzgProof::Shplonk(proof) => proof.compressed_size(),
            })
            .sum()
    }
    pub fn metadata_bytes(&self) -> usize {
        self.groups.len() * 24
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size_64_groups_partition_each_128_point_row_as_cosets() {
        let scheme = Rs2dKzgCosetGroup::setup(128, 64, 1, 64, 1).unwrap();
        let mut positions = scheme.groups[0]
            .iter()
            .flat_map(|group| group.local_positions.iter().copied())
            .collect::<Vec<_>>();
        positions.sort_unstable();
        assert_eq!(positions, (0..128).collect::<Vec<_>>());
        assert_eq!(
            scheme.groups[0][0].local_positions,
            (0..128).step_by(2).collect::<Vec<_>>()
        );
        assert_eq!(
            scheme.groups[0][1].local_positions,
            (1..128).step_by(2).collect::<Vec<_>>()
        );
    }

    #[test]
    fn optimized_coset_group_authenticates_a_sampled_row() {
        let scheme = Rs2dKzgCosetGroup::setup(128, 64, 1, 64, 1).unwrap();
        let message = (1..=4096).map(|x| Fr::from(x as u64)).collect::<Vec<_>>();
        let prepared = scheme.prepare(BlockId::new([0x44; 32]), &message).unwrap();
        let plan = scheme.sample(&prepared.header, &[0]).unwrap();
        let response = scheme.respond(&prepared, &plan).unwrap();
        scheme.verify(&prepared.header, &plan, &response).unwrap();
    }

    #[test]
    fn one_cell_covers_a_64_point_row() {
        let scheme = Rs2dKzgCosetGroup::setup(64, 32, 1, 64, 1).unwrap();
        assert_eq!(scheme.groups[0].len(), 1);
        assert_eq!(scheme.groups[0][0].local_positions, (0..64).collect::<Vec<_>>());
        let message = (1..=1024).map(|x| Fr::from(x as u64)).collect::<Vec<_>>();
        let prepared = scheme.prepare(BlockId::new([0x46; 32]), &message).unwrap();
        let plan = scheme.sample(&prepared.header, &[0]).unwrap();
        let response = scheme.respond(&prepared, &plan).unwrap();
        scheme.verify(&prepared.header, &plan, &response).unwrap();
    }

    #[test]
    fn shplonk_group_authenticates_a_sampled_row() {
        let scheme = Rs2dKzgCosetGroup::setup_shplonk(128, 64, 1, 64, 1).unwrap();
        let message = (1..=4096).map(|x| Fr::from(x as u64)).collect::<Vec<_>>();
        let prepared = scheme.prepare(BlockId::new([0x45; 32]), &message).unwrap();
        let plan = scheme.sample(&prepared.header, &[0]).unwrap();
        let response = scheme.respond(&prepared, &plan).unwrap();
        scheme.verify(&prepared.header, &plan, &response).unwrap();
        assert!(matches!(
            response.groups[0].proof,
            GroupedKzgProof::Shplonk(_)
        ));
    }
}
