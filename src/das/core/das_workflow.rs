//! Shared commit, encode, open, sample, disperse, and verify.
//! This file keeps proposer and light-client roles independent of the code or PCS.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub use crate::das::core::errors::{
    CodeError, ExtractionError, PrepareError, SetupError, VerificationError,
};
use crate::das::core::proof_serialization::ProofMeasurements;
use crate::das::core::protocol_config::{CodeConfig, ProtocolConfig, ProtocolConfigDigest};
use crate::pcs::{ArcPcs, OpeningPoint, VerificationTiming};
use ark_ff::{FftField, Zero};
use ark_serialize::{CanonicalSerialize, Compress};
use rand::SeedableRng;
use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use rayon::ThreadPool;
use rayon::prelude::*;

use crate::das::core::scalar_opening::{OpeningStrategy, ScalarOpening};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BlockId([u8; 32]);

impl BlockId {
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LocalCodeId(usize);

impl LocalCodeId {
    pub(crate) const fn new(value: usize) -> Self {
        Self(value)
    }
    pub const fn get(self) -> usize {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct LocalPosition {
    local_code: LocalCodeId,
    local_index: usize,
}

impl LocalPosition {
    pub(crate) const fn new(local_code: LocalCodeId, local_index: usize) -> Self {
        Self {
            local_code,
            local_index,
        }
    }
    pub const fn local_code(self) -> LocalCodeId {
        self.local_code
    }
    pub const fn local_index(self) -> usize {
        self.local_index
    }
}

#[derive(Clone, Copy, Debug)]
pub struct EvaluationClaim<F> {
    global_index: usize,
    local: LocalPosition,
    point: F,
    domain_index: usize,
    value: F,
}

impl<F: Copy> EvaluationClaim<F> {
    pub(crate) const fn new(
        global_index: usize,
        local: LocalPosition,
        point: F,
        domain_index: usize,
        value: F,
    ) -> Self {
        Self {
            global_index,
            local,
            point,
            domain_index,
            value,
        }
    }
    pub const fn global_index(&self) -> usize {
        self.global_index
    }
    pub const fn local_position(&self) -> LocalPosition {
        self.local
    }
    pub const fn point(&self) -> F {
        self.point
    }
    pub const fn domain_index(&self) -> usize {
        self.domain_index
    }
    pub const fn value(&self) -> F {
        self.value
    }
    pub(crate) fn opening_point(&self) -> OpeningPoint<F> {
        OpeningPoint::new(self.point, self.domain_index)
    }
}

pub struct LocalCode<F> {
    coefficients: Vec<F>,
    claims: Vec<EvaluationClaim<F>>,
}

/// Degree-`< k0` local polynomials derived from the original block before
/// any encoded symbols are evaluated.
pub struct PolynomialBlock<F> {
    local_polynomials: Vec<Vec<F>>,
}

impl<F> PolynomialBlock<F> {
    pub fn new(
        local_polynomials: Vec<Vec<F>>,
        expected_codes: usize,
        expected_coefficients: usize,
    ) -> Result<Self, CodeError> {
        if local_polynomials.len() != expected_codes
            || local_polynomials
                .iter()
                .any(|coefficients| coefficients.len() != expected_coefficients)
        {
            return Err(CodeError::InvalidPolynomialShape);
        }
        Ok(Self { local_polynomials })
    }

    pub fn local_polynomials(&self) -> &[Vec<F>] {
        &self.local_polynomials
    }
}

impl<F> LocalCode<F> {
    pub(crate) fn new(coefficients: Vec<F>, claims: Vec<EvaluationClaim<F>>) -> Self {
        Self {
            coefficients,
            claims,
        }
    }
    pub fn coefficients(&self) -> &[F] {
        &self.coefficients
    }
    pub fn claims(&self) -> &[EvaluationClaim<F>] {
        &self.claims
    }
}

pub struct EncodedBlock<F> {
    symbols: Vec<F>,
    local_codes: Vec<LocalCode<F>>,
}

impl<F> EncodedBlock<F> {
    pub(crate) fn new(
        symbols: Vec<F>,
        local_codes: Vec<LocalCode<F>>,
        expected_codes: usize,
        expected_len: usize,
    ) -> Result<Self, CodeError> {
        if local_codes.len() != expected_codes
            || local_codes
                .iter()
                .any(|local| local.claims.len() != expected_len)
        {
            return Err(CodeError::InvalidEncodedShape);
        }
        Ok(Self {
            symbols,
            local_codes,
        })
    }
    pub fn symbols(&self) -> &[F] {
        &self.symbols
    }
    pub fn local_codes(&self) -> &[LocalCode<F>] {
        &self.local_codes
    }
}

pub trait ErasureCode: Clone + Send + Sync + 'static {
    type Field: FftField + CanonicalSerialize + Send + Sync + 'static;
    fn profile(&self) -> CodeConfig;
    fn message_len(&self) -> usize;
    fn codeword_len(&self) -> usize;
    fn local_code_count(&self) -> usize;
    fn local_dimension(&self) -> usize;
    fn local_code_len(&self) -> usize;
    /// Number of PCS commitments included in the public header. BCC publishes
    /// one commitment per local arc, while 2D-RS publishes only the source-row
    /// commitments and derives encoded-row commitments from them homomorphically.
    fn published_commitment_count(&self) -> usize {
        self.local_code_count()
    }
    /// Optional polynomial coefficient vectors used to form the header commitments.
    /// If absent, each local polynomial is committed directly.
    fn header_polynomials(
        &self,
        _message: &[Self::Field],
        _polynomials: &PolynomialBlock<Self::Field>,
    ) -> Result<Option<Vec<Vec<Self::Field>>>, CodeError> {
        Ok(None)
    }
    /// Return the information needed to derive a local-code commitment from the
    /// header commitments. If unavailable, the local-code commitment is read
    /// directly from the header.
    fn header_commitment_weights(&self, _local_code: usize) -> Option<Vec<Self::Field>> {
        None
    }
    /// Convert the input message into local degree-`< k0` polynomials before
    /// encoding the message. The PCS commitment function then commits to these
    /// polynomials.
    fn polynomialize(
        &self,
        message: &[Self::Field],
    ) -> Result<PolynomialBlock<Self::Field>, CodeError>;
    /// Encode the committed local polynomials to produce the encoded symbols and
    /// their evaluation claims.
    fn encode_polynomials(
        &self,
        polynomials: &PolynomialBlock<Self::Field>,
    ) -> Result<EncodedBlock<Self::Field>, CodeError>;
    fn encode(&self, message: &[Self::Field]) -> Result<EncodedBlock<Self::Field>, CodeError> {
        let polynomials = self.polynomialize(message)?;
        self.encode_polynomials(&polynomials)
    }
    fn canonical_position(&self, global_index: usize) -> Result<LocalPosition, CodeError>;
    fn canonical_claim(
        &self,
        global_index: usize,
        value: Self::Field,
    ) -> Result<EvaluationClaim<Self::Field>, CodeError>;
    fn reception_threshold(&self) -> usize;
    fn decode(&self, received: &[Option<Self::Field>]) -> Result<Vec<Self::Field>, CodeError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct PreparationMetrics {
    pub encode: Duration,
    pub commit: Duration,
    pub open: Duration,
    pub opening: OpeningBreakdown,
}

    /// Records the time and memory used to prepare all opening proofs before
    /// clients sample positions.
#[derive(Clone, Copy, Debug, Default)]
pub struct OpeningBreakdown {
    pub group_mapping: Duration,
    pub point_preparation: Duration,
    pub state_clone_or_rebuild: Duration,
    pub evaluation_check: Duration,
    pub whir_cryptographic_prove: Duration,
    pub proof_serialization: Duration,
    pub proof_compression: Duration,
    pub peak_or_estimated_working_memory_bytes: usize,
    pub uncompressed_proof_oracle_bytes: usize,
    pub compressed_proof_oracle_bytes: usize,
}

impl PreparationMetrics {
    pub fn total_proving(&self) -> Duration {
        self.encode + self.commit + self.open
    }
}

pub struct ConsensusHeader<C> {
    block_id: BlockId,
    profile_id: ProtocolConfigDigest,
    commitments: Vec<C>,
}

impl<C> ConsensusHeader<C> {
    pub const fn block_id(&self) -> BlockId {
        self.block_id
    }
    pub const fn profile_id(&self) -> ProtocolConfigDigest {
        self.profile_id
    }
    pub fn local_commitments(&self) -> &[C] {
        &self.commitments
    }
}

pub struct OpeningEntry<F, Proof> {
    claim: EvaluationClaim<F>,
    proof: Proof,
}
pub struct LocalOpeningOracle<F, Proof> {
    entries: Vec<OpeningEntry<F, Proof>>,
}

pub struct DispersalSet<F, Proof> {
    local_oracles: Vec<LocalOpeningOracle<F, Proof>>,
}

impl<F: Copy, Proof: Clone> DispersalSet<F, Proof> {
    pub fn local_code_count(&self) -> usize {
        self.local_oracles.len()
    }
    pub fn opening_count(&self) -> usize {
        self.local_oracles
            .iter()
            .map(|oracle| oracle.entries.len())
            .sum()
    }
    pub fn local_opening_counts(&self) -> impl Iterator<Item = usize> + '_ {
        self.local_oracles.iter().map(|oracle| oracle.entries.len())
    }

    pub fn proof_oracle_bytes<P>(&self, pcs: &P) -> usize
    where
        F: ark_ff::FftField,
        P: ArcPcs<F, Proof = Proof>,
    {
        self.local_oracles
            .iter()
            .flat_map(|oracle| oracle.entries.iter())
            .map(|entry| pcs.proof_bytes(&entry.proof))
            .sum()
    }

    pub fn respond(
        &self,
        plan: &SamplePlan,
    ) -> Result<SampleResponses<F, Proof>, VerificationError> {
        let responses = plan
            .samples
            .iter()
            .map(|sample| {
                let entry = self
                    .local_oracles
                    .get(sample.local.local_code().get())
                    .and_then(|oracle| oracle.entries.get(sample.local.local_index()))
                    .ok_or(VerificationError::MissingResponse)?;
                if entry.claim.global_index() != sample.global_index {
                    return Err(VerificationError::NonCanonicalClaim);
                }
                Ok(SampleResponse {
                    global_index: entry.claim.global_index(),
                    value: entry.claim.value(),
                    proof: entry.proof.clone(),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(SampleResponses { responses })
    }
}

pub struct PreparedBlock<F, C, Proof> {
    pub header: ConsensusHeader<C>,
    pub dispersal: DispersalSet<F, Proof>,
    pub metrics: PreparationMetrics,
}

pub struct CommittedBlock<F, C, State> {
    header: ConsensusHeader<C>,
    polynomials: PolynomialBlock<F>,
    states: Vec<State>,
    commit: Duration,
}

/// State after commitment and erasure encoding. It retains the PCS state and
/// the corresponding claims needed to generate scalar opening proofs.
pub struct EncodedCommittedBlock<F, C, State> {
    header: ConsensusHeader<C>,
    encoded: EncodedBlock<F>,
    states: Vec<State>,
    commit: Duration,
    encode: Duration,
}

impl<F, C, State> CommittedBlock<F, C, State> {
    pub fn header(&self) -> &ConsensusHeader<C> {
        &self.header
    }
}

impl<F, C, State> EncodedCommittedBlock<F, C, State> {
    pub fn header(&self) -> &ConsensusHeader<C> {
        &self.header
    }
}

#[derive(Clone, Debug)]
struct PlannedSample {
    global_index: usize,
    local: LocalPosition,
}

#[derive(Clone, Debug)]
pub struct SamplePlan {
    block_id: BlockId,
    profile_id: ProtocolConfigDigest,
    indices: Vec<usize>,
    samples: Vec<PlannedSample>,
}

impl SamplePlan {
    pub fn sampled_indices(&self) -> &[usize] {
        &self.indices
    }
}

#[derive(Clone)]
pub struct SampleResponse<F, Proof> {
    global_index: usize,
    value: F,
    proof: Proof,
}

impl<F: Copy, Proof> SampleResponse<F, Proof> {
    pub const fn global_index(&self) -> usize {
        self.global_index
    }
    pub const fn value(&self) -> F {
        self.value
    }
    pub fn proof(&self) -> &Proof {
        &self.proof
    }
}

pub struct SampleResponses<F, Proof> {
    responses: Vec<SampleResponse<F, Proof>>,
}

impl<F, Proof> SampleResponses<F, Proof> {
    pub fn len(&self) -> usize {
        self.responses.len()
    }
    pub fn is_empty(&self) -> bool {
        self.responses.is_empty()
    }
    pub fn get(&self, index: usize) -> Option<&SampleResponse<F, Proof>> {
        self.responses.get(index)
    }

    pub fn authenticated_values(&self) -> Vec<(usize, F)>
    where
        F: Copy,
    {
        self.responses
            .iter()
            .map(|response| (response.global_index, response.value))
            .collect()
    }
}

pub struct AuthenticatedLocalCommitment<C> {
    local_code: LocalCodeId,
    commitment: C,
    profile_id: ProtocolConfigDigest,
}

pub struct VerifiedTranscript<F> {
    block_id: BlockId,
    profile_id: ProtocolConfigDigest,
    indices: Vec<usize>,
    samples: Vec<(usize, F)>,
}

impl<F> VerifiedTranscript<F> {
    pub fn sampled_indices(&self) -> &[usize] {
        &self.indices
    }
    pub fn samples(&self) -> &[(usize, F)] {
        &self.samples
    }
}

pub struct BlockProposer<C, P>
where
    C: ErasureCode,
    P: ArcPcs<C::Field>,
{
    code: C,
    pcs: Arc<P>,
    profile: ProtocolConfig,
    pool: Arc<ThreadPool>,
}

pub struct LightClientVerifier<C, P>
where
    C: ErasureCode,
    P: ArcPcs<C::Field>,
{
    code: C,
    pcs: Arc<P>,
    profile: ProtocolConfig,
}

pub struct SetupArtifacts<C, P>
where
    C: ErasureCode,
    P: ArcPcs<C::Field>,
{
    pub proposer: BlockProposer<C, P>,
    pub verifier: LightClientVerifier<C, P>,
}

pub fn setup_roles<C, P>(
    code: C,
    pcs: P,
    profile: ProtocolConfig,
    threads: usize,
) -> Result<SetupArtifacts<C, P>, SetupError>
where
    C: ErasureCode,
    P: ArcPcs<C::Field>,
{
    if threads == 0 || profile.proposer_threads() != threads || profile.code() != code.profile() {
        return Err(SetupError::ConfigMismatch);
    }
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .stack_size(16 * 1024 * 1024)
        .thread_name(|index| format!("das-proposer-{index}"))
        .build()
        .map_err(|_| SetupError::ThreadPool)?;
    let pcs = Arc::new(pcs);
    Ok(SetupArtifacts {
        proposer: BlockProposer {
            code: code.clone(),
            pcs: Arc::clone(&pcs),
            profile: profile.clone(),
            pool: Arc::new(pool),
        },
        verifier: LightClientVerifier { code, pcs, profile },
    })
}

impl<C, P> BlockProposer<C, P>
where
    C: ErasureCode,
    P: ArcPcs<C::Field>,
{
    pub fn message_len(&self) -> usize {
        self.code.message_len()
    }
    pub fn profile(&self) -> &ProtocolConfig {
        &self.profile
    }

    pub fn pcs(&self) -> &P {
        self.pcs.as_ref()
    }

    pub fn commit(
        &self,
        block_id: BlockId,
        message: &[C::Field],
    ) -> Result<CommittedBlock<C::Field, P::Commitment, P::ProverState>, PrepareError> {
        if message.len() != self.code.message_len() {
            return Err(PrepareError::WrongMessageLength {
                got: message.len(),
                expected: self.code.message_len(),
            });
        }
        // The proposer constructs and commits to the local polynomials before
        // evaluating them to produce the encoded codeword symbols.
        let started = Instant::now();
        let polynomials = self.pool.install(|| self.code.polynomialize(message))?;
        let committed = self.pool.install(|| {
            polynomials
                .local_polynomials()
                .par_iter()
                .map(|coefficients| self.pcs.commit(coefficients))
                .collect::<Result<Vec<_>, _>>()
        })?;
        let commit = started.elapsed();
        let (commitments, states): (Vec<_>, Vec<_>) = committed.into_iter().unzip();
        let header_commitments = match self.code.header_polynomials(message, &polynomials)? {
            Some(coefficients) => self.pool.install(|| {
                coefficients
                    .par_iter()
                    .map(|coefficients| self.pcs.commit(coefficients).map(|(commitment, _)| commitment))
                    .collect::<Result<Vec<_>, _>>()
            })?,
            None => commitments.clone(),
        };
        if header_commitments.len() != self.code.published_commitment_count() {
            return Err(PrepareError::Code(CodeError::InvalidPolynomialShape));
        }

        Ok(CommittedBlock {
            header: ConsensusHeader {
                block_id,
                profile_id: self.profile.id(),
                commitments: header_commitments,
            },
            polynomials,
            states,
            commit,
        })
    }

    pub fn encode(
        &self,
        committed: CommittedBlock<C::Field, P::Commitment, P::ProverState>,
    ) -> Result<EncodedCommittedBlock<C::Field, P::Commitment, P::ProverState>, PrepareError> {
        let started = Instant::now();
        let encoded = self
            .pool
            .install(|| self.code.encode_polynomials(&committed.polynomials))?;
        let encode = started.elapsed();

        Ok(EncodedCommittedBlock {
            header: committed.header,
            encoded,
            states: committed.states,
            commit: committed.commit,
            encode,
        })
    }

    pub fn open(
        &self,
        encoded: EncodedCommittedBlock<C::Field, P::Commitment, P::ProverState>,
    ) -> Result<PreparedBlock<C::Field, P::Commitment, P::Proof>, PrepareError> {
        let started = Instant::now();
        let proof_sets = self.pool.install(|| {
            encoded
                .states
                .par_iter()
                .zip(encoded.encoded.local_codes())
                .map(|(state, local)| {
                    ScalarOpening::precompute(self.pcs.as_ref(), state, local.claims())
                })
                .collect::<Result<Vec<_>, _>>()
        })?;
        let open = started.elapsed();

        let mut local_oracles = Vec::with_capacity(encoded.encoded.local_codes().len());
        for (local, proofs) in encoded.encoded.local_codes().iter().zip(proof_sets) {
            if proofs.len() != local.claims().len() {
                return Err(PrepareError::WrongProofCount);
            }
            local_oracles.push(LocalOpeningOracle {
                entries: local
                    .claims()
                    .iter()
                    .copied()
                    .zip(proofs)
                    .map(|(claim, proof)| OpeningEntry { claim, proof })
                    .collect(),
            });
        }
        Ok(PreparedBlock {
            header: encoded.header,
            dispersal: DispersalSet { local_oracles },
            metrics: PreparationMetrics {
                encode: encoded.encode,
                commit: encoded.commit,
                open,
                opening: OpeningBreakdown::default(),
            },
        })
    }

    /// Run the proposer workflow in order: commit the local polynomials, encode the
    /// message, and generate the opening proofs.
    pub fn prepare(
        &self,
        block_id: BlockId,
        message: &[C::Field],
    ) -> Result<PreparedBlock<C::Field, P::Commitment, P::Proof>, PrepareError> {
        let committed = self.commit(block_id, message)?;
        let encoded = self.encode(committed)?;
        self.open(encoded)
    }
}

impl<C, P> LightClientVerifier<C, P>
where
    C: ErasureCode,
    P: ArcPcs<C::Field>,
{
    pub fn profile(&self) -> &ProtocolConfig {
        &self.profile
    }
    pub fn sample_count(&self) -> usize {
        self.profile.sample_count()
    }

    pub fn proof_measurements(
        &self,
        header: &ConsensusHeader<P::Commitment>,
        responses: &SampleResponses<C::Field, P::Proof>,
    ) -> Result<ProofMeasurements, VerificationError> {
        self.validate_header(header)?;
        let header_bytes = self.profile.id().serialized_size()
            + header
                .commitments
                .iter()
                .map(|commitment| self.pcs.commitment_bytes(commitment))
                .sum::<usize>();
        let sample_data_bytes = responses.len() * C::Field::zero().serialized_size(Compress::Yes);
        let verify_proof_bytes = responses
            .responses
            .iter()
            .map(|response| self.pcs.proof_bytes(&response.proof))
            .sum();
        let sample_metadata_bytes = responses.responses.len() * std::mem::size_of::<u64>();
        Ok(ProofMeasurements {
            header_bytes,
            sample_data_bytes,
            verify_proof_bytes,
            sample_metadata_bytes,
            light_client_download_bytes: header_bytes
                + sample_data_bytes
                + verify_proof_bytes
                + sample_metadata_bytes,
        })
    }

    fn validate_header(
        &self,
        header: &ConsensusHeader<P::Commitment>,
    ) -> Result<(), VerificationError> {
        if header.profile_id != self.profile.id() {
            return Err(VerificationError::WrongConfig);
        }
        if header.commitments.len() != self.code.published_commitment_count() {
            return Err(VerificationError::WrongCommitmentCount);
        }
        Ok(())
    }

    pub fn v1(
        &self,
        header: &ConsensusHeader<P::Commitment>,
        seed: [u8; 32],
    ) -> Result<SamplePlan, VerificationError> {
        self.validate_header(header)?;
        let mut indices = (0..self.code.codeword_len()).collect::<Vec<_>>();
        indices.shuffle(&mut StdRng::from_seed(seed));
        self.v1_from_indices(header, &indices[..self.sample_count()])
    }

    pub fn v1_from_indices(
        &self,
        header: &ConsensusHeader<P::Commitment>,
        indices: &[usize],
    ) -> Result<SamplePlan, VerificationError> {
        self.validate_header(header)?;
        if indices.len() != self.sample_count() {
            return Err(VerificationError::WrongSampleCount);
        }
        let mut seen = std::collections::BTreeSet::new();
        let samples = indices
            .iter()
            .copied()
            .map(|global_index| {
                if !seen.insert(global_index) {
                    return Err(VerificationError::DuplicateSample);
                }
                let local = self
                    .code
                    .canonical_position(global_index)
                    .map_err(|_| VerificationError::PositionOutOfRange)?;
                Ok(PlannedSample {
                    global_index,
                    local,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(SamplePlan {
            block_id: header.block_id,
            profile_id: header.profile_id,
            indices: indices.to_vec(),
            samples,
        })
    }

    pub fn commitment_for(
        &self,
        header: &ConsensusHeader<P::Commitment>,
        global_index: usize,
    ) -> Result<AuthenticatedLocalCommitment<P::Commitment>, VerificationError> {
        self.validate_header(header)?;
        let local = self
            .code
            .canonical_position(global_index)
            .map_err(|_| VerificationError::PositionOutOfRange)?;
        let commitment = match self.code.header_commitment_weights(local.local_code().get()) {
            Some(weights) => self
                .pcs
                .derive_commitment(&header.commitments, &weights)
                .map_err(|_| VerificationError::WrongCommitmentCount)?,
            None => header
                .commitments
                .get(local.local_code().get())
                .cloned()
                .ok_or(VerificationError::WrongCommitmentCount)?,
        };
        Ok(AuthenticatedLocalCommitment {
            local_code: local.local_code(),
            commitment,
            profile_id: header.profile_id,
        })
    }

    pub fn verify_sample(
        &self,
        authenticated: AuthenticatedLocalCommitment<P::Commitment>,
        response: &SampleResponse<C::Field, P::Proof>,
    ) -> Result<(), VerificationError> {
        if authenticated.profile_id != self.profile.id() {
            return Err(VerificationError::WrongConfig);
        }
        let claim = self
            .code
            .canonical_claim(response.global_index, response.value)
            .map_err(|_| VerificationError::PositionOutOfRange)?;
        if claim.local_position().local_code() != authenticated.local_code {
            return Err(VerificationError::WrongCommitment);
        }
        self.pcs
            .verify(
                &authenticated.commitment,
                claim.point(),
                claim.value(),
                &response.proof,
            )
            .map_err(|_| VerificationError::InvalidProof)
    }

    pub fn v2(
        &self,
        header: &ConsensusHeader<P::Commitment>,
        plan: &SamplePlan,
        responses: &SampleResponses<C::Field, P::Proof>,
    ) -> Result<VerifiedTranscript<C::Field>, VerificationError> {
        self.v2_with_timing(header, plan, responses)
            .map(|(transcript, _)| transcript)
    }

    pub fn v2_with_timing(
        &self,
        header: &ConsensusHeader<P::Commitment>,
        plan: &SamplePlan,
        responses: &SampleResponses<C::Field, P::Proof>,
    ) -> Result<(VerifiedTranscript<C::Field>, VerificationTiming), VerificationError> {
        self.validate_header(header)?;
        if plan.block_id != header.block_id
            || plan.profile_id != header.profile_id
            || responses.responses.len() != plan.samples.len()
        {
            return Err(VerificationError::PlanMismatch);
        }
        let verification_started = Instant::now();
        let mut commitment_selection = Duration::ZERO;
        let mut evaluation_point = Duration::ZERO;
        let mut batch_preparation = Duration::ZERO;
        let mut samples = Vec::with_capacity(plan.samples.len());
        let mut selected_commitments = Vec::with_capacity(plan.samples.len());
        let mut claims = Vec::with_capacity(plan.samples.len());
        for (planned, response) in plan.samples.iter().zip(&responses.responses) {
            if response.global_index != planned.global_index {
                return Err(VerificationError::PlanMismatch);
            }
            let started = Instant::now();
            let commitment = self.commitment_for(header, response.global_index)?;
            commitment_selection += started.elapsed();
            let started = Instant::now();
            let claim = self
                .code
                .canonical_claim(response.global_index, response.value)
                .map_err(|_| VerificationError::PositionOutOfRange)?;
            evaluation_point += started.elapsed();
            if claim.local_position().local_code() != commitment.local_code {
                return Err(VerificationError::WrongCommitment);
            }
            let started = Instant::now();
            selected_commitments.push(commitment.commitment);
            claims.push((claim.point(), claim.value(), &response.proof));
            samples.push((response.global_index, response.value));
            batch_preparation += started.elapsed();
        }
        let entries = selected_commitments
            .iter()
            .zip(claims.iter())
            .map(|(commitment, (point, value, proof))| (commitment, *point, *value, *proof))
            .collect::<Vec<_>>();
        let timing = self
            .pcs
            .verify_batch_timed(&entries)
            .map_err(|_| VerificationError::InvalidProof)?;
        let total = verification_started.elapsed();
        let pcs_verification = timing.total.saturating_sub(timing.decompression);
        Ok((
            VerifiedTranscript {
                block_id: header.block_id,
                profile_id: header.profile_id,
                indices: plan.indices.clone(),
                samples,
            },
            VerificationTiming {
                commitment_selection,
                evaluation_point,
                batch_preparation,
                proof_deserialization: Duration::ZERO,
                decompression: timing.decompression,
                pcs_verification,
                total,
            },
        ))
    }

    pub fn ext(
        &self,
        header: &ConsensusHeader<P::Commitment>,
        transcripts: &[VerifiedTranscript<C::Field>],
    ) -> Result<Vec<C::Field>, ExtractionError> {
        self.validate_header(header)
            .map_err(ExtractionError::Verification)?;
        let mut received = BTreeMap::new();
        for transcript in transcripts {
            if transcript.block_id != header.block_id || transcript.profile_id != header.profile_id
            {
                return Err(ExtractionError::WrongTranscript);
            }
            for &(index, value) in &transcript.samples {
                if received
                    .insert(index, value)
                    .is_some_and(|old| old != value)
                {
                    return Err(ExtractionError::ConflictingValue);
                }
            }
        }
        if received.len() < self.code.reception_threshold() {
            return Err(ExtractionError::InsufficientReception {
                got: received.len(),
                required: self.code.reception_threshold(),
            });
        }
        let mut symbols = vec![None; self.code.codeword_len()];
        for (index, value) in received {
            symbols[index] = Some(value);
        }
        self.code.decode(&symbols).map_err(ExtractionError::Code)
    }
}

#[cfg(test)]
mod workflow_order_tests {
    use std::sync::{Arc, Mutex};

    use ark_bls12_381::Fr;

    use super::*;
    use crate::pcs::{PcsError, kzg::KzgStrategy};

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Event {
        PolynomializeStart,
        PolynomializeEnd,
        CommitStart,
        CommitEnd,
        EncodeStart,
        EncodeEnd,
        OpenStart,
        OpenEnd,
    }

    type Events = Arc<Mutex<Vec<Event>>>;

    fn record(events: &Events, event: Event) {
        events.lock().expect("event log lock").push(event);
    }

    #[derive(Clone)]
    struct RecordingCode {
        events: Events,
    }

    impl ErasureCode for RecordingCode {
        type Field = Fr;

        fn profile(&self) -> CodeConfig {
            CodeConfig::Rs2d { n0: 2, k0: 1 }
        }

        fn message_len(&self) -> usize {
            1
        }

        fn codeword_len(&self) -> usize {
            2
        }

        fn local_code_count(&self) -> usize {
            2
        }

        fn local_dimension(&self) -> usize {
            1
        }

        fn local_code_len(&self) -> usize {
            1
        }

        fn polynomialize(&self, message: &[Fr]) -> Result<PolynomialBlock<Fr>, CodeError> {
            record(&self.events, Event::PolynomializeStart);
            let result =
                PolynomialBlock::new(vec![vec![message[0]], vec![message[0] + Fr::from(1)]], 2, 1);
            record(&self.events, Event::PolynomializeEnd);
            result
        }

        fn encode_polynomials(
            &self,
            polynomials: &PolynomialBlock<Fr>,
        ) -> Result<EncodedBlock<Fr>, CodeError> {
            record(&self.events, Event::EncodeStart);
            let local_codes = polynomials
                .local_polynomials()
                .iter()
                .enumerate()
                .map(|(index, coefficients)| {
                    let value = coefficients[0];
                    LocalCode::new(
                        coefficients.clone(),
                        vec![EvaluationClaim::new(
                            index,
                            LocalPosition::new(LocalCodeId::new(index), 0),
                            Fr::from(index as u64),
                            0,
                            value,
                        )],
                    )
                })
                .collect::<Vec<_>>();
            let symbols = local_codes
                .iter()
                .map(|local| local.claims()[0].value())
                .collect();
            let result = EncodedBlock::new(symbols, local_codes, 2, 1);
            record(&self.events, Event::EncodeEnd);
            result
        }

        fn canonical_position(&self, global_index: usize) -> Result<LocalPosition, CodeError> {
            (global_index < 2)
                .then(|| LocalPosition::new(LocalCodeId::new(global_index), 0))
                .ok_or(CodeError::PositionOutOfRange)
        }

        fn canonical_claim(
            &self,
            global_index: usize,
            value: Fr,
        ) -> Result<EvaluationClaim<Fr>, CodeError> {
            Ok(EvaluationClaim::new(
                global_index,
                self.canonical_position(global_index)?,
                Fr::from(global_index as u64),
                0,
                value,
            ))
        }

        fn reception_threshold(&self) -> usize {
            1
        }

        fn decode(&self, received: &[Option<Fr>]) -> Result<Vec<Fr>, CodeError> {
            received
                .iter()
                .flatten()
                .next()
                .copied()
                .map(|value| vec![value])
                .ok_or(CodeError::InvalidEncodedShape)
        }
    }

    struct RecordingPcs {
        events: Events,
    }

    impl ArcPcs<Fr> for RecordingPcs {
        type Commitment = Fr;
        type ProverState = Fr;
        type Proof = ();

        fn commit(&self, coefficients: &[Fr]) -> Result<(Fr, Fr), PcsError> {
            record(&self.events, Event::CommitStart);
            let result = Ok((coefficients[0], coefficients[0]));
            record(&self.events, Event::CommitEnd);
            result
        }

        fn precompute_openings(
            &self,
            _state: &Fr,
            points: &[OpeningPoint<Fr>],
        ) -> Result<Vec<()>, PcsError> {
            record(&self.events, Event::OpenStart);
            let result = Ok(vec![(); points.len()]);
            record(&self.events, Event::OpenEnd);
            result
        }

        fn verify(
            &self,
            _commitment: &Fr,
            _point: Fr,
            _value: Fr,
            _proof: &(),
        ) -> Result<(), PcsError> {
            Ok(())
        }

        fn commitment_bytes(&self, _commitment: &Fr) -> usize {
            32
        }

        fn proof_bytes(&self, _proof: &()) -> usize {
            0
        }
    }

    #[test]
    fn proposer_completes_commit_phase_before_encode_and_encode_before_open() {
        let events = Events::default();
        let code = RecordingCode {
            events: Arc::clone(&events),
        };
        let pcs = RecordingPcs {
            events: Arc::clone(&events),
        };
        let profile = ProtocolConfig::new(
            code.profile(),
            crate::das::core::protocol_config::FieldConfig::Bls12381Scalar,
            crate::das::core::protocol_config::PcsConfig::Kzg {
                strategy: KzgStrategy::Fk20,
            },
            1,
            [0x99; 32],
            2,
        );
        let setup = setup_roles(code, pcs, profile, 2).expect("recording setup");

        setup
            .proposer
            .prepare(BlockId::new([0x55; 32]), &[Fr::from(7)])
            .expect("ordered proposer workflow");

        let actual = events.lock().expect("event log lock").clone();
        assert_eq!(actual.len(), 12);
        assert_eq!(actual[0], Event::PolynomializeStart);
        assert_eq!(actual[1], Event::PolynomializeEnd);

        let encode_start = actual
            .iter()
            .position(|event| *event == Event::EncodeStart)
            .expect("encode start event");
        assert_eq!(
            actual[..encode_start]
                .iter()
                .filter(|&&event| event == Event::CommitEnd)
                .count(),
            2,
            "encoding started before every PCS commitment completed"
        );
        let encode_end = actual
            .iter()
            .position(|event| *event == Event::EncodeEnd)
            .expect("encode end event");
        assert!(
            actual[..encode_end]
                .iter()
                .all(|event| !matches!(event, Event::OpenStart | Event::OpenEnd)),
            "an opening started before encoding completed"
        );
        assert_eq!(
            actual[encode_end + 1..]
                .iter()
                .filter(|&&event| event == Event::OpenStart)
                .count(),
            2
        );
        assert_eq!(
            actual[encode_end + 1..]
                .iter()
                .filter(|&&event| event == Event::OpenEnd)
                .count(),
            2
        );
    }
}
