//! Generic DAS workflow and shared data structures.

pub(crate) mod das_workflow;
pub(crate) mod errors;
pub(crate) mod proof_serialization;
pub(crate) mod protocol_config;
mod scalar_opening;

pub use das_workflow::{
    AuthenticatedLocalCommitment, BlockId, BlockProposer, CommittedBlock, ConsensusHeader,
    DispersalSet, EncodedBlock, EncodedCommittedBlock, ErasureCode, EvaluationClaim,
    LightClientVerifier, LocalCode, LocalCodeId, LocalPosition, PolynomialBlock,
    PreparationMetrics, PreparedBlock, SamplePlan, SampleResponse, SampleResponses, SetupArtifacts,
    VerifiedTranscript, setup_roles,
};
pub use errors::{CodeError, ExtractionError, PrepareError, SetupError, VerificationError};
pub use proof_serialization::ProofMeasurements;
pub use protocol_config::{
    CodeConfig, FieldConfig, OpeningMode, PcsConfig, ProtocolConfig, ProtocolConfigDigest,
};
