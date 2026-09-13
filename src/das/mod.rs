//! Generic, role-separated data-availability sampling construction.

pub mod bcc_kzg;
pub mod bcc_whir;
pub mod core;
pub mod erasure_code;
pub mod rs2d_kzg;

pub use core::{
    AuthenticatedLocalCommitment, BlockId, BlockProposer, CodeConfig, CodeError, CommittedBlock,
    ConsensusHeader, DispersalSet, EncodedBlock, EncodedCommittedBlock, ErasureCode,
    ExtractionError, FieldConfig, LightClientVerifier, LocalCodeId, LocalPosition, OpeningMode,
    PcsConfig, PolynomialBlock, PreparationMetrics, PrepareError, PreparedBlock, ProofMeasurements,
    ProtocolConfig, ProtocolConfigDigest, SamplePlan, SampleResponse, SampleResponses,
    SetupArtifacts, SetupError, VerificationError, VerifiedTranscript, setup_roles,
};
