//! Generic, role-separated data-availability sampling construction.

pub mod bcc_kzg;
pub mod bcc_whir;
pub mod erasure_code;
pub mod core;
pub mod rs2d_kzg;

pub use core::{
    AuthenticatedLocalCommitment, BlockId, BlockProposer, CodeError, CodeConfig, CommittedBlock,
    ConsensusHeader, DispersalSet, EncodedBlock, EncodedCommittedBlock, ErasureCode,
    ExtractionError, FieldConfig, LightClientVerifier, LocalCodeId, LocalPosition,
    OpeningMode, PcsConfig, PolynomialBlock, PreparationMetrics, PrepareError, PreparedBlock,
    ProofMeasurements, ProtocolConfig, ProtocolConfigDigest, SamplePlan, SampleResponse,
    SampleResponses, SetupArtifacts, SetupError, VerificationError, VerifiedTranscript, setup_roles,
};
