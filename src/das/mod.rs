//! Generic, role-separated data-availability sampling construction.

pub mod bcc_kzg;
pub mod bcc_whir;
pub mod code;
mod construction;
mod profile;
pub mod rs2d_das;

pub use construction::{
    AuthenticatedLocalCommitment, BlockId, BlockProposer, CodeError, CommittedBlock,
    ConsensusHeader, DispersalSet, EncodedBlock, EncodedCommittedBlock, ErasureCode,
    ExtractionError, LightClientVerifier, LocalCodeId, LocalPosition, PolynomialBlock,
    PreparationMetrics, PrepareError, PreparedBlock, SamplePlan, SampleResponse, SampleResponses,
    SetupArtifacts, SetupError, VerificationError, VerifiedTranscript, WireSizes, setup_roles,
};
pub use profile::{
    CodeProfile, FieldProfile, OpeningProfileId, PcsProfile, ProtocolProfile, ProtocolProfileId,
};
