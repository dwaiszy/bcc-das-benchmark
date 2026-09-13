//! Generic, role-separated data-availability sampling construction.

pub mod bcc_kzg;
pub mod bcc_whir;
pub mod code;
mod errors;
mod das_lifecycle;
mod protocol_profile;
mod proof_serialization;
pub mod rs2d_kzg;

pub use das_lifecycle::{
    AuthenticatedLocalCommitment, BlockId, BlockProposer, CommittedBlock,
    ConsensusHeader, DispersalSet, EncodedBlock, EncodedCommittedBlock, ErasureCode,
    LightClientVerifier, LocalCodeId, LocalPosition, PolynomialBlock, PreparationMetrics,
    PreparedBlock, SamplePlan, SampleResponse, SampleResponses,
    SetupArtifacts, VerifiedTranscript, setup_roles,
};
pub use errors::{CodeError, ExtractionError, PrepareError, SetupError, VerificationError};
pub use proof_serialization::ProofMeasurements;
pub use protocol_profile::{
    CodeProfile, FieldProfile, OpeningProfileId, PcsProfile, ProtocolProfile, ProtocolProfileId,
};
