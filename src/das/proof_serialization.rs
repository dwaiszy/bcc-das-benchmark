//! Serialized proof and sample-size measurements for light-client responses.

/// Serialized byte sizes for consensus metadata and one light-client sample batch.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProofMeasurements {
    pub header_bytes: usize,
    pub sample_data_bytes: usize,
    pub verify_proof_bytes: usize,
    pub sample_metadata_bytes: usize,
    pub light_client_download_bytes: usize,
}
