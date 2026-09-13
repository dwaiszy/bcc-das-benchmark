//! Protocol configuration and deterministic configuration digests.

use sha2::{Digest, Sha256};

use crate::BcParams;
use crate::pcs::kzg::KzgStrategy;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ProtocolConfigDigest([u8; 32]);
impl ProtocolConfigDigest {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    pub const fn serialized_size(&self) -> usize {
        32
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FieldConfig {
    Bls12381Scalar,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CodeConfig {
    Bcc(BcParams),
    Rs2d { n0: usize, k0: usize },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PcsConfig {
    Kzg { strategy: KzgStrategy },
    WhirJohnson { security_bits: u16 },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OpeningMode {
    Scalar,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtocolConfig {
    id: ProtocolConfigDigest,
    code: CodeConfig,
    field: FieldConfig,
    pcs: PcsConfig,
    opening: OpeningMode,
    sample_count: usize,
    setup_id: [u8; 32],
    format_version: u16,
    proposer_threads: usize,
}

impl ProtocolConfig {
    pub(crate) fn new(
        code: CodeConfig,
        field: FieldConfig,
        pcs: PcsConfig,
        sample_count: usize,
        setup_id: [u8; 32],
        proposer_threads: usize,
    ) -> Self {
        let mut encoded = Vec::new();
        match code {
            CodeConfig::Bcc(params) => {
                encoded.push(1);
                encoded.extend_from_slice(&(params.mu as u64).to_le_bytes());
                encoded.extend_from_slice(&(params.omega as u64).to_le_bytes());
                encoded.extend_from_slice(&(params.rho as u64).to_le_bytes());
            }
            CodeConfig::Rs2d { n0, k0 } => {
                encoded.push(2);
                encoded.extend_from_slice(&(n0 as u64).to_le_bytes());
                encoded.extend_from_slice(&(k0 as u64).to_le_bytes());
            }
        }
        encoded.push(match field {
            FieldConfig::Bls12381Scalar => 1,
        });
        match pcs {
            PcsConfig::Kzg { strategy } => {
                encoded.push(1);
                encoded.push(match strategy {
                    KzgStrategy::Plain => 1,
                    KzgStrategy::Fk20 => 2,
                    KzgStrategy::Shplonk => 3,
                });
            }
            PcsConfig::WhirJohnson { security_bits } => {
                encoded.push(2);
                encoded.extend_from_slice(&security_bits.to_le_bytes());
            }
        }
        encoded.push(1);
        encoded.extend_from_slice(&(sample_count as u64).to_le_bytes());
        encoded.extend_from_slice(&setup_id);
        encoded.extend_from_slice(&1_u16.to_le_bytes());
        encoded.extend_from_slice(&(proposer_threads as u64).to_le_bytes());
        let id = ProtocolConfigDigest(Sha256::digest(&encoded).into());
        Self {
            id,
            code,
            field,
            pcs,
            opening: OpeningMode::Scalar,
            sample_count,
            setup_id,
            format_version: 1,
            proposer_threads,
        }
    }
    pub const fn id(&self) -> ProtocolConfigDigest {
        self.id
    }
    pub const fn code(&self) -> CodeConfig {
        self.code
    }
    pub const fn field(&self) -> FieldConfig {
        self.field
    }
    pub const fn pcs(&self) -> PcsConfig {
        self.pcs
    }
    pub const fn opening(&self) -> OpeningMode {
        self.opening
    }
    pub const fn sample_count(&self) -> usize {
        self.sample_count
    }
    pub const fn setup_id(&self) -> &[u8; 32] {
        &self.setup_id
    }
    pub const fn format_version(&self) -> u16 {
        self.format_version
    }
    pub const fn proposer_threads(&self) -> usize {
        self.proposer_threads
    }
}
