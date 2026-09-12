use sha2::{Digest, Sha256};

use crate::BcParams;
use crate::pcs::kzg::KzgStrategy;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ProtocolProfileId([u8; 32]);
impl ProtocolProfileId {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    pub const fn wire_bytes(&self) -> usize {
        32
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FieldProfile {
    Bls12381Scalar,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CodeProfile {
    Bcc(BcParams),
    Rs2d { n0: usize, k0: usize },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PcsProfile {
    Kzg {
        strategy: KzgStrategy,
    },
    WhirJohnson {
        security_bits: u16,
    },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OpeningProfileId {
    PaperScalar,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtocolProfile {
    id: ProtocolProfileId,
    code: CodeProfile,
    field: FieldProfile,
    pcs: PcsProfile,
    opening: OpeningProfileId,
    sample_count: usize,
    setup_id: [u8; 32],
    wire_version: u16,
    proposer_threads: usize,
}

impl ProtocolProfile {
    pub(crate) fn new(
        code: CodeProfile,
        field: FieldProfile,
        pcs: PcsProfile,
        sample_count: usize,
        setup_id: [u8; 32],
        proposer_threads: usize,
    ) -> Self {
        let mut encoded = Vec::new();
        match code {
            CodeProfile::Bcc(params) => {
                encoded.push(1);
                encoded.extend_from_slice(&(params.mu as u64).to_le_bytes());
                encoded.extend_from_slice(&(params.omega as u64).to_le_bytes());
                encoded.extend_from_slice(&(params.rho as u64).to_le_bytes());
            }
            CodeProfile::Rs2d { n0, k0 } => {
                encoded.push(2);
                encoded.extend_from_slice(&(n0 as u64).to_le_bytes());
                encoded.extend_from_slice(&(k0 as u64).to_le_bytes());
            }
        }
        encoded.push(match field {
            FieldProfile::Bls12381Scalar => 1,
        });
        match pcs {
            PcsProfile::Kzg { strategy } => {
                encoded.push(1);
                encoded.push(match strategy {
                    KzgStrategy::Plain => 1,
                    KzgStrategy::Fk20 => 2,
                    KzgStrategy::Shplonk => 3,
                });
            }
            PcsProfile::WhirJohnson { security_bits } => {
                encoded.push(2);
                encoded.extend_from_slice(&security_bits.to_le_bytes());
            }
        }
        encoded.push(1);
        encoded.extend_from_slice(&(sample_count as u64).to_le_bytes());
        encoded.extend_from_slice(&setup_id);
        encoded.extend_from_slice(&1_u16.to_le_bytes());
        encoded.extend_from_slice(&(proposer_threads as u64).to_le_bytes());
        let id = ProtocolProfileId(Sha256::digest(&encoded).into());
        Self {
            id,
            code,
            field,
            pcs,
            opening: OpeningProfileId::PaperScalar,
            sample_count,
            setup_id,
            wire_version: 1,
            proposer_threads,
        }
    }
    pub const fn id(&self) -> ProtocolProfileId {
        self.id
    }
    pub const fn code(&self) -> CodeProfile {
        self.code
    }
    pub const fn field(&self) -> FieldProfile {
        self.field
    }
    pub const fn pcs(&self) -> PcsProfile {
        self.pcs
    }
    pub const fn opening(&self) -> OpeningProfileId {
        self.opening
    }
    pub const fn sample_count(&self) -> usize {
        self.sample_count
    }
    pub const fn setup_id(&self) -> &[u8; 32] {
        &self.setup_id
    }
    pub const fn wire_version(&self) -> u16 {
        self.wire_version
    }
    pub const fn proposer_threads(&self) -> usize {
        self.proposer_threads
    }
}
