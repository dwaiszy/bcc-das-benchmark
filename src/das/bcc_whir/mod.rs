//! BCC+WHIR setup and adapter.

use ark_bls12_381::Fr;
use whir::cmdline_utils::AvailableHash;
use whir::parameters::ProtocolParameters;
use whir::protocols::params::DecodingRegime;

use super::code::BccCode;
use super::das_lifecycle::{ErasureCode, SetupArtifacts, SetupError, setup_roles};
use super::protocol_profile::{FieldProfile, PcsProfile, ProtocolProfile};
use crate::BcParams;
use crate::pcs::whir::WhirLocalCodeScheme;

pub const SECURITY_BITS: usize = 128;
pub type BccWhir = SetupArtifacts<BccCode<Fr>, WhirLocalCodeScheme>;

pub fn parameters() -> ProtocolParameters {
    ProtocolParameters {
        decoding_regime: DecodingRegime::Johnson,
        starting_log_inv_rate: 1,
        initial_folding_factor: 2,
        folding_factor: 2,
        security_level: SECURITY_BITS,
        pow_bits: 0,
        batch_size: 1,
        hash_id: AvailableHash::Blake3.hash_id(),
    }
}

pub fn setup(params: BcParams, proposer_threads: usize) -> Result<BccWhir, SetupError> {
    let code = BccCode::new(params)?;
    let pcs = WhirLocalCodeScheme::setup(params.k0() - 1, &parameters());
    let profile = ProtocolProfile::new(
        code.profile(),
        FieldProfile::Bls12381Scalar,
        PcsProfile::WhirJohnson {
            security_bits: SECURITY_BITS as u16,
        },
        6,
        [0x57; 32],
        proposer_threads,
    );
    setup_roles(code, pcs, profile, proposer_threads)
}
