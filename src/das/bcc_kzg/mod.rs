//! BCC+KZG setup and adapter.

use ark_bls12_381::Fr;

use super::code::BccCode;
use super::das_lifecycle::{ErasureCode, SetupArtifacts, SetupError, setup_roles};
use super::protocol_profile::{FieldProfile, PcsProfile, ProtocolProfile};
use crate::BcParams;
use crate::pcs::kzg::{KzgArcPcs, KzgStrategy};

pub type BccKzg = SetupArtifacts<BccCode<Fr>, KzgArcPcs>;

pub fn setup(params: BcParams, proposer_threads: usize) -> Result<BccKzg, SetupError> {
    let code = BccCode::new(params)?;
    let mut rng = ark_std::test_rng();
    let pcs = KzgArcPcs::setup_fk20(params.k0() - 1, params.num_eval_points(), &mut rng)?;
    let profile = ProtocolProfile::new(
        code.profile(),
        FieldProfile::Bls12381Scalar,
        PcsProfile::Kzg {
            strategy: KzgStrategy::Fk20,
        },
        6,
        [0x4b; 32],
        proposer_threads,
    );
    setup_roles(code, pcs, profile, proposer_threads)
}
