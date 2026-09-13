//! BCC+KZG setup and adapter.

use ark_bls12_381::Fr;

use crate::BcParams;
use crate::das::core::{
    ErasureCode, FieldConfig, PcsConfig, ProtocolConfig, SetupArtifacts, SetupError, setup_roles,
};
use crate::das::erasure_code::BccCode;
use crate::pcs::kzg::{KzgArcPcs, KzgStrategy};

pub type BccKzg = SetupArtifacts<BccCode<Fr>, KzgArcPcs>;

/// Configure BCC+KZG with the caller's sampler-derived scalar sample count.
pub fn setup(
    params: BcParams,
    sample_count: usize,
    proposer_threads: usize,
) -> Result<BccKzg, SetupError> {
    let code = BccCode::new(params)?;
    let mut rng = ark_std::test_rng();
    let pcs = KzgArcPcs::setup_fk20(params.k0() - 1, params.num_eval_points(), &mut rng)?;
    let config = ProtocolConfig::new(
        code.profile(),
        FieldConfig::Bls12381Scalar,
        PcsConfig::Kzg {
            strategy: KzgStrategy::Fk20,
        },
        sample_count,
        [0x4b; 32],
        proposer_threads,
    );
    setup_roles(code, pcs, config, proposer_threads)
}
