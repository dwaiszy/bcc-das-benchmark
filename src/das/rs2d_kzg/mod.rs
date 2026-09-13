//! 2D-RS+KZG setup and adapter.

use ark_bls12_381::Fr;

use crate::das::core::{
    ErasureCode, FieldConfig, PcsConfig, ProtocolConfig, SetupArtifacts, SetupError, setup_roles,
};
use crate::das::erasure_code::Rs2dCode;
use crate::pcs::kzg::{KzgArcPcs, KzgStrategy};

pub type Rs2dKzg = SetupArtifacts<Rs2dCode<Fr>, KzgArcPcs>;

/// Configure 2D-RS+KZG with the caller's sampler-derived scalar sample count.
pub fn setup(
    n0: usize,
    k0: usize,
    sample_count: usize,
    proposer_threads: usize,
) -> Result<Rs2dKzg, SetupError> {
    let code = Rs2dCode::new(n0, k0)?;
    let mut rng = ark_std::test_rng();
    let pcs = KzgArcPcs::setup_fk20(k0 - 1, n0, &mut rng)?;
    let config = ProtocolConfig::new(
        code.profile(),
        FieldConfig::Bls12381Scalar,
        PcsConfig::Kzg {
            strategy: KzgStrategy::Fk20,
        },
        sample_count,
        [0x52; 32],
        proposer_threads,
    );
    setup_roles(code, pcs, config, proposer_threads)
}
