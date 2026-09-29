//! 2D-RS+KZG setup and adapter.

use ark_bls12_381::Fr;

use crate::das::core::{
    ErasureCode, FieldConfig, PcsConfig, ProtocolConfig, SetupArtifacts, SetupError, setup_roles,
};
use crate::das::erasure_code::Rs2dCode;
use crate::pcs::kzg::{KzgArcPcs, KzgStrategy};

pub type Rs2dKzg = SetupArtifacts<Rs2dCode<Fr>, KzgArcPcs>;

/// Configure 2D-RS+KZG with the given parameters.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::das::BlockId;
    use ark_bls12_381::Fr;

    #[test]
    fn scalar_rs2d_header_publishes_only_source_row_commitments() {
        let artifacts = setup(64, 32, 1, 1).expect("RS2D scalar setup");
        let message = (0..1024)
            .map(|i| Fr::from((i + 1) as u64))
            .collect::<Vec<_>>();
        let prepared = artifacts
            .proposer
            .prepare(BlockId::new([0xB6; 32]), &message)
            .expect("RS2D scalar preparation");

        assert_eq!(prepared.header.local_commitments().len(), 32);
        // Row 63 is an encoded row, so successful verification proves that
        // its commitment was derived from the 32 published source rows.
        let plan = artifacts
            .verifier
            .v1_from_indices(&prepared.header, &[63 * 64 + 7])
            .expect("RS2D sample plan");
        let responses = prepared
            .dispersal
            .respond(&plan)
            .expect("RS2D scalar response");
        artifacts
            .verifier
            .v2(&prepared.header, &plan, &responses)
            .expect("derived encoded-row commitment must verify");
    }
}
