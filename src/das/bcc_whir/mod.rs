//! BCC+WHIR setup and adapter.

use crate::pcs::whir::WhirField;
use whir::cmdline_utils::AvailableHash;
use whir::parameters::ProtocolParameters;
use whir::protocols::params::DecodingRegime;

use crate::das::core::{
    setup_roles, ErasureCode, FieldConfig, PcsConfig, ProtocolConfig, SetupArtifacts, SetupError,
};
use crate::das::erasure_code::BccCode;
use crate::pcs::whir::WhirLocalCodeScheme;
use crate::BcParams;

pub const SECURITY_BITS: usize = 80;
pub type BccWhir = SetupArtifacts<BccCode<WhirField>, WhirLocalCodeScheme>;

pub fn configured_security_bits() -> usize {
    std::env::var("DAS_BENCH_PCS_SOUNDNESS_BITS")
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|&value: &usize| value > 0)
        .unwrap_or(SECURITY_BITS)
}

pub fn parameters_with_security(security_level: usize) -> ProtocolParameters {
    ProtocolParameters {
        decoding_regime: DecodingRegime::Johnson,
        starting_log_inv_rate: 1,
        initial_folding_factor: 2,
        folding_factor: 2,
        security_level,
        pow_bits: 0,
        batch_size: 1,
        hash_id: AvailableHash::Blake3.hash_id(),
    }
}

pub fn parameters() -> ProtocolParameters {
    parameters_with_security(configured_security_bits())
}

/// Choose the smallest WHIR polynomial degree bound whose evaluation domain
/// satisfies the configured initial folding depth.
///
/// When `k0 = 2`, a BCC local polynomial has degree one, but the WHIR
/// configuration requires an initial domain of size four. We therefore pad the
/// degree bound to that domain size so the `(mu, k) = (64, 64)` parameter set
/// remains compatible with the unchanged WHIR configuration.
pub fn whir_max_degree(params: BcParams) -> usize {
    let minimum_domain = 1usize << parameters().initial_folding_factor;
    (params.k0() - 1).max(minimum_domain - 1)
}

/// Configure BCC+WHIR-JB with the given parameters.
pub fn setup(
    params: BcParams,
    sample_count: usize,
    proposer_threads: usize,
) -> Result<BccWhir, SetupError> {
    let code = BccCode::new(params)?;
    let pcs = WhirLocalCodeScheme::setup(whir_max_degree(params), &parameters());
    let config = ProtocolConfig::new(
        code.profile(),
        FieldConfig::Goldilocks2,
        PcsConfig::WhirJohnson {
            security_bits: configured_security_bits() as u16,
        },
        sample_count,
        [0x57; 32],
        proposer_threads,
    );
    setup_roles(code, pcs, config, proposer_threads)
}

#[cfg(test)]
mod arc_batch_tests {
    use super::*;
    use ark_poly::DenseUVPolynomial;

    #[test]
    fn one_proof_authenticates_complete_arc() {
        let params = BcParams {
            mu: 4,
            omega: 4,
            rho: 12,
        };
        let code = BccCode::<WhirField>::new(params).unwrap();
        let input = (1..=params.k())
            .map(|x| WhirField::from(x as u64))
            .collect::<Vec<_>>();
        let polynomials = code.polynomialize(&input).unwrap();
        let encoded = code.encode_polynomials(&polynomials).unwrap();
        let pcs = WhirLocalCodeScheme::setup(whir_max_degree(params), &parameters());
        let local = &encoded.local_codes()[0];
        let (commitment, state) = pcs.commit(
            &ark_poly::univariate::DensePolynomial::from_coefficients_vec(
                local.coefficients().to_vec(),
            ),
        );
        let points = local
            .claims()
            .iter()
            .map(|claim| claim.point())
            .collect::<Vec<_>>();
        let values = local
            .claims()
            .iter()
            .map(|claim| claim.value())
            .collect::<Vec<_>>();
        let proof = pcs
            .open_all_with_evaluations_checked(&state, &points, &values)
            .unwrap();
        assert!(pcs
            .verify_all_checked(&commitment, &points, &values, &proof)
            .is_ok());
    }
}
