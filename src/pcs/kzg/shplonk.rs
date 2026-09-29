//! SHPLONK arbitrary-point multiproofs.

use super::*;
use ark_serialize::CanonicalDeserialize;

impl KzgLocalCodeScheme {
    /// Open points `S` with `I` interpolating the values and `Z_S=prod(X-z)`.
    /// The first witness commits to `(f-I)/Z_S`; the second opens the reduced claim.
    pub fn open_multipoint(
        &self,
        poly: &UniPoly,
        commitment: &Commitment<Bls12_381>,
        points: &[Fr],
    ) -> MultipointProof {
        let values: Vec<Fr> = points.iter().map(|&z| poly.evaluate(&z)).collect();
        let i_coeffs = interpolate_coeffs(points, &values);
        let mut h_coeffs = sub_coeffs(&poly.coeffs, &i_coeffs);
        for &z in points {
            h_coeffs = synthetic_divide_linear(&h_coeffs, z);
        }
        let w1 = msm(&h_coeffs, &self.powers.powers_of_g[..h_coeffs.len()]).into_affine();
        let u = multipoint_challenge(commitment, points, &values, &w1);
        let i_u = UniPoly::from_coefficients_slice(&i_coeffs).evaluate(&u);
        let z_s_u = points.iter().fold(Fr::one(), |acc, &z| acc * (u - z));
        let mut l_coeffs = poly.coeffs.clone();
        l_coeffs.resize(l_coeffs.len().max(1), Fr::zero());
        l_coeffs[0] -= i_u;
        for (i, &c) in h_coeffs.iter().enumerate() {
            l_coeffs[i] -= z_s_u * c;
        }
        let l_quotient = synthetic_divide_linear(&l_coeffs, u);
        let w2 = msm(&l_quotient, &self.powers.powers_of_g[..l_quotient.len()]).into_affine();
        MultipointProof { w1, w2 }
    }

    /// Verify both witnesses with the SHPLONK pairing equation at Fiat–Shamir `u`.
    pub fn verify_multipoint(
        &self,
        commitment: &Commitment<Bls12_381>,
        points: &[Fr],
        values: &[Fr],
        proof: &MultipointProof,
    ) -> bool {
        if points.is_empty() || points.len() != values.len() {
            return false;
        }
        for i in 0..points.len() {
            if points[i + 1..].contains(&points[i]) {
                return false;
            }
        }
        let i_coeffs = interpolate_coeffs(points, values);
        let u = multipoint_challenge(commitment, points, values, &proof.w1);
        let i_u = UniPoly::from_coefficients_slice(&i_coeffs).evaluate(&u);
        let z_s_u = points.iter().fold(Fr::one(), |acc, &z| acc * (u - z));
        let l_commit = commitment.0.into_group() - self.vk.g * i_u - proof.w1 * z_s_u;
        let rhs_inner = self.vk.beta_h.into_group() - self.vk.h * u;
        let (lhs, rhs) = rayon::join(
            || Bls12_381::pairing(l_commit, self.vk.h),
            || Bls12_381::pairing(proof.w2, rhs_inner),
        );
        lhs == rhs
    }
}

/// Two G1 elements; proof size is independent of `|points|`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MultipointProof {
    pub(crate) w1: G1Affine,
    pub(crate) w2: G1Affine,
}

impl MultipointProof {
    pub fn expected_serialized_size() -> usize {
        2 * G1Affine::zero().compressed_size()
    }

    pub fn compressed_size(&self) -> usize {
        self.w1.compressed_size() + self.w2.compressed_size()
    }

    pub fn serialized_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.compressed_size());
        self.w1
            .serialize_compressed(&mut bytes)
            .expect("serialize SHPLONK witness");
        self.w2
            .serialize_compressed(&mut bytes)
            .expect("serialize SHPLONK witness");
        bytes
    }

    pub fn from_serialized_bytes(bytes: &[u8]) -> Option<Self> {
        let mut reader = bytes;
        let w1 = G1Affine::deserialize_compressed(&mut reader).ok()?;
        let w2 = G1Affine::deserialize_compressed(&mut reader).ok()?;
        reader.is_empty().then_some(Self { w1, w2 })
    }
}
