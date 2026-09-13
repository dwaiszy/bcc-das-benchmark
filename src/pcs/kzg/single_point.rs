//! Plain KZG10 single-point openings.

use super::*;

impl KzgLocalCodeScheme {
    /// Commit `f` as `[f(beta)]_1`.
    pub fn commit(&self, poly: &UniPoly) -> (Commitment<Bls12_381>, Randomness<Fr, UniPoly>) {
        Kzg::commit(&self.powers, poly, None, None).expect("commit: degree exceeds setup")
    }

    /// Open `f` at `z`; the witness commits to `(f(X)-f(z))/(X-z)`.
    pub fn open(&self, poly: &UniPoly, point: Fr, r: &Randomness<Fr, UniPoly>) -> Proof<Bls12_381> {
        Kzg::open(&self.powers, poly, point, r).expect("open: degree exceeds setup")
    }

    /// Check the KZG pairing equation for `f(z) = value`.
    pub fn verify(
        &self,
        commitment: &Commitment<Bls12_381>,
        point: Fr,
        value: Fr,
        proof: &Proof<Bls12_381>,
    ) -> bool {
        Kzg::check(&self.vk, commitment, point, value, proof).unwrap_or(false)
    }
}
