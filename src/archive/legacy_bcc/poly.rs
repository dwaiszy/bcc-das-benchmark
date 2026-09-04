//! Polynomial interpolation used by the legacy BCC pair decoder.

use ark_ff::Field;

/// Barycentric interpolation weights for distinct points.
pub struct Interpolator<F: Field> {
    weights: Vec<F>,
}

impl<F: Field> Interpolator<F> {
    /// Computes the interpolation weights.
    pub fn new(points: &[F]) -> Self {
        let mut weights = vec![F::one(); points.len()];
        for i in 0..points.len() {
            let mut w = F::one();
            for j in 0..points.len() {
                if i != j {
                    w *= points[i] - points[j];
                }
            }
            weights[i] = w.inverse().unwrap();
        }
        Self { weights }
    }

    /// Returns weights in input-point order.
    pub fn weights(&self) -> &[F] {
        &self.weights
    }
}
