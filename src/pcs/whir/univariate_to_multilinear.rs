//! Conversion from univariate coefficients to WHIR multilinear evaluations.

use ark_ff::Field;

/// Boolean-hypercube evaluations of the multilinear polynomial whose
/// monomials are the binary decomposition of the univariate exponents.
pub fn coeffs_to_hypercube_evals<F: Field>(coeffs: &[F], num_vars: usize) -> Vec<F> {
    let len = 1usize << num_vars;
    assert!(coeffs.len() <= len, "polynomial exceeds WHIR dimension");
    let mut evaluations = coeffs.to_vec();
    evaluations.resize(len, F::ZERO);
    for bit in 0..num_vars {
        for index in 0..len {
            if (index >> bit) & 1 == 1 {
                evaluations[index] = evaluations[index] + evaluations[index ^ (1 << bit)];
            }
        }
    }
    evaluations
}

/// Multilinear point corresponding to a univariate evaluation at `z`.
pub fn multilinear_point<F: Field>(z: F, num_vars: usize) -> Vec<F> {
    let mut point = Vec::with_capacity(num_vars);
    let mut power = z;
    for _ in 0..num_vars {
        point.push(power);
        power = power.square();
    }
    point
}
