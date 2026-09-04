use ark_ff::FftField;
use ark_poly::univariate::DensePolynomial;
use ark_poly::{DenseUVPolynomial, EvaluationDomain, Radix2EvaluationDomain};

fn pad<F: FftField>(coeffs: &[F], len: usize) -> Vec<F> {
    let mut v = coeffs.to_vec();
    v.resize(len, F::zero());
    v
}

fn vanishing_poly_coeffs<F: FftField>(points: &[F]) -> Vec<F> {
    let mut poly = DensePolynomial::from_coefficients_vec(vec![F::one()]);
    for &p in points {
        let factor = DensePolynomial::from_coefficients_vec(vec![-p, F::one()]);
        poly = &poly * &factor;
    }
    poly.coeffs
}

fn recover_message_coeffs<F: FftField>(
    domain: &Radix2EvaluationDomain<F>,
    k0: usize,
    offset: F,
    received: &[Option<F>],
) -> Option<Vec<F>> {
    let n = domain.size();
    let erased: Vec<usize> = (0..n).filter(|&i| received[i].is_none()).collect();
    if erased.len() > n - k0 {
        return None;
    }
    let erased_points: Vec<F> = erased.iter().map(|&i| domain.element(i)).collect();
    let z_coeffs = vanishing_poly_coeffs(&erased_points);
    let z_evals_on_domain = domain.fft(&pad(&z_coeffs, n));
    let e_evals: Vec<F> = (0..n).map(|i| received[i].unwrap_or(F::zero())).collect();
    let ez_evals: Vec<F> = e_evals
        .iter()
        .zip(z_evals_on_domain.iter())
        .map(|(&e, &z)| e * z)
        .collect();
    let fz_coeffs = domain.ifft(&ez_evals);
    let coset = domain.get_coset(offset)?;
    let fz_evals_coset = coset.fft(&fz_coeffs);
    let z_evals_coset = coset.fft(&pad(&z_coeffs, n));
    let f_evals_coset: Vec<F> = fz_evals_coset
        .iter()
        .zip(z_evals_coset.iter())
        .map(|(&fz, &z)| fz * z.inverse().unwrap())
        .collect();
    let f_coeffs = coset.ifft(&f_evals_coset);
    Some(f_coeffs[..k0].to_vec())
}

pub fn fft_erasure_decode<F: FftField>(
    domain: &Radix2EvaluationDomain<F>,
    k0: usize,
    offset: F,
    received: &[Option<F>],
) -> Option<Vec<F>> {
    let n = domain.size();
    if received.iter().all(|v| v.is_some()) {
        return Some(received.iter().map(|v| v.unwrap()).collect());
    }
    let f_coeffs = recover_message_coeffs(domain, k0, offset, received)?;
    Some(domain.fft(&pad(&f_coeffs, n)))
}

pub(crate) fn fft_erasure_decode_coeffs<F: FftField>(
    domain: &Radix2EvaluationDomain<F>,
    k0: usize,
    offset: F,
    received: &[Option<F>],
) -> Option<Vec<F>> {
    recover_message_coeffs(domain, k0, offset, received)
}

pub(crate) fn find_offset_outside_domain<F: FftField>(domain: &Radix2EvaluationDomain<F>) -> F {
    let mut candidate = F::from(2u64);
    let mut next = 3u64;
    while domain.evaluate_vanishing_polynomial(candidate).is_zero() {
        candidate = F::from(next);
        next += 1;
    }
    candidate
}
