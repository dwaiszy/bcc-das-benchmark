//! Shared setup and algebra for the three KZG opening modules.
//!
//! A commitment proves evaluations of a local polynomial `f`. Coset proofs
//! use `h=(f-r)/(X^l-g^l)`, while SHPLONK reduces arbitrary points to one KZG
//! check. The concrete opening interfaces live in `single_point.rs`, `coset.rs`,
//! and `shplonk.rs`.

use crate::fft::FftBlockCirculantCode;
use ark_bls12_381::{Bls12_381, Fr};
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{Field, One, UniformRand, Zero};
use ark_poly::univariate::DensePolynomial;
use ark_poly::{DenseUVPolynomial, EvaluationDomain, Polynomial, Radix2EvaluationDomain};
use ark_poly_commit::Error as PcError;
use ark_poly_commit::kzg10::{Commitment, KZG10, Powers, Proof, Randomness, VerifierKey};
use ark_serialize::CanonicalSerialize;
use ark_std::rand::RngCore;
use std::borrow::Cow;

use crate::pcs::{ArcPcs, OpeningPoint, PcsError};

pub type UniPoly = DensePolynomial<Fr>;
type Kzg = KZG10<Bls12_381, UniPoly>;
type G1 = <Bls12_381 as Pairing>::G1;
type G1Affine = <Bls12_381 as Pairing>::G1Affine;
type G2 = <Bls12_381 as Pairing>::G2;
type G2Affine = <Bls12_381 as Pairing>::G2Affine;

/// SRS and verifier key for local-code polynomials of degree `< k0`.
///
/// This setup is demo-only: it samples and discards the setup trapdoor `beta`
/// locally instead of using an MPC ceremony.
///
/// The setup is built manually because coset verification needs the extra
/// G2 element `[beta^coset_size]_2`, while vanilla `Kzg::setup` only exposes
/// `[1]_2` and `[beta]_2`.
#[derive(Clone)]
pub struct KzgLocalCodeScheme {
    powers: Powers<'static, Bls12_381>,
    vk: VerifierKey<Bls12_381>,
    /// Coset size used by PeerDAS-style multiproofs.
    coset_size: usize,
    /// Extra SRS element `[beta^coset_size]_2` for coset verification.
    beta_h_pow_coset: G2Affine,
    /// Transposed FK20 SRS FFT, so each frequency bucket is one MSM.
    xext_fft_t: Vec<Vec<G1Affine>>,
    /// Encoded-domain cell count used by FK20.
    fk20_m: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KzgStrategy {
    Plain,
    Fk20,
    Shplonk,
}

/// Scalar-opening KZG adapter. The retained strategies remain separate PCS
/// implementations; the generic DAS oracle uses FK20.
pub struct KzgArcPcs {
    inner: KzgLocalCodeScheme,
    strategy: KzgStrategy,
}

pub struct KzgProverState {
    polynomial: UniPoly,
}

impl KzgArcPcs {
    pub fn setup_fk20<R: RngCore>(
        max_degree: usize,
        evaluation_domain: usize,
        rng: &mut R,
    ) -> Result<Self, PcsError> {
        let inner = KzgLocalCodeScheme::setup_peerdas(max_degree, 1, evaluation_domain, rng)
            .map_err(|_| PcsError::Setup)?;
        Ok(Self {
            inner,
            strategy: KzgStrategy::Fk20,
        })
    }

    pub const fn strategy(&self) -> KzgStrategy {
        self.strategy
    }
}

impl ArcPcs<Fr> for KzgArcPcs {
    type Commitment = Commitment<Bls12_381>;
    type ProverState = KzgProverState;
    type Proof = Proof<Bls12_381>;

    fn commit(
        &self,
        coefficients: &[Fr],
    ) -> Result<(Self::Commitment, Self::ProverState), PcsError> {
        let polynomial = UniPoly::from_coefficients_vec(coefficients.to_vec());
        let (commitment, _) = self.inner.commit(&polynomial);
        Ok((commitment, KzgProverState { polynomial }))
    }

    fn precompute_openings(
        &self,
        state: &Self::ProverState,
        points: &[OpeningPoint<Fr>],
    ) -> Result<Vec<Self::Proof>, PcsError> {
        if self.strategy != KzgStrategy::Fk20 {
            return Err(PcsError::Open);
        }
        let all = self.inner.open_coset_all(&state.polynomial);
        points
            .iter()
            .map(|point| {
                all.get(point.domain_index())
                    .cloned()
                    .ok_or(PcsError::UnsupportedPoint)
            })
            .collect()
    }

    fn verify(
        &self,
        commitment: &Self::Commitment,
        point: Fr,
        value: Fr,
        proof: &Self::Proof,
    ) -> Result<(), PcsError> {
        self.inner
            .verify(commitment, point, value, proof)
            .then_some(())
            .ok_or(PcsError::Verification)
    }

    fn commitment_bytes(&self, commitment: &Self::Commitment) -> usize {
        commitment.compressed_size()
    }

    fn derive_commitment(
        &self,
        commitments: &[Self::Commitment],
        weights: &[Fr],
    ) -> Result<Self::Commitment, PcsError> {
        if commitments.len() != weights.len() {
            return Err(PcsError::Commit);
        }
        Ok(self
            .inner
            .linear_combination_commitment(commitments, weights))
    }

    fn verify_batch(
        &self,
        entries: &[(&Self::Commitment, Fr, Fr, &Self::Proof)],
    ) -> Result<(), PcsError> {
        // The existing coset verifier handles scalar FK20 proofs when the
        // coset size is one. Preserve plain verification for other cases.
        if entries.is_empty()
            || self.inner.coset_size != 1
            || entries
                .iter()
                .any(|(_, point, _, proof)| point.is_zero() || proof.random_v.is_some())
        {
            for &(commitment, point, value, proof) in entries {
                self.verify(commitment, point, value, proof)?;
            }
            return Ok(());
        }
        let values: Vec<_> = entries.iter().map(|entry| [entry.2]).collect();
        let cosets: Vec<_> = entries
            .iter()
            .zip(&values)
            .map(|(&(commitment, point, _, proof), value)| {
                (commitment, point, value.as_slice(), proof)
            })
            .collect();
        self.inner
            .batch_verify_coset(&cosets)
            .then_some(())
            .ok_or(PcsError::Verification)
    }

    fn proof_bytes(&self, proof: &Self::Proof) -> usize {
        // KzgArcPcs always creates non-hiding openings (`random_v == None`).
        // Its scalar-proof payload is therefore only the compressed G1 witness;
        // the Arkworks Option tag is an in-memory serialization detail, not a
        // field transmitted by this DAS response format.
        debug_assert!(proof.random_v.is_none());
        proof.w.compressed_size()
    }
}

impl KzgLocalCodeScheme {
    /// Derive a commitment to a linear combination of committed polynomials.
    /// This is used by RS2D to avoid publishing commitments for extended rows.
    pub fn linear_combination_commitment(
        &self,
        commitments: &[Commitment<Bls12_381>],
        weights: &[Fr],
    ) -> Commitment<Bls12_381> {
        assert_eq!(commitments.len(), weights.len());
        let bases = commitments.iter().map(|c| c.0).collect::<Vec<_>>();
        Commitment(msm(weights, &bases).into_affine())
    }
    /// Build a demo SRS for degree-`<= max_degree` polynomials.
    pub fn setup<R: RngCore>(
        max_degree: usize,
        coset_size: usize,
        rng: &mut R,
    ) -> Result<Self, PcError> {
        let fk20_m = (max_degree + 1).div_ceil(coset_size.max(1)).max(1);
        Self::setup_with_fk20_cells(max_degree, coset_size, fk20_m, rng)
    }

    /// Build a PeerDAS-sized SRS where FK20 is indexed by encoded cells.
    pub fn setup_peerdas<R: RngCore>(
        max_degree: usize,
        cell_size: usize,
        extended_cell_count: usize,
        rng: &mut R,
    ) -> Result<Self, PcError> {
        assert!(
            extended_cell_count.is_power_of_two(),
            "PeerDAS cell count must be a power of two"
        );
        assert!(
            extended_cell_count >= (max_degree + 1).div_ceil(cell_size.max(1)),
            "extended domain must contain the polynomial coefficient domain"
        );
        Self::setup_with_fk20_cells(max_degree, cell_size, extended_cell_count, rng)
    }

    fn setup_with_fk20_cells<R: RngCore>(
        max_degree: usize,
        coset_size: usize,
        fk20_m: usize,
        rng: &mut R,
    ) -> Result<Self, PcError> {
        if max_degree < 1 {
            return Err(PcError::DegreeIsZero);
        }
        let beta = Fr::rand(rng);
        let g = G1::rand(rng);
        let gamma_g = G1::rand(rng);
        let h = G2::rand(rng);

        let mut powers_of_g = Vec::with_capacity(max_degree + 1);
        let mut powers_of_gamma_g = Vec::with_capacity(max_degree + 1);
        let mut cur_g = g;
        let mut cur_gamma_g = gamma_g;
        for _ in 0..=max_degree {
            powers_of_g.push(cur_g.into_affine());
            powers_of_gamma_g.push(cur_gamma_g.into_affine());
            cur_g *= beta;
            cur_gamma_g *= beta;
        }

        let h_affine = h.into_affine();
        let beta_h = (h * beta).into_affine();
        let beta_h_pow_coset = (h * beta.pow([coset_size as u64])).into_affine();

        let powers = Powers {
            powers_of_g: Cow::Owned(powers_of_g),
            powers_of_gamma_g: Cow::Owned(powers_of_gamma_g),
        };
        let vk = VerifierKey {
            g: g.into_affine(),
            gamma_g: gamma_g.into_affine(),
            h: h_affine,
            beta_h,
            prepared_h: h_affine.into(),
            prepared_beta_h: beta_h.into(),
        };
        // FK20 setup data: precompute the SRS Toeplitz FFT and store it
        // transposed so each column can feed one MSM directly.
        let cs = coset_size.max(1);
        let powers_of_g_slice: &[G1Affine] = powers.powers_of_g.as_ref();
        let mut xext_fft_t: Vec<Vec<G1Affine>> = Vec::new();
        if fk20_m >= 2 {
            let domain_2m = Radix2EvaluationDomain::<Fr>::new(2 * fk20_m)
                .expect("2*fk20_m must support an FFT domain");
            xext_fft_t = vec![Vec::with_capacity(cs); 2 * fk20_m];
            for i in 0..cs {
                // x[j] = powers_of_g[(fk20_m-1-j)*cs - 1 - i] for j=0..fk20_m-2,
                // then x[fk20_m-1] = identity (P1_INF).
                let mut x = Vec::with_capacity(fk20_m);
                for j in 0..fk20_m - 1 {
                    let idx = (fk20_m - 1 - j) * cs - 1 - i;
                    // Zero-pad missing high coefficients in the extended domain.
                    x.push(
                        powers_of_g_slice
                            .get(idx)
                            .map_or_else(G1::zero, |p| p.into_group()),
                    );
                }
                x.push(G1::zero());
                x.resize(2 * fk20_m, G1::zero());
                let row = domain_2m.fft(&x);
                let row_affine = G1::normalize_batch(&row);
                // Only the first `2*fk20_m` entries are used downstream.
                for (j, p) in row_affine.into_iter().take(2 * fk20_m).enumerate() {
                    xext_fft_t[j].push(p);
                }
            }
        }

        Ok(KzgLocalCodeScheme {
            powers,
            vk,
            coset_size,
            beta_h_pow_coset,
            xext_fft_t,
            fk20_m,
        })
    }
}

mod coset;
mod shplonk;
mod single_point;
pub use shplonk::MultipointProof;

/// Fiat-Shamir point `u` for SHPLONK.
fn multipoint_challenge(
    commitment: &Commitment<Bls12_381>,
    points: &[Fr],
    values: &[Fr],
    w1: &G1Affine,
) -> Fr {
    use ark_ff::PrimeField;
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    let mut buf = Vec::new();
    commitment
        .0
        .serialize_compressed(&mut buf)
        .expect("serialize");
    hasher.update(&buf);
    for (&z, &v) in points.iter().zip(values) {
        buf.clear();
        z.serialize_compressed(&mut buf).expect("serialize");
        hasher.update(&buf);
        buf.clear();
        v.serialize_compressed(&mut buf).expect("serialize");
        hasher.update(&buf);
    }
    buf.clear();
    w1.serialize_compressed(&mut buf).expect("serialize");
    hasher.update(&buf);
    Fr::from_le_bytes_mod_order(&hasher.finalize())
}

/// Coefficient-wise subtraction with zero padding.
fn sub_coeffs(a: &[Fr], b: &[Fr]) -> Vec<Fr> {
    let len = a.len().max(b.len());
    (0..len)
        .map(|i| {
            let av = a.get(i).copied().unwrap_or(Fr::zero());
            let bv = b.get(i).copied().unwrap_or(Fr::zero());
            av - bv
        })
        .collect()
}

/// Divide by `(X - root)` via synthetic division.
/// The recurrence is `q[i-1] = coeffs[i] + root*q[i]`.
fn synthetic_divide_linear(coeffs: &[Fr], root: Fr) -> Vec<Fr> {
    let d = coeffs.len();
    if d <= 1 {
        return Vec::new();
    }
    let mut q = vec![Fr::zero(); d - 1];
    q[d - 2] = coeffs[d - 1];
    for i in (1..d - 1).rev() {
        q[i - 1] = coeffs[i] + root * q[i];
    }
    q
}

/// Fiat-Shamir combiner for batched coset verification.
fn fiat_shamir_challenge(entries: &[(&Commitment<Bls12_381>, Fr, &[Fr], &Proof<Bls12_381>)]) -> Fr {
    use ark_ff::PrimeField;
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    let mut buf = Vec::new();
    for &(commitment, g_c, values, proof) in entries {
        buf.clear();
        commitment
            .0
            .serialize_compressed(&mut buf)
            .expect("serialize");
        hasher.update(&buf);
        buf.clear();
        g_c.serialize_compressed(&mut buf).expect("serialize");
        hasher.update(&buf);
        for v in values {
            buf.clear();
            v.serialize_compressed(&mut buf).expect("serialize");
            hasher.update(&buf);
        }
        buf.clear();
        proof.serialize_compressed(&mut buf).expect("serialize");
        hasher.update(&buf);
    }
    Fr::from_le_bytes_mod_order(&hasher.finalize())
}

/// Multi-scalar multiplication `sum_i scalars[i] * bases[i]`.
fn msm(scalars: &[Fr], bases: &[<Bls12_381 as Pairing>::G1Affine]) -> G1 {
    G1::msm_unchecked(bases, scalars)
}

/// Build the residue-`i` Toeplitz vector used by FK20.
fn strided_toeplitz_coeffs(coeffs: &[Fr], i: usize, l: usize, m: usize) -> Vec<Fr> {
    let n = coeffs.len();
    let mut tc = Vec::with_capacity(2 * m);
    tc.push(coeffs[n - 1 - i]);
    tc.extend(std::iter::repeat(Fr::zero()).take(m + 1));
    for q in 2..m {
        tc.push(coeffs[q * l - i - 1]);
    }
    tc
}

/// Reverse-bit permutation used by PeerDAS cell ordering.
/// If `len = 2^b`, it reverses the low `b` bits of each index.
pub fn reverse_bit_order_permutation(len: usize) -> Vec<usize> {
    assert!(len.is_power_of_two(), "length must be a power of two");
    let bits = len.trailing_zeros();
    (0..len as u32)
        .map(|i| (i.reverse_bits() >> (u32::BITS - bits)) as usize)
        .collect()
}

/// Apply [`reverse_bit_order_permutation`] to an array.
pub fn apply_reverse_bit_order<T: Clone>(arr: &[T]) -> Vec<T> {
    reverse_bit_order_permutation(arr.len())
        .into_iter()
        .map(|i| arr[i].clone())
        .collect()
}

/// Divide by `X^r - c` using block synthetic division.
/// Writing `Y = X^r` gives block recurrence `q_{j-1} = a_j + c q_j`.
/// For `deg(f) < 2r`, the quotient is just `coeffs[r..]`.
fn synthetic_division_quotient(coeffs: &[Fr], r: usize, c: Fr) -> Vec<Fr> {
    let m = coeffs.len().div_ceil(r).max(1);
    let mut padded = coeffs.to_vec();
    padded.resize(m * r, Fr::zero());
    if m < 2 {
        return Vec::new(); // deg f < r: f is already reduced mod (X^r - c).
    }
    let chunk = |j: usize| padded[j * r..(j + 1) * r].to_vec();

    let mut q: Vec<Vec<Fr>> = vec![Vec::new(); m - 1];
    q[m - 2] = chunk(m - 1);
    for j in (1..m - 1).rev() {
        let a_j = chunk(j);
        let q_j = &q[j];
        q[j - 1] = a_j
            .iter()
            .zip(q_j.iter())
            .map(|(&a, &qq)| a + c * qq)
            .collect();
    }
    q.into_iter().flatten().collect()
}

/// Interpolate the unique degree-`< points.len()` polynomial through
/// `(points[i], values[i])`, returned in monomial basis.
fn interpolate_coeffs(points: &[Fr], values: &[Fr]) -> Vec<Fr> {
    assert_eq!(points.len(), values.len(), "points/values length mismatch");
    if points.is_empty() {
        return Vec::new();
    }

    // Build Z(X) = product_i (X - points[i]) once. Each Lagrange basis is
    // then Z(X)/(X-points[i]) divided by its value at points[i]. This keeps
    // arbitrary-point interpolation quadratic instead of rebuilding every
    // basis product independently (cubic), which matters for complete arcs.
    let mut vanishing = vec![Fr::one()];
    for &point in points {
        let mut next = vec![Fr::zero(); vanishing.len() + 1];
        for (degree, coeff) in vanishing.iter().copied().enumerate() {
            next[degree] -= coeff * point;
            next[degree + 1] += coeff;
        }
        vanishing = next;
    }

    let mut acc = vec![Fr::zero(); points.len()];
    for (&point, &value) in points.iter().zip(values) {
        let basis = synthetic_divide_linear(&vanishing, point);
        let denominator = basis
            .iter()
            .rev()
            .fold(Fr::zero(), |evaluation, coefficient| {
                evaluation * point + coefficient
            });
        let scale = value
            * denominator
                .inverse()
                .expect("duplicate interpolation points");
        for (target, coefficient) in acc.iter_mut().zip(basis) {
            *target += coefficient * scale;
        }
    }
    acc
}

/// Interpolate local code `i`'s degree-`< k0` message polynomial.
pub fn local_message_polynomial(
    code: &FftBlockCirculantCode<Fr>,
    i: usize,
    codeword: &[Fr],
) -> UniPoly {
    let support = code.params().local_support(i);
    let k0 = code.params().k0();
    let pts: Vec<Fr> = support[..k0].iter().map(|&j| code.eval_point(j)).collect();
    let vals: Vec<Fr> = support[..k0].iter().map(|&j| codeword[j]).collect();
    DensePolynomial::from_coefficients_vec(interpolate_coeffs(&pts, &vals))
}

#[cfg(test)]
#[path = "benchmarks.rs"]
mod benchmarks;
#[cfg(test)]
#[path = "tests.rs"]
mod tests;
