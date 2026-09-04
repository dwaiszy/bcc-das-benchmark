//! Construction and systematic encoding for [`FftTwoDRsCode`] -- see the
//! parent module's docs for the systematic-embedding layout and the FFT
//! eligibility requirement.

use crate::error::BcError;
use ark_ff::FftField;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use rayon::prelude::*;

fn is_pow2(n: usize) -> bool {
    n != 0 && (n & (n - 1)) == 0
}

#[derive(Clone, Debug)]
pub struct FftTwoDRsCode<F: FftField> {
    pub(super) n0: usize,
    pub(super) k0: usize,
    pub(super) domain_k0: Radix2EvaluationDomain<F>,
    pub(super) domain_n0: Radix2EvaluationDomain<F>,
    /// Field element used by FFT erasure decoding.
    pub(super) offset: F,
}

impl<F: FftField> FftTwoDRsCode<F> {
    pub fn new(n0: usize, k0: usize) -> Self {
        assert!(k0 < n0, "k0 must be strictly less than n0");
        assert!(
            is_pow2(n0),
            "FFT-based construction requires n0 to be a power of 2, got {n0}"
        );
        assert!(
            is_pow2(k0),
            "FFT-based construction requires k0 to be a power of 2, got {k0}"
        );
        let domain_k0 =
            Radix2EvaluationDomain::new(k0).expect("field must support an FFT domain of size k0");
        let domain_n0 =
            Radix2EvaluationDomain::new(n0).expect("field must support an FFT domain of size n0");
        assert_eq!(domain_k0.size(), k0);
        assert_eq!(domain_n0.size(), n0);
        debug_assert_eq!(domain_n0.element(n0 / k0), domain_k0.element(1));
        let offset = crate::fft::rs::find_offset_outside_domain(&domain_n0);
        FftTwoDRsCode {
            n0,
            k0,
            domain_k0,
            domain_n0,
            offset,
        }
    }

    pub fn n0(&self) -> usize {
        self.n0
    }
    pub fn k0(&self) -> usize {
        self.k0
    }
    /// Global codeword length `n0^2`.
    pub fn n(&self) -> usize {
        self.n0 * self.n0
    }
    /// Global message length `k0^2`.
    pub fn k(&self) -> usize {
        self.k0 * self.k0
    }
    pub fn d(&self) -> usize {
        (self.n0 - self.k0 + 1) * (self.n0 - self.k0 + 1)
    }

    /// The evaluation point at `domain_n0` natural index `idx`.
    pub fn eval_point(&self, idx: usize) -> F {
        self.domain_n0.element(idx)
    }

    /// Extend `k0` known values (interpreted as evaluations over
    /// `domain_k0`, in `domain_k0`'s own natural order) to all `n0`
    /// `domain_n0` evaluations, via IFFT(k0) + FFT(n0).
    fn extend(&self, known: &[F]) -> Vec<F> {
        debug_assert_eq!(known.len(), self.k0);
        let coeffs = self.domain_k0.ifft(known);
        let mut padded = coeffs;
        padded.resize(self.n0, F::zero());
        self.domain_n0.fft(&padded)
    }

    /// Extends the message and also returns its polynomial coefficients.
    fn extend_with_coeffs(&self, known: &[F]) -> (Vec<F>, Vec<F>) {
        debug_assert_eq!(known.len(), self.k0);
        let coeffs = self.domain_k0.ifft(known);
        let mut padded = coeffs.clone();
        padded.resize(self.n0, F::zero());
        let evals = self.domain_n0.fft(&padded);
        (coeffs, evals)
    }

    /// Systematic encode: message is `k0*k0` symbols, row-major (message
    /// row `r`, column `c` -> `message[r*k0+c]`). Returns the `n0*n0`
    /// codeword, row-major by `domain_n0` natural index.
    pub fn encode(&self, message: &[F]) -> Result<Vec<F>, BcError> {
        if message.len() != self.k() {
            return Err(BcError::BadMessageLength {
                got: message.len(),
                expected: self.k(),
            });
        }

        // Stage 1: every message-row extension is independent. Indexed
        // parallel collection preserves row-major order.
        let stage1: Vec<F> = message
            .par_chunks_exact(self.k0)
            .map(|row_known| self.extend(row_known))
            .collect::<Vec<_>>()
            .into_iter()
            .flatten()
            .collect();

        // Stage 2: compute all column extensions concurrently. Assemble the
        // resulting columns sequentially to avoid shared mutable writes.
        let columns: Vec<Vec<F>> = (0..self.n0)
            .into_par_iter()
            .map(|c| {
                let known: Vec<F> = (0..self.k0).map(|r| stage1[r * self.n0 + c]).collect();
                self.extend(&known)
            })
            .collect();
        let mut result = vec![F::zero(); self.n0 * self.n0];
        for (c, column) in columns.into_iter().enumerate() {
            for (r, value) in column.into_iter().enumerate() {
                result[r * self.n0 + c] = value;
            }
        }
        Ok(result)
    }

    /// Encodes the message and returns each row's coefficients.
    pub fn encode_with_row_polys(&self, message: &[F]) -> Result<(Vec<F>, Vec<Vec<F>>), BcError> {
        if message.len() != self.k() {
            return Err(BcError::BadMessageLength {
                got: message.len(),
                expected: self.k(),
            });
        }

        // Stage 1: extend all message rows concurrently while retaining the
        // coefficient vectors needed for the systematic final rows.
        let stage1_rows: Vec<_> = message
            .par_chunks_exact(self.k0)
            .map(|row_known| self.extend_with_coeffs(row_known))
            .collect();
        let (stage1_coeffs, filled_rows): (Vec<_>, Vec<_>) = stage1_rows.into_iter().unzip();
        let stage1: Vec<F> = filled_rows.into_iter().flatten().collect();

        // Stage 2: extend all columns concurrently, then transpose the
        // collected columns into the row-major codeword deterministically.
        let columns: Vec<Vec<F>> = (0..self.n0)
            .into_par_iter()
            .map(|c| {
                let known: Vec<F> = (0..self.k0).map(|r| stage1[r * self.n0 + c]).collect();
                self.extend(&known)
            })
            .collect();
        let mut result = vec![F::zero(); self.n0 * self.n0];
        for (c, column) in columns.into_iter().enumerate() {
            for (r, value) in column.into_iter().enumerate() {
                result[r * self.n0 + c] = value;
            }
        }

        let step = self.n0 / self.k0;
        let row_polys = (0..self.n0)
            .into_par_iter()
            .map(|i| {
                if i % step == 0 {
                    stage1_coeffs[i / step].clone()
                } else {
                    let known: Vec<F> = (0..self.k0)
                        .map(|m| result[i * self.n0 + m * step])
                        .collect();
                    self.domain_k0.ifft(&known)
                }
            })
            .collect();

        Ok((result, row_polys))
    }

    /// Extract the `k0*k0` message symbols back out of a full
    /// (erasure-free) codeword, row-major (`message[r*k0+c]`) -- the
    /// inverse of the systematic embedding in `encode`/`encode_with_row_polys`:
    /// message row `r`, column `c` sits at grid position `(r*step, c*step)`
    /// where `step = n0/k0` (see module docs).
    pub fn message_from_codeword(&self, codeword: &[F]) -> Result<Vec<F>, BcError> {
        if codeword.len() != self.n() {
            return Err(BcError::BadCodewordLength {
                got: codeword.len(),
                expected: self.n(),
            });
        }
        let step = self.n0 / self.k0;
        let mut message = Vec::with_capacity(self.k());
        for r in 0..self.k0 {
            for c in 0..self.k0 {
                message.push(codeword[(r * step) * self.n0 + c * step]);
            }
        }
        Ok(message)
    }
}
