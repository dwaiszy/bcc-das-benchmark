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

    /// Coefficients expressing an encoded row as a linear combination of the
    /// k0 source rows.  This lets a PCS derive commitments for extended rows
    /// homomorphically without publishing those commitments.
    pub fn source_row_weights(&self, row: usize) -> Vec<F> {
        assert!(row < self.n0);
        (0..self.k0)
            .map(|source| {
                let mut basis = vec![F::zero(); self.k0];
                basis[source] = F::one();
                self.extend(&basis)[row]
            })
            .collect()
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

    /// Systematic encode: message is `k0*k0` symbols, row-major (message
    /// row `r`, column `c` -> `message[r*k0+c]`). Returns the `n0*n0`
    /// codeword, row-major by `domain_n0` natural index.
    pub fn encode(&self, message: &[F]) -> Result<Vec<F>, BcError> {
        let row_polynomials = self.row_polynomials(message)?;
        self.encode_from_row_polynomials(&row_polynomials)
    }

    /// Derive every degree-`< k0` row polynomial from the original `k0 × k0`
    /// data matrix.  The vertical extension is performed coefficient-wise,
    /// leaving horizontal evaluation (the encoded rows) for the encode stage.
    pub fn row_polynomials(&self, message: &[F]) -> Result<Vec<Vec<F>>, BcError> {
        if message.len() != self.k() {
            return Err(BcError::BadMessageLength {
                got: message.len(),
                expected: self.k(),
            });
        }

        let source_row_coefficients = message
            .par_chunks_exact(self.k0)
            .map(|row| self.domain_k0.ifft(row))
            .collect::<Vec<_>>();
        let coefficient_columns = (0..self.k0)
            .into_par_iter()
            .map(|coefficient| {
                let column = source_row_coefficients
                    .iter()
                    .map(|row| row[coefficient])
                    .collect::<Vec<_>>();
                self.extend(&column)
            })
            .collect::<Vec<_>>();
        Ok((0..self.n0)
            .map(|row| {
                (0..self.k0)
                    .map(|coefficient| coefficient_columns[coefficient][row])
                    .collect()
            })
            .collect())
    }

    /// Polynomials for the original k0 source rows before the vertical
    /// extension. These are the only row polynomials committed by the
    /// protocol; extended-row commitments are linear combinations of them.
    pub fn source_row_polynomials(&self, message: &[F]) -> Result<Vec<Vec<F>>, BcError> {
        if message.len() != self.k() {
            return Err(BcError::BadMessageLength {
                got: message.len(),
                expected: self.k(),
            });
        }
        Ok(message
            .par_chunks_exact(self.k0)
            .map(|row| self.domain_k0.ifft(row))
            .collect())
    }

    /// Evaluate previously derived row polynomials over the encoded domain.
    pub fn encode_from_row_polynomials(
        &self,
        row_polynomials: &[Vec<F>],
    ) -> Result<Vec<F>, BcError> {
        if row_polynomials.len() != self.n0
            || row_polynomials.iter().any(|coeffs| coeffs.len() != self.k0)
        {
            return Err(BcError::BadMessageLength {
                got: row_polynomials.iter().map(Vec::len).sum(),
                expected: self.n0 * self.k0,
            });
        }
        Ok(row_polynomials
            .par_iter()
            .map(|coeffs| {
                let mut padded = coeffs.clone();
                padded.resize(self.n0, F::zero());
                self.domain_n0.fft(&padded)
            })
            .collect::<Vec<_>>()
            .into_iter()
            .flatten()
            .collect())
    }

    /// Encodes the message and returns each row's coefficients.
    pub fn encode_with_row_polys(&self, message: &[F]) -> Result<(Vec<F>, Vec<Vec<F>>), BcError> {
        let row_polys = self.row_polynomials(message)?;
        let result = self.encode_from_row_polynomials(&row_polys)?;
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
