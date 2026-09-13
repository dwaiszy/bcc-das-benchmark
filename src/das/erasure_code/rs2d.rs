//! Two-dimensional Reed–Solomon erasure-code adapter for generic DAS.
//! It exposes source-row commitments and encoded-row evaluation claims.

use std::panic::{catch_unwind, AssertUnwindSafe};

use ark_ff::FftField;
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};

use crate::das::core::CodeConfig;
use crate::das::core::{
    CodeError, EncodedBlock, ErasureCode, EvaluationClaim, LocalCode, LocalCodeId, LocalPosition,
    PolynomialBlock,
};
use crate::fft::FftTwoDRsCode;

#[derive(Clone)]
pub struct Rs2dCode<F: FftField> {
    inner: FftTwoDRsCode<F>,
}

impl<F: FftField> Rs2dCode<F> {
    pub fn new(n0: usize, k0: usize) -> Result<Self, CodeError> {
        if k0 == 0 || k0 >= n0 || !k0.is_power_of_two() || !n0.is_power_of_two() {
            return Err(CodeError::InvalidGeometry);
        }
        catch_unwind(AssertUnwindSafe(|| FftTwoDRsCode::new(n0, k0)))
            .map(|inner| Self { inner })
            .map_err(|_| CodeError::InvalidGeometry)
    }
    pub fn n0(&self) -> usize {
        self.inner.n0()
    }
    pub fn k0(&self) -> usize {
        self.inner.k0()
    }
}

impl<F> ErasureCode for Rs2dCode<F>
where
    F: FftField + Send + Sync + 'static,
{
    type Field = F;
    fn profile(&self) -> CodeConfig {
        CodeConfig::Rs2d {
            n0: self.n0(),
            k0: self.k0(),
        }
    }
    fn message_len(&self) -> usize {
        self.inner.k()
    }
    fn codeword_len(&self) -> usize {
        self.inner.n()
    }
    fn local_code_count(&self) -> usize {
        self.n0()
    }
    fn local_dimension(&self) -> usize {
        self.k0()
    }
    fn local_code_len(&self) -> usize {
        self.n0()
    }

    fn polynomialize(&self, message: &[F]) -> Result<PolynomialBlock<F>, CodeError> {
        PolynomialBlock::new(
            self.inner.row_polynomials(message)?,
            self.local_code_count(),
            self.local_dimension(),
        )
    }

    fn encode_polynomials(
        &self,
        polynomials: &PolynomialBlock<F>,
    ) -> Result<EncodedBlock<F>, CodeError> {
        let symbols = self
            .inner
            .encode_from_row_polynomials(polynomials.local_polynomials())?;
        let mut local_codes = Vec::with_capacity(self.n0());
        for (row, coefficients) in polynomials.local_polynomials().iter().enumerate() {
            let polynomial = DensePolynomial::from_coefficients_vec(coefficients.to_vec());
            let mut claims = Vec::with_capacity(self.n0());
            for column in 0..self.n0() {
                let global_index = row * self.n0() + column;
                let point = self.inner.eval_point(column);
                let value = symbols[global_index];
                if polynomial.evaluate(&point) != value {
                    return Err(CodeError::InconsistentLocalPolynomial);
                }
                claims.push(EvaluationClaim::new(
                    global_index,
                    LocalPosition::new(LocalCodeId::new(row), column),
                    point,
                    column,
                    value,
                ));
            }
            local_codes.push(LocalCode::new(coefficients.to_vec(), claims));
        }
        EncodedBlock::new(
            symbols,
            local_codes,
            self.local_code_count(),
            self.local_code_len(),
        )
    }

    fn canonical_position(&self, global_index: usize) -> Result<LocalPosition, CodeError> {
        if global_index >= self.codeword_len() {
            return Err(CodeError::PositionOutOfRange);
        }
        Ok(LocalPosition::new(
            LocalCodeId::new(global_index / self.n0()),
            global_index % self.n0(),
        ))
    }

    fn canonical_claim(
        &self,
        global_index: usize,
        value: F,
    ) -> Result<EvaluationClaim<F>, CodeError> {
        let local = self.canonical_position(global_index)?;
        Ok(EvaluationClaim::new(
            global_index,
            local,
            self.inner.eval_point(local.local_index()),
            local.local_index(),
            value,
        ))
    }

    fn reception_threshold(&self) -> usize {
        self.inner.n() - self.inner.d() + 1
    }
    fn decode(&self, received: &[Option<F>]) -> Result<Vec<F>, CodeError> {
        let codeword = self.inner.decode(received)?;
        self.inner
            .message_from_codeword(&codeword)
            .map_err(CodeError::from)
    }
}
