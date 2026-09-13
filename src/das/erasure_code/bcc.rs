//! BCC erasure-code adapter for the generic DAS construction.
//! It maps global BCC positions to arc-local polynomials and claims.

use std::panic::{catch_unwind, AssertUnwindSafe};

use ark_ff::FftField;
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};

use crate::das::core::CodeConfig;
use crate::das::core::{
    CodeError, EncodedBlock, ErasureCode, EvaluationClaim, LocalCode, LocalCodeId, LocalPosition,
    PolynomialBlock,
};
use crate::{BcParams, FftBlockCirculantCode};

#[derive(Clone)]
pub struct BccCode<F: FftField> {
    inner: FftBlockCirculantCode<F>,
}

impl<F: FftField> BccCode<F> {
    pub fn new(params: BcParams) -> Result<Self, CodeError> {
        if params.mu < 2
            || !params.mu.is_multiple_of(2)
            || params.omega == 0
            || !params.omega.is_power_of_two()
            || params.rho == 0
            || !(params.omega + params.rho).is_power_of_two()
        {
            return Err(CodeError::InvalidGeometry);
        }
        catch_unwind(AssertUnwindSafe(|| FftBlockCirculantCode::new(params)))
            .map(|inner| Self { inner })
            .map_err(|_| CodeError::InvalidGeometry)
    }
    pub fn params(&self) -> BcParams {
        *self.inner.params()
    }
}

impl<F> ErasureCode for BccCode<F>
where
    F: FftField + Send + Sync + 'static,
{
    type Field = F;
    fn profile(&self) -> CodeConfig {
        CodeConfig::Bcc(self.params())
    }
    fn message_len(&self) -> usize {
        self.params().k()
    }
    fn codeword_len(&self) -> usize {
        self.params().n()
    }
    fn local_code_count(&self) -> usize {
        self.params().mu
    }
    fn local_dimension(&self) -> usize {
        self.params().k0()
    }
    fn local_code_len(&self) -> usize {
        self.params().n0()
    }

    fn polynomialize(&self, message: &[F]) -> Result<PolynomialBlock<F>, CodeError> {
        PolynomialBlock::new(
            self.inner.local_polynomials(message)?,
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
            .encode_from_local_polynomials(polynomials.local_polynomials())?;
        let mut local_codes = Vec::with_capacity(self.params().mu);
        for (arc_id, coefficients) in polynomials.local_polynomials().iter().enumerate() {
            let positions = self.params().local_support(arc_id);
            let polynomial = DensePolynomial::from_coefficients_vec(coefficients.to_vec());
            let mut claims = Vec::with_capacity(positions.len());
            for (local_index, global_index) in positions.into_iter().enumerate() {
                let point = self.inner.eval_point(global_index);
                let value = symbols[global_index];
                if polynomial.evaluate(&point) != value {
                    return Err(CodeError::InconsistentLocalPolynomial);
                }
                claims.push(EvaluationClaim::new(
                    global_index,
                    LocalPosition::new(LocalCodeId::new(arc_id), local_index),
                    point,
                    self.inner.domain_index(global_index),
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
            LocalCodeId::new(self.params().canonical_local_code(global_index)),
            global_index % self.params().period(),
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
            self.inner.eval_point(global_index),
            self.inner.domain_index(global_index),
            value,
        ))
    }

    fn reception_threshold(&self) -> usize {
        self.params().n() - 2 * self.params().rho
    }
    fn decode(&self, received: &[Option<F>]) -> Result<Vec<F>, CodeError> {
        let codeword = crate::fft::decode(&self.inner, received)?;
        self.inner
            .message_from_codeword(&codeword)
            .map_err(CodeError::from)
    }
}
