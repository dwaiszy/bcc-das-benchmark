//! Systematic FFT encoder for `C_BC[mu, 2, omega, rho]`.
//! Message blocks are placed first; each local code then computes its parity.

use crate::error::BcError;
use crate::fft::bcc::points::FftPoints;
use crate::fft::bcc::topology::BcParams;
use ark_ff::FftField;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use rayon::prelude::*;

#[derive(Clone, Debug)]
pub struct FftBlockCirculantCode<F: FftField> {
    points: FftPoints<F>,
}

impl<F: FftField> FftBlockCirculantCode<F> {
    pub fn new(params: BcParams) -> Self {
        FftBlockCirculantCode {
            points: FftPoints::new(params),
        }
    }

    pub fn params(&self) -> &BcParams {
        self.points.params()
    }

    pub fn eval_point(&self, j: usize) -> F {
        self.points.eval_point(j)
    }

    /// Index of a codeword position in the underlying evaluation domain.
    pub fn domain_index(&self, j: usize) -> usize {
        self.points.domain_index(j)
    }

    pub(crate) fn points(&self) -> &FftPoints<F> {
        &self.points
    }

    pub fn encode(&self, message: &[F]) -> Result<Vec<F>, BcError> {
        let local_polynomials = self.local_polynomials(message)?;
        self.encode_from_local_polynomials(&local_polynomials)
    }

    /// Interpolate the degree-`< k0` polynomials represented by the original
    /// data in each pair of neighboring information blocks.  This operation
    /// does not evaluate parity symbols, so callers may commit to these
    /// polynomials before encoding the block.
    pub fn local_polynomials(&self, message: &[F]) -> Result<Vec<Vec<F>>, BcError> {
        let params = *self.params();
        let codeword = self.place_message(message)?;
        Ok((0..params.mu)
            .into_par_iter()
            .map(|i| self.interpolate_local(i, &codeword))
            .collect())
    }

    /// Evaluate previously interpolated local polynomials and assemble the
    /// global BCC codeword. Shared information positions must agree under
    /// both neighboring polynomials.
    pub fn encode_from_local_polynomials(
        &self,
        local_polynomials: &[Vec<F>],
    ) -> Result<Vec<F>, BcError> {
        let params = *self.params();
        if local_polynomials.len() != params.mu
            || local_polynomials
                .iter()
                .any(|coeffs| coeffs.len() != params.k0())
        {
            return Err(BcError::BadMessageLength {
                got: local_polynomials.iter().map(Vec::len).sum(),
                expected: params.mu * params.k0(),
            });
        }

        let local_values = local_polynomials
            .par_iter()
            .enumerate()
            .map(|(i, coeffs)| {
                let role_a_is_i = i.is_multiple_of(2);
                let information = self.points.domain_k0.fft(coeffs);
                let parity = self.compute_parity_from_coeffs(role_a_is_i, coeffs);
                let mut values = Vec::with_capacity(params.n0());
                values.extend(
                    (0..params.omega)
                        .map(|m| information[if role_a_is_i { 2 * m } else { 2 * m + 1 }]),
                );
                values.extend(parity);
                values.extend(
                    (0..params.omega)
                        .map(|m| information[if role_a_is_i { 2 * m + 1 } else { 2 * m }]),
                );
                values
            })
            .collect::<Vec<_>>();

        let mut codeword = vec![None; params.n()];
        for (i, values) in local_values.into_iter().enumerate() {
            for (position, value) in params.local_support(i).into_iter().zip(values) {
                if codeword[position].is_some_and(|existing| existing != value) {
                    return Err(BcError::InvalidParams(
                        "neighboring local polynomials disagree on an overlap".into(),
                    ));
                }
                codeword[position] = Some(value);
            }
        }
        Ok(Self::finish_codeword(codeword))
    }

    /// Encodes the message and returns local polynomial coefficients.
    pub fn encode_with_local_polys(&self, message: &[F]) -> Result<(Vec<F>, Vec<Vec<F>>), BcError> {
        let local_polys = self.local_polynomials(message)?;
        let codeword = self.encode_from_local_polynomials(&local_polys)?;
        Ok((codeword, local_polys))
    }

    /// Places systematic message blocks in an incomplete codeword.
    fn place_message(&self, message: &[F]) -> Result<Vec<Option<F>>, BcError> {
        let params = *self.params();
        if message.len() != params.k() {
            return Err(BcError::BadMessageLength {
                got: message.len(),
                expected: params.k(),
            });
        }

        // Stage 1: place all message blocks in the global codeword.
        let mut codeword = vec![None; params.n()];
        for block in 0..params.mu {
            for (offset, position) in params.info_block(block).into_iter().enumerate() {
                codeword[position] = Some(message[block * params.omega + offset]);
            }
        }
        Ok(codeword)
    }

    /// Converts a fully populated temporary codeword into its output form.
    fn finish_codeword(codeword: Vec<Option<F>>) -> Vec<F> {
        codeword
            .into_iter()
            .map(|value| value.expect("every position written"))
            .collect()
    }

    /// Re-encodes local code `i` from its two information blocks.
    pub fn reencode_local_from_message(&self, i: usize, message: &[F]) -> Result<Vec<F>, BcError> {
        let params = *self.params();
        if message.len() != params.k0() {
            return Err(BcError::BadMessageLength {
                got: message.len(),
                expected: params.k0(),
            });
        }
        if i >= params.mu {
            return Err(BcError::InvalidParams(format!(
                "local code index {i} out of range (mu = {})",
                params.mu
            )));
        }

        let mut codeword: Vec<Option<F>> = vec![None; params.n()];
        for (t, &pos) in params.info_block(i).iter().enumerate() {
            codeword[pos] = Some(message[t]);
        }
        for (t, &pos) in params.info_block((i + 1) % params.mu).iter().enumerate() {
            codeword[pos] = Some(message[params.omega + t]);
        }

        let (_coeffs, parity) = self.encode_local_full(i, &codeword);

        // Return local support order: [info_i | parity_i | info_{i+1}].
        let mut out = Vec::with_capacity(params.n0());
        out.extend_from_slice(&message[..params.omega]);
        out.extend_from_slice(&parity);
        out.extend_from_slice(&message[params.omega..]);
        Ok(out)
    }

    /// Extracts the message symbols from a complete codeword.
    pub fn message_from_codeword(&self, codeword: &[F]) -> Result<Vec<F>, BcError> {
        let params = self.params();
        if codeword.len() != params.n() {
            return Err(BcError::BadCodewordLength {
                got: codeword.len(),
                expected: params.n(),
            });
        }
        let mut message = Vec::with_capacity(params.k());
        for b in 0..params.mu {
            for &pos in &params.info_block(b) {
                message.push(codeword[pos]);
            }
        }
        Ok(message)
    }

    /// Computes local coefficients with IFFT and parity values with FFT.
    fn encode_local_full(&self, i: usize, codeword: &[Option<F>]) -> (Vec<F>, Vec<F>) {
        let coeffs = self.interpolate_local(i, codeword);
        let parity = self.compute_parity_from_coeffs(i.is_multiple_of(2), &coeffs);
        (coeffs, parity)
    }

    /// Interpolate one local source polynomial without evaluating parity.
    fn interpolate_local(&self, i: usize, codeword: &[Option<F>]) -> Vec<F> {
        let params = *self.params();
        let role_a_is_i = i.is_multiple_of(2);
        let (block_a, block_b) = if role_a_is_i {
            (i, (i + 1) % params.mu)
        } else {
            ((i + 1) % params.mu, i)
        };
        let info_a = params.info_block(block_a);
        let info_b = params.info_block(block_b);

        // Interleave both information blocks on the local FFT domain.
        let mut v = vec![F::zero(); params.k0()];
        for k in 0..params.omega {
            v[2 * k] = codeword[info_a[k]]
                .expect("info positions are always known before encode_local runs");
            v[2 * k + 1] = codeword[info_b[k]]
                .expect("info positions are always known before encode_local runs");
        }
        self.points.domain_k0.ifft(&v)
    }

    /// Computes parity values with restricted FFTs on the parity cosets.
    fn compute_parity_from_coeffs(&self, role_a_is_i: bool, coeffs: &[F]) -> Vec<F> {
        let params = *self.params();
        let mut parity = Vec::with_capacity(params.rho);
        for (c, local_offset, count) in self.points.leftover_cosets_for_role(role_a_is_i) {
            let g = self.points.coset_representative(c);
            let coset_evals = restricted_coset_eval(coeffs, g, &self.points.domain_omega);
            parity.extend_from_slice(&coset_evals[local_offset..local_offset + count]);
        }
        debug_assert_eq!(parity.len(), params.rho);
        parity
    }

    /// Fills missing local information and parity symbols from coefficients.
    pub(crate) fn fill_local_support_from_coeffs(
        &self,
        i: usize,
        coeffs: &[F],
        codeword: &mut [Option<F>],
    ) {
        let params = *self.params();
        let role_a_is_i = i.is_multiple_of(2);
        let (block_a, block_b) = if role_a_is_i {
            (i, (i + 1) % params.mu)
        } else {
            ((i + 1) % params.mu, i)
        };
        let info_a = params.info_block(block_a);
        let info_b = params.info_block(block_b);

        // Recover information values with an inverse local FFT.
        let v = self.points.domain_k0.fft(coeffs);
        for k in 0..params.omega {
            if codeword[info_a[k]].is_none() {
                codeword[info_a[k]] = Some(v[2 * k]);
            }
            if codeword[info_b[k]].is_none() {
                codeword[info_b[k]] = Some(v[2 * k + 1]);
            }
        }

        // Recover parity values with restricted FFTs.
        let parity = self.compute_parity_from_coeffs(role_a_is_i, coeffs);
        for (&pos, &val) in params.parity_block(i).iter().zip(parity.iter()) {
            if codeword[pos].is_none() {
                codeword[pos] = Some(val);
            }
        }
    }
}

/// Evaluates a local polynomial on one parity coset using a restricted FFT.
fn restricted_coset_eval<F: FftField>(
    coeffs: &[F],
    g: F,
    domain_omega: &Radix2EvaluationDomain<F>,
) -> Vec<F> {
    let omega = domain_omega.size();
    debug_assert_eq!(coeffs.len(), 2 * omega);
    let g_pow_omega = g.pow([omega as u64]);
    let mut twisted = Vec::with_capacity(omega);
    let mut g_pow_l = F::one();
    for l in 0..omega {
        let folded = coeffs[l] + g_pow_omega * coeffs[omega + l];
        twisted.push(folded * g_pow_l);
        g_pow_l *= g;
    }
    domain_omega.fft(&twisted)
}
