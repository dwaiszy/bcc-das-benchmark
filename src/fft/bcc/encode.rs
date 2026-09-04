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

    pub(crate) fn points(&self) -> &FftPoints<F> {
        &self.points
    }

    pub fn encode(&self, message: &[F]) -> Result<Vec<F>, BcError> {
        let params = *self.params();

        // Stage 1: place all message blocks in the global codeword.
        let mut codeword = self.place_message(message)?;

        // Stage 2: compute only parity because this path does not return coefficients.
        let local_parities: Vec<Vec<F>> = (0..params.mu)
            .into_par_iter()
            .map(|i| self.encode_local_full(i, &codeword).1)
            .collect();

        // Stage 3: copy each local parity block into the global codeword.
        for (i, parity_values) in local_parities.into_iter().enumerate() {
            for (&pos, &value) in params.parity_block(i).iter().zip(&parity_values) {
                codeword[pos] = Some(value);
            }
        }

        Ok(Self::finish_codeword(codeword))
    }

    /// Encodes the message and returns local polynomial coefficients.
    pub fn encode_with_local_polys(&self, message: &[F]) -> Result<(Vec<F>, Vec<Vec<F>>), BcError> {
        let params = *self.params();

        // Stage 1: place all message blocks in the global codeword.
        let mut codeword = self.place_message(message)?;

        // Stage 2: extend local codes independently in parallel.
        let local_results: Vec<_> = (0..params.mu)
            .into_par_iter()
            .map(|i| self.encode_local_full(i, &codeword))
            .collect();

        // Stage 3: copy each local parity block into the global codeword.
        let mut local_polys = Vec::with_capacity(params.mu);
        for (i, (coeffs, parity_values)) in local_results.into_iter().enumerate() {
            for (&pos, &val) in params.parity_block(i).iter().zip(parity_values.iter()) {
                codeword[pos] = Some(val);
            }
            local_polys.push(coeffs);
        }

        let codeword = Self::finish_codeword(codeword);
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
        let coeffs = self.points.domain_k0.ifft(&v);
        let parity = self.compute_parity_from_coeffs(role_a_is_i, &coeffs);
        (coeffs, parity)
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
