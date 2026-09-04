//! Iterative FFT-based decoder for the 2D-RS code.

use super::encode::FftTwoDRsCode;
use crate::error::BcError;
use crate::fft::rs::fft_erasure_decode;
use ark_ff::FftField;

impl<F: FftField> FftTwoDRsCode<F> {
    /// Decodes the grid by alternating row and column RS recovery.
    pub fn decode(&self, received: &[Option<F>]) -> Result<Vec<F>, BcError> {
        // Stage 1: validate the input grid dimensions.
        if received.len() != self.n() {
            return Err(BcError::BadCodewordLength {
                got: received.len(),
                expected: self.n(),
            });
        }
        // Each row and column is an [n0, k0] RS code.
        let max_erasures = self.n0 - self.k0;
        let mut m: Vec<Option<F>> = received.to_vec();
        let mut column = vec![None; self.n0];

        loop {
            let mut progressed = false;

            // Stage 2: decode rows within their RS erasure capacity.
            for r in 0..self.n0 {
                let row = &m[r * self.n0..(r + 1) * self.n0];
                let erasures = row.iter().filter(|v| v.is_none()).count();
                if erasures == 0 || erasures > max_erasures {
                    continue;
                }
                // Decode the row with FFT and merge its values.
                if let Some(filled) = fft_erasure_decode(&self.domain_n0, self.k0, self.offset, row)
                {
                    m[r * self.n0..(r + 1) * self.n0]
                        .iter_mut()
                        .zip(filled.iter())
                        .for_each(|(slot, &v)| *slot = Some(v));
                    progressed = true;
                }
            }
            // Stage 3: decode columns using values recovered from the row pass.
            for c in 0..self.n0 {
                for r in 0..self.n0 {
                    column[r] = m[r * self.n0 + c];
                }
                let erasures = column.iter().filter(|v| v.is_none()).count();
                if erasures == 0 || erasures > max_erasures {
                    continue;
                }
                // Decode the column with FFT and merge its values.
                if let Some(filled) =
                    fft_erasure_decode(&self.domain_n0, self.k0, self.offset, &column)
                {
                    for r in 0..self.n0 {
                        m[r * self.n0 + c] = Some(filled[r]);
                    }
                    progressed = true;
                }
            }
            // Stage 4: stop when neither pass makes progress.
            if !progressed {
                break;
            }
        }

        // Stage 5: reject any remaining erasures.
        if m.iter().any(|v| v.is_none()) {
            return Err(BcError::Uncorrectable);
        }
        Ok(m.into_iter().map(Option::unwrap).collect())
    }
}
