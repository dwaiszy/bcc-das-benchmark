//! PeerDAS coset multiproofs and their FK20 opening optimization.

use super::*;

impl KzgLocalCodeScheme {
    /// Open the coset `g_c H`; the witness commits to
    /// `h=(f-r)/(X^l-g_c^l)`, where `r` interpolates the `l` values.
    pub fn open_coset(&self, poly: &UniPoly, g_c: Fr) -> Proof<Bls12_381> {
        let l = self.coset_size;
        let q = synthetic_division_quotient(&poly.coeffs, l, g_c.pow([l as u64]));
        Proof {
            w: msm(&q, &self.powers.powers_of_g[..q.len()]).into_affine(),
            random_v: None,
        }
    }

    /// Compute all coset witnesses with FK20's Toeplitz FFT/ MSM procedure.
    pub fn open_coset_all(&self, poly: &UniPoly) -> Vec<Proof<Bls12_381>> {
        let l = self.coset_size;
        let m = self.fk20_m;
        assert!(
            poly.coeffs.len().div_ceil(l).max(1) <= m,
            "polynomial does not fit in the encoded FK20 evaluation domain"
        );
        if m < 2 {
            return vec![
                Proof {
                    w: G1::zero().into_affine(),
                    random_v: None
                };
                m
            ];
        }
        let n = m * l;
        let mut coeffs = poly.coeffs.clone();
        coeffs.resize(n, Fr::zero());
        let domain_2m =
            Radix2EvaluationDomain::<Fr>::new(2 * m).expect("2m must support an FFT domain");
        let mut tc_fft_t: Vec<Vec<Fr>> = vec![Vec::with_capacity(l); 2 * m];
        for i in 0..l {
            for (j, v) in domain_2m
                .fft(&strided_toeplitz_coeffs(&coeffs, i, l, m))
                .into_iter()
                .enumerate()
            {
                tc_fft_t[j].push(v);
            }
        }
        let hext_fft: Vec<G1> = (0..2 * m)
            .map(|j| msm(&tc_fft_t[j], &self.xext_fft_t[j]))
            .collect();
        let h_full = domain_2m.ifft(&hext_fft);
        let h = &h_full[..m];
        let domain_m = Radix2EvaluationDomain::<Fr>::new(m).expect("m must support an FFT domain");
        domain_m
            .fft(h)
            .into_iter()
            .map(|w| Proof {
                w: w.into_affine(),
                random_v: None,
            })
            .collect()
    }

    /// Reference implementation: open each coset independently.
    pub fn open_coset_all_naive(&self, poly: &UniPoly) -> Vec<Proof<Bls12_381>> {
        let domain =
            Radix2EvaluationDomain::<Fr>::new(self.fk20_m * self.coset_size).expect("coset domain");
        (0..self.fk20_m)
            .map(|s| self.open_coset(poly, domain.element(s)))
            .collect()
    }

    /// Verify a coset proof using `e(C-C_r,H)=e(W,[beta^l]-g_c^l H)`.
    pub fn verify_coset(
        &self,
        commitment: &Commitment<Bls12_381>,
        g_c: Fr,
        values: &[Fr],
        proof: &Proof<Bls12_381>,
    ) -> bool {
        let commit_r = match self.commit_r_from_values(g_c, values) {
            Some(c) => c,
            None => return false,
        };
        let lhs_inner = commitment.0.into_group() - commit_r;
        let rhs_inner =
            self.beta_h_pow_coset.into_group() - self.vk.h * g_c.pow([self.coset_size as u64]);
        let (lhs, rhs) = rayon::join(
            || Bls12_381::pairing(lhs_inner, self.vk.h),
            || Bls12_381::pairing(proof.w, rhs_inner),
        );
        lhs == rhs
    }

    /// Batch coset checks by Fiat–Shamir combining them into two pairings.
    pub fn batch_verify_coset(
        &self,
        entries: &[(&Commitment<Bls12_381>, Fr, &[Fr], &Proof<Bls12_381>)],
    ) -> bool {
        if entries.is_empty() {
            return false;
        }
        let challenge = fiat_shamir_challenge(entries);
        let mut lhs = G1::zero();
        let mut rhs = G1::zero();
        let mut weight = Fr::one();
        for &(commitment, g_c, values, proof) in entries {
            let commit_r = match self.commit_r_from_values(g_c, values) {
                Some(c) => c,
                None => return false,
            };
            lhs += proof.w * weight;
            rhs += (commitment.0.into_group() - commit_r
                + proof.w * g_c.pow([self.coset_size as u64]))
                * weight;
            weight *= challenge;
        }
        let (a, b) = rayon::join(
            || Bls12_381::pairing(lhs, self.beta_h_pow_coset),
            || Bls12_381::pairing(rhs, self.vk.h),
        );
        a == b
    }

    fn commit_r_from_values(&self, g_c: Fr, values: &[Fr]) -> Option<G1> {
        if values.len() != self.coset_size || g_c.is_zero() {
            return None;
        }
        let domain = Radix2EvaluationDomain::<Fr>::new(self.coset_size)
            .filter(|d| d.size() == self.coset_size)?;
        let twisted = domain.ifft(values);
        let g_inv = g_c.inverse().expect("nonzero checked above");
        let mut inv_pow = Fr::one();
        let folded: Vec<Fr> = twisted
            .iter()
            .map(|&t| {
                let c = t * inv_pow;
                inv_pow *= g_inv;
                c
            })
            .collect();
        let avail = self.powers.powers_of_g.len();
        if folded.len() > avail && folded[avail..].iter().any(|c| !c.is_zero()) {
            return None;
        }
        let usable = folded.len().min(avail);
        Some(msm(&folded[..usable], &self.powers.powers_of_g[..usable]))
    }
}
