//! FFT evaluation points for `C_BC[mu, 2, omega, rho]`.
//! Information points use two cosets of `H_omega`; parity points use the
//! remaining cosets. `omega` and `rho + omega` must be powers of two.

use crate::fft::bcc::topology::BcParams;
use ark_ff::FftField;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};

/// Whether `n` is a power of two (`n >= 1`).
fn is_pow2(n: usize) -> bool {
    n != 0 && (n & (n - 1)) == 0
}

/// FFT-friendly evaluation points for a `C_BC[mu, 2, omega, rho]` code.
#[derive(Clone, Debug)]
pub struct FftPoints<F: FftField> {
    params: BcParams,
    /// Local message domain of size `2*omega`.
    pub(crate) domain_k0: Radix2EvaluationDomain<F>,
    /// Auxiliary encoding and decoding domain of size `2*(rho+omega)`.
    pub(crate) domain_n: Radix2EvaluationDomain<F>,
    /// Subdomain used by restricted-FFT parity evaluation.
    pub(crate) domain_omega: Radix2EvaluationDomain<F>,
    step0: usize,
    /// Leftover points, ordered as parity roles A then B.
    leftover: Vec<usize>,
    /// Fixed offset outside `domain_n` for erasure decoding.
    pub(crate) offset: F,
}

impl<F: FftField> FftPoints<F> {
    pub fn new(params: BcParams) -> Self {
        assert!(
            is_pow2(params.omega),
            "FFT-based construction requires omega to be a power of 2, got {}",
            params.omega
        );
        assert!(
            is_pow2(params.period()),
            "FFT-based construction requires rho+omega to be a power of 2, got {}",
            params.period()
        );
        let k0 = params.k0();
        let n = params.num_eval_points();
        let domain_k0 = Radix2EvaluationDomain::new(k0)
            .expect("field must support an FFT domain of size 2*omega");
        let domain_n = Radix2EvaluationDomain::new(n)
            .expect("field must support an FFT domain of size 2*(rho+omega)");
        assert_eq!(domain_k0.size(), k0);
        assert_eq!(domain_n.size(), n);
        let step0 = n / params.omega;
        assert!(
            step0 >= 4 && step0.is_multiple_of(2),
            "internal invariant: step0 must be even and >= 4"
        );

        // Verify subgroup nesting in debug builds.
        debug_assert_eq!(domain_n.element(step0 / 2), domain_k0.element(1));

        let leftover = Self::compute_leftover(step0, params.omega, params.rho);
        let offset = crate::fft::rs::find_offset_outside_domain(&domain_n);

        let domain_omega = Radix2EvaluationDomain::new(params.omega)
            .expect("field must support an FFT domain of size omega");
        assert_eq!(domain_omega.size(), params.omega);
        // Verify the smaller subgroup in debug builds.
        debug_assert_eq!(domain_n.element(step0), domain_omega.element(1));

        FftPoints {
            params,
            domain_k0,
            domain_n,
            domain_omega,
            step0,
            leftover,
            offset,
        }
    }

    /// Returns the cosets supplying the `2*rho` parity points.
    fn leftover_coset_plan(step0: usize, omega: usize, rho: usize) -> Vec<(usize, usize)> {
        let mut plan = Vec::new();
        let mut remaining = 2 * rho;
        for c in 0..step0 {
            if c == 0 || c == step0 / 2 {
                continue;
            }
            if remaining == 0 {
                break;
            }
            let take = remaining.min(omega);
            plan.push((c, take));
            remaining -= take;
        }
        assert_eq!(
            remaining, 0,
            "not enough leftover cosets for parity (internal invariant)"
        );
        plan
    }

    /// Returns parity points as flat domain indices.
    fn compute_leftover(step0: usize, omega: usize, rho: usize) -> Vec<usize> {
        let mut out = Vec::with_capacity(2 * rho);
        for (c, take) in Self::leftover_coset_plan(step0, omega, rho) {
            for m in 0..take {
                out.push(c + m * step0);
            }
            if out.len() >= 2 * rho {
                break;
            }
        }
        out.truncate(2 * rho);
        assert_eq!(
            out.len(),
            2 * rho,
            "not enough leftover points for parity (internal invariant)"
        );
        out
    }

    pub fn params(&self) -> &BcParams {
        &self.params
    }

    /// Returns the representative of coset `c`.
    pub(crate) fn coset_representative(&self, c: usize) -> F {
        self.domain_n.element(c)
    }

    /// Returns the parity coset plan.
    pub(crate) fn leftover_cosets(&self) -> Vec<(usize, usize)> {
        Self::leftover_coset_plan(self.step0, self.params.omega, self.params.rho)
    }

    /// Returns coset slices for one parity role.
    pub(crate) fn leftover_cosets_for_role(&self, role_a: bool) -> Vec<(usize, usize, usize)> {
        let rho = self.params.rho;
        let (range_start, range_end) = if role_a { (0, rho) } else { (rho, 2 * rho) };
        let mut pieces = Vec::new();
        let mut cursor = 0usize;
        for (c, take) in self.leftover_cosets() {
            let block_start = cursor;
            let block_end = cursor + take;
            let overlap_start = range_start.max(block_start);
            let overlap_end = range_end.min(block_end);
            if overlap_start < overlap_end {
                pieces.push((c, overlap_start - block_start, overlap_end - overlap_start));
            }
            cursor = block_end;
            if cursor >= range_end {
                break;
            }
        }
        pieces
    }

    /// Returns the domain index of an information point.
    fn info_domain_index(&self, role_a: bool, m: usize) -> usize {
        let base = if role_a { 0 } else { self.step0 / 2 };
        base + m * self.step0
    }

    /// Returns the domain index of a parity point.
    pub(crate) fn parity_domain_index_pub(&self, role_a: bool, m: usize) -> usize {
        if role_a {
            self.leftover[m]
        } else {
            self.leftover[self.params.rho + m]
        }
    }

    /// Maps a global position to a domain index.
    pub fn domain_index(&self, j: usize) -> usize {
        let p = self.params.period();
        let block = j / p;
        let local = j % p;
        let role_a = block.is_multiple_of(2);
        if local < self.params.omega {
            self.info_domain_index(role_a, local)
        } else {
            self.parity_domain_index_pub(role_a, local - self.params.omega)
        }
    }

    /// Returns the evaluation point for a global position.
    pub fn eval_point(&self, j: usize) -> F {
        self.domain_n.element(self.domain_index(j))
    }

    pub fn step0(&self) -> usize {
        self.step0
    }
}
