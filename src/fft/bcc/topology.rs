//! Layout and parameter helpers for BCC.
//!
//! This file keeps the repo's simplified index layout, but exposes the paper's
//! subgroup vocabulary explicitly:
//!
//! - `H1` is the local-code evaluation domain used for interpolation.
//! - `H2` is the smaller subgroup whose cosets organize the overlap structure.
//! - `H3` is the next level down, used for the paper's per-cell coset view.
//!
//! In the current implementation these names map onto the existing FFT-point
//! layout rather than a freshly modeled algebraic object. That is deliberate:
//! it lets the decoder follow the paper's control flow without changing the
//! encoder/decoder data model at the same time.

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct BcParams {
    pub mu: usize,
    pub omega: usize,
    pub rho: usize,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct BcTopology {
    params: BcParams,
}

impl BcTopology {
    pub fn new(params: BcParams) -> Self {
        Self { params }
    }

    pub fn params(&self) -> BcParams {
        self.params
    }

    pub fn h1_size(&self) -> usize {
        self.params.k0()
    }

    pub fn h2_size(&self) -> usize {
        self.params.omega
    }

    pub fn h3_size(&self) -> usize {
        self.params.rho
    }

    pub fn h1_local_support(&self, i: usize) -> Vec<usize> {
        self.params.local_support(i)
    }

    pub fn h2_overlap(&self, i: usize) -> Vec<usize> {
        self.params.info_block((i + 1) % self.params.mu)
    }

    pub fn h3_parity_role_a(&self, i: usize) -> Vec<usize> {
        self.params.parity_block(i)
    }
}

impl BcParams {
    pub fn period(&self) -> usize {
        self.omega + self.rho
    }
    pub fn n0(&self) -> usize {
        2 * self.omega + self.rho
    }
    pub fn k0(&self) -> usize {
        2 * self.omega
    }
    pub fn n(&self) -> usize {
        self.mu * self.period()
    }
    pub fn k(&self) -> usize {
        self.mu * self.omega
    }
    pub fn num_eval_points(&self) -> usize {
        2 * self.period()
    }
    pub fn info_block(&self, b: usize) -> Vec<usize> {
        let base = b * self.period();
        (0..self.omega).map(|m| base + m).collect()
    }
    pub fn parity_block(&self, b: usize) -> Vec<usize> {
        let base = b * self.period();
        (0..self.rho).map(|m| base + self.omega + m).collect()
    }
    pub fn local_support(&self, i: usize) -> Vec<usize> {
        let mut out = self.info_block(i);
        out.extend(self.parity_block(i));
        out.extend(self.info_block((i + 1) % self.mu));
        out
    }
}
