//! Reproducible configuration and measurement rules for the DAS benchmark.

use std::fmt::Write as _;

use ark_ff::PrimeField;
use rand::rngs::{OsRng, StdRng};
use rand::seq::SliceRandom;
use rand::{RngCore, SeedableRng};

/// These BCC parameters give global `(k, n) = (16, 64), (64, 256),
/// (256, 1024), (1024, 4096), (4096, 16384)`.  Each point also has a
/// square rate-1/4 2D-RS baseline.
pub const OMEGAS: [usize; 5] = [4, 16, 64, 256, 1024];
pub const BCC_SAMPLE_COUNT: usize = 6;
pub const RS2D_SAMPLE_COUNT: usize = 8;
pub const PROPOSER_THREADS: usize = 14;

/// Return the configured proposer parallelism, defaulting to the standard
/// benchmark thread count.
pub fn proposer_threads() -> usize {
    std::env::var("DAS_PROPOSER_THREADS")
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|&value| value > 0)
        .unwrap_or(PROPOSER_THREADS)
}
pub const WARMUP_RUNS: usize = 1;
pub const MEASURED_RUNS: usize = 10;
pub const SAMPLING_MODEL: &str = "unique_within_lc_shared_random_permutation";
pub const PROOF_SCOPE_BCC: &str = "full_arc_local_scalar_oracle";
pub const PROOF_SCOPE_RS2D: &str = "full_row_scalar_oracle";
pub const PROOF_ORDER: &str = "local_code_then_local_index";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MatchedParameters {
    pub omega: usize,
    pub k: usize,
    pub n: usize,
    pub mu: usize,
    pub rho: usize,
    pub bcc_k0: usize,
    pub bcc_n0: usize,
    pub rs2d_k0: usize,
    pub rs2d_n0: usize,
}

impl MatchedParameters {
    pub fn rate_one_quarter(omega: usize) -> Self {
        assert!(omega.is_power_of_two(), "omega must be a power of two");
        let k = 4 * omega;
        let n = 4 * k;
        let rs2d_n0 = n.isqrt();
        assert_eq!(rs2d_n0 * rs2d_n0, n, "2D-RS n must be square");
        let result = Self {
            omega,
            k,
            n,
            mu: 4,
            rho: 3 * omega,
            bcc_k0: 2 * omega,
            bcc_n0: 5 * omega,
            rs2d_k0: rs2d_n0 / 2,
            rs2d_n0,
        };
        result.validate();
        result
    }

    pub fn validate(self) {
        assert_eq!(self.k, self.mu * self.omega);
        assert_eq!(self.n, self.mu * (self.omega + self.rho));
        assert_eq!(self.n, 4 * self.k);
        assert_eq!(self.bcc_k0, 2 * self.omega);
        assert_eq!(self.bcc_n0, self.bcc_k0 + self.rho);
        assert_eq!(self.rs2d_n0, 2 * self.rs2d_k0);
        assert_eq!(self.rs2d_k0 * self.rs2d_k0, self.k);
        assert_eq!(self.rs2d_n0 * self.rs2d_n0, self.n);
    }

    pub fn bcc_proof_count(self) -> usize {
        self.mu * self.bcc_n0
    }

    pub fn rs2d_proof_count(self) -> usize {
        self.rs2d_n0 * self.rs2d_n0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MasterInput {
    values: Vec<u64>,
    seed: [u8; 32],
    hash: [u8; 32],
}

impl MasterInput {
    pub fn generate(k: usize, seed: [u8; 32]) -> Self {
        assert!(k > 0);
        let mut rng = StdRng::from_seed(seed);
        let mut values = (0..k).map(|_| rng.next_u64()).collect::<Vec<_>>();
        if values.iter().all(|value| *value == 0) {
            values[0] = 1;
        }
        let hash = hash_u64_values(&values);
        Self { values, seed, hash }
    }

    pub fn embed<F: PrimeField>(&self) -> Vec<F> {
        self.values.iter().copied().map(F::from).collect()
    }

    pub fn seed_hex(&self) -> String {
        hex(&self.seed)
    }

    pub fn hash_hex(&self) -> String {
        hex(&self.hash)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MasterSampleSchedule {
    indices: Vec<usize>,
    seed: [u8; 32],
    hash: [u8; 32],
}

impl MasterSampleSchedule {
    pub fn generate(n: usize, seed: [u8; 32]) -> Self {
        assert!(n >= RS2D_SAMPLE_COUNT);
        let mut permutation = (0..n).collect::<Vec<_>>();
        permutation.shuffle(&mut StdRng::from_seed(seed));
        let indices = permutation[..RS2D_SAMPLE_COUNT].to_vec();
        let hash = hash_schedule(n, &indices);
        Self {
            indices,
            seed,
            hash,
        }
    }

    pub fn indices(&self) -> &[usize] {
        &self.indices
    }

    pub fn bcc_indices(&self) -> &[usize] {
        &self.indices[..BCC_SAMPLE_COUNT]
    }

    pub fn seed_hex(&self) -> String {
        hex(&self.seed)
    }

    pub fn hash_hex(&self) -> String {
        hex(&self.hash)
    }
}

pub fn fresh_seed() -> [u8; 32] {
    let mut seed = [0_u8; 32];
    OsRng.fill_bytes(&mut seed);
    seed
}

pub fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

fn hash_u64_values(values: &[u64]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"bcc-das-master-input-v1\0");
    for value in values {
        hasher.update(&value.to_le_bytes());
    }
    *hasher.finalize().as_bytes()
}

fn hash_schedule(n: usize, indices: &[usize]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"bcc-das-unique-schedule-v1\0");
    hasher.update(&(n as u64).to_le_bytes());
    for index in indices {
        hasher.update(&(*index as u64).to_le_bytes());
    }
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn paper_geometries_are_matched() {
        let actual = OMEGAS.map(MatchedParameters::rate_one_quarter);
        assert_eq!(actual.map(|p| p.k), [16, 64, 256, 1024, 4096]);
        assert_eq!(actual.map(|p| p.bcc_k0), [8, 32, 128, 512, 2048]);
        assert_eq!(actual.map(|p| p.bcc_n0), [20, 80, 320, 1280, 5120]);
        assert_eq!(actual.map(|p| p.rs2d_k0), [4, 8, 16, 32, 64]);
        assert_eq!(actual.map(|p| p.rs2d_n0), [8, 16, 32, 64, 128]);
        assert!(actual.into_iter().all(|p| p.n == 4 * p.k));
    }

    #[test]
    fn schedule_is_unique_replayable_and_prefix_shared() {
        let first = MasterSampleSchedule::generate(4096, [7; 32]);
        let replay = MasterSampleSchedule::generate(4096, [7; 32]);
        assert_eq!(first, replay);
        assert_eq!(first.indices().len(), RS2D_SAMPLE_COUNT);
        assert_eq!(
            first
                .indices()
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
                .len(),
            RS2D_SAMPLE_COUNT
        );
        assert_eq!(first.bcc_indices(), &first.indices()[..BCC_SAMPLE_COUNT]);
    }

    #[test]
    fn light_client_schedules_have_no_global_disjointness_requirement() {
        // Scheduling is stateless: two clients selecting the same seed may
        // overlap completely, and neither schedule is rejected or changed.
        let client_a = MasterSampleSchedule::generate(64, [19; 32]);
        let client_b = MasterSampleSchedule::generate(64, [19; 32]);
        assert_eq!(client_a.indices(), client_b.indices());
    }

    #[test]
    fn bcc_oracle_counts_both_overlap_representations() {
        let params = MatchedParameters::rate_one_quarter(256);
        assert_eq!(params.bcc_proof_count(), 4 * 1280);
        assert_eq!(params.rs2d_proof_count(), params.n);
        assert!(params.bcc_proof_count() > params.n);
    }
}
