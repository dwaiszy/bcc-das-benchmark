//! Configuration and measurement setups for the DAS benchmark.

use std::fmt::Write as _;

use rand::rngs::{OsRng, StdRng};
use rand::seq::SliceRandom;
use rand::{Rng, RngCore, SeedableRng};

/// These BCC parameters give global `(k, n) = (16, 64), (64, 256),
/// (256, 1024), (1024, 4096), (4096, 16384)`.
pub const OMEGAS: [usize; 5] = [4, 16, 64, 256, 1024];

/// Section 6 evaluates the sampler-quality bound for this many independent
/// light clients.
pub const LIGHT_CLIENT_COUNT: usize = 1_000;

/// The paper targets a sampler failure probability of at most `10^-9`.
pub const SAMPLING_FAILURE_PROBABILITY: f64 = 1e-9;
/// Integer bit value corresponding to the paper's `10^-9` sampling target.
pub const SAMPLING_SOUNDNESS_BITS: usize = 30;
/// The paper reports all measurements using a single proposer thread.
pub const PROPOSER_THREADS: usize = 1;

/// Optional benchmark overrides.
pub fn configured_light_client_count() -> usize {
    std::env::var("DAS_BENCH_LIGHT_CLIENTS")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&v: &usize| v > 0)
        .unwrap_or(LIGHT_CLIENT_COUNT)
}

pub fn configured_failure_probability() -> f64 {
    std::env::var("DAS_BENCH_FAILURE_PROBABILITY")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&v: &f64| v > 0.0 && v < 1.0)
        .unwrap_or(SAMPLING_FAILURE_PROBABILITY)
}

/// A conservative integer-bit representation of the configured epsilon.
pub fn configured_soundness_bits() -> usize {
    (-configured_failure_probability().log2()).ceil() as usize
}

/// Return the proposer thread count used by the benchmark. The default matches
/// the paper's single-thread evaluation.
pub fn proposer_threads() -> usize {
    std::env::var("DAS_PROPOSER_THREADS")
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|&value| value > 0)
        .unwrap_or(PROPOSER_THREADS)
}

pub fn configured_group_size() -> usize {
    std::env::var("DAS_BENCH_GROUP_SIZE")
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value| {
            matches!(
                value,
                8 | 16 | 32 | 64 | 128 | 256 | 512 | 1024 | 1280 | 2560 | 5120
            )
        })
        .unwrap_or(64)
}

/// Optional group-size setting for batch-opening benchmark - WHIR PCS.
pub fn configured_group_sizes() -> Vec<usize> {
    std::env::var("DAS_BENCH_GROUP_SIZES")
        .ok()
        .map(|value| {
            value
                .split(',')
                .filter_map(|part| part.trim().parse::<usize>().ok())
                .filter(|size| {
                    matches!(
                        *size,
                        8 | 16 | 32 | 64 | 128 | 256 | 512 | 1024 | 1280 | 2560 | 5120
                    )
                })
                .collect::<Vec<_>>()
        })
        .filter(|sizes| !sizes.is_empty())
        .unwrap_or_else(|| vec![configured_group_size()])
}
pub const WARMUP_RUNS: usize = 1;
pub const MEASURED_RUNS: usize = 10;
pub const SAMPLING_MODEL: &str = "uniform_with_replacement";
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
        Self::rate_one_quarter_with_mu(omega, 4)
    }

    /// Rate-1/4 geometry for an even BCC block count `mu`.
    ///
    /// The parameters satisfy `k = mu * omega`. Thus, increasing the number of
    /// BCC blocks reduces the block width. The default setting is `mu = 4`.
    pub fn rate_one_quarter_with_mu(omega: usize, mu: usize) -> Self {
        assert!(omega.is_power_of_two(), "omega must be a power of two");
        assert!(mu >= 2 && mu % 2 == 0, "mu must be an even integer >= 2");
        let k = mu * omega;
        let n = 4 * k;
        let rs2d_n0 = n.isqrt();
        assert_eq!(rs2d_n0 * rs2d_n0, n, "2D-RS n must be square");
        let result = Self {
            omega,
            k,
            n,
            mu,
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

    /// BCC reception threshold `t = n - 2 rho` from Section 6.
    pub fn bcc_reception_threshold(self) -> usize {
        self.n - 2 * self.rho
    }

    pub fn bcc_withheld_limit(self) -> usize {
        self.bcc_reception_threshold() - 1
    }

    /// Minimum distance of the square 2D-RS product code.
    pub fn rs2d_minimum_distance(self) -> usize {
        let row_distance = self.rs2d_n0 - self.rs2d_k0 + 1;
        row_distance * row_distance
    }

    /// 2D-RS reception threshold `t = n - d + 1` from Section 6.
    pub fn rs2d_reception_threshold(self) -> usize {
        self.n - self.rs2d_minimum_distance() + 1
    }

    pub fn rs2d_withheld_limit(self) -> usize {
        self.rs2d_reception_threshold() - 1
    }

    /// Minimum number of samples required by the collective sampling bound.
    pub fn bcc_q_min(self) -> usize {
        minimum_sample_count_from_q_min(
            self.n,
            self.bcc_withheld_limit(),
            configured_light_client_count(),
            configured_soundness_bits(),
        )
    }

    pub fn rs2d_q_min(self) -> usize {
        minimum_sample_count_from_q_min(
            self.n,
            self.rs2d_withheld_limit(),
            configured_light_client_count(),
            configured_soundness_bits(),
        )
    }

    /// Required scalar samples for either BCC PCS instantiation.
    pub fn bcc_sample_count(self) -> usize {
        minimum_sample_count_from_q_min(
            self.n,
            self.bcc_withheld_limit(),
            configured_light_client_count(),
            configured_soundness_bits(),
        )
    }

    /// Required scalar samples for the 2D-RS+KZG baseline.
    pub fn rs2d_sample_count(self) -> usize {
        minimum_sample_count_from_q_min(
            self.n,
            self.rs2d_withheld_limit(),
            configured_light_client_count(),
            configured_soundness_bits(),
        )
    }
}

/// Section 6's with-replacement sampler bound:
///
/// `ceil((lambda ln 2 + ln binom(n, t - 1)) / (ell ln(n / (t - 1))))`.
///
/// `ell` is [`LIGHT_CLIENT_COUNT`] and `lambda` is
/// [`SAMPLING_SOUNDNESS_BITS`].
pub fn minimum_sample_count(n: usize, reception_threshold: usize) -> usize {
    minimum_sample_count_from_q_min(
        n,
        reception_threshold - 1,
        LIGHT_CLIENT_COUNT,
        SAMPLING_SOUNDNESS_BITS,
    )
}

pub fn minimum_sample_count_for(
    n: usize,
    reception_threshold: usize,
    light_clients: usize,
    soundness_bits: usize,
) -> usize {
    minimum_sample_count_from_q_min(
        n,
        reception_threshold - 1,
        light_clients,
        soundness_bits,
    )
}

/// Exact floating-point epsilon variant of the collective sampler bound.
pub fn minimum_sample_count_for_epsilon(
    n: usize,
    reception_threshold: usize,
    light_clients: usize,
    epsilon: f64,
) -> usize {
    assert!((1..n).contains(&(reception_threshold - 1)));
    assert!(light_clients > 0 && epsilon > 0.0 && epsilon < 1.0);
    let delta = reception_threshold - 1;
    let numerator = ln_binomial(n, delta) + (-epsilon.ln());
    let denominator = (light_clients as f64) * ((n as f64) / (delta as f64)).ln();
    let mut q = (numerator / denominator).ceil() as usize;
    let log_bound = |q: usize| ln_binomial(n, delta) + (light_clients as f64) * (q as f64) * ((delta as f64) / (n as f64)).ln();
    while log_bound(q) > epsilon.ln() { q += 1; }
    while q > 0 && log_bound(q - 1) <= epsilon.ln() { q -= 1; }
    q
}

/// Generic collective sampling bound parameterized by `q_min`.
///
/// `q_min` is the maximum number of withheld/unavailable symbols that can be
/// tolerated while still failing to reach the reconstruction threshold. For
/// a reconstruction threshold `t`, use `q_min = t - 1`. The bound is then:
///
/// `ceil((lambda ln 2 + ln binom(n, q_min)) /
///       (ell ln(n / q_min)))`.
pub fn minimum_sample_count_from_q_min(
    n: usize,
    q_min: usize,
    light_clients: usize,
    soundness_bits: usize,
) -> usize {
    assert!(n > 1, "codeword length must exceed one");
    assert!((1..n).contains(&q_min), "q_min must lie in 1..n");
    assert!(light_clients > 0, "light client count must be positive");
    let numerator =
        (soundness_bits as f64) * std::f64::consts::LN_2 + ln_binomial(n, q_min);
    let denominator = (light_clients as f64) * ((n as f64) / (q_min as f64)).ln();
    (numerator / denominator).ceil() as usize
}

pub fn per_node_sample_count(answerable_fraction: f64, failure_bits: usize) -> usize {
    assert!(answerable_fraction > 0.0 && answerable_fraction < 1.0);
    ((failure_bits as f64) / (-answerable_fraction.log2())).ceil() as usize
}

pub fn required_nodes_bound(
    universe_size: usize,
    reconstruction_fraction: f64,
    samples_per_node: usize,
    failure_bits: usize,
) -> usize {
    assert!(universe_size > 0 && samples_per_node > 0);
    assert!(reconstruction_fraction > 0.0 && reconstruction_fraction < 1.0);
    ((universe_size as f64 + failure_bits as f64)
        / ((samples_per_node as f64) * (-reconstruction_fraction.log2())))
    .ceil() as usize
}

fn ln_binomial(n: usize, k: usize) -> f64 {
    let k = k.min(n - k);
    (1..=k)
        .map(|i| ((n - k + i) as f64).ln() - (i as f64).ln())
        .sum()
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

    pub fn embed<F: From<u64>>(&self) -> Vec<F> {
        self.values.iter().copied().map(F::from).collect()
    }

    pub fn seed_hex(&self) -> String {
        hex(&self.seed)
    }

    pub fn hash_hex(&self) -> String {
        hex(&self.hash)
    }

    /// Encode the benchmark input as little-endian `u64` values using the shared
    /// representation.
    pub fn serialized_le_bytes(&self) -> Vec<u8> {
        self.values
            .iter()
            .flat_map(|value| value.to_le_bytes())
            .collect()
    }

    pub fn symbol_count(&self) -> usize {
        self.values.len()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MasterSampleSet {
    indices: Vec<usize>,
    seed: [u8; 32],
    hash: [u8; 32],
}

impl MasterSampleSet {
    pub fn generate(n: usize, sample_count: usize, seed: [u8; 32]) -> Self {
        assert!(sample_count > 0 && sample_count <= n);
        let mut permutation = (0..n).collect::<Vec<_>>();
        permutation.shuffle(&mut StdRng::from_seed(seed));
        let indices = permutation[..sample_count].to_vec();
        let hash = hash_sample_set(n, &indices, false);
        Self {
            indices,
            seed,
            hash,
        }
    }

    pub fn generate_with_replacement(n: usize, sample_count: usize, seed: [u8; 32]) -> Self {
        assert!(n > 0 && sample_count > 0);
        let mut rng = StdRng::from_seed(seed);
        let indices = (0..sample_count)
            .map(|_| rng.gen_range(0..n))
            .collect::<Vec<_>>();
        let hash = hash_sample_set(n, &indices, true);
        Self {
            indices,
            seed,
            hash,
        }
    }

    pub fn indices(&self) -> &[usize] {
        &self.indices
    }

    pub fn prefix(&self, sample_count: usize) -> &[usize] {
        assert!(sample_count <= self.indices.len());
        &self.indices[..sample_count]
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

/// Read a 32-byte hexadecimal seed from the environment. Generate a fresh seed
/// when the variable is missing or invalid.
pub fn configured_seed(name: &str) -> [u8; 32] {
    std::env::var(name)
        .ok()
        .and_then(|value| {
            if value.len() != 64 {
                return None;
            }
            let mut seed = [0_u8; 32];
            for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
                seed[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
            }
            Some(seed)
        })
        .unwrap_or_else(fresh_seed)
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
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

fn hash_sample_set(n: usize, indices: &[usize], with_replacement: bool) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(if with_replacement {
        b"bcc-das-replacement-sample_set-v1\0" as &[u8]
    } else {
        b"bcc-das-unique-sample_set-v1\0"
    });
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
    fn section_six_sample_counts_match_all_benchmark_geometries() {
        let actual = OMEGAS.map(MatchedParameters::rate_one_quarter);
        assert_eq!(
            actual.map(MatchedParameters::bcc_sample_count),
            [1, 1, 2, 6, 24]
        );
        assert_eq!(
            actual.map(MatchedParameters::rs2d_sample_count),
            [1, 1, 2, 8, 32]
        );
        assert_eq!(actual[3].bcc_reception_threshold(), 2560);
        assert_eq!(actual[3].rs2d_reception_threshold(), 3008);
        assert_eq!(actual[3].bcc_withheld_limit(), 2559);
        assert_eq!(actual[3].rs2d_withheld_limit(), 3007);
        assert_eq!(
            actual[3].bcc_q_min(),
            6
        );
        assert_eq!(
            actual[3].rs2d_q_min(),
            8
        );
    }

    #[test]
    fn sample_set_is_unique_replayable_and_prefix_shared() {
        let parameters = MatchedParameters::rate_one_quarter(256);
        let first = MasterSampleSet::generate(4096, parameters.rs2d_sample_count(), [7; 32]);
        let replay = MasterSampleSet::generate(4096, parameters.rs2d_sample_count(), [7; 32]);
        assert_eq!(first, replay);
        assert_eq!(first.indices().len(), parameters.rs2d_sample_count());
        assert_eq!(
            first
                .indices()
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
                .len(),
            parameters.rs2d_sample_count()
        );
        assert_eq!(
            first.prefix(parameters.bcc_sample_count()),
            &first.indices()[..6]
        );
    }

    #[test]
    fn light_client_sample_sets_have_no_global_disjointness_requirement() {
        // Each client generates its sample set independently. Identical seeds may
        // produce identical or overlapping positions.
        let client_a = MasterSampleSet::generate(64, 1, [19; 32]);
        let client_b = MasterSampleSet::generate(64, 1, [19; 32]);
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
