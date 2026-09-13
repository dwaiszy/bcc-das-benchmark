//! Controlled BCC+KZG, BCC+WHIR, and RS2D+KZG DAS benchmark.
//! It measures setup, commit, encode, opening, sampling, verification, and
//! proof-size measurements, then emits one reproducible JSON object per row.

use std::error::Error;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ark_bls12_381::Fr as BlsFr;
use block_circulant_codes::BcParams;
use block_circulant_codes::benchmark_config::{
    MEASURED_RUNS, MasterInput, MasterSampleSchedule, MatchedParameters, OMEGAS, PROOF_ORDER,
    PROOF_SCOPE_BCC, PROOF_SCOPE_RS2D, SAMPLING_MODEL, WARMUP_RUNS, fresh_seed, hex,
    proposer_threads,
};
use block_circulant_codes::das::{
    BlockId, ErasureCode, PreparedBlock, SetupArtifacts, bcc_kzg, bcc_whir, rs2d_kzg,
};
use block_circulant_codes::pcs::ArcPcs;

#[derive(Clone, Copy)]
struct Meta {
    scheme: &'static str,
    field: &'static str,
    pcs: &'static str,
    security_bits: Option<usize>,
    security_parameters: &'static str,
    status: &'static str,
    proof_scope: &'static str,
    verifier_threads: usize,
    proof_encoding: &'static str,
}

struct Row {
    run: usize,
    timestamp: u64,
    git: String,
    meta: Meta,
    profile: String,
    setup_id: String,
    p: MatchedParameters,
    samples: Vec<usize>,
    sample_seed: String,
    schedule_hash: String,
    input_seed: String,
    input_hash: String,
    commitments: usize,
    proofs: usize,
    setup: Duration,
    encode: Duration,
    commit: Duration,
    open: Duration,
    verify: Duration,
    decompress: Duration,
    verify_crypto: Duration,
    header_bytes: usize,
    data_bytes: usize,
    metadata_bytes: usize,
    proof_bytes: usize,
}

impl Row {
    fn json(&self) -> String {
        let ix = self
            .samples
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let security = self
            .meta
            .security_bits
            .map_or_else(|| "null".into(), |v| v.to_string());
        let ms = |d: Duration| d.as_secs_f64() * 1000.0;
        let total = self.encode + self.commit + self.open;
        // A verifier needs the published commitment metadata plus the sampled
        // values, response metadata, and opening proofs.
        let download = self.header_bytes + self.data_bytes + self.metadata_bytes + self.proof_bytes;
        format!(
            concat!(
                "{{\"schema_version\":\"bcc-das-benchmark-v3\",\"run_id\":{},\"warmup\":false,\"timestamp_unix_seconds\":{},\"git_commit\":\"{}\",",
                "\"scheme\":\"{}\",\"field\":\"{}\",\"pcs\":\"{}\",\"security_target_bits\":{},",
                "\"security_parameters\":\"{}\",\"profile_status\":\"{}\",\"profile_id\":\"{}\",\"setup_id\":\"{}\",",
                "\"omega\":{},\"k\":{},\"n\":{},\"mu\":{},\"rho\":{},\"local_k\":{},\"local_n\":{},",
                "\"opening_profile\":\"paper-scalar\",\"sampling_model\":\"{}\",\"sample_count\":{},\"sample_indices\":[{}],",
                "\"sample_seed\":\"{}\",\"sample_schedule_hash\":\"{}\",\"input_seed\":\"{}\",\"input_hash\":\"{}\",",
                "\"proposer_threads\":{},\"verifier_threads\":{},\"proof_encoding\":\"{}\",\"commitment_count\":{},\"proof_scope\":\"{}\",",
                "\"proof_order\":\"{}\",\"proposer_proof_count\":{},\"setup_ms\":{:.6},\"encode_ms\":{:.6},",
                "\"commit_ms\":{:.6},\"open_ms\":{:.6},\"proposer_ms\":{:.6},\"total_proving_ms\":{:.6},\"decompress_ms\":{:.6},\"verify_crypto_ms\":{:.6},\"verify_ms\":{:.6},",
                "\"header_bytes\":{},\"sample_data_bytes\":{},\"sample_metadata_bytes\":{},\"verify_proof_bytes\":{},",
                "\"light_client_download_bytes\":{}}}"
            ),
            self.run,
            self.timestamp,
            self.git,
            self.meta.scheme,
            self.meta.field,
            self.meta.pcs,
            security,
            self.meta.security_parameters,
            self.meta.status,
            self.profile,
            self.setup_id,
            self.p.omega,
            self.p.k,
            self.p.n,
            self.p.mu,
            self.p.rho,
            if self.meta.proof_scope == PROOF_SCOPE_BCC {
                self.p.bcc_k0
            } else {
                self.p.rs2d_k0
            },
            if self.meta.proof_scope == PROOF_SCOPE_BCC {
                self.p.bcc_n0
            } else {
                self.p.rs2d_n0
            },
            SAMPLING_MODEL,
            self.samples.len(),
            ix,
            self.sample_seed,
            self.schedule_hash,
            self.input_seed,
            self.input_hash,
            proposer_threads(),
            self.meta.verifier_threads,
            self.meta.proof_encoding,
            self.commitments,
            self.meta.proof_scope,
            PROOF_ORDER,
            self.proofs,
            ms(self.setup),
            ms(self.encode),
            ms(self.commit),
            ms(self.open),
            ms(total),
            ms(total),
            ms(self.decompress),
            ms(self.verify_crypto),
            ms(self.verify),
            self.header_bytes,
            self.data_bytes,
            self.metadata_bytes,
            self.proof_bytes,
            download
        )
    }
}

#[allow(clippy::too_many_arguments)]
fn finish<C, P>(
    a: &SetupArtifacts<C, P>,
    b: &PreparedBlock<C::Field, P::Commitment, P::Proof>,
    setup: Duration,
    p: MatchedParameters,
    meta: Meta,
    samples: &[usize],
    input: &MasterInput,
    schedule: &MasterSampleSchedule,
    run: usize,
) -> Result<Row, Box<dyn Error>>
where
    C: ErasureCode,
    P: ArcPcs<C::Field>,
{
    let plan = a.verifier.v1_from_indices(&b.header, samples)?;
    let responses = b.dispersal.respond(&plan)?;
    let started = Instant::now();
    let (transcript, verification_timing) =
        a.verifier.v2_with_timing(&b.header, &plan, &responses)?;
    let verify = started.elapsed();
    if transcript.sampled_indices() != samples {
        return Err("V2 changed the sample schedule".into());
    }
    let local_n = if meta.proof_scope == PROOF_SCOPE_BCC {
        p.bcc_n0
    } else {
        p.rs2d_n0
    };
    let local_code_count = if meta.proof_scope == PROOF_SCOPE_BCC {
        p.mu
    } else {
        p.rs2d_n0
    };
    let counts = b.dispersal.local_opening_counts().collect::<Vec<_>>();
    if counts.len() != local_code_count || counts.iter().any(|&n| n != local_n) {
        return Err(format!(
            "{} returned a non-canonical local oracle: {counts:?}",
            meta.scheme
        )
        .into());
    }
    let expected = if meta.proof_scope == PROOF_SCOPE_BCC {
        p.bcc_proof_count()
    } else {
        p.rs2d_proof_count()
    };
    if b.dispersal.opening_count() != expected {
        return Err(format!(
            "{} returned {} proofs, expected {expected}",
            meta.scheme,
            b.dispersal.opening_count()
        )
        .into());
    }
    let measurements = a.verifier.proof_measurements(&b.header, &responses)?;
    let profile = a.proposer.profile();
    Ok(Row {
        run,
        timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        git: git_commit(),
        meta,
        profile: hex(profile.id().as_bytes()),
        setup_id: hex(profile.setup_id()),
        p,
        samples: samples.to_vec(),
        sample_seed: schedule.seed_hex(),
        schedule_hash: schedule.hash_hex(),
        input_seed: input.seed_hex(),
        input_hash: input.hash_hex(),
        commitments: b.header.local_commitments().len(),
        proofs: b.dispersal.opening_count(),
        setup,
        encode: b.metrics.encode,
        commit: b.metrics.commit,
        open: b.metrics.open,
        verify,
        decompress: verification_timing.decompression,
        verify_crypto: verify.saturating_sub(verification_timing.decompression),
        header_bytes: measurements.header_bytes,
        data_bytes: measurements.sample_data_bytes,
        metadata_bytes: measurements.sample_metadata_bytes,
        proof_bytes: measurements.verify_proof_bytes,
    })
}

fn selected(name: &str) -> bool {
    std::env::var("DAS_BENCH_ONLY").map_or(true, |v| v.split(',').any(|x| x.trim() == name))
}
fn git_commit() -> String {
    std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().into())
        .unwrap_or_else(|| "unknown".into())
}

fn one_geometry(p: MatchedParameters, run: usize) -> Result<Vec<Row>, Box<dyn Error>> {
    let bp = BcParams {
        mu: p.mu,
        omega: p.omega,
        rho: p.rho,
    };
    let input = MasterInput::generate(p.k, fresh_seed());
    let bls = input.embed::<BlsFr>();
    let block = BlockId::new(fresh_seed());
    let schedule = MasterSampleSchedule::generate(p.n, fresh_seed());
    let mut rows = Vec::new();
    // A scheme is fully processed and dropped before the next begins.  This
    // both matches the benchmark contract's independent-scheme timing and
    // prevents four complete opening oracles being resident at once.
    if selected("bcc-kzg") {
        let started = Instant::now();
        let a = bcc_kzg::setup(bp, proposer_threads())?;
        let s = started.elapsed();
        let committed = a.proposer.commit(block, &bls)?;
        let encoded = a.proposer.encode(committed)?;
        let b = a.proposer.open(encoded)?;
        rows.push(finish(
            &a,
            &b,
            s,
            p,
            Meta {
                scheme: "bcc-kzg",
                field: "bls12-381-scalar",
                pcs: "kzg-fk20",
                security_bits: Some(128),
                security_parameters: "benchmark-only SRS; algebraic group model",
                status: "benchmark",
                proof_scope: PROOF_SCOPE_BCC,
                verifier_threads: 1,
                proof_encoding: "compressed-g1-witness",
            },
            schedule.bcc_indices(),
            &input,
            &schedule,
            run,
        )?);
    }
    if selected("bcc-whir") {
        let started = Instant::now();
        let a = bcc_whir::setup(bp, proposer_threads())?;
        let s = started.elapsed();
        let committed = a.proposer.commit(block, &bls)?;
        let encoded = a.proposer.encode(committed)?;
        let b = a.proposer.open(encoded)?;
        rows.push(finish(
            &a,
            &b,
            s,
            p,
            Meta {
                scheme: "bcc-whir",
                field: "bls12-381-scalar",
                pcs: "whir-johnson",
                security_bits: Some(128),
                security_parameters: "Johnson bound; Blake3; PoW=0",
                status: "benchmark",
                proof_scope: PROOF_SCOPE_BCC,
                verifier_threads: 1,
                proof_encoding: "zstd-level-3",
            },
            schedule.bcc_indices(),
            &input,
            &schedule,
            run,
        )?);
    }
    if selected("rs2d-kzg") {
        let started = Instant::now();
        let a = rs2d_kzg::setup(p.rs2d_n0, p.rs2d_k0, proposer_threads())?;
        let s = started.elapsed();
        let committed = a.proposer.commit(block, &bls)?;
        let encoded = a.proposer.encode(committed)?;
        let b = a.proposer.open(encoded)?;
        rows.push(finish(
            &a,
            &b,
            s,
            p,
            Meta {
                scheme: "rs2d-kzg",
                field: "bls12-381-scalar",
                pcs: "kzg-fk20",
                security_bits: Some(128),
                security_parameters: "benchmark-only SRS; algebraic group model",
                status: "benchmark",
                proof_scope: PROOF_SCOPE_RS2D,
                verifier_threads: 1,
                proof_encoding: "compressed-g1-witness",
            },
            schedule.indices(),
            &input,
            &schedule,
            run,
        )?);
    }
    Ok(rows)
}

fn env_n(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}
fn main() -> Result<(), Box<dyn Error>> {
    let omegas = std::env::var("DAS_BENCH_OMEGA")
        .ok()
        .and_then(|v| v.parse().ok())
        .map_or_else(|| OMEGAS.to_vec(), |v| vec![v]);
    if omegas.iter().any(|v| !OMEGAS.contains(v)) {
        return Err("DAS_BENCH_OMEGA must be 4,16,64,256, or 1024".into());
    }
    let explicit = std::env::var("DAS_BENCH_RUN")
        .ok()
        .and_then(|v| v.parse().ok());
    let warmups = if explicit.is_some() {
        0
    } else {
        env_n("DAS_BENCH_WARMUPS", WARMUP_RUNS)
    };
    let runs = env_n("DAS_BENCH_RUNS", MEASURED_RUNS);
    if explicit.is_none() && runs == 0 {
        return Err("DAS_BENCH_RUNS must be positive".into());
    }
    let mut plan = (0..warmups).map(|r| (r, true)).collect::<Vec<_>>();
    if let Some(r) = explicit {
        plan.push((r, false))
    } else {
        plan.extend((1..=runs).map(|r| (r, false)))
    }
    for (run, warmup) in plan {
        for &omega in &omegas {
            eprintln!(
                "run={run} warmup={warmup} omega={omega} threads={}",
                proposer_threads()
            );
            for row in one_geometry(MatchedParameters::rate_one_quarter(omega), run)? {
                if !warmup {
                    println!("{}", row.json())
                }
            }
        }
    }
    Ok(())
}
