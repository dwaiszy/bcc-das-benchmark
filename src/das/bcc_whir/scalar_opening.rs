//! Scalar-opening benchmark for BCC+WHIR-JB.
//!
//! Each sampled BCC position is verified by one WHIR proof
//! independently. This is used for the paper's Table 4.

use std::collections::BTreeSet;
use std::error::Error;
use std::time::Instant;

use ark_poly::DenseUVPolynomial;
use rayon::ThreadPoolBuilder;
use block_circulant_codes::benchmark_config::{
    configured_failure_probability, configured_light_client_count, configured_seed,
    minimum_sample_count_for_epsilon, MasterInput, MasterSampleSet,
};
use block_circulant_codes::das::bcc_whir::{parameters, whir_max_degree};
use block_circulant_codes::das::core::ErasureCode;
use block_circulant_codes::das::erasure_code::BccCode;
use block_circulant_codes::pcs::whir::{WhirCommitment, WhirField, WhirLocalCodeScheme, WhirProof};
use block_circulant_codes::BcParams;

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name).ok().and_then(|x| x.parse().ok()).unwrap_or(default)
}

fn params_for(k: usize, n: usize) -> Result<BcParams, Box<dyn Error>> {
    let mu = env_usize("DAS_BENCH_MU", 32);
    if !matches!(mu, 32 | 64) || k % mu != 0 || n != 4 * k || k == 0 {
        return Err("mu must be 32 or 64 and divide k; geometry must satisfy n=4k".into());
    }
    let omega = k / mu;
    let rho = n / mu - omega;
    let params = BcParams { mu, omega, rho };
    let code = BccCode::<WhirField>::new(params)?;
    if code.message_len() != k || code.codeword_len() != n {
        return Err("derived BCC geometry does not match requested k,n".into());
    }
    Ok(params)
}

fn main() -> Result<(), Box<dyn Error>> {
    println!("skipped_point=(16,64)");
    println!("skipped_reason=\"invalid for the requested fixed mu values because k/mu is not an integer\"");

    let k = env_usize("DAS_BENCH_K", 64);
    let n = env_usize("DAS_BENCH_N", 4 * k);
    let params = params_for(k, n)?;
    let code = BccCode::<WhirField>::new(params)?;
    let mu = params.mu;
    let omega = params.omega;
    let rho = params.rho;
    let ell = configured_light_client_count();
    let epsilon = configured_failure_probability();
    let t = code.reception_threshold();
    let q = minimum_sample_count_for_epsilon(n, t, ell, epsilon);
    let input = MasterInput::generate(k, configured_seed("DAS_BENCH_INPUT_SEED"));
    let message = input.embed::<WhirField>();
    let pcs = WhirLocalCodeScheme::try_setup(whir_max_degree(params), &parameters())?;
    let pool = ThreadPoolBuilder::new().num_threads(1).build()?;

    let polynomials = code.polynomialize(&message)?;
    let encode_started = Instant::now();
    let encoded = pool.install(|| code.encode_polynomials(&polynomials))?;
    let encode_ms = encode_started.elapsed().as_secs_f64() * 1000.0;

    let commit_started = Instant::now();
    let committed = pool.install(|| {
        polynomials
            .local_polynomials()
            .iter()
            .map(|coefficients| {
                let polynomial = ark_poly::univariate::DensePolynomial::from_coefficients_vec(
                    coefficients.to_vec(),
                );
                pcs.commit(&polynomial)
            })
            .collect::<Vec<(WhirCommitment, block_circulant_codes::pcs::whir::WhirState)>>()
    });
    let commit_ms = commit_started.elapsed().as_secs_f64() * 1000.0;
    let commitments: Vec<_> = committed.iter().map(|x| &x.0).collect();
    let states: Vec<_> = committed.iter().map(|x| &x.1).collect();

    let sample_set = MasterSampleSet::generate_with_replacement(
        n, q, configured_seed("DAS_BENCH_SAMPLE_SEED"),
    );
    let indices = sample_set.indices();
    let d = indices
        .iter()
        .map(|&global| params.canonical_local_code(global))
        .collect::<BTreeSet<_>>()
        .len();

    let header_bytes = 32 + commitments.iter().map(|c| c.compressed_size()).sum::<usize>();
    println!("schema=bcc-whir-jb-scalar-opening-v1");
    println!("k={k}");
    println!("n={n}");
    println!("mu={mu}");
    println!("omega={omega}");
    println!("rho={rho}");
    println!("k0={}", params.k0());
    println!("n0={}", params.n0());
    println!("distance={}", 2 * rho + 1);
    println!("reconstruction_threshold={t}");
    println!("q_min={q}");
    println!("epsilon_das={epsilon:.12e}");
    println!("light_clients={ell}");
    println!("local_rate={}/{}", params.k0(), params.n0());
    println!("global_rate=1/4");
    println!("whir_local_domain_size={}", 1usize << whir_max_degree(params).next_power_of_two().ilog2());
    println!("number_of_commitments={mu}");
    println!("field=Goldilocks2");
    println!("field_domain_valid=true");
    println!("encode_ms={encode_ms:.6}");
    println!("commit_ms={commit_ms:.6}");
    println!("empirical_distinct_arcs={d}");
    println!("header_bytes={header_bytes}");
    println!("compression_level={}", WhirProof::compression_level());

    let opening_started = Instant::now();
    let mut proofs = Vec::with_capacity(q);
    for &global in indices {
        let arc = params.canonical_local_code(global);
        let claim = encoded.local_codes()[arc].claims()[global % params.period()];
        let point = claim.point();
        let value = claim.value();
        let (proof, _timing) = pcs.open_all_with_evaluations_checked_timed(
            states[arc], &[point], &[value],
        )?;
        proofs.push((arc, point, value, proof));
    }
    let opening_ms = opening_started.elapsed().as_secs_f64() * 1000.0;

    let verify_started = Instant::now();
    for (arc, point, value, proof) in &proofs {
        pcs.verify_all_checked(commitments[*arc], &[*point], &[*value], proof)?;
    }
    let verify_ms = verify_started.elapsed().as_secs_f64() * 1000.0;

    let proof_bytes: usize = proofs.iter().map(|x| x.3.compressed_size()).sum();
    let uncompressed_proof_bytes: usize = proofs.iter().map(|x| x.3.uncompressed_size()).sum();
    let values_bytes = q * 16;
    let metadata_bytes = q * 8;
    let total_bytes = header_bytes + proof_bytes + values_bytes + metadata_bytes;
    println!(
        "scalar_opening q={} d={} proof_transcripts={} proof_bytes={} uncompressed_proof_bytes={} proof_bytes_per_claim={:.6} proof_bytes_per_touched_arc={:.6} total_lc_bytes={} opening_ms={:.6} verify_ms={:.6} verify_ms_per_claim={:.9} verify_ms_per_transcript={:.9} values_bytes={} metadata_bytes={} header_bytes={} total_network_bytes={}",
        q, d, proofs.len(), proof_bytes, uncompressed_proof_bytes,
        proof_bytes as f64 / q as f64, proof_bytes as f64 / d as f64,
        total_bytes, opening_ms, verify_ms, verify_ms / q as f64,
        verify_ms / proofs.len() as f64, values_bytes, metadata_bytes, header_bytes,
        total_bytes * ell,
    );

    if let Some(trials) = std::env::var("DAS_BENCH_SAMPLE_SET_TRIALS").ok().and_then(|v| v.parse::<usize>().ok()).filter(|&v| v > 0) {
        // For each position, cache its deterministic scalar proof size once,
        // then reuse those sizes to calculate communication across 10,000 sample sets.
        // This measures response bytes only, not proving.
        let mut scalar_proof_sizes = Vec::with_capacity(n);
        for global in 0..n {
            let arc = params.canonical_local_code(global);
            let local = &encoded.local_codes()[arc];
            let claim = local.claims()[global % params.period()];
            let point = claim.point();
            let value = claim.value();
            let (proof, _timing) = pcs.open_all_with_evaluations_checked_timed(
                states[arc], &[point], &[value],
            )?;
            scalar_proof_sizes.push(proof.compressed_size());
        }
        let mut totals = Vec::with_capacity(trials);
        let mut proof_sizes = Vec::with_capacity(trials);
        let mut touched_arcs = Vec::with_capacity(trials);
        for trial in 0..trials {
            let mut seed = [0_u8; 32];
            seed[..8].copy_from_slice(&(trial as u64).to_le_bytes());
            let sample_set = MasterSampleSet::generate_with_replacement(n, q, seed);
            let proofs = sample_set.indices().iter().map(|&global| scalar_proof_sizes[global]).sum::<usize>();
            touched_arcs.push(sample_set.indices().iter().map(|&global| params.canonical_local_code(global)).collect::<BTreeSet<_>>().len());
            totals.push(header_bytes + proofs + q * 16 + q * 8);
            proof_sizes.push(proofs);
        }
        let mean = totals.iter().sum::<usize>() as f64 / totals.len() as f64;
        let min = *totals.iter().min().unwrap();
        let max = *totals.iter().max().unwrap();
        totals.sort_unstable();
        let median = if totals.len() % 2 == 0 {
            (totals[totals.len() / 2 - 1] as f64 + totals[totals.len() / 2] as f64) / 2.0
        } else {
            totals[totals.len() / 2] as f64
        };
        let variance = totals.iter().map(|&x| {
            let delta = x as f64 - mean;
            delta * delta
        }).sum::<f64>() / (totals.len().saturating_sub(1).max(1) as f64);
        println!("sample_set_audit_mode=scalar_only");
        println!("sample_set_audit_trials={trials}");
        println!("sample_set_audit_mean_total_lc_bytes={mean:.6}");
        println!("sample_set_audit_mean_proof_bytes={:.6}", proof_sizes.iter().sum::<usize>() as f64 / proof_sizes.len() as f64);
        println!("sample_set_audit_mean_distinct_arcs={:.6}", touched_arcs.iter().sum::<usize>() as f64 / touched_arcs.len() as f64);
        println!("sample_set_audit_median_total_lc_bytes={median:.6}");
        println!("sample_set_audit_min_total_lc_bytes={min}");
        println!("sample_set_audit_max_total_lc_bytes={max}");
        println!("sample_set_audit_sd_total_lc_bytes={:.6}", variance.sqrt());
    }
    Ok(())
}
