//FRIDA benchmark using the shared DAS configuration.

use std::mem::size_of;
use std::time::{Duration, Instant};

use block_circulant_codes::benchmark_config::{
    configured_failure_probability, configured_light_client_count, configured_seed,
    configured_soundness_bits, minimum_sample_count_for_epsilon, MasterInput, MasterSampleSet,
};
#[cfg(test)]
use block_circulant_codes::benchmark_config::minimum_sample_count_for;
use frida_poc::prover::proof::FridaProof;
use frida_poc::prover::{builder::FridaProverBuilder, ProverCommitment};
use frida_poc::core::queries::calculate_num_queries;
use frida_poc::core::data::{build_evaluations_from_data, encoded_data_element_count};
use frida_poc::verifier::das::FridaDasVerifier;
use frida_poc::winterfell::{
    f128::BaseElement, winter_crypto::hashers::Blake3_256, Deserializable, FieldElement,
    FriOptions, Serializable,
};
use rand::{rngs::StdRng, RngCore, SeedableRng};

type FridaField = BaseElement;
type FridaHash = Blake3_256<FridaField>;

const LOGICAL_SYMBOLS: usize = 4_096;
const DEFAULT_PCS_SOUNDNESS_BITS: usize = 80;
const DEFAULT_FRI_QUERIES: usize = 118;

/// Each client request contains the sampled global position encoded using the
/// benchmark's request format. The response contains the corresponding encoded
/// value and FRIDA opening proof; the position is not repeated in the response.
fn request_bytes(positions: &[usize]) -> usize {
    positions.to_vec().to_bytes().len()
}

/// FRIDA's FRI verifier takes its final randomness as an initial-domain query
/// position `s_0`. Consequently the paper's query-selection algorithm is
/// `QSelect(rho_1, ..., rho_r, j) = j`: the later positions are obtained by
/// repeatedly applying the FRI folding. The FRI transcript determines
/// the folding challenges; it need not alter this final query position.
fn qselect_position(requested_index: usize, domain_size: usize) -> usize {
    assert!(requested_index < domain_size, "QSelect index out of range");
    requested_index
}

fn client_sample_set(
    challenge_rng: &mut StdRng,
    domain_size: usize,
    samples_per_client: usize,
) -> MasterSampleSet {
    let mut client_seed = [0_u8; 32];
    challenge_rng.fill_bytes(&mut client_seed);
    MasterSampleSet::generate_with_replacement(domain_size, samples_per_client, client_seed)
}

#[derive(Clone, Copy, Debug)]
struct FridaProfile {
    name: &'static str,
    payload_bytes: usize,
    blowup: usize,
    folding_factor: usize,
    remainder_size: usize,
}

/// A precomputed FRIDA opening for one encoded position. The position is stored
/// explicitly so the opening can be verified and its byte size measured.
#[derive(Clone)]
struct MaterializedOpening {
    position: usize,
    value: FridaField,
    opening_bytes: Vec<u8>,
}

fn profile(name: &str, payload_bytes: usize) -> Result<FridaProfile, String> {
    match name {
        "frida-matched-rate" => Ok(FridaProfile {
            name: "frida-matched-rate",
            payload_bytes,
            blowup: 4,
            folding_factor: 4,
            // A final domain of 4 with dimension 1 requires a constant
            // remainder polynomial (maximum degree 0).
            remainder_size: 0,
        }),
        "frida-native" => Ok(FridaProfile {
            name: "frida-native",
            payload_bytes,
            blowup: 2,
            folding_factor: 4,
            remainder_size: 2,
        }),
        other => Err(format!(
            "unknown FRIDA profile {other}; use frida-matched-rate or frida-native"
        )),
    }
}

fn storage_index(position: usize, domain_size: usize, folding_factor: usize) -> usize {
    let row_length = domain_size / folding_factor;
    (position % row_length) * folding_factor + (position / row_length)
}

fn env_usize(name: &str, default: usize) -> Result<usize, String> {
    std::env::var(name)
        .ok()
        .map(|value| {
            value
                .parse()
                .map_err(|_| format!("{name} must be an integer, got {value}"))
        })
        .unwrap_or(Ok(default))
}

fn env_flag(name: &str) -> bool {
    matches!(std::env::var(name).as_deref(), Ok("1" | "true" | "yes"))
}

fn build_full_opening_material(
    prover: &frida_poc::prover::FridaProver<FridaField, FridaHash>,
    domain_size: usize,
    folding_factor: usize,
) -> Vec<MaterializedOpening> {
    (0..domain_size)
        .map(|position| {
            let value = prover.get_first_layer_evaluations()
                [storage_index(position, domain_size, folding_factor)];
            MaterializedOpening {
                position,
                value,
                opening_bytes: prover.open(&[position]).to_bytes(),
            }
        })
        .collect()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let profile_name =
        std::env::var("FRIDA_PROFILE").unwrap_or_else(|_| "frida-matched-rate".into());
    let logical_symbols = env_usize("DAS_BENCH_LOGICAL_SYMBOLS", LOGICAL_SYMBOLS)?;
    let payload_bytes = logical_symbols * size_of::<u64>();
    let profile = profile(&profile_name, payload_bytes)?;
    let pcs_soundness_bits = env_usize("FRIDA_PCS_SOUNDNESS_BITS", DEFAULT_PCS_SOUNDNESS_BITS)?;
    let light_clients = configured_light_client_count();
    let soundness_bits = configured_soundness_bits();
    let epsilon_das = configured_failure_probability();

    let input_seed = configured_seed("DAS_BENCH_INPUT_SEED");
    let sample_seed = configured_seed("DAS_BENCH_SAMPLE_SEED");
    let input = MasterInput::generate(logical_symbols, input_seed);
    let data = input.serialized_le_bytes();
    assert_eq!(data.len(), profile.payload_bytes);

    let options = FriOptions::new(
        profile.blowup,
        profile.folding_factor,
        profile.remainder_size,
    );
    let encoded_domain_for_timing = encoded_data_element_count::<FridaField>(data.len())
        .next_power_of_two()
        * profile.blowup;
    let rs_encode_started = Instant::now();
    let _rs_encoded = build_evaluations_from_data::<FridaField>(
        &data,
        encoded_domain_for_timing,
        profile.blowup,
    )?;
    let rs_encode_ms = rs_encode_started.elapsed().as_secs_f64() * 1000.0;
    let derived_fri_queries = calculate_num_queries(
        data.len(), &options, 1, pcs_soundness_bits as u32,
    )?;
    let fri_queries = env_usize("FRIDA_FRI_QUERIES", DEFAULT_FRI_QUERIES)?;
    let builder = FridaProverBuilder::<FridaField, FridaHash>::new(options.clone());

    let commit_and_prove_started = Instant::now();
    let (commitment, prover) = builder.commit_and_prove(&data, fri_queries)?;
    let commit_and_prove_ms = commit_and_prove_started.elapsed().as_secs_f64() * 1000.0;
    let fri_transcript_bytes = commitment.proof.to_bytes().len();

    let domain_size = commitment.domain_size;
    let reconstruction_threshold = domain_size / options.blowup_factor();
    let expected_samples = minimum_sample_count_for_epsilon(
        domain_size,
        reconstruction_threshold,
        light_clients,
        epsilon_das,
    );
    let requested_samples = std::env::var("FRIDA_DAS_SAMPLES")
        .ok()
        .map(|value| value.parse::<usize>())
        .transpose()?;
    let das_samples = requested_samples.unwrap_or(expected_samples);
    let header: ProverCommitment<FridaHash> = ProverCommitment {
        roots: commitment.roots.clone(),
        domain_size,
        poly_count: commitment.poly_count,
    };
    let commitment_root_count = header.roots.len();

    // Build verifier state and verify the FRI transcript against the commitment roots.
    let common_verify_started = Instant::now();
    let (verifier, _) =
        FridaDasVerifier::<FridaField, FridaHash, FridaHash>::new(commitment, options.clone())?;
    let common_fri_verify_ms = common_verify_started.elapsed().as_secs_f64() * 1000.0;

    let commitment_header_bytes = header.to_bytes().len();
    let commitment_delivery_bytes = commitment_header_bytes + fri_transcript_bytes;

    // Optional full-opening measurement. When enabled, it precomputes one opening
    // for every encoded position. By default, the benchmark remains request-driven
    // and produces openings only for client-requested positions.
    let precompute_all_openings = env_flag("FRIDA_PRECOMPUTE_ALL_OPENINGS");
    let full_opening_started = Instant::now();
    let full_openings = precompute_all_openings.then(|| {
        build_full_opening_material(&prover, domain_size, profile.folding_factor)
    });
    let full_opening_generation = full_opening_started.elapsed();
    let full_opening_value_bytes = full_openings
        .as_ref()
        .map(|entries| entries.len() * <FridaField as FieldElement>::ELEMENT_BYTES)
        .unwrap_or(0);
    let full_opening_proof_bytes = full_openings
        .as_ref()
        .map(|entries| entries.iter().map(|entry| entry.opening_bytes.len()).sum::<usize>())
        .unwrap_or(0);
    let full_opening_material_bytes = full_opening_value_bytes + full_opening_proof_bytes;
    let full_opening_verify_started = Instant::now();
    if let Some(entries) = &full_openings {
        for entry in entries {
            let proof = FridaProof::read_from_bytes(&entry.opening_bytes).map_err(|error| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("precomputed FRIDA opening proof failed to deserialize: {error:?}"),
                )
            })?;
            verifier.verify(&proof, &[entry.value], &[entry.position])?;
        }
    }
    let full_opening_verification = full_opening_verify_started.elapsed();


    // The client chooses the next position, sends it, waits for the response, and verifies that
    // response before choosing the next position.  The sample_set is generated
    // ahead of time only to make the run deterministic; no positions are sent
    // to the proposer ahead of their round.
    let mut challenge_rng = StdRng::from_seed(sample_seed);
    let mut challenge_generation = Duration::ZERO;
    let mut response_opening = Duration::ZERO;
    let mut opening_verification = Duration::ZERO;
    let mut total_request_bytes = 0_usize;
    let mut total_value_bytes = 0_usize;
    let mut total_opening_proof_bytes = 0_usize;
    let mut per_client_download_bytes = Vec::with_capacity(light_clients);
    let mut per_client_proof_bytes = Vec::with_capacity(light_clients);
    let mut first_sample_set_digest = None;

    for client in 0..light_clients {
        let challenge_started = Instant::now();
        let sample_set = client_sample_set(&mut challenge_rng, domain_size, das_samples);
        challenge_generation += challenge_started.elapsed();
        if client == 0 {
            first_sample_set_digest = Some(sample_set.hash_hex());
        }

        let mut client_opening_proof_bytes = 0_usize;

        for &position in sample_set.indices() {
            // One request/response round: LC -> proposer -> LC.
            let qselect_position = qselect_position(position, domain_size);
            total_request_bytes += request_bytes(&[qselect_position]);
            let evaluation = prover.get_first_layer_evaluations()
                [storage_index(qselect_position, domain_size, profile.folding_factor)];

            let open_started = Instant::now();
            let opening_proof = prover.open(&[qselect_position]);
            response_opening += open_started.elapsed();

            total_value_bytes += <FridaField as FieldElement>::ELEMENT_BYTES;
            let opening_bytes = opening_proof.to_bytes().len();
            total_opening_proof_bytes += opening_bytes;
            client_opening_proof_bytes += opening_bytes;

            let verify_started = Instant::now();
            verifier.verify(&opening_proof, &[evaluation], &[qselect_position])?;
            opening_verification += verify_started.elapsed();
        }
        per_client_download_bytes.push(
            commitment_delivery_bytes
                + das_samples * <FridaField as FieldElement>::ELEMENT_BYTES
                + client_opening_proof_bytes,
        );
        per_client_proof_bytes.push(fri_transcript_bytes + client_opening_proof_bytes);
    }

    let response_metadata_bytes = 0_usize;
    let total_response_bytes =
        total_value_bytes + response_metadata_bytes + total_opening_proof_bytes;
    let mean_request_bytes = total_request_bytes as f64 / light_clients as f64;
    let mean_value_bytes = total_value_bytes as f64 / light_clients as f64;
    let mean_opening_proof_bytes = total_opening_proof_bytes as f64 / light_clients as f64;
    let mean_response_bytes = total_response_bytes as f64 / light_clients as f64;
    let shared_commitment_network_bytes =
        commitment_delivery_bytes + total_request_bytes + total_response_bytes;
    let unicast_commitment_network_bytes =
        light_clients * commitment_delivery_bytes + total_request_bytes + total_response_bytes;
    let commitment_header_delivery_bytes = light_clients * commitment_header_bytes;
    let fri_transcript_delivery_bytes = light_clients * fri_transcript_bytes;
    let non_decodable_delivery_bytes =
        light_clients * commitment_delivery_bytes + total_opening_proof_bytes;
    let mean_non_decodable_bytes = commitment_delivery_bytes as f64 + mean_opening_proof_bytes;
    let sample_set_mean = per_client_download_bytes.iter().sum::<usize>() as f64
        / per_client_download_bytes.len() as f64;
    let sample_set_variance = per_client_download_bytes.iter().map(|&x| {
        let delta = x as f64 - sample_set_mean;
        delta * delta
    }).sum::<f64>() / (per_client_download_bytes.len().saturating_sub(1).max(1) as f64);
    let sample_set_sd = sample_set_variance.sqrt();
    let sample_set_min = *per_client_download_bytes.iter().min().unwrap();
    let sample_set_max = *per_client_download_bytes.iter().max().unwrap();
    per_client_download_bytes.sort_unstable();
    let sample_set_median = if per_client_download_bytes.len() % 2 == 0 {
        (per_client_download_bytes[per_client_download_bytes.len() / 2 - 1] as f64
            + per_client_download_bytes[per_client_download_bytes.len() / 2] as f64) / 2.0
    } else {
        per_client_download_bytes[per_client_download_bytes.len() / 2] as f64
    };

    println!("schema=frida-interactive-das-benchmark-v2");
    println!("interaction_model=one_symbol_request_response_round");
    println!("profile={}", profile.name);
    println!("logical_payload_bytes={}", data.len());
    println!("logical_symbol_count={}", input.symbol_count());
    println!("native_field=f128::BaseElement");
    println!(
        "native_field_element_bytes={}",
        <FridaField as FieldElement>::ELEMENT_BYTES
    );
    println!("padded_message_dimension={}", reconstruction_threshold);
    println!("encoded_domain_size={}", domain_size);
    println!("rate={}/{}", reconstruction_threshold, domain_size);
    println!("reconstruction_threshold={}", reconstruction_threshold);
    println!("q_min={expected_samples}");
    println!("withheld_limit={}", reconstruction_threshold - 1);
    println!("blowup={}", options.blowup_factor());
    println!("folding_factor={}", profile.folding_factor);
    println!("remainder_size={}", profile.remainder_size);
    println!("fri_queries={fri_queries}");
    println!("derived_fri_queries={derived_fri_queries}");
    println!(
        "fri_query_source={}",
        if std::env::var_os("FRIDA_FRI_QUERIES").is_some() {
            "override"
        } else {
            "paper_default"
        }
    );
    println!("light_clients={light_clients}");
    println!("sampling_failure_bits={soundness_bits}");
    println!("availability_sampling_target={epsilon_das:.12e}");
    println!("pcs_soundness_bits={pcs_soundness_bits}");
    println!("pcs_soundness_target=2^-{pcs_soundness_bits}");
    println!("availability_sampling_model=uniform_with_replacement_independent_clients");
    println!("frida_backend_kind=real_fri_merkle_protocol");
    println!("qselect_definition=QSelect(rho_1,...,rho_r,j)=j; later_queries=fold(j)");
    println!("qselect_binding=each_opening_is_verified_against_the_client_requested_j");
    println!("availability_security_definition=collective_security_with_1000_independent_lcs");
    println!("availability_formula=C(N,Delta)*(Delta/N)^(Q*L)");
    println!("sampling_claim=collective_reconstruction_not_standalone_client_security");
    println!("availability_samples_per_client={das_samples}");
    println!("calculated_samples_per_client={expected_samples}");
    println!(
        "sample_count_source={}",
        if requested_samples.is_some() {
            "override"
        } else {
            "calculated"
        }
    );
    println!(
        "challenge_seed={}",
        block_circulant_codes::benchmark_config::hex(&sample_seed)
    );
    println!(
        "first_client_sample_set_digest={}",
        first_sample_set_digest.expect("at least one light client")
    );
    println!("common_commit_and_prove_ms={commit_and_prove_ms:.3}");
    println!("rs_encode_ms={rs_encode_ms:.3}");
    println!("common_commit_preparation_ms={:.3}", (commit_and_prove_ms - rs_encode_ms).max(0.0));
    println!("common_fri_verify_ms={common_fri_verify_ms:.3}");
    println!(
        "full_opening_precomputation_mode={}",
        if precompute_all_openings {
            "enabled"
        } else {
            "disabled_request_driven_baseline"
        }
    );
    println!("full_opening_positions={}", full_openings.as_ref().map_or(0, Vec::len));
    println!(
        "full_opening_generation_ms={:.3}",
        full_opening_generation.as_secs_f64() * 1000.0
    );
    println!(
        "full_opening_verification_ms={:.3}",
        full_opening_verification.as_secs_f64() * 1000.0
    );
    println!("full_opening_value_bytes={full_opening_value_bytes}");
    println!("full_opening_proof_bytes={full_opening_proof_bytes}");
    println!("full_opening_material_bytes={full_opening_material_bytes}");
    println!(
        "full_opening_material_plus_common_bytes={}",
        full_opening_material_bytes
            + if precompute_all_openings { commitment_delivery_bytes } else { 0 }
    );
    println!(
        "proposer_total_full_precomputation_ms={:.3}",
        if precompute_all_openings {
            commit_and_prove_ms + full_opening_generation.as_secs_f64() * 1000.0
        } else {
            0.0
        }
    );
    println!(
        "challenge_generation_total_ms={:.3}",
        challenge_generation.as_secs_f64() * 1000.0
    );
    println!(
        "challenge_generation_mean_ms={:.6}",
        challenge_generation.as_secs_f64() * 1000.0 / light_clients as f64
    );
    println!(
        "proposer_response_opening_total_ms={:.3}",
        response_opening.as_secs_f64() * 1000.0
    );
    println!(
        "proposer_response_opening_mean_ms={:.6}",
        response_opening.as_secs_f64() * 1000.0 / light_clients as f64
    );
    println!(
        "lc_opening_verify_total_ms={:.3}",
        opening_verification.as_secs_f64() * 1000.0
    );
    println!(
        "lc_opening_verify_mean_ms={:.6}",
        opening_verification.as_secs_f64() * 1000.0 / light_clients as f64
    );
    println!(
        "lc_cold_verify_mean_ms={:.6}",
        common_fri_verify_ms + opening_verification.as_secs_f64() * 1000.0 / light_clients as f64
    );
    println!(
        "proposer_total_interactive_ms={:.3}",
        commit_and_prove_ms + response_opening.as_secs_f64() * 1000.0
    );
    println!("commitment_header_bytes={commitment_header_bytes}");
    println!("unique_commitment_objects=1");
    println!("unique_commitment_roots={commitment_root_count}");
    println!("commitment_object_deliveries={light_clients}");
    println!(
        "commitment_root_deliveries={}",
        commitment_root_count * light_clients
    );
    println!("commitment_header_delivery_bytes={commitment_header_delivery_bytes}");
    println!("fri_transcript_bytes={fri_transcript_bytes}");
    println!("fri_transcript_deliveries={light_clients}");
    println!("fri_transcript_delivery_bytes={fri_transcript_delivery_bytes}");
    println!("commitment_delivery_bytes={commitment_delivery_bytes}");
    println!("client_request_bytes_total={total_request_bytes}");
    println!("client_request_bytes_mean={mean_request_bytes:.3}");
    println!("interactive_rounds_total={}", light_clients * das_samples);
    println!("returned_value_bytes_total={total_value_bytes}");
    println!("returned_value_bytes_mean={mean_value_bytes:.3}");
    println!("response_metadata_bytes_total={response_metadata_bytes}");
    println!("response_metadata_note=0; positions_are_counted_in_client_requests");
    println!("opening_proof_bytes_total={total_opening_proof_bytes}");
    println!("opening_proof_bytes_mean={mean_opening_proof_bytes:.3}");
    println!("opening_proof_deliveries={}", light_clients * das_samples);
    println!("non_decodable_delivery_bytes_total={non_decodable_delivery_bytes}");
    println!("sample_set_audit_mode=one_lc_actual_response");
    println!("measured_light_clients={}", per_client_download_bytes.len());
    println!("sample_set_audit_mean_total_lc_bytes={sample_set_mean:.6}");
    println!("sample_set_audit_mean_proof_bytes={:.6}", per_client_proof_bytes.iter().sum::<usize>() as f64 / per_client_proof_bytes.len() as f64);
    println!("sample_set_audit_median_total_lc_bytes={sample_set_median:.6}");
    println!("sample_set_audit_min_total_lc_bytes={sample_set_min}");
    println!("sample_set_audit_max_total_lc_bytes={sample_set_max}");
    println!("sample_set_audit_sd_total_lc_bytes={sample_set_sd:.6}");
    println!("non_decodable_delivery_bytes_mean={mean_non_decodable_bytes:.3}");
    println!("proposer_response_bytes_total={total_response_bytes}");
    println!("proposer_response_bytes_mean={mean_response_bytes:.3}");
    println!("network_population_clients={light_clients}");
    println!("primary_network_accounting=independent_unicast");
    println!("total_network_bytes_primary={unicast_commitment_network_bytes}");
    println!("total_network_bytes_unicast_commitment={unicast_commitment_network_bytes}");
    println!("total_network_bytes_shared_commitment={shared_commitment_network_bytes}");
    println!(
        "network_inefficiency_primary={:.6}",
        unicast_commitment_network_bytes as f64 / data.len() as f64
    );
    println!("hash_function=Blake3_256");
    println!(
        "security_note=each client independently samples positions uniformly with replacement after the commitment; availability is conditional on authenticated openings, an accepted FRI transcript, coding/proximity assumptions, and honest random sampling. FRI, Merkle, Fiat-Shamir, and implementation errors are separate."
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frida_profiles_use_shared_sample_count() {
        assert_eq!(minimum_sample_count_for(65_536, 16_384, 1_000, 128), 27);
        assert_eq!(minimum_sample_count_for(32_768, 16_384, 1_000, 128), 33);
    }

    #[test]
    fn shared_sample_set_is_seeded_and_non_consecutive() {
        let a = MasterSampleSet::generate(32_768, 33, [7u8; 32]);
        let b = MasterSampleSet::generate(32_768, 33, [7u8; 32]);
        let c = MasterSampleSet::generate(32_768, 33, [8u8; 32]);
        assert_eq!(a.indices(), b.indices());
        assert_ne!(a.indices(), c.indices());
        assert!(a.indices().iter().all(|&position| position < 32_768));
        assert_ne!(a.indices(), &(0..33).collect::<Vec<_>>());
    }

    #[test]
    fn interactive_client_sample_sets_are_reproducible_and_distinct_between_clients() {
        let mut first = StdRng::from_seed([7u8; 32]);
        let mut second = StdRng::from_seed([7u8; 32]);
        let first_sample_sets = (0..3)
            .map(|_| client_sample_set(&mut first, 64, 6))
            .collect::<Vec<_>>();
        let second_sample_sets = (0..3)
            .map(|_| client_sample_set(&mut second, 64, 6))
            .collect::<Vec<_>>();

        assert_eq!(first_sample_sets, second_sample_sets);
        assert_ne!(first_sample_sets[0].indices(), first_sample_sets[1].indices());
        assert_eq!(
            request_bytes(first_sample_sets[0].indices()),
            first_sample_sets[0].indices().to_vec().to_bytes().len()
        );
    }

    #[test]
    fn folding_mapping_is_in_range() {
        for position in 0..65_536 {
            assert!(storage_index(position, 65_536, 4) < 65_536);
        }
    }

    #[test]
    fn qselect_is_the_fri_final_query_position() {
        assert_eq!(qselect_position(0, 16), 0);
        assert_eq!(qselect_position(15, 16), 15);
    }

    #[test]
    fn mapped_values_and_openings_verify() {
        let data = vec![9u8; 128];
        let options = FriOptions::new(2, 4, 2);
        let builder = FridaProverBuilder::<FridaField, FridaHash>::new(options.clone());
        let (commitment, prover) = builder.commit_and_prove(&data, 4).unwrap();
        let position = 3;
        let evaluation = prover.get_first_layer_evaluations()
            [storage_index(position, commitment.domain_size, options.folding_factor())];
        let proof = prover.open(&[position]);
        let (verifier, _) =
            FridaDasVerifier::<FridaField, FridaHash, FridaHash>::new(commitment, options).unwrap();

        assert!(verifier.verify(&proof, &[evaluation], &[position]).is_ok());
        assert!(verifier
            .verify(&proof, &[evaluation + FridaField::ONE], &[position])
            .is_err());
        assert!(verifier
            .verify(&proof, &[evaluation], &[(position + 1) % 16])
            .is_err());
    }

    #[test]
    fn sequential_single_symbol_rounds_verify_independently() {
        let data = vec![11u8; 256];
        let options = FriOptions::new(2, 4, 2);
        let builder = FridaProverBuilder::<FridaField, FridaHash>::new(options.clone());
        let (commitment, prover) = builder.commit_and_prove(&data, 4).unwrap();
        let domain_size = commitment.domain_size;
        let (verifier, _) =
            FridaDasVerifier::<FridaField, FridaHash, FridaHash>::new(commitment, options).unwrap();

        for position in [3usize, 7usize] {
            let evaluation =
                prover.get_first_layer_evaluations()[storage_index(position, domain_size, 4)];
            let proof = prover.open(&[position]);
            assert!(verifier.verify(&proof, &[evaluation], &[position]).is_ok());
        }
    }

    #[test]
    fn serialized_frida_integrity_mutations_reject() {
        let data = vec![13u8; 256];
        let options = FriOptions::new(2, 4, 2);
        let builder = FridaProverBuilder::<FridaField, FridaHash>::new(options.clone());
        let (commitment, prover) = builder.commit_and_prove(&data, 4).unwrap();
        let position = 5;
        let evaluation = prover.get_first_layer_evaluations()
            [storage_index(position, commitment.domain_size, options.folding_factor())];
        let proof = prover.open(&[position]);
        let proof_bytes = proof.to_bytes();

        fn roundtrip(bytes: &[u8]) -> FridaProof {
            let mut reader = frida_poc::winterfell::winter_utils::SliceReader::new(bytes);
            FridaProof::read_from(&mut reader).unwrap()
        }

        let roundtripped_commitment = {
            let bytes = commitment.to_bytes();
            let mut reader = frida_poc::winterfell::winter_utils::SliceReader::new(&bytes);
            frida_poc::prover::Commitment::<FridaHash>::read_from(&mut reader).unwrap()
        };
        let (verifier, _) = FridaDasVerifier::<FridaField, FridaHash, FridaHash>::new(
            roundtripped_commitment,
            options,
        )
        .unwrap();

        assert!(verifier
            .verify(&roundtrip(&proof_bytes), &[evaluation], &[position])
            .is_ok());

        let mut initial_layer_corruption = proof_bytes.clone();
        let initial_index = initial_layer_corruption.len() / 3;
        initial_layer_corruption[initial_index] ^= 1;
        let initial_result = roundtrip(&initial_layer_corruption);
        assert!(verifier
            .verify(&initial_result, &[evaluation], &[position])
            .is_err());

        let mut rejected_folded_corruption = false;
        for index in proof_bytes.len() / 2..proof_bytes.len() {
            let mut folded_layer_corruption = proof_bytes.clone();
            folded_layer_corruption[index] ^= 1;
            let folded_result = roundtrip(&folded_layer_corruption);
            if verifier
                .verify(&folded_result, &[evaluation], &[position])
                .is_err()
            {
                rejected_folded_corruption = true;
                break;
            }
        }
        assert!(rejected_folded_corruption);
    }
}
