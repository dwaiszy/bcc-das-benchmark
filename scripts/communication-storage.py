#!/usr/bin/env python3
"""Run and summarize the Section 5.4 communication and storage comparison."""

import argparse
import csv
import json
import os
import statistics
import subprocess
from pathlib import Path


KS = [16, 64, 256, 1024, 4096]
SEED_INPUT = "00" * 31 + "01"
SEED_SAMPLE = "00" * 31 + "02"


def env_base(args):
    return {
        **os.environ,
        "DAS_PROPOSER_THREADS": str(args.threads),
        "DAS_BENCH_LIGHT_CLIENTS": "1000",
        "DAS_BENCH_FAILURE_PROBABILITY": "1e-9",
        "DAS_BENCH_SAMPLING": "with_replacement",
        "DAS_BENCH_INPUT_SEED": SEED_INPUT,
        "DAS_BENCH_SAMPLE_SEED": SEED_SAMPLE,
        "DAS_BENCH_PCS_SOUNDNESS_BITS": "80",
        "DAS_BENCH_WARMUPS": "0",
        "DAS_BENCH_RUNS": "1",
    }


def run(cmd, env):
    result = subprocess.run(cmd, cwd=Path(__file__).resolve().parents[1], env=env,
                            text=True, capture_output=True, check=True)
    return result.stdout


def write_csv(path, rows):
    fields = []
    for row in rows:
        for key in row:
            if key not in fields:
                fields.append(key)
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def summarize(values):
    return statistics.median(values), min(values), max(values)


def main():
    global KS
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=10)
    ap.add_argument("--threads", type=int, default=1)
    ap.add_argument("--output-dir", default="results/table5-communication-storage")
    ap.add_argument(
        "--ks",
        default=",".join(map(str, KS)),
        help="comma-separated subset of supported dimensions (default: full scaling set)",
    )
    ap.add_argument("--aggregate-only", action="store_true")
    args = ap.parse_args()
    try:
        KS = [int(k.strip()) for k in args.ks.split(",") if k.strip()]
    except ValueError as error:
        raise SystemExit(f"--ks must contain integers: {error}")
    if not KS or any(k not in {16, 64, 256, 1024, 4096} for k in KS):
        raise SystemExit("--ks must be a non-empty subset of 16,64,256,1024,4096")
    root = Path(__file__).resolve().parents[1]
    out = root / args.output_dir
    out.mkdir(parents=True, exist_ok=True)
    proposer_raw = []
    lc_raw = []
    frida_raw = []
    run_indices = range(1, args.runs + 1)
    if not args.aggregate_only:
      for run_index in run_indices:
        for k in KS:
            omega = k // 4
            env = env_base(args)
            env.update({"DAS_BENCH_ONLY": "bcc-kzg,rs2d-kzg,bcc-whir",
                        "DAS_BENCH_OMEGA": str(omega)})
            stdout = run(["target/release/examples/das_benchmark"], env)
            for line in stdout.splitlines():
                if line.startswith("{"):
                    row = json.loads(line)
                    if row.get("scheme") in {"bcc-kzg", "rs2d-kzg", "bcc-whir"}:
                        proposer_raw.append(row)
                        lc_raw.append(row)
            # FRIDA's native FRI implementation rejects 118 queries on n=64.
            fri_queries = "32" if k == 16 else "118"
            fenv = env_base(args)
            fenv.update({"DAS_BENCH_LOGICAL_SYMBOLS": str(k),
                        "FRIDA_FRI_QUERIES": fri_queries,
                        "FRIDA_PCS_SOUNDNESS_BITS": "80"})
            fstdout = run(["target/release/examples/frida_benchmark"], fenv)
            vals = {}
            for line in fstdout.splitlines():
                if "=" in line:
                    key, value = line.split("=", 1)
                    vals[key] = value
            vals["k"] = k
            vals["run"] = run_index
            frida_raw.append(vals)
            print(f"completed run={run_index}/{args.runs} k={k}", flush=True)
      write_csv(out / "table5-generic-raw.csv", proposer_raw)
      write_csv(out / "table5-frida-raw.csv", frida_raw)
    else:
      with (out / "table5-generic-raw.csv").open(newline="") as handle:
        proposer_raw = list(csv.DictReader(handle))
      for row in proposer_raw:
        row["k"] = int(row["k"])
      lc_raw = proposer_raw.copy()
      with (out / "table5-frida-raw.csv").open(newline="") as handle:
        frida_raw = list(csv.DictReader(handle))
      for row in frida_raw:
        row["k"] = int(row["k"])
        row["run"] = int(row["run"])

    schemes = {"bcc-kzg": "BCC+KZG", "rs2d-kzg": "RS2D+KZG",
               "bcc-whir": "BCC+WHIR-JB", "frida": "FRIDA"}
    proposer_rows = []
    for scheme in schemes:
        for k in KS:
            rows = ([r for r in proposer_raw if r["scheme"] == scheme and r["k"] == k]
                    if scheme != "frida" else [r for r in frida_raw if r["k"] == k])
            if scheme == "frida":
                assert all(int(r["encoded_domain_size"]) == 4 * k for r in rows)
                assert all(int(r["pcs_soundness_bits"]) == 80 for r in rows)
                assert all(int(r["fri_queries"]) == (32 if k == 16 else 118) for r in rows)
                assert all(r["fri_query_source"] == "override" for r in rows)
                assert all(r["availability_sampling_model"] == "uniform_with_replacement_independent_clients" for r in rows)
                metrics = {
                    "encode_ms": [0.0 for _ in rows],
                    "commit_ms": [float(r["common_commit_and_prove_ms"]) for r in rows],
                    "open_ms": [float(r["proposer_response_opening_total_ms"]) for r in rows],
                    "proposer_total_ms": [float(r["proposer_total_interactive_ms"]) for r in rows],
                }
                n = int(rows[0]["encoded_domain_size"])
                q = int(rows[0]["q_min"])
                rate = "1/4"
            else:
                assert all(int(r["n"]) == 4 * k for r in rows)
                assert all(r["sampling_model"] == "uniform_with_replacement" for r in rows)
                assert all(int(r["sampling_light_clients"]) == 1000 for r in rows)
                assert all(int(r["sampling_failure_bits"]) == 30 for r in rows)
                metrics = {"encode_ms": [float(r["encode_ms"]) for r in rows],
                           "commit_ms": [float(r["commit_ms"]) for r in rows],
                           "open_ms": [float(r["open_ms"]) for r in rows],
                           "proposer_total_ms": [float(r["proposer_ms"]) for r in rows]}
                n = int(rows[0]["n"])
                q = int(rows[0]["q_min"])
                rate = "1/4"
            row = {"scheme": schemes[scheme], "k": k, "n": n, "rate": rate, "Q_min": q}
            for metric, values in metrics.items():
                med, low, high = summarize(values)
                row[metric] = med
                if metric == "proposer_total_ms":
                    row["median_total_ms"], row["min_total_ms"], row["max_total_ms"] = med, low, high
            proposer_rows.append(row)

    proposer_fields = ["scheme", "k", "n", "rate", "Q_min", "encode_ms", "commit_ms",
                       "open_ms", "proposer_total_ms", "median_total_ms", "min_total_ms", "max_total_ms"]
    with (out / "table5-proposer-measurements.csv").open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=proposer_fields)
        writer.writeheader(); writer.writerows(proposer_rows)

    lc_rows = []
    for scheme in schemes:
        for k in KS:
            if scheme == "frida":
                rows = [r for r in frida_raw if r["k"] == k]
                def nums(key): return [float(r[key]) for r in rows]
                def ints(key): return [int(r[key]) for r in rows]
                fields = {
                    "Q_min": ints("q_min"), "verify_ms": nums("lc_cold_verify_mean_ms"),
                    "challenge_generation_ms": nums("challenge_generation_mean_ms"),
                    "sample_symbol_bytes": nums("returned_value_bytes_mean"),
                    "proof_bytes": nums("opening_proof_bytes_mean"),
                    "persistent_commitment_bytes": nums("commitment_header_bytes"),
                    "persistent_header_bytes": nums("commitment_header_bytes"),
                    "fri_transcript_bytes": nums("fri_transcript_bytes"),
                    "client_response_bytes": nums("proposer_response_bytes_mean"),
                    "client_request_bytes": nums("client_request_bytes_mean"),
                    "total_client_download_bytes": [float(r["commitment_delivery_bytes"]) + float(r["proposer_response_bytes_mean"]) for r in rows],
                    "total_client_communication_bytes": [float(r["commitment_delivery_bytes"]) + float(r["proposer_response_bytes_mean"]) + float(r["client_request_bytes_mean"]) for r in rows],
                }
                n = int(rows[0]["encoded_domain_size"])
            else:
                rows = [r for r in lc_raw if r["scheme"] == scheme and r["k"] == k]
                fields = {
                    "Q_min": [int(r["q_min"]) for r in rows],
                    "verify_ms": [float(r["verify_ms"]) for r in rows],
                    "challenge_generation_ms": [float(r["lc_challenge_generation_mean_ms"]) for r in rows],
                    "sample_symbol_bytes": [float(r["sample_data_bytes"]) for r in rows],
                    "proof_bytes": [float(r["verify_proof_bytes"]) for r in rows],
                    "persistent_commitment_bytes": [float(r["header_bytes"]) - 32 for r in rows],
                    "persistent_header_bytes": [float(r["header_bytes"]) for r in rows],
                    "fri_transcript_bytes": [0.0 for _ in rows],
                    "client_response_bytes": [float(r["sample_data_bytes"]) + float(r["sample_metadata_bytes"]) + float(r["verify_proof_bytes"]) for r in rows],
                    "client_request_bytes": [float(r["client_request_bytes"]) for r in rows],
                    "total_client_download_bytes": [float(r["light_client_download_bytes"]) for r in rows],
                    "total_client_communication_bytes": [float(r["total_client_communication_bytes"]) for r in rows],
                }
                n = int(rows[0]["n"])
            row = {"scheme": schemes[scheme], "k": k, "n": n}
            for field, values in fields.items():
                median = statistics.median(values)
                row[field] = median
                if field in {"verify_ms", "challenge_generation_ms"}:
                    prefix = "verify" if field == "verify_ms" else "challenge_generation"
                    row[f"median_{prefix}_ms"] = median
                    row[f"min_{prefix}_ms"] = min(values)
                    row[f"max_{prefix}_ms"] = max(values)
            lc_rows.append(row)
    lc_fields = ["scheme", "k", "n", "Q_min", "verify_ms", "median_verify_ms",
                 "min_verify_ms", "max_verify_ms", "sample_symbol_bytes",
                 "challenge_generation_ms", "median_challenge_generation_ms",
                 "min_challenge_generation_ms", "max_challenge_generation_ms",
                 "proof_bytes", "persistent_commitment_bytes", "fri_transcript_bytes",
                 "persistent_header_bytes", "client_response_bytes", "client_request_bytes",
                 "total_client_download_bytes", "total_client_communication_bytes"]
    with (out / "table5-client-measurements.csv").open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=lc_fields)
        writer.writeheader(); writer.writerows(lc_rows)

    parameter_rows = []
    for k in KS:
        generic = next(r for r in proposer_raw if r["k"] == k and r["scheme"] == "bcc-kzg")
        rs = next(r for r in proposer_raw if r["k"] == k and r["scheme"] == "rs2d-kzg")
        omega = int(generic["omega"]); n = int(generic["n"]); rho = int(generic["rho"])
        parameter_rows.append({"scheme": "BCC", "k": k, "n": n, "mu": int(generic["mu"]),
                              "theta": 2, "omega": omega, "rho": rho,
                              "k0": int(generic["local_k"]), "n0": int(generic["local_n"]),
                              "minimum_distance": 2 * rho + 1,
                              "reception_threshold": int(generic["reception_threshold"]),
                              "Q_min": int(generic["q_min"]),
                              "number_of_commitments": int(generic["commitment_count"]),
                              "serialized_commitment_bytes": int(generic["header_bytes"]) - 32,
                              "serialized_header_bytes": int(generic["header_bytes"])})
        rs_k0 = int(rs["local_k"]); rs_n0 = int(rs["local_n"])
        parameter_rows.append({"scheme": "RS2D", "k": k, "n": n, "mu": "", "theta": "",
                              "omega": "", "rho": "", "k0": rs_k0, "n0": rs_n0,
                              "minimum_distance": (rs_n0 - rs_k0 + 1) ** 2,
                              "reception_threshold": int(rs["reception_threshold"]),
                              "Q_min": int(rs["q_min"]),
                              "number_of_commitments": int(rs["commitment_count"]),
                              "serialized_commitment_bytes": int(rs["header_bytes"]) - 32,
                              "serialized_header_bytes": int(rs["header_bytes"])})
    parameter_fields = ["scheme", "k", "n", "mu", "theta", "omega", "rho", "k0", "n0",
                        "minimum_distance", "reception_threshold", "Q_min",
                        "number_of_commitments", "serialized_commitment_bytes",
                        "serialized_header_bytes"]
    with (out / "table5-parameters.csv").open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=parameter_fields)
        writer.writeheader(); writer.writerows(parameter_rows)

    # One paper-facing row per scheme and k, combining the proposer, LC, and
    # coding-layer measurements.  FRIDA's one commitment object and roots are
    # kept distinct from its FRI transcript.
    combined_rows = []
    for scheme_name in schemes.values():
        for k in KS:
            pr = next(r for r in proposer_rows if r["scheme"] == scheme_name and r["k"] == k)
            lr = next(r for r in lc_rows if r["scheme"] == scheme_name and r["k"] == k)
            if scheme_name in {"BCC+KZG", "BCC+WHIR-JB"}:
                par = next(r for r in parameter_rows if r["scheme"] == "BCC" and int(r["k"]) == k)
            elif scheme_name == "RS2D+KZG":
                par = next(r for r in parameter_rows if r["scheme"] == "RS2D" and int(r["k"]) == k)
            else:
                par = {field: "" for field in parameter_fields}
            combined_rows.append({
                "scheme": scheme_name, "k": k, "n": pr["n"], "rate": pr["rate"],
                "mu": par["mu"], "omega": par["omega"], "rho": par["rho"],
                "k0": par["k0"], "n0": par["n0"],
                "distance": par["minimum_distance"], "reception_threshold": par["reception_threshold"],
                "Q_min": lr["Q_min"],
                "num_commitments": par["number_of_commitments"] if scheme_name != "FRIDA" else 1,
                "persistent_commitment_bytes": lr["persistent_commitment_bytes"],
                "persistent_header_bytes": lr["persistent_header_bytes"],
                "sampled_symbol_bytes": lr["sample_symbol_bytes"], "proof_bytes": lr["proof_bytes"],
                "fri_transcript_bytes": lr["fri_transcript_bytes"],
                "client_request_bytes": lr["client_request_bytes"],
                "total_client_download_bytes": lr["total_client_download_bytes"],
                "total_client_communication_bytes": lr["total_client_communication_bytes"],
                "encode_ms": pr["encode_ms"], "commit_ms": pr["commit_ms"],
                "open_ms": pr["open_ms"], "proposer_total_ms": pr["proposer_total_ms"],
                "verify_ms": lr["verify_ms"],
            })
    combined_fields = ["scheme", "k", "n", "rate", "mu", "omega", "rho", "k0", "n0",
                       "distance", "reception_threshold", "Q_min", "num_commitments",
                       "persistent_commitment_bytes", "sampled_symbol_bytes", "proof_bytes",
                       "fri_transcript_bytes", "persistent_header_bytes", "client_request_bytes",
                       "total_client_download_bytes", "total_client_communication_bytes", "encode_ms",
                       "commit_ms", "open_ms", "proposer_total_ms", "verify_ms"]
    with (out / "table5-comparison-details.csv").open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=combined_fields)
        writer.writeheader(); writer.writerows(combined_rows)

    # Output a CSV file with the same columns as Table 5 in the paper, but only for k=4096.
    if 4096 in KS:
        table5_rows = []
        for row in (r for r in combined_rows if r["k"] == 4096):
            field_bytes = 16 if row["scheme"] in {"BCC+WHIR-JB", "FRIDA"} else 32
            encoded_data_bytes = int(row["n"]) * field_bytes
            table5_rows.append({
                "scheme": row["scheme"],
                "commitment_header_bytes": row["persistent_header_bytes"],
                "commitment_header_kib": row["persistent_header_bytes"] / 1024.0,
                "encoded_data_bytes": encoded_data_bytes,
                "encoded_data_kib": encoded_data_bytes / 1024.0,
                "samples_per_client": row["Q_min"],
                "request_bytes": row["client_request_bytes"],
                "download_bytes": row["total_client_download_bytes"],
                "total_per_node_communication_bytes": row["total_client_download_bytes"],
                "total_per_node_communication_kib": row["total_client_download_bytes"] / 1024.0,
            })
        table5_fields = list(table5_rows[0])
        with (out / "table5.csv").open("w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=table5_fields)
            writer.writeheader(); writer.writerows(table5_rows)
    configuration_rows = [
        {"parameter": "light_clients", "value": 1000},
        {"parameter": "das_failure_target", "value": "1e-9"},
        {"parameter": "pcs_target", "value": "2^-80 for WHIR and FRIDA; native BLS12-381 profile for KZG"},
        {"parameter": "fri_queries", "value": "118; 32 only at k=16"},
        {"parameter": "sampling", "value": "uniform with replacement; independently seeded per client"},
        {"parameter": "proposer_threads", "value": args.threads},
        {"parameter": "runs", "value": args.runs},
        {"parameter": "input_seed", "value": SEED_INPUT},
        {"parameter": "sample_seed", "value": SEED_SAMPLE},
        {"parameter": "setup_timing", "value": "excluded"},
    ]
    write_csv(out / "table5-configuration.csv", configuration_rows)


if __name__ == "__main__":
    main()
