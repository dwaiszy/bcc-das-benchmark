#!/usr/bin/env python3
"""Run the Section 5.2 / Table 3 BCC versus 2D-RS KZG comparison."""

import csv
import json
import math
import os
import statistics
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "results/table3-bcc-rs2d-kzg"
INPUT_SEED = "00" * 31 + "01"
SAMPLE_SEED = "00" * 31 + "02"
N = 16_384
ELL = 1_000
EPSILON = 1e-9
MEASURED = 30
WARMUPS = 10


def log_binomial(n, k):
    k = min(k, n - k)
    return sum(math.log(n - k + i) - math.log(i) for i in range(1, k + 1))


def sampler_log_nu(delta, q):
    return log_binomial(N, delta) + q * ELL * math.log(delta / N)


def stats(values):
    values = [float(v) for v in values]
    mean = statistics.mean(values)
    stdev = statistics.stdev(values) if len(values) > 1 else 0.0
    half = 2.045 * stdev / math.sqrt(len(values))  # t_0.975,29
    return {
        "mean": mean, "median": statistics.median(values), "stdev": stdev,
        "min": min(values), "max": max(values),
        "ci95_low": mean - half, "ci95_high": mean + half,
    }


def run_benchmark():
    OUT.mkdir(parents=True, exist_ok=True)
    env = {
        **os.environ,
        "DAS_BENCH_ONLY": "bcc-kzg,rs2d-kzg",
        "DAS_BENCH_OMEGA": "1024",
        "DAS_BENCH_MU": "4",
        "DAS_BENCH_RUNS": str(MEASURED),
        "DAS_BENCH_WARMUPS": str(WARMUPS),
        "DAS_PROPOSER_THREADS": "1",
        "DAS_BENCH_LIGHT_CLIENTS": "1000",
        "DAS_BENCH_FAILURE_PROBABILITY": "1e-9",
        "DAS_BENCH_SAMPLING": "with_replacement",
        "DAS_BENCH_INPUT_SEED": INPUT_SEED,
        "DAS_BENCH_SAMPLE_SEED": SAMPLE_SEED,
    }
    command = ["target/release/examples/das_benchmark"]
    result = subprocess.run(command, cwd=ROOT, env=env, text=True,
                            capture_output=True, check=True)
    rows = [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]
    fields = list(rows[0])
    with (OUT / "table3-raw.csv").open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader(); writer.writerows(rows)
    return rows


def make_report(rows):
    by_scheme = {scheme: [r for r in rows if r["scheme"] == scheme]
                 for scheme in ("bcc-kzg", "rs2d-kzg")}
    names = {"bcc-kzg": "BCC+KZG", "rs2d-kzg": "2D-RS+KZG"}
    delta = {"bcc-kzg": int(by_scheme["bcc-kzg"][0]["withheld_limit"]),
             "rs2d-kzg": int(by_scheme["rs2d-kzg"][0]["withheld_limit"])}
    q = {s: int(by_scheme[s][0]["q_min"]) for s in by_scheme}
    sampler = {}
    for s in by_scheme:
        sampler[s] = {
            "N": N, "t": int(by_scheme[s][0]["reception_threshold"]),
            "Delta": delta[s], "Q_min": q[s],
            "log10_nu_q": sampler_log_nu(delta[s], q[s]) / math.log(10),
            "log10_nu_q_minus_1": sampler_log_nu(delta[s], q[s] - 1) / math.log(10)
            if q[s] > 1 else None,
        }
        assert sampler_log_nu(delta[s], q[s]) <= math.log(EPSILON) + 1e-9
        if q[s] > 1:
            assert sampler_log_nu(delta[s], q[s] - 1) > math.log(EPSILON) - 1e-9
    timing = {}
    comm = {}
    for s, values in by_scheme.items():
        timing[s] = {field: stats([r[field] for r in values])
                     for field in ("encode_ms", "commit_ms", "open_ms", "proposer_ms", "verify_ms")}
        constant_fields = {field: sorted({int(r[field]) for r in values})
                           for field in ("sample_data_bytes", "sample_metadata_bytes",
                                         "verify_proof_bytes", "header_bytes",
                                         "light_client_download_bytes", "commitment_count")}
        comm[s] = constant_fields

    # The protocol profile digest is 32 bytes; commitment bytes are the
    # serialized KZG commitment list, while header_bytes includes that digest.
    csv_rows = []
    for s in ("bcc-kzg", "rs2d-kzg"):
        r0 = by_scheme[s][0]
        csv_rows.append({
            "scheme": names[s], "k": r0["k"], "n": r0["n"], "rate": "1/4",
            "mu": r0["mu"], "omega": r0["omega"], "rho": r0["rho"],
            "k0": r0["local_k"], "n0": r0["local_n"],
            "distance": 2 * int(r0["rho"]) + 1 if s == "bcc-kzg" else int(r0["n"]) - int(r0["reception_threshold"]) + 1,
            "reception_threshold": r0["reception_threshold"], "Q_min": r0["q_min"],
            "log10_nu_Q": sampler[s]["log10_nu_q"],
            "log10_nu_Q_minus_1": sampler[s]["log10_nu_q_minus_1"],
            "num_commitments": r0["commitment_count"],
            "persistent_commitment_bytes": int(r0["header_bytes"]) - 32,
            "persistent_header_bytes": r0["header_bytes"],
            "sampled_symbol_bytes": r0["sample_data_bytes"],
            "proof_bytes": r0["verify_proof_bytes"],
            "metadata_bytes": r0["sample_metadata_bytes"],
            "total_client_download_bytes": r0["light_client_download_bytes"],
            "encode_ms_mean": timing[s]["encode_ms"]["mean"],
            "commit_ms_mean": timing[s]["commit_ms"]["mean"],
            "open_ms_mean": timing[s]["open_ms"]["mean"],
            "proposer_ms_mean": timing[s]["proposer_ms"]["mean"],
            "verify_ms_mean": timing[s]["verify_ms"]["mean"],
        })
    fields = list(csv_rows[0])
    with (OUT / "table3-bcc-rs2d-kzg.csv").open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields); writer.writeheader(); writer.writerows(csv_rows)

    # Raw per-run timing CSV for reproducibility and confidence-interval audit.
    with (OUT / "table3-timing-raw.csv").open("w", newline="") as f:
        fields = ["scheme", "run", "encode_ms", "commit_ms", "open_ms", "proposer_ms", "verify_ms"]
        writer = csv.DictWriter(f, fieldnames=fields); writer.writeheader()
        for s, vals in by_scheme.items():
            for run_index, row in enumerate(vals, 1):
                writer.writerow({"scheme": names[s], "run": run_index, **{field: row[field] for field in fields[2:]}})

    with (OUT / "table3-timing-statistics.csv").open("w", newline="") as f:
        fields = ["scheme", "metric", "mean_ms", "median_ms", "stdev_ms", "min_ms", "max_ms", "ci95_low_ms", "ci95_high_ms"]
        writer = csv.DictWriter(f, fieldnames=fields); writer.writeheader()
        for s in ("bcc-kzg", "rs2d-kzg"):
            for metric in ("encode_ms", "commit_ms", "open_ms", "proposer_ms", "verify_ms"):
                x = timing[s][metric]
                writer.writerow({"scheme": names[s], "metric": metric, **{
                    "mean_ms": x["mean"], "median_ms": x["median"], "stdev_ms": x["stdev"],
                    "min_ms": x["min"], "max_ms": x["max"], "ci95_low_ms": x["ci95_low"],
                    "ci95_high_ms": x["ci95_high"]}})

    print((OUT / "table3-bcc-rs2d-kzg.csv").read_text(), end="")


if __name__ == "__main__":
    make_report(run_benchmark())
