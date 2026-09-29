#!/usr/bin/env python3
"""Generate the Section 5.3 / Table 4 BCC+WHIR-JB versus FRIDA results."""
import csv
import math
import statistics
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "results" / "table4-bcc-whir-frida"
KS = (64, 256, 1024, 4096)
MU_BY_K = {64: 32, 256: 32, 1024: 64, 4096: 64}
RUNS, ELL, EPS = 200, 1000, 1e-9

def f(row, key): return float(row[key])
def i(row, key): return int(float(row[key]))

def summary(values):
    values = list(values)
    sd = statistics.stdev(values) if len(values) > 1 else 0.0
    return {"mean": statistics.mean(values), "median": statistics.median(values), "sd": sd,
            "min": min(values), "max": max(values), "ci95": 1.96 * sd / math.sqrt(len(values))}

def ratio(a, b): return a["mean"] / b["mean"]
def ratio_ci(a, b):
    r = ratio(a, b)
    se_rel = math.sqrt((a["sd"] / math.sqrt(RUNS) / a["mean"]) ** 2 +
                       (b["sd"] / math.sqrt(RUNS) / b["mean"]) ** 2)
    return r, 1.96 * r * se_rel

def ln_binom(n, r):
    return math.lgamma(n + 1.0) - math.lgamma(r + 1.0) - math.lgamma(n - r + 1.0)

def sci(log_value):
    exponent = math.floor(log_value / math.log(10.0))
    mantissa = 10.0 ** (log_value / math.log(10.0) - exponent)
    return f"{mantissa:.6f}e{exponent:+d}"

def sampler(n, t, q):
    delta = t - 1
    log_current = ln_binom(n, delta) + ELL * q * math.log(delta / n)
    log_previous = ln_binom(n, delta) + ELL * (q - 1) * math.log(delta / n)
    assert log_current <= math.log(EPS) and (q == 1 or log_previous > math.log(EPS))
    return delta, sci(log_current), sci(log_previous)

def audit_bcc(audit_rows, k):
    row = next(r for r in audit_rows if r["scheme"] == "bcc" and i(r, "k") == k)
    assert i(row, "sample_set_audit_trials") == 10000
    return {"mean": f(row, "sample_set_audit_mean_total_lc_bytes"),
            "median": f(row, "sample_set_audit_median_total_lc_bytes"),
            "sd": f(row, "sample_set_audit_sd_total_lc_bytes"),
            "min": f(row, "sample_set_audit_min_total_lc_bytes"),
            "max": f(row, "sample_set_audit_max_total_lc_bytes"),
            "ci95": 1.96 * f(row, "sample_set_audit_sd_total_lc_bytes") / 100.0,
            "proof_mean": f(row, "sample_set_audit_mean_proof_bytes"),
            "mean_distinct_arcs": f(row, "sample_set_audit_mean_distinct_arcs")}

def audit_frida(audit_rows, k):
    audits = [r for r in audit_rows if r["scheme"] == "frida" and i(r, "k") == k]
    assert len(audits) == 10
    assert all(i(x, "measured_light_clients") == 1000 for x in audits)

    mean = statistics.mean(f(x, "sample_set_audit_mean_total_lc_bytes") for x in audits)
    variance_numerator = sum(
        999 * f(x, "sample_set_audit_sd_total_lc_bytes") ** 2
        + 1000 * (f(x, "sample_set_audit_mean_total_lc_bytes") - mean) ** 2
        for x in audits
    )
    sd = math.sqrt(variance_numerator / 9999)
    medians = {f(x, "sample_set_audit_median_total_lc_bytes") for x in audits}
    assert len(medians) == 1, "FRIDA audit medians vary; retain individual sample_set distributions"
    return {"mean": mean, "median": medians.pop(), "sd": sd,
            "min": min(f(x, "sample_set_audit_min_total_lc_bytes") for x in audits),
            "max": max(f(x, "sample_set_audit_max_total_lc_bytes") for x in audits),
            "ci95": 1.96 * sd / 100.0,
            "proof_mean": statistics.mean(f(x, "sample_set_audit_mean_proof_bytes") for x in audits)}

def main():
    with (OUT / "table4-timing-raw.csv").open(newline="") as handle:
        timing_rows = list(csv.DictReader(handle))
    with (OUT / "table4-communication-audit-raw.csv").open(newline="") as handle:
        audit_rows = list(csv.DictReader(handle))
    rows = []
    for k in KS:
        b_rows = [r for r in timing_rows if r["scheme"] == "bcc" and i(r, "k") == k and r["warmup"] == "false"]
        fr = [r for r in timing_rows if r["scheme"] == "frida" and i(r, "k") == k and r["warmup"] == "false"]
        assert len(b_rows) == len(fr) == RUNS, (k, len(b_rows), len(fr))
        b = [(row, row) for row in b_rows]
        b0, br0, fr0 = b[0][0], b[0][1], fr[0]
        mu = MU_BY_K[k]
        assert (i(b0, "k"), i(b0, "n"), i(b0, "mu"), i(b0, "omega"), i(b0, "rho")) == (k, 4*k, mu, k//mu, 3*k//mu)
        assert i(br0, "proof_transcripts") == i(b0, "q_min")
        assert i(fr0, "encoded_domain_size") == 4*k
        assert i(fr0, "q_min") > 0
        assert i(fr0, "pcs_soundness_bits") == 80
        assert i(fr0, "fri_queries") == 118
        assert fr0["fri_query_source"] == "override"
        assert fr0["availability_sampling_model"] == "uniform_with_replacement_independent_clients"

        b_encode = summary(f(x, "encode_ms") for x, _ in b)
        b_commit = summary(f(x, "commit_ms") for x, _ in b)
        b_open = summary(f(y, "opening_ms") for _, y in b)
        b_total = summary(f(x, "encode_ms") + f(x, "commit_ms") + f(y, "opening_ms") for x, y in b)
        b_verify = summary(f(y, "verify_ms") for _, y in b)
        f_encode = summary(f(x, "rs_encode_ms") for x in fr)
        f_commit = summary(f(x, "common_commit_preparation_ms") for x in fr)
        f_open = summary(f(x, "proposer_response_opening_mean_ms") for x in fr)
        f_total = summary(f(x, "rs_encode_ms") + f(x, "common_commit_preparation_ms") + f(x, "proposer_response_opening_mean_ms") for x in fr)
        f_verify = summary(f(x, "lc_cold_verify_mean_ms") for x in fr)
        b_comm, f_comm = audit_bcc(audit_rows, k), audit_frida(audit_rows, k)

        _, bnu, bprev = sampler(4*k, i(b0, "reconstruction_threshold"), i(b0, "q_min"))
        _, fnu, fprev = sampler(4*k, i(fr0, "reconstruction_threshold"), i(fr0, "q_min"))
        b_header, b_values, b_metadata = i(br0, "header_bytes"), i(br0, "values_bytes"), i(br0, "metadata_bytes")
        f_header, f_values = i(fr0, "commitment_header_bytes"), i(fr0, "returned_value_bytes_mean")
        b_proof, f_proof = b_comm["proof_mean"], f_comm["proof_mean"]
        assert abs(b_header + b_proof + b_values + b_metadata - b_comm["mean"]) < 1e-5
        assert abs(f_header + f_proof + f_values - f_comm["mean"]) < 1e-5
        pr, pr_ci = ratio(b_total, f_total), ratio_ci(b_total, f_total)[1]
        vr, vr_ci = ratio(b_verify, f_verify), ratio_ci(b_verify, f_verify)[1]
        cr, cr_ci = ratio(b_comm, f_comm), ratio_ci(b_comm, f_comm)[1]
        row = {
            "k": k, "n": 4*k, "mu": mu, "omega": i(b0,"omega"), "rho": i(b0,"rho"), "k0": i(b0,"k0"), "n0": i(b0,"n0"), "distance_d": i(b0,"distance"),
            "bcc_t": i(b0,"reconstruction_threshold"), "frida_t": i(fr0,"reconstruction_threshold"), "bcc_Q_min": i(b0,"q_min"), "frida_Q_min": i(fr0,"q_min"), "frida_Q_FRI": i(fr0,"fri_queries"),
            "bcc_local_rate": b0["local_rate"], "global_rate": "1/4", "whir_domain_size": i(b0,"whir_local_domain_size"), "bcc_field": b0["field"], "bcc_field_element_bytes": 16,
            "frida_field": fr0["native_field"], "frida_field_element_bytes": i(fr0,"native_field_element_bytes"),
            "mean_distinct_arcs": b_comm["mean_distinct_arcs"], "bcc_proof_transcripts": i(br0,"proof_transcripts"),
        }
        for prefix, data in (("bcc_encode",b_encode),("bcc_commit",b_commit),("bcc_open",b_open),("bcc_prover",b_total),("bcc_verify",b_verify),("frida_encode",f_encode),("frida_commit",f_commit),("frida_open",f_open),("frida_prover",f_total),("frida_verify",f_verify),("bcc_comm",b_comm),("frida_comm",f_comm)):
            for stat in ("mean","median","sd","min","max","ci95"):
                row[f"{prefix}_{stat}"] = data[stat]
        row.update({"bcc_header_bytes":b_header,"bcc_proof_bytes":b_proof,"bcc_values_bytes":b_values,"bcc_metadata_bytes":b_metadata,
                    "frida_header_bytes":f_header,"frida_proof_bytes":f_proof,"frida_values_bytes":f_values,"frida_metadata_bytes":0,
                    "bcc_network_bytes_1000":b_comm["mean"]*1000,"frida_network_bytes_1000":f_comm["mean"]*1000,
                    "prover_ratio_whir_frida":pr,"prover_ratio_ci95":pr_ci,"verify_ratio_whir_frida":vr,"verify_ratio_ci95":vr_ci,"comm_ratio_whir_frida":cr,"comm_ratio_ci95":cr_ci,
                    "network_ratio_whir_frida":cr,"bcc_nu_Q":bnu,"bcc_nu_Q_minus_1":bprev,"frida_nu_Q":fnu,"frida_nu_Q_minus_1":fprev})
        rows.append(row)

    fieldnames = list(rows[0])
    with (OUT / "table4-bcc-whir-frida.csv").open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames); writer.writeheader(); writer.writerows(rows)

if __name__ == "__main__": main()
