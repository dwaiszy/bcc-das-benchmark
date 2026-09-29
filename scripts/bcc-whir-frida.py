#!/usr/bin/env python3
"""Run the Section 5.3 / Table 4 BCC+WHIR-JB versus FRIDA benchmark."""
import os
import csv
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "results" / "table4-bcc-whir-frida"
KS = (64, 256, 1024, 4096)
MU_BY_K = {64: 32, 256: 32, 1024: 64, 4096: 64}
WARMUPS = 10
MEASURED_PER_SCHEME = 200
INPUT_SEED = "0" * 63 + "1"
SAMPLE_SEED = "0" * 63 + "2"

COMMON = {
    "DAS_BENCH_LIGHT_CLIENTS": "1000",
    "DAS_BENCH_FAILURE_PROBABILITY": "1e-9",
    "DAS_PROPOSER_THREADS": "1",
    "DAS_BENCH_INPUT_SEED": INPUT_SEED,
    "DAS_BENCH_SAMPLE_SEED": SAMPLE_SEED,
    "DAS_BENCH_PCS_SOUNDNESS_BITS": "80",
}

def with_env(extra):
    env = os.environ.copy()
    env.update(COMMON)
    env.update(extra)
    return env

def parse_output(output):
    row = {}
    for line in output.splitlines():
        if line.startswith("scalar_opening "):
            for token in line.split()[1:]:
                key, value = token.split("=", 1)
                row[key] = value
        elif "=" in line:
            key, value = line.split("=", 1)
            row[key] = value
    return row


def run(command, env):
    result = subprocess.run(command, cwd=ROOT, env=env, text=True,
                            capture_output=True, check=True)
    return parse_output(result.stdout)


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

def seed_for(index):
    return f"{index:064x}"

def main():
    assert MEASURED_PER_SCHEME % 2 == 0
    bcc = ROOT / "target" / "release" / "examples" / "bcc_whir_jb_scalar_opening"
    frida = ROOT / "target" / "release" / "examples" / "frida_benchmark"
    OUT.mkdir(parents=True, exist_ok=True)
    timing_rows = []
    audit_rows = []
    plan = []
    for k in KS:
        for _ in range(WARMUPS):
            plan += [(k, "bcc", True), (k, "frida", True)]
        for cycle in range(MEASURED_PER_SCHEME // 2):
            order = ("bcc", "frida", "frida", "bcc") if cycle % 2 == 0 else ("frida", "bcc", "bcc", "frida")
            plan += [(k, scheme, False) for scheme in order]

    counts = {(k, scheme): 0 for k in KS for scheme in ("bcc", "frida")}
    for sequence, (k, scheme, warmup) in enumerate(plan, start=1):
        if scheme == "bcc":
            env = with_env({"DAS_BENCH_K": str(k), "DAS_BENCH_N": str(4 * k),
                            "DAS_BENCH_MU": str(MU_BY_K[k]),
                            "DAS_BENCH_SCALAR_ONLY": "1"})
            row = run([str(bcc)], env)
        else:
            env = with_env({"DAS_BENCH_LOGICAL_SYMBOLS": str(k),
                            "FRIDA_PROFILE": "frida-matched-rate",
                            "FRIDA_PCS_SOUNDNESS_BITS": "80",
                            "FRIDA_FRI_QUERIES": "118"})
            row = run([str(frida)], env)
        timing_rows.append({"record_type": "timing", "scheme": scheme, "k": k,
                            "warmup": str(warmup).lower(), "sequence": sequence, **row})
        if not warmup:
            counts[(k, scheme)] += 1
        if sequence % 40 == 0:
            complete = ", ".join(f"k{k}:{counts[(k,'bcc')]}/{counts[(k,'frida')]}" for k in KS)
            print(f"completed={sequence}/{len(plan)} {complete}", flush=True)

    # Independent serialized-response sample_set audits. BCC runs 10,000
    # distinct deterministic sample_sets in one process. FRIDA runs ten
    # distinct 1,000-client sample_sets, changing only the deterministic seed.
    for k in KS:
        row = run([str(bcc)], with_env({"DAS_BENCH_K": str(k), "DAS_BENCH_N": str(4 * k),
                                        "DAS_BENCH_MU": str(MU_BY_K[k]),
                                        "DAS_BENCH_SCALAR_ONLY": "1",
                                        "DAS_BENCH_SAMPLE_SET_TRIALS": "10000"}))
        audit_rows.append({"record_type": "communication_audit", "scheme": "bcc",
                           "k": k, "audit": 1, **row})
        for audit in range(10):
            row = run([str(frida)], with_env({"DAS_BENCH_LOGICAL_SYMBOLS": str(k),
                                              "FRIDA_PROFILE": "frida-matched-rate",
                                              "FRIDA_PCS_SOUNDNESS_BITS": "80",
                                              "FRIDA_FRI_QUERIES": "118",
                                              "DAS_BENCH_SAMPLE_SEED": seed_for(audit + 100)}))
            audit_rows.append({"record_type": "communication_audit", "scheme": "frida",
                               "k": k, "audit": audit + 1, **row})

    write_csv(OUT / "table4-timing-raw.csv", timing_rows)
    write_csv(OUT / "table4-communication-audit-raw.csv", audit_rows)

if __name__ == "__main__":
    main()
