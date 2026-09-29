#!/usr/bin/env python3
"""Scalar BCC+WHIR-JB comparison for mu=32 and mu=64."""
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "results" / "whir_scalar_mu32_vs_mu64"
RAW = OUT / "raw"
RAW.mkdir(parents=True, exist_ok=True)
KS = (64, 256, 1024, 4096)
MUS = (32, 64)
WARMUPS = 10
RUNS = 200
INPUT_SEED = "0" * 63 + "1"
SAMPLE_SEED = "0" * 63 + "2"

COMMON = {
    "DAS_BENCH_LIGHT_CLIENTS": "1000",
    "DAS_BENCH_FAILURE_PROBABILITY": "1e-9",
    "DAS_PROPOSER_THREADS": "1",
    "DAS_BENCH_INPUT_SEED": INPUT_SEED,
    "DAS_BENCH_SAMPLE_SEED": SAMPLE_SEED,
    "DAS_BENCH_PCS_SOUNDNESS_BITS": "80",
    "DAS_BENCH_SCALAR_ONLY": "1",
}

def env_for(extra):
    env = os.environ.copy(); env.update(COMMON); env.update(extra); return env

def run(binary, env, path):
    with path.open("w") as handle:
        subprocess.run([str(binary)], cwd=ROOT, env=env, stdout=handle,
                       stderr=subprocess.STDOUT, check=True)

def main():
    binary = ROOT / "target" / "release" / "examples" / "bcc_whir_jb_scalar_opening"
    plan = []
    for k in KS:
        for _ in range(WARMUPS):
            plan += [(k, 32, True), (k, 64, True)]
        for cycle in range(RUNS // 2):
            order = (32, 64, 64, 32) if cycle % 2 == 0 else (64, 32, 32, 64)
            plan += [(k, mu, False) for mu in order]

    counts = {(k, mu): 0 for k in KS for mu in MUS}
    for seq, (k, mu, warmup) in enumerate(plan, start=1):
        suffix = "warmup" if warmup else "measured"
        path = RAW / f"bcc_mu{mu}_k{k}_{suffix}_{seq:05d}.txt"
        run(binary, env_for({"DAS_BENCH_K": str(k), "DAS_BENCH_N": str(4*k), "DAS_BENCH_MU": str(mu)}), path)
        if not warmup: counts[(k, mu)] += 1
        if seq % 40 == 0:
            progress = ", ".join(f"k{k}:mu{mu}={counts[(k,mu)]}" for k in KS for mu in MUS)
            print(f"completed={seq}/{len(plan)} {progress}", flush=True)

    for k in KS:
        for mu in MUS:
            path = RAW / f"bcc_mu{mu}_k{k}_sample_set_audit.txt"
            run(binary, env_for({"DAS_BENCH_K": str(k), "DAS_BENCH_N": str(4*k),
                                 "DAS_BENCH_MU": str(mu), "DAS_BENCH_SAMPLE_SET_TRIALS": "10000"}), path)

    (OUT / "reproduction_commands.txt").write_text(
        "cargo build --release --example bcc_whir_jb_scalar_opening\n"
        "python3 scripts/bcc-whir-mu-test.py\n"
        "python3 scripts/report-bcc-whir-mu-test.py\n"
    )

if __name__ == "__main__": main()
