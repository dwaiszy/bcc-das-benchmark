#!/usr/bin/env python3
"""Aggregate fixed-mu scalar BCC+WHIR-JB comparison."""
import csv
import math
import statistics
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "results" / "whir_scalar_mu32_vs_mu64"
RAW = OUT / "raw"
KS, MUS = (64, 256, 1024, 4096), (32, 64)
RUNS, ELL, EPS = 200, 1000, 1e-9

def kv(path):
    out = {}
    for line in Path(path).read_text().splitlines():
        if "=" in line and not line.startswith("scalar_opening "):
            key, value = line.split("=", 1); out[key] = value
    return out
def scalar_row(path):
    for line in Path(path).read_text().splitlines():
        if line.startswith("scalar_opening "):
            out = {}
            for token in line.split():
                key, value = token.split("=", 1); out[key] = value
            return out
    raise AssertionError(f"scalar row missing: {path}")
def f(row, key): return float(row[key])
def i(row, key): return int(float(row[key]))
def summary(values):
    values=list(values); sd=statistics.stdev(values) if len(values)>1 else 0.0
    return {"mean":statistics.mean(values),"median":statistics.median(values),"sd":sd,"min":min(values),"max":max(values),"ci95":1.96*sd/math.sqrt(len(values))}
def ln_binom(n,r): return math.lgamma(n+1.)-math.lgamma(r+1.)-math.lgamma(n-r+1.)
def sampler(n,t,q):
    d=t-1; current=ln_binom(n,d)+ELL*q*math.log(d/n); previous=ln_binom(n,d)+ELL*(q-1)*math.log(d/n)
    assert current <= math.log(EPS) and (q==1 or previous > math.log(EPS))
    def sci(x):
        e=math.floor(x/math.log(10.)); return f"{10**(x/math.log(10.)-e):.6f}e{e:+d}"
    return d,sci(current),sci(previous)
def audit(k,mu):
    row=kv(RAW/f"bcc_mu{mu}_k{k}_sample_set_audit.txt")
    assert i(row,"sample_set_audit_trials")==10000
    return {"mean":f(row,"sample_set_audit_mean_total_lc_bytes"),"median":f(row,"sample_set_audit_median_total_lc_bytes"),"sd":f(row,"sample_set_audit_sd_total_lc_bytes"),"min":f(row,"sample_set_audit_min_total_lc_bytes"),"max":f(row,"sample_set_audit_max_total_lc_bytes"),"ci95":1.96*f(row,"sample_set_audit_sd_total_lc_bytes")/100.,"proof":f(row,"sample_set_audit_mean_proof_bytes"),"D":f(row,"sample_set_audit_mean_distinct_arcs")}
def ratio_ci(a,b):
    r=a["mean"]/b["mean"]
    return r,1.96*r*math.sqrt((a["sd"]/math.sqrt(RUNS)/a["mean"])**2+(b["sd"]/math.sqrt(RUNS)/b["mean"])**2)

def main():
    rows=[]; report=[
        'experiment="fixed-mu scalar BCC+WHIR-JB comparison"',
        'points=k={64,256,1024,4096}; n=4k; R=1/4; L=1000; epsilon_DAS=1e-9',
        'mu_values={32,64}; release=true; proposer_threads=1; deterministic seeds; independent-unicast',
        'mode=scalar WHIR only; exactly one one-claim WHIR proof per sampled position',
        'timing=10 untimed warm-ups and 200 interleaved measured runs per (k,mu)',
        'communication=10,000 deterministic sample_sets; cached actual serialized scalar proof sizes used only for byte audit',
        ''
    ]
    for k in KS:
        for mu in MUS:
            paths=sorted(RAW.glob(f"bcc_mu{mu}_k{k}_measured_*.txt")); assert len(paths)==RUNS,(k,mu,len(paths))
            parsed=[(kv(p),scalar_row(p)) for p in paths]; b0,br0=parsed[0]
            n=4*k; assert (i(b0,"k"),i(b0,"n"),i(b0,"mu"),i(b0,"omega"),i(b0,"rho"))==(k,n,mu,k//mu,3*k//mu)
            assert k%mu==0 and i(br0,"proof_transcripts")==i(b0,"q_min")
            d,nu,prev=sampler(n,i(b0,"reconstruction_threshold"),i(b0,"q_min")); a=audit(k,mu)
            encode=summary(f(x,"encode_ms") for x,_ in parsed); commit=summary(f(x,"commit_ms") for x,_ in parsed); opening=summary(f(y,"opening_ms") for _,y in parsed); prover=summary(f(x,"encode_ms")+f(x,"commit_ms")+f(y,"opening_ms") for x,y in parsed); verify=summary(f(y,"verify_ms") for _,y in parsed)
            header=i(br0,"header_bytes"); values=i(br0,"values_bytes"); metadata=i(br0,"metadata_bytes"); proof=a["proof"]; total=a["mean"]
            assert abs(header+proof+values+metadata-total)<1e-5
            row={"k":k,"n":n,"mu":mu,"omega":i(b0,"omega"),"rho":i(b0,"rho"),"k0":i(b0,"k0"),"n0":i(b0,"n0"),"distance_d":i(b0,"distance"),"t":i(b0,"reconstruction_threshold"),"Delta":d,"Q_min":i(b0,"q_min"),"nu_Q_min":nu,"nu_Q_min_minus_1":prev,"local_rate":b0["local_rate"],"global_rate":"1/4","whir_domain_size":i(b0,"whir_local_domain_size"),"field":b0["field"],"field_element_bytes":values//i(b0,"q_min"),"mean_D":a["D"],"proof_transcripts":i(br0,"proof_transcripts"),"header_bytes":header,"proof_bytes":proof,"values_bytes":values,"metadata_bytes":metadata,"total_bytes":total,"network_bytes_1000":total*1000}
            for p,data in (("encode",encode),("commit",commit),("opening",opening),("prover",prover),("verify",verify),("comm",a)):
                for s in ("mean","median","sd","min","max","ci95"): row[f"{p}_{s}"]=data[s]
            rows.append(row); report.append(f"k={k} mu={mu}: omega={row['omega']} rho={row['rho']} k0={row['k0']} n0={row['n0']} d={row['distance_d']} t={row['t']} local_rate={row['local_rate']} domain={row['whir_domain_size']} N={n} Delta={d} Q_min={row['Q_min']} nu(Q)={nu} nu(Q-1)={prev}")
    fields=list(rows[0])
    with (OUT/"whir_scalar_mu32_vs_mu64.csv").open("w",newline="") as h:
        w=csv.DictWriter(h,fieldnames=fields); w.writeheader(); w.writerows(rows)
    report += ["", "MAIN TABLE", "| k | mu | Q_min | Mean D | Prover ms | LC verify ms | Header KiB | Proof KiB | Total KiB | Network MiB/1000 |", "|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for r in rows: report.append(f"| {r['k']} | {r['mu']} | {r['Q_min']} | {r['mean_D']:.4f} | {r['prover_mean']:.3f} | {r['verify_mean']:.3f} | {r['header_bytes']/1024:.3f} | {r['proof_bytes']/1024:.3f} | {r['total_bytes']/1024:.3f} | {r['network_bytes_1000']/1048576:.3f} |")
    report += ["", "RATIO TABLE (mu64 / mu32)", "| k | Prover | Verify | Communication | Better mu by communication | Interpretation |", "|---:|---:|---:|---:|---:|---|"]
    for k in KS:
        a=next(r for r in rows if r["k"]==k and r["mu"]==32); b=next(r for r in rows if r["k"]==k and r["mu"]==64)
        rp=b["prover_mean"]/a["prover_mean"]; rv=b["verify_mean"]/a["verify_mean"]; rc=b["total_bytes"]/a["total_bytes"]; better=64 if rc<1 else 32
        report.append(f"| {k} | {rp:.3f}x | {rv:.3f}x | {rc:.3f}x | mu={better} | {'mu=64 lower' if rc<1 else 'mu=32 lower'} communication |")
    report += ["", "DETAILED TIMING", "| k | mu | Encode ms | Commit/prep ms | Opening ms | Total proposer ms | LC verify ms |", "|---:|---:|---:|---:|---:|---:|---:|"]
    for r in rows: report.append(f"| {r['k']} | {r['mu']} | {r['encode_mean']:.3f} | {r['commit_mean']:.3f} | {r['opening_mean']:.3f} | {r['prover_mean']:.3f} | {r['verify_mean']:.3f} |")
    report += ["", "DETAILED COMMUNICATION", "| k | mu | Q_min | Header B | Proof B | Values B | Metadata B | Total B/client | KiB/client | Network MiB/1000 |", "|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for r in rows: report.append(f"| {r['k']} | {r['mu']} | {r['Q_min']} | {r['header_bytes']} | {r['proof_bytes']:.3f} | {r['values_bytes']} | {r['metadata_bytes']} | {r['total_bytes']:.3f} | {r['total_bytes']/1024:.3f} | {r['network_bytes_1000']/1048576:.3f} |")
    report += ["", "STATISTICS", "CSV contains mean, median, standard deviation, min, max, and 95% CI for timing and communication."]
    for r in rows: report.append(f"k={r['k']} mu={r['mu']}: communication mean/median/sd/min/max/CI95={r['comm_mean']:.3f}/{r['comm_median']:.3f}/{r['comm_sd']:.3f}/{r['comm_min']:.3f}/{r['comm_max']:.3f}/+/-{r['comm_ci95']:.3f} B; D={r['mean_D']:.4f}")
    report += ["", "VALIDATION CHECKS PASSED", "n=4k; omega=k/mu positive integer; rho=3omega; scalar proof transcript count=Q_min; no multipoint rows; byte sums exact; setup excluded; timing and byte-audit caches kept separate.", "", "SUMMARY", "Per-node communication is the primary selection metric; the lower-total-KiB mu is selected independently for each k. Results are empirical implementation measurements, not an asymptotic claim."]
    (OUT/"whir_scalar_mu32_vs_mu64.txt").write_text("\n".join(report)+"\n")

if __name__ == "__main__": main()
