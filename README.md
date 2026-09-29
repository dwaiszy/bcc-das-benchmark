# Block-Circulant DAS benchmark artifact

This repository contains the implementation and benchmark drivers used to
compare BCC+KZG, 2D-RS+KZG, BCC+WHIR-JB, and FRIDA. Generated measurements
are intentionally excluded: each command below writes fresh outputs under
`results/`.

## Requirements

- Rust and Cargo (the pinned dependency versions are in `Cargo.lock`)
- Python 3
- Network access on the first Cargo build, to fetch the pinned FRIDA revision

Build the benchmark executables once:

```sh
cargo build --release --examples
```

## Reproducing the paper comparisons

### BCC+KZG versus 2D-RS+KZG

```sh
python3 scripts/bcc-rs2d-kzg.py
```

This runs the matched KZG comparison and writes raw measurements, summaries,
and a report to `results/table3-bcc-rs2d-kzg/`.

### BCC+WHIR-JB versus FRIDA

Run the matched BCC and FRIDA test, then aggregate its output:

```sh
python3 scripts/bcc-whir-frida.py
python3 scripts/report-bcc-whir-frida.py
```

The paper table uses the BCC measurements at `(k, mu) = (64, 32), (256, 32),
(1024, 64), (4096, 64)` and the corresponding FRIDA measurements.
Outputs are written to `results/table4-bcc-whir-frida/`.

### Four-scheme communication comparison

```sh
python3 scripts/communication-storage.py --runs 5 --threads 1 --ks 4096
```

This runs BCC+KZG, 2D-RS+KZG, BCC+WHIR-JB, and FRIDA at the paper geometry.
Use `--help` for the adjustable run count, thread count, output directory, and
problem sizes. All raw measurements, configuration data, statistics, and final
paper tables are written as CSV files under the corresponding `results/`
directory. The scripts do not generate graphs, PDFs, Markdown, or LaTeX.

## Layout

- `src/` — BCC and 2D-RS codes, KZG and WHIR adapters, and shared DAS logic.
- `benchmarks/das_benchmark.rs` — BCC+KZG, 2D-RS+KZG, and BCC+WHIR-JB runner.
- `src/das/bcc_whir/scalar_opening.rs` — scalar BCC+WHIR-JB measurement runner.
- `benchmarks/frida_benchmark.rs` — FRIDA measurement runner.
- `scripts/` — reproducible benchmark and aggregation drivers only.

Run the implementation tests with:

```sh
cargo test --lib --bins
```
