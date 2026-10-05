# BCC data availability sampling benchmarks

Implementations and benchmarks for Section 5 of the paper, covering BCC+KZG, 2D-RS+KZG, BCC+WHIR-JB, and FRIDA.

Scripts save CSV files in `results/`, which is excluded from Git. The repository does not include measured results.

## Build and test

You need Rust with edition 2024 support, Cargo, and Python 3. The Python scripts use only the standard library. The first build needs network access to fetch dependencies pinned in `Cargo.lock`.

Run all commands from the repository root:

```sh
cargo test --locked --all-targets
cargo build --locked --release --examples
```

The build creates three binaries in `target/release/examples/`: `das_benchmark`, `bcc_whir_jb_scalar_opening`, and `frida_benchmark`. The scripts below run them automatically.

## Run the benchmarks

All comparisons use rate `1/4`, 1,000 light clients, a sampling failure target of `10^-9`, sampling with replacement, and one proposer thread. WHIR-JB and FRIDA use an 80-bit polynomial commitment security target; FRIDA uses 118 FRI queries at the tested sizes. The scripts set the seeds and parameters.


| Paper comparison                                | Commands                                                                             | Output CSV                                                |
| ----------------------------------------------- | ------------------------------------------------------------------------------------ | --------------------------------------------------------- |
| Section 5.2, Table 3: BCC+KZG vs 2D-RS+KZG      | `python3 scripts/bcc-rs2d-kzg.py`                                                    | `results/table3-bcc-rs2d-kzg/table3-bcc-rs2d-kzg.csv`     |
| Section 5.3, Table 4: BCC+WHIR-JB vs FRIDA      | `python3 scripts/bcc-whir-frida.py`, then `python3 scripts/report-bcc-whir-frida.py` | `results/table4-bcc-whir-frida/table4-bcc-whir-frida.csv` |
| Section 5.4, Table 5: communication and storage | `python3 scripts/communication-storage.py --runs 10 --threads 1 --ks 4096`           | `results/table5-communication-storage/table5.csv`         |



| Table | Parameters                                            | Runs                                              |
| ----- | ----------------------------------------------------- | ------------------------------------------------- |
| 3     | `k=4096`, `n=16384`                                   | 30 measured runs                                  |
| 4     | `k=64,256,1024,4096`; BCC arc counts `mu=32,32,64,64` | 200 measured runs per scheme and size             |
| 5     | `k=4096`, `n=16384`                                   | 10 measured runs                                  |


These benchmarks can take a long time, especially scalar WHIR proofs. Timings vary by machine. The paper used one thread on an Apple M4 Pro MacBook Pro.

For a shorter Table 5 check:

```sh
python3 scripts/communication-storage.py --runs 1 --threads 1 --ks 4096 --output-dir results/table5-check
```

Each comparison result is saved in the CSV files. 

## Read the results

Check the parameters and input data sizes before comparing timings:

- **Table 3:** `Q_min=24` for BCC and `32` for 2D-RS; 4 and 64 commitments; client downloads of about 2.28 and 5.78 KiB.
- **Table 4:** BCC arc counts `mu=32,32,64,64`; FRIDA `fri_queries=118`. Divide `bcc_comm_mean` and `frida_comm_mean` by 1024 to convert bytes to KiB.
- **Table 5:** samples per client are `24,32,24,7`, and downloads are approx `2.28,5.78,967.97,66.42` KiB, in the order BCC+KZG, 2D-RS+KZG, BCC+WHIR-JB, FRIDA.

In `table5.csv`, the paper's total per-node communication column reports client **download**. Request bytes are listed separately; the detailed client CSV includes requests plus downloads. FRIDA download includes one FRI transcript per client. Sizes are in bytes unless the column name ends in `_kib`.

## Code layout


| Path                      | Contents                                            |
| ------------------------- | --------------------------------------------------- |
| `benchmarks/`             | DAS and FRIDA benchmarks                            |
| `scripts/`                | Benchmark scripts and CSV reports                   |
| `src/benchmark_config.rs` | Shared input, sampling indexes, and code parameters |
| `src/das/`                | DAS workflow and BCC/2D-RS implementations          |
| `src/fft/`                | BCC and 2D-RS encoding and decoding                 |
| `src/pcs/`                | KZG and WHIR PCS implementations                    |
| `src/archive/`            | PCS batch-opening (not used in the paper)           |


The scalar WHIR benchmark source is `src/das/bcc_whir/scalar_opening.rs`, also referred to as the `bcc_whir_jb_scalar_opening` Cargo example.

The optional `bcc-whir-mu-test.py` and `report-bcc-whir-mu-test.py` scripts compare BCC setup parameters separately. 
