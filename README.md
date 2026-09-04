# block-circulant-codes

## Controlled four-scheme DAS benchmark

The controlled benchmark in `examples/benchmark-das-schemes.rs` compares
BCC+KZG, BCC+WHIR, BCC+Titan, and 2D-RS+KZG with one immutable `Vec<u64>`
input and one immutable ordered eight-index schedule per `(k, run)`. Samples
are scalar (`D=1`) and all primary PCS paths produce one proof per requested
position. KZG uses individual `open` and `verify` calls for both codes.

The five rate-1/4 geometries and the 1-warm-up/10-measurement contract live in
`configs/paper_rate_1_4.toml`. A complete single-threaded run is:

```bash
scripts/run_single_core.sh results/raw/controlled.jsonl
```

The runner checks the pinned WHIR and Titan commits and requires both upstream
worktrees to be clean before and after execution. Each JSONL row records the
message/sample seeds, BLAKE3 input and schedule hashes, exact ordered indices,
separate timing phases, and exact commitment/symbol/proof byte totals. Locally
derivable indices and configuration identifiers are not counted as download.

For a quick correctness smoke test at `(k,n)=(16,64)`:

```bash
RAYON_NUM_THREADS=1 DAS_BENCH_OMEGA=4 DAS_BENCH_RUN=1 \
  DAS_BENCH_JSONL=1 DAS_TITAN_MODE=normal \
  cargo run --release --example benchmark-das-schemes
```

A Rust implementation of **block circulant codes** (`C_BC[μ, λ=2, ω, ρ]`),
from B. Sasidharan, E. Viterbo, S. H. Dau, *"Block Circulant Codes with
Application to Decentralized Systems,"* arXiv:2406.12160 — an
erasure-correcting code designed for blockchain data-availability sampling,
with a KZG-commitment-compatible local structure.

> Full paper-fidelity notes, the FFT-based (PeerDAS) variant's derivation,
> the 2D-RS baseline comparison, DAS-sampling reproduction, dependency
> rationale, and known limitations all live in [`notes/`](notes/README.md). This
> file covers only how the code itself is put together.

## BCC+WHIR prototype status

`src/das/bcc_whir` implements the independent-arc construction: the header is
an ordered tuple of one WHIR commitment per BCC arc, and the proposer
precomputes one complete-evaluation WHIR opening for every BCC arc before
light-client sampling. Verification derives the canonical arc, local position, and BCC
evaluation point from the requested global index rather than trusting response
metadata.

The adapter pins WHIR to revision `92652ca01e215548c98e11834e110c43994b94c1`.
It embeds each coefficient-form local BCC polynomial `f(X)` into the
multilinear polynomial `g` satisfying `f(z) = g(z, z², z⁴, ...)`; see
`src/pcs/multilinear_bridge.rs` for the precise conversion. The FFT BCC
schedule makes `k0 = 2ω` a power of two, so this prototype does not pad arcs.

> WHIR is an academic prototype and has not received careful code review. It
> is **not production-ready**. Independent arc commitments authenticate their
> own evaluations, but do not themselves prove BCC overlap consistency;
> honest BCC encoding and consistent overlaps remain a protocol assumption.

```
cargo test
cargo run --example basic_roundtrip
cargo run --example kzg_demo
cargo run --example fft_roundtrip
```

## The construction, in one picture

For λ = 2, `μ` local Reed-Solomon codes are arranged in a circle. Each
contributes `ω` new "info" symbols and `ρ` "parity" symbols, and
consecutive local codes *share* their `ω`-symbol overlap — a local code's
own info block also serves as its left neighbor's right-overlap block:

```
[ info_1 | parity_1 | info_2 | parity_2 | ... | info_μ | parity_μ ]  (circular)
           \___________________/
              local code i's support = info_i, parity_i, info_{i+1}
              (n0 = 2ω+ρ symbols, k0 = 2ω of them are "message")
```

* Global code: `n = μ(ρ+ω)`, `k = μω`, `d = 2ρ+1`.
* Each local code: an `[n0=2ω+ρ, k0=2ω, d0=ρ+1]` MDS (Reed-Solomon) code.
* A global position `j`'s evaluation point is `Λ[j mod 2(ρ+ω)]` — only
  `2(ρ+ω)` distinct evaluation points exist in total, reused by every local
  code around the ring (`crate::code`'s `Λ` is arbitrary field elements;
  `crate::fft`'s is roots of unity — see `notes/02-fft-path.md` for why).

## Encode flow

Two passes, both in [`src/fft/bcc/encode.rs`](src/fft/bcc/encode.rs)
(`FftBlockCirculantCode::encode`):

```
message (k symbols)
  --> write directly into every info_b block (no computation)
  --> for each local code i, independently and in parallel:
        gather its 2ω known info values + their evaluation points
        interpolate the unique degree-<k0 polynomial through them
        evaluate it at the ρ parity positions
  --> codeword (n symbols)
```

`crate::fft::FftBlockCirculantCode::encode` does the same two passes, but
completes each local code via IFFT (known values -> polynomial
coefficients) + FFT (evaluate at parity points) instead of Lagrange
interpolation — same shape, different arithmetic, `O(n log n)` instead of
`O(n0²)`. It requires `omega` and `rho+omega` to both be powers of 2.

## Decode flow

Two phases, iterated to a fixed point since progress in one can unlock the
other ([`src/decoder.rs`](src/decoder.rs)):

```
received (n symbols, some erased)
  --> loop:
        Phase 1: any local code with 0 < erasures <= rho
                 -> fill via Lagrange interpolation (same as encode's completion step)
        Phase 2: any adjacent pair of local codes with 0 < combined erasures <= 2*rho
                 -> build their joint parity-check matrix (Lagrange/barycentric
                    weighted, not plain Vandermonde -- see notes/01-the-code.md)
                 -> solve for the erased entries via Gauss-Jordan elimination
        if neither phase made progress this round, stop
  --> all filled?  Ok(codeword)  :  Err(Uncorrectable)
```

Guaranteed to succeed whenever total erasures `<= 2*rho` (Theorem III.1);
may also succeed on larger, favorably-shaped patterns.
`crate::fft`'s decoder has the identical two-phase shape — Phase 1 uses an
FFT-based Reed-Solomon reconstruction (`fft/rs.rs`) instead of Lagrange
interpolation, Phase 2 is unchanged.

## Module map

| Module | What it does |
|---|---|
| `topology` | `BcParams`: the periodic info/parity ring layout, local code supports `A_i`. |
| `poly` | `Interpolator` (Lagrange), `RsCode` (local code: `fill` does both encode-completion and erasure decoding), `interpolate_coeffs` (for KZG). |
| `code` | `BlockCirculantCode`: construction + systematic encode. |
| `decoder` | Two-phase erasure decoder (Lagrange + Gauss-Jordan). |
| `linalg` | Generic Gauss-Jordan solver backing Phase 2. |
| `kzg` | KZG10 commit/open/verify wired to local codes' message polynomials. |
| `fft/points` | Subgroup/coset evaluation-point construction for the FFT variant. |
| `fft/rs` | Standalone FFT-based ("Z(X)") erasure decoder for one domain. |
| `fft/code` | `FftBlockCirculantCode`: IFFT+FFT systematic encoder. |
| `fft/decoder` | Two-phase decoder: FFT-based Phase 1, Gauss-Jordan Phase 2. |
| `rs2d` | `TwoDRsCode`: 2D Reed-Solomon (row/column product code) baseline. |

## Example: encode → erase → decode

```rust
use ark_bls12_381::Fr;
use ark_ff::UniformRand;
use block_circulant_codes::{decode, BcParams, BlockCirculantCode};

let rng = &mut ark_std::test_rng();
let params = BcParams::new(4, 2, 2); // mu=4, omega=2, rho=2 -> [n=16, k=8, d=5]
let code = BlockCirculantCode::<Fr>::new(params);

let message: Vec<Fr> = (0..params.k()).map(|_| Fr::rand(rng)).collect();
let codeword = code.encode(&message)?;

let mut received: Vec<Option<Fr>> = codeword.iter().map(|&v| Some(v)).collect();
received[3] = None; // erase up to 2*rho = 4 symbols, anywhere
received[7] = None;

let recovered = decode(&code, &received)?;
assert_eq!(recovered, codeword);
```

See `examples/basic_roundtrip.rs`, `examples/fft_roundtrip.rs`, and
`examples/kzg_demo.rs` for full, runnable versions.
