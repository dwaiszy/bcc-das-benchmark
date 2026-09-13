# Block-Circulant DAS

This repository contains a generic data-availability-sampling (DAS)
construction with BCC and 2D Reed–Solomon erasure codes, backed by KZG or
WHIR polynomial commitments.

## Code structure

```text
src/
├── das/
│   ├── das_lifecycle.rs      Generic proposer/light-client lifecycle
│   ├── code/
│   │   ├── bcc.rs             BCC arc adapter
│   │   └── rs2d.rs            2D-RS row/column adapter
│   ├── bcc_kzg/               BCC + KZG setup
│   ├── bcc_whir/              BCC + WHIR setup
│   ├── rs2d_kzg/              2D-RS + KZG setup
│   ├── protocol_profile.rs    Protocol and benchmark profiles
│   └── proof_serialization.rs Serialized proof and sample-size measurements
├── pcs/
│   ├── mod.rs                 Common PCS interface (`ArcPcs`)
│   ├── kzg/                   KZG commit/open/verify implementations
│   └── whir/                  WHIR adapter and proof serialization
├── fft/
│   ├── bcc/                   FFT-based BCC encoding and decoding
│   └── rs2d/                  FFT-based 2D-RS encoding and decoding
├── benchmark_config.rs        Benchmark parameters and run configuration
└── error.rs                   Shared error types
```

## How the layers fit together

`das/das_lifecycle.rs` defines the scheme-independent workflow:

```text
commit original polynomials
        ↓
encode with the erasure code
        ↓
open every encoded position
        ↓
light client samples positions
        ↓
verify values against the appropriate commitment
```

The generic roles are parameterized by two implementations:

```rust
BlockProposer<C, P>
LightClientVerifier<C, P>
```

`C` implements `ErasureCode` and supplies polynomialization, encoding, index
mapping, and decoding. `P` implements `ArcPcs` and supplies commitment,
opening, verification, and proof-size operations.

## DAS schemes

### BCC + KZG

`BccCode` creates one degree-`< k0` polynomial per BCC arc. KZG publishes one
commitment per arc, encodes each arc, and generates scalar openings for its
local positions. A sampled global index is mapped to its owning arc and
verified against that arc commitment.

### BCC + WHIR

This uses the identical BCC polynomial and sampling logic as BCC+KZG. Only the
PCS changes: WHIR creates and verifies the opening proof, with its adapter
handling the coefficient-to-multilinear conversion and proof compression.

### 2D-RS + KZG

The source data is a `k0 × k0` matrix. RS encoding extends rows and columns to
an `n0 × n0` matrix. The header publishes commitments only for the `k0` source
rows; commitments for encoded rows are derived homomorphically from those
source commitments using the vertical RS coefficients.

## Benchmark and tests

The benchmark configuration records setup, commit, encode, opening, verification,
commitment counts, proof counts, and serialized sizes. Header/commitment
metadata is reported separately from per-sample light-client download.

Tests are organized around the same public lifecycle for every scheme:

```text
commit → encode → open → sample → disperse → verify
```

PCS-specific correctness tests are colocated with the PCS adapters, including
KZG opening tests and WHIR serialization/verification tests.
