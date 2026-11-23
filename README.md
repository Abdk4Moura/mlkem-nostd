# mlkem-nostd

Portable, `no_std`, allocation-free **ML-KEM (FIPS 203)** in Rust.

> **Research code. Unaudited. Not production ready.**
>
> This is an independent implementation written to mirror FIPS 203 closely so
> that reviewers can check each function against its numbered algorithm. It has
> not been audited and should not protect real secrets yet.

## Status

| Gate | Deliverable | Status |
| --- | --- | --- |
| 1 | Crate skeleton, pinned toolchain, CI, ACVP harness | **Complete** |
| 2 | `field`, `poly`, `ntt`, `hash`, `sample` with unit tests | **Complete** |
| 3 | K-PKE and ML-KEM; all NIST ACVP vectors for all three sets | **Complete**: 75/75 keyGen, 165/165 encapDecap |
| 4 | Property tests, RustCrypto cross-check, dudect, Criterion, Docker repro | **Complete**: `reproduce.sh` was validated end-to-end under WSL; `docker build` itself was not run (no Docker daemon). |
| 5 | 4–6 page write-up and tagged release | **Write-up and `v0.1.0` tag done**; Zenodo DOI pending a deposit under the author's account |

## What ships

* ML-KEM-512, ML-KEM-768 and ML-KEM-1024: KeyGen, Encaps, Decaps, including
  implicit rejection.
* FIPS 203 Section 7 input checks: encapsulation key type/modulus check and
  decapsulation key hash check. `EncapsKey::from_bytes`, `DecapsKey::from_bytes`
  and `Ciphertext::from_bytes` are the only byte-to-key parsers, so an unchecked
  byte string never becomes a usable key.
* `no_std`, no `alloc`, `#![forbid(unsafe_code)]`.
* Dependencies limited to `sha3`, `subtle`, `zeroize` and `rand_core`.
* Secret keys and intermediate secrets zeroized; `DecapsKey` and `SharedSecret`
  zeroize on drop.
* ACVP known-answer tests, property tests, RustCrypto byte-for-byte cross-check,
  dudect timing harness, Criterion benchmarks, and a one-command reproducer.

## Parameter sets

| Parameter set | k | η1 | du, dv | Encaps key | Decaps key | Ciphertext |
| --- | ---: | ---: | --- | ---: | ---: | ---: |
| ML-KEM-512 | 2 | 3 | 10, 4 | 800 B | 1632 B | 768 B |
| ML-KEM-768 | 3 | 2 | 10, 4 | 1184 B | 2400 B | 1088 B |
| ML-KEM-1024 | 4 | 2 | 11, 5 | 1568 B | 3168 B | 1568 B |

All sets use `n = 256`, `q = 3329`, `η2 = 2`, and a 32-byte shared secret.

## Usage

```toml
[dependencies]
mlkem-nostd = { path = "." }
rand_core = { version = "0.6", features = ["getrandom"] }
```

```rust
use mlkem_nostd::{Kem, MlKem768};

let mut rng = rand_core::OsRng;

let (ek, dk) = MlKem768::keygen(&mut rng);
let (ct, k_send) = MlKem768::encaps(&ek, &mut rng);
let k_recv = MlKem768::decaps(&dk, &ct);
assert_eq!(k_send, k_recv);
```

Parsing bytes:

```rust
use mlkem_nostd::kem::{Ciphertext, DecapsKey, EncapsKey};

let ek = EncapsKey::<mlkem_nostd::MlKem768>::from_bytes(ek_bytes)?;
let dk = DecapsKey::<mlkem_nostd::MlKem768>::from_bytes(dk_bytes)?;
let ct = Ciphertext::<mlkem_nostd::MlKem768>::from_bytes(ct_bytes)?;
```

The deterministic FIPS 203 entry points used by the test harness are public:
`kem::keygen_internal(d, z)`, `kem::encaps_internal(ek, m)` and
`kem::decaps_internal(dk, ct)`. Do not use them in production with predictable
inputs.

## Design

The crate follows FIPS 203 one module per layer:

| Module | Contents | FIPS 203 |
| --- | --- | --- |
| `params` | `ParameterSet` trait and the three marker types | Section 8 |
| `field` | Arithmetic mod 3329; Barrett reduction; constant-time conditional subtract | Section 2 |
| `poly` | 256 coefficients, add/sub, `ByteEncode`/`ByteDecode`, `Compress`/`Decompress` | Algorithms 5, 6; Section 4.2.1 |
| `ntt` | Forward/inverse NTT, `MultiplyNTTs`, `BaseCaseMultiply`, ζ = 17 tables | Algorithms 9–12 |
| `sample` | `SampleNTT` (SHAKE128) and `SamplePolyCBD` (SHAKE256 PRF) | Algorithms 7, 8 |
| `hash` | H, G, J, PRF, XOF wrappers | Section 4.1 |
| `kpke` | K-PKE KeyGen, Encrypt, Decrypt | Algorithms 13–15 |
| `kem` | ML-KEM KeyGen, Encaps, Decaps and Section 7 checks | Algorithms 16–21 |

Parameter sets are type-level marker types. The same monomorphized code runs
for all three; loops are bounded by associated constants and there is no
runtime enum dispatch.

### Constant-time choices

* No branch, array index or loop bound depends on secret data.
* Modular addition/subtraction use a branch-free conditional subtract. Modular
  multiplication uses a Barrett reduction with a 48-bit reciprocal.
* `Compress` uses multiply-and-shift, never `/` or `%`, on secret coefficients.
  This is the KyberSlash bug class: early Kyber implementations divided secret
  coefficients by `q`, and the variable-time division leaked through the
  compressor. See the write-up for the full discussion.
* Decapsulation compares the re-encrypted ciphertext with
  `subtle::ConstantTimeEq` and selects the real or implicit-rejection key with
  `subtle::ConditionallySelectable` (on the copyable byte array, because
  `SharedSecret` zeroizes on drop and therefore cannot be `Copy`).
* Key checks use `subtle::ConstantTimeEq`.
* `DecapsKey` and `SharedSecret` have `ZeroizeOnDrop`; intermediate secret
  polynomials and hash inputs are zeroized before returning.

No formal verification is claimed. The dudect harness is a statistical check,
not a proof.

## Testing

The official NIST ACVP files are pinned to ACVP-Server commit
`975de31eb83d87039ec88934fdc47d8c312b892d` and verified against
`vectors/SHA256SUMS`.

```bash
# Known answers: all 75 keyGen and 165 encapDecap vectors
cargo test --release --features acvp --test acvp -- --nocapture

# Unit tests: field exhaustive, NTT round-trip, encode/decode, compression bounds
cargo test --release --lib

# 10,000 proptest cases per set, including implicit rejection
cargo test --release --test properties

# Byte-identical keys/ciphertexts/secrets with RustCrypto ml-kem 0.3.4
cargo test --release --test crosscheck

# no_std target
cargo build --release --target thumbv7em-none-eabihf
```

ACVP result: **75/75 keyGen and 165/165 encapDecap vectors pass** for all three
parameter sets, including the `encapsulationKeyCheck` and
`decapsulationKeyCheck` negative cases.

## Benchmarks

Native Windows run (Rust 1.88.0, `--release`, LTO enabled). These are
machine-specific; run `./reproduce.sh` in Docker for the recorded environment.
Criterion mean latency in microseconds; lower is better. The optional liboqs
comparison was not run for this release.

<!-- BENCH-TABLE-START -->
| Parameter set | Operation | Ours (µs) | RustCrypto (µs) | Ours / RustCrypto |
| --- | --- | ---: | ---: | ---: |
| ML-KEM-512 | KeyGen | 38.50 | 43.86 | 0.88 |
| ML-KEM-512 | Encaps | 38.14 | 45.76 | 0.83 |
| ML-KEM-512 | Decaps | 50.99 | 64.76 | 0.79 |
| ML-KEM-768 | KeyGen | 53.81 | 69.76 | 0.77 |
| ML-KEM-768 | Encaps | 65.46 | 73.73 | 0.89 |
| ML-KEM-768 | Decaps | 74.39 | 98.89 | 0.75 |
| ML-KEM-1024 | KeyGen | 78.31 | 106.82 | 0.73 |
| ML-KEM-1024 | Encaps | 81.61 | 107.18 | 0.76 |
| ML-KEM-1024 | Decaps | 106.94 | 141.43 | 0.76 |
<!-- BENCH-TABLE-END -->

### Timing

A dudect run with 1,000,000 measurements on the same Windows machine gave
`max t = +2.52` for decapsulation on valid versus mutated ciphertexts and
`+2.26` for `Compress_10` on uniform versus extreme coefficients.
Both are below the 4.5 threshold; this is a statistical check, not a proof.

## Reproducibility

```bash
docker build -t mlkem-nostd .
mkdir -p results
docker run --rm -v "$PWD/results:/work/results" mlkem-nostd
```

For a faster local pass before the full 1,000,000-sample timing run:

```bash
DUDECT_SAMPLES=10000 ./reproduce.sh
```

`reproduce.sh` runs, in order: vector hash check, fmt, clippy (host and
`thumbv7em-none-eabihf`), unit tests, cross-check, property tests, ACVP tests,
the `no_std` build, 1,000,000-sample dudect runs, and Criterion benchmarks. It
writes `results/` containing:

* `environment.txt` - date, toolchain, kernel, CPU;
* `dudect-decaps.csv` and `dudect-compress.csv` - raw timing samples plus text
  output with the max t statistic;
* `benchmarks.csv` and `benchmarks.md` - Criterion means with CPU, kernel and
  toolchain columns;
* `benchmarks.svg` - a dependency-free bar chart.

The Docker base image is pinned by manifest digest and `rust-toolchain.toml` pins
Rust 1.88.0.

## Security notes and limitations

* Research code, unaudited, not production ready.
* Portable Rust only; no SIMD or assembly.
* No formal verification. hax/Jasmin-style work is related work only.
* ML-DSA and hybrid KEMs are out of scope.
* The implementation assumes a constant-time SHA-3 implementation from
  RustCrypto `sha3`. Side channels in the hash implementation are not addressed
  here.
* The benchmarks do not include RNG cost; they call deterministic entry points
  so that both implementations measure the same ML-KEM work.

## Layout

```text
.
├── Cargo.toml
├── rust-toolchain.toml
├── Dockerfile
├── reproduce.sh
├── scripts/
│   ├── fetch-vectors.sh
│   ├── bench_to_csv.py
│   └── plot_bench.py
├── vectors/                 # pinned ACVP JSON + SHA256SUMS
├── src/
│   ├── params.rs
│   ├── field.rs
│   ├── poly.rs
│   ├── ntt.rs
│   ├── sample.rs
│   ├── hash.rs
│   ├── kpke.rs
│   ├── kem.rs
│   └── lib.rs
├── tests/
│   ├── acvp.rs
│   ├── properties.rs
│   └── crosscheck.rs
├── benches/
│   ├── kem.rs
│   └── dudect.rs
└── paper/
    ├── paper.md
    └── paper.pdf
```

The write-up is available as `paper/paper.md` and `paper/paper.pdf` (6 pages).

## Citation

`CITATION.cff` and `.zenodo.json` are included. The Zenodo DOI is minted when
the tagged release is deposited; until then cite the repository and tag
`v0.1.0`.

## License

MIT OR Apache-2.0.
