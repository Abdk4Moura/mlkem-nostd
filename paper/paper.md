# ML-KEM in `no_std` Rust

### A portable, allocation-free FIPS 203 implementation

**Abdulkabir Agboola** · November 2026

> Research code. Unaudited. Not production ready.

## Abstract

ML-KEM is the module-lattice key-encapsulation mechanism standardized by NIST
in FIPS 203. This paper describes `mlkem-nostd`, an independent Rust
implementation targeting constrained and embedded environments. The crate is
`no_std`, allocation-free, forbids unsafe code, and implements all three FIPS
203 parameter sets with a single monomorphized code path. It supports KeyGen,
Encaps and Decaps (including implicit rejection) and enforces the Section 7
encapsulation-key modulus check and decapsulation-key hash check. Correctness is
demonstrated against the official NIST ACVP vectors (75/75 key-generation and
165/165 encapsulation/decapsulation cases, including negative key-check cases),
against 10,000 property-test cases per parameter set, and byte-for-byte against
RustCrypto's `ml-kem`. The arithmetic is branch-free on secret data and avoids
division and remainder operations on secret coefficients, the bug class
popularized by KyberSlash. A dudect harness and Criterion benchmarks compare the
implementation with the RustCrypto reference, and a Docker-based reproducer
regenerates every number.

## 1. Introduction

FIPS 203 [1] specifies ML-KEM, derived from CRYSTALS-Kyber [2], as a
post-quantum key-encapsulation mechanism. Deployments range from servers to
microcontrollers, but much of the optimized ecosystem assumes a 64-bit CPU,
SIMD, assembly, or at least the Rust standard library. Those assumptions are a
poor fit for bare-metal firmware and for reviewers who want to audit a small,
portable implementation against the standard.

This work has three goals:

1. **Traceability.** The crate mirrors the structure of FIPS 203, one module per
   layer and one function per numbered algorithm, so a reviewer can compare code
   and standard line by line.
2. **Portability.** The library is `no_std`, performs no heap allocation, uses
   only four RustCrypto dependencies, and builds for
   `thumbv7em-none-eabihf`.
3. **Evidence.** Official ACVP vectors, property tests, a byte-for-byte
   cross-check, a timing harness, benchmarks, and a one-command reproducer
   support the claims.

This is not a production-ready library. It has not been audited, formally
verified, or subjected to a certification process. The contribution is a
careful, reproducible research implementation and the measurements around it.

## 2. FIPS 203 in brief

ML-KEM works over the ring `R_q = Z_q[X]/(X^256 + 1)` with `q = 3329`. A
K-PKE component scheme encrypts a 32-byte message; the KEM wraps it with
Fujisaki–Okamoto-style hashing and implicit rejection.

| Parameter set | k | η1 | η2 | du | dv | ek | dk | ct |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| ML-KEM-512 | 2 | 3 | 2 | 10 | 4 | 800 | 1632 | 768 |
| ML-KEM-768 | 3 | 2 | 2 | 10 | 4 | 1184 | 2400 | 1088 |
| ML-KEM-1024 | 4 | 2 | 2 | 11 | 5 | 1568 | 3168 | 1568 |

Sizes are in bytes. A decapsulation key is the concatenation
`dkPKE || ek || H(ek) || z`. Key generation hashes `d || k` with SHA3-512 to
derive the matrix seed `rho` and the error seed `sigma`. Encapsulation hashes
`m || H(ek)` to derive the shared key and the encryption randomness.
Decapsulation decrypts `m'`, re-encrypts, compares the result with the received
ciphertext in constant time, and returns `J(z || c)` on mismatch.

Section 7 adds two input checks that are easy to overlook:

* **Encapsulation key modulus check.** Every 12-bit coefficient must be
  canonically encoded; `ByteEncode_12(ByteDecode_12(ek)) == ek`.
* **Decapsulation key hash check.** The embedded `H(ek)` must match a fresh hash
  of the embedded encapsulation key.

Our API makes these checks mandatory: a key can only be constructed through
`EncapsKey::from_bytes` or `DecapsKey::from_bytes`, both of which return an
error on failure. This follows the "unchecked bytes never become a key" design
used in the earlier ECQV work.

## 3. Implementation

### 3.1 Structure

| Module | Contents | FIPS 203 |
| --- | --- | --- |
| `params` | `ParameterSet`, three marker types | Section 8 |
| `field` | arithmetic mod 3329 | Section 2 |
| `poly` | `ByteEncode`/`ByteDecode`, `Compress`/`Decompress` | Algorithms 5, 6 |
| `ntt` | forward/inverse NTT, `MultiplyNTTs`, zeta tables | Algorithms 9–12 |
| `sample` | `SampleNTT`, `SamplePolyCBD` | Algorithms 7, 8 |
| `hash` | H, G, J, PRF, XOF | Section 4.1 |
| `kpke` | K-PKE KeyGen, Encrypt, Decrypt | Algorithms 13–15 |
| `kem` | ML-KEM, Section 7 checks | Algorithms 16–21 |

Parameter sets are zero-sized marker types implementing a trait with associated
constants. The same generic code is instantiated three times. Array sizes are
taken from the largest set (four polynomials, 3168 key bytes) because stable
Rust does not permit associated-constant array lengths in generic structs
without `generic_const_exprs`. The unused tail is zeroed and never read; the
public accessors return exactly `P::EK_BYTES`, `P::DK_BYTES` or `P::CT_BYTES`.

### 3.2 Field arithmetic

Coefficients are stored as canonical `u16` values in `[0, q)`. Addition reduces
`a + b` with a branch-free conditional subtraction:

```text
t = a + b - q          (wrapping)
result = t + ((t >> 15) * q)
```

Subtraction uses `a + q - b` followed by the same reduction. Multiplication uses
a 48-bit reciprocal: for `a,b < q`, the product is below `q^2`, and
`floor(a*b/q)` is computed exactly as `(a*b * ceil(2^48/q)) >> 48`. The
remainder is then `a*b - q*floor(a*b/q)`. The `field` unit tests check all
`q^2 = 11,082,241` input pairs against the `%` operator.

`Compress_d(x)` is implemented without division:

```text
num = (x << d) + q/2
c   = ((num * ceil(2^48/q)) >> 48) mod 2^d
```

This is exactly the FIPS rounding formula, but with a multiply and shift instead
of a variable-time integer division. `Decompress_d(y)` is
`(q*y + 2^(d-1)) >> d`. Exhaustive tests cover every `x < q` and every `d` in
`{1,4,5,10,11}`, including the circular error bound and the wrap at `q`.

### 3.3 NTT and sampling

The zeta tables are generated at compile time from `zeta = 17` and `BitRev7`.
The forward transform follows Algorithm 9. The inverse transform follows
Algorithm 10: it walks the same table in reverse and multiplies by
`3303 = 128^{-1} mod q`. `MultiplyNTTs` uses the odd powers
`zeta^{2*BitRev7(i)+1}`. A unit test compares the NTT-domain product with a
schoolbook negacyclic convolution, which catches sign and index mistakes that a
round-trip test alone would miss.

`SampleNTT` absorbs `rho || j || i` into SHAKE128. SHAKE128's rate is 168 bytes,
which is divisible by 3, so each block can be parsed independently into 12-bit
candidate pairs; rejected candidates are skipped. `SamplePolyCBD` expands
`PRF(s, b)` to `64*eta` bytes and sums individual bits, not bit-weighted
integers. That distinction matters: an early version of the Python reference
used weighted bits and produced plausible-looking but wrong keys.

### 3.4 Keys, errors and zeroization

`EncapsKey`, `DecapsKey` and `Ciphertext` are fixed-size wrappers around the
largest buffer. `EncapsKey::from_bytes` performs the length and modulus checks;
`DecapsKey::from_bytes` performs the length and hash checks; `Ciphertext` checks
its length. `DecapsKey` implements `Drop` and zeroizes its buffer; `SharedSecret`
derives `Zeroize` and `ZeroizeOnDrop`. Intermediate polynomials and hash inputs
inside `kpke` and `kem` are explicitly zeroized before returning, including on
the implicit-rejection path.

Zeroizing on drop makes `SharedSecret` non-`Copy`. `subtle`'s
`ConditionallySelectable` requires `Copy`, so decapsulation selects between the
two 32-byte arrays and then wraps the result. The selection still goes through
`subtle`; only the wrapper is constructed afterwards.

## 4. Constant-time design

The implementation follows a small set of rules:

1. No branch, array index, or loop bound depends on secret data.
2. No `/` or `%` is applied to a secret coefficient. Secret modular arithmetic
   uses conditional subtraction and Barrett reduction; compression uses the
   reciprocal above.
3. Comparisons of secret values use `subtle::ConstantTimeEq`.
4. Decapsulation selects the real or rejection key with
   `subtle::ConditionallySelectable`, never an `if`.
5. Secret buffers are zeroized on drop or before returning.

### 4.1 KyberSlash

In 2023–2024, a family of timing vulnerabilities dubbed **KyberSlash** showed
that several Kyber implementations divided secret coefficients by `q` during
compression or decompression [7]. Because integer division latency depends on
the dividend on many CPUs, a single secret-dependent `% q` in the compressor
leaked information about the decrypted message across repeated decapsulations.
The fix is not to make the division "look constant time" but to remove it: use a
multiply-and-shift reciprocal, or a fixed sequence of conditional subtractions.

`mlkem-nostd` uses the reciprocal approach for `Compress`, `field::mul`, and
Barrett reduction. The only divisions in the crate are on public values
(lengths, indices, compile-time table generation). Version-control history and
tests are structured so that a reviewer can grep for `/` and `%` and check each
remaining occurrence by hand.

The timing harness compares valid and invalid ciphertexts, which exercises the
implicit-rejection comparison and selection. A second harness compares
`Compress_10` on uniformly random coefficients with coefficients fixed at
`q - 1`. With 1,000,000 measurements, neither distribution produced a dudect
t-statistic above the 4.5 threshold; the observed values are reported in
Section 6.

### 4.2 Caveats

Constant-time source code is not a proof. Compiler transformations, the
constant-time behavior of SHA-3, cache effects, and microarchitectural details
all matter. The dudect harness is a statistical detector, not a verification
tool. The implementation depends on RustCrypto `sha3` for Keccak; its timing
properties are assumed, not re-established here. Formal verification is out of
scope, and hax/Jasmin work on ML-KEM is cited as related [9] rather than
duplicated.

## 5. Correctness and testing

### 5.1 ACVP vectors

The official ACVP files are pinned to ACVP-Server commit
`975de31eb83d87039ec88934fdc47d8c312b892d` and verified by SHA-256 before use.
`cargo test --features acvp` loads every case and dispatches by parameter set and
function.

| Test group | Cases | Result |
| --- | ---: | --- |
| KeyGen, all sets | 75 | 75/75 pass |
| Encapsulation, all sets | 75 | 75/75 pass |
| Decapsulation, all sets | 30 | 30/30 pass |
| Encapsulation key check | 30 | 30/30 pass |
| Decapsulation key check | 30 | 30/30 pass |

The key-check groups include both accepting and rejecting inputs. They were
useful for catching two easy mistakes: applying the modulus check to only the
first polynomial chunk, and treating the hash check as a length check.

### 5.2 Other tests

* **Unit tests.** Exhaustive field addition, subtraction and multiplication; NTT
  round-trip; NTT multiplication versus schoolbook convolution; encode/decode
  round-trips for every `d`; compression error bounds; SHA-3 known answers;
  sampling known answers.
* **Property tests.** 10,000 `proptest` cases per parameter set for
  `Decaps(Encaps(ek)) = K`, plus 10,000 mutated-ciphertext cases per set that
  check the result equals `J(z || c)` and differs from the real key.
* **Cross-check.** For identical seeds, our keys, ciphertexts and shared secrets
  are byte-identical to RustCrypto `ml-kem` 0.3.4, including the expanded
  decapsulation key.
* **`no_std`.** The crate builds for `thumbv7em-none-eabihf` with no `alloc` and
  no `std`; CI also runs clippy against that target.

## 6. Performance

Benchmarks use Criterion and deterministic entry points on both sides, so RNG
cost is excluded. The reference is RustCrypto `ml-kem` 0.3.4 [4] with its default
(no-zeroize) feature set. Results below are from a native Windows 11 run on an
Intel64 Family 6 Model 186 CPU with Rust 1.88.0, LTO and `codegen-units = 1`.
Numbers are machine-specific and should be regenerated with Docker.

| Parameter set | Operation | Ours (µs) | RustCrypto (µs) | Ratio |
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

The portable implementation is between 0.73× and 0.89× the reference latency on
this machine. That result should not be read as a general claim: the comparison
uses different SHA-3 crate versions, the reference supports optional PKCS#8 and
zeroization features that are disabled here, and both implementations are
sensitive to compiler and CPU details. The useful conclusion is that a simple
fixed-array implementation with a 48-bit reciprocal and compile-time zeta tables
is competitive without SIMD or assembly.

Dudect [8] results (1,000,000 samples):

| Experiment | Max t | Verdict |
| --- | ---: | --- |
| Decaps: valid vs. mutated ciphertext | +2.52 | no leak flagged at 4.5 |
| Compress_10: uniform vs. extreme coefficients | +2.26 | no leak flagged at 4.5 |

## 7. Reproducibility and release

The repository contains:

* `Dockerfile` with Rust 1.88.0 and Python 3 for the reporting scripts;
* `rust-toolchain.toml` pinned to 1.88.0;
* `scripts/fetch-vectors.sh`, pinned to an ACVP-Server commit and checking
  `vectors/SHA256SUMS`;
* `reproduce.sh`, which runs formatting, clippy, all tests, the `no_std` build,
  1,000,000-sample dudect runs, Criterion benchmarks, and writes `results/`;
* `.github/workflows/ci.yml` for fmt, clippy, tests, ACVP and the `no_std`
  target.

`results/` contains `environment.txt` (CPU, kernel, toolchain), raw dudect CSV
and text output, Criterion means in `benchmarks.csv`, a Markdown table, and an
SVG chart. Recording the CPU model and toolchain in each CSV is deliberate:
latency numbers are only meaningful with that context.

The release is tagged `v0.1.0`. `CITATION.cff` and `.zenodo.json` are included.
A Zenodo DOI is minted when the tag is deposited; until then the repository and
tag are the stable identifiers. The Docker base image is pinned by manifest digest.

## 8. Limitations and future work

* No audit, no formal verification, no side-channel certification.
* Portable Rust only; SIMD and assembly are out of scope. A vectorized backend
  would change the performance story, not the API.
* The implementation relies on RustCrypto `sha3`; a fully self-contained
  constant-time Keccak would remove that trust assumption.
* ML-DSA and hybrid KEMs are separate work.
* Future work could include a liboqs comparison, hax/Jasmin verification of the
  NTT and compression routines, `cargo-fuzz` differential testing, and a
  Cortex-M cycle-count study.

## 9. Conclusion

`mlkem-nostd` shows that a direct, auditable transcription of FIPS 203 into
`no_std` Rust can pass every official ACVP vector, match a mature RustCrypto
implementation byte for byte, avoid the KyberSlash division pattern, and remain
competitive on speed without SIMD or assembly. The implementation, tests,
benchmarks, and reproducer are released together so that the claims can be
checked rather than taken on trust.

## References

1. NIST, *FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard*,
   August 2024. https://csrc.nist.gov/pubs/fips/203/final
2. J. Bos, L. Ducas, E. Kiltz, T. Lepoint, V. Lyubashevsky, J. M. Schanck,
   P. Schwabe, G. Seiler, D. Stehlé, *CRYSTALS-Kyber: A CCA-Secure
   Module-Lattice-Based KEM*, IEEE EuroS&P 2018.
3. NIST, *ACVP-Server* test vectors, commit
   `975de31eb83d87039ec88934fdc47d8c312b892d`.
   https://github.com/usnistgov/ACVP-Server
4. RustCrypto, *ml-kem* crate, version 0.3.4.
   https://github.com/RustCrypto/KEMs
5. RustCrypto, *sha3*, *subtle*, *zeroize*, and *rand_core* crates.
6. Open Quantum Safe, *liboqs*. https://github.com/open-quantum-safe/liboqs
7. D. J. Bernstein, K. Bhargavan, et al., *KyberSlash: Exploiting
   secret-dependent division timings in Kyber implementations*, 2024.
   https://kyberslash.cr.yp.to/
8. G. Becker, et al., *dudect: Dude, is my code constant time?*, DATE 2017.
9. hax and Jasmin projects, as related formal-verification work for
   constant-time cryptographic code.
