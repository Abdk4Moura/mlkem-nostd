# Changelog

## 0.1.0 - 2026-11-23

Initial research release.

* ML-KEM-512, ML-KEM-768 and ML-KEM-1024 KeyGen, Encaps and Decaps with
  implicit rejection.
* FIPS 203 Section 7 encapsulation-key modulus check and decapsulation-key
  hash check, enforced by the checked byte parsers.
* `no_std`, no `alloc`, `#![forbid(unsafe_code)]`; dependencies are `sha3`,
  `subtle`, `zeroize` and `rand_core`.
* Branch-free field arithmetic, division-free compression, constant-time
  decapsulation selection, and zeroization of secret material.
* NIST ACVP known-answer tests: 75/75 keyGen and 165/165 encapDecap vectors.
* 10,000 property-test cases per parameter set, mutated-ciphertext implicit
  rejection properties, and a byte-for-byte RustCrypto `ml-kem` cross-check.
* dudect timing harness and Criterion benchmarks.
* Docker reproducer, pinned ACVP vector hashes, GitHub Actions CI, and a
  6-page write-up.
