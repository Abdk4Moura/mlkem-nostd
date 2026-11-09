//! # mlkem-nostd
//!
//! A portable, `no_std`, allocation-free implementation of ML-KEM as
//! standardized in [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final).
//!
//! > **Research code. Unaudited. Not production ready.**
//!
//! The crate implements all three parameter sets (ML-KEM-512, ML-KEM-768 and
//! ML-KEM-1024) and follows the module layout of the standard so that each
//! function can be checked against its numbered algorithm:
//!
//! | Module | FIPS 203 |
//! | --- | --- |
//! | [`params`] | Section 8 |
//! | [`field`] | Section 2, arithmetic modulo 3329 |
//! | [`poly`] | Algorithms 5 and 6, Section 4.2.1 |
//! | [`ntt`] | Algorithms 9 to 12 |
//! | [`sample`] | Algorithms 7 and 8 |
//! | [`hash`] | Section 4.1 |
//! | [`kpke`] | Algorithms 13 to 15 |
//! | [`kem`] | Algorithms 16 to 21 and Section 7 checks |
//!
//! ## Constant-time rules
//!
//! * No branch, array index or loop bound depends on secret data.
//! * Secret arithmetic uses branch-free modular addition/subtraction and a
//!   multiply-and-shift Barrett reduction; there is no `/` or `%` on secret
//!   values. `Compress` uses the same division-free technique.
//! * Decapsulation compares ciphertexts with [`subtle::ConstantTimeEq`] and
//!   selects the real or implicit-rejection key with
//!   [`subtle::ConditionallySelectable`].
//! * Secret key material is zeroized on drop; intermediate secrets are
//!   zeroized before returning.
//!
//! ## Example
//!
//! ```ignore
//! use mlkem_nostd::{Kem, MlKem768};
//!
//! let mut rng = /* a rand_core::CryptoRngCore */;
//! let (ek, dk) = MlKem768::keygen(&mut rng);
//! let (ct, k_send) = MlKem768::encaps(&ek, &mut rng);
//! let k_recv = MlKem768::decaps(&dk, &ct);
//! assert_eq!(k_send, k_recv);
//! ```

#![no_std]
#![forbid(unsafe_code)]
#![allow(clippy::needless_range_loop)]
#![warn(missing_debug_implementations)]
#![warn(unreachable_pub)]

#[cfg(test)]
extern crate std;

pub mod field;
pub mod hash;
pub mod ntt;
pub mod params;
pub mod poly;
pub mod sample;

pub use params::{MlKem1024, MlKem512, MlKem768, ParameterSet};
