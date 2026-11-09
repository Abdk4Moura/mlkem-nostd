//! The symmetric primitives of FIPS 203 Section 4.1, built on the RustCrypto
//! `sha3` crate.
//!
//! * `H` is SHA3-256.
//! * `G` is SHA3-512, split into two 32-byte halves.
//! * `J` and `PRF` are SHAKE256.
//! * `XOF` is SHAKE128.

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Digest, Sha3_256, Sha3_512, Shake256};

/// `H(x) = SHA3-256(x)`.
#[must_use]
pub fn h(input: &[u8]) -> [u8; 32] {
    let digest = Sha3_256::digest(input);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// `G(x) = SHA3-512(x)`, split into two 32-byte outputs.
#[must_use]
pub fn g(input: &[u8]) -> ([u8; 32], [u8; 32]) {
    let digest = Sha3_512::digest(input);
    let mut left = [0u8; 32];
    let mut right = [0u8; 32];
    left.copy_from_slice(&digest[..32]);
    right.copy_from_slice(&digest[32..]);
    (left, right)
}

/// `J(x) = SHAKE256(x, 32)`, used for implicit rejection.
#[must_use]
pub fn j(input: &[u8]) -> [u8; 32] {
    let mut shake = Shake256::default();
    shake.update(input);
    let mut reader = shake.finalize_xof();
    let mut out = [0u8; 32];
    reader.read(&mut out);
    out
}

/// `PRF_eta(s, b) = SHAKE256(s || b, 64*eta)`.
pub fn prf(seed: &[u8; 32], counter: u8, out: &mut [u8]) {
    let mut shake = Shake256::default();
    shake.update(seed);
    shake.update(&[counter]);
    let mut reader = shake.finalize_xof();
    reader.read(out);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha3_256_known_answer() {
        assert_eq!(
            hex::encode(h(b"abc")),
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
        );
    }

    #[test]
    fn sha3_512_known_answer() {
        let (left, right) = g(b"abc");
        assert_eq!(
            hex::encode([left, right].concat()),
            "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e\
             10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
        );
    }
}
