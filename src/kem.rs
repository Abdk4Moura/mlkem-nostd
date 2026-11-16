//! The ML-KEM key-encapsulation mechanism of FIPS 203 Section 6
//! (Algorithms 16 to 21), plus the Section 7 input checks.

use core::fmt;
use core::marker::PhantomData;

use rand_core::CryptoRngCore;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::hash;
use crate::kpke;
use crate::params::ParameterSet;
use crate::poly::POLY_BYTES;

/// Maximum encapsulation key size (ML-KEM-1024).
pub const MAX_EK_BYTES: usize = 1568;
/// Maximum decapsulation key size (ML-KEM-1024).
pub const MAX_DK_BYTES: usize = 3168;
/// Maximum ciphertext size (ML-KEM-1024).
pub const MAX_CT_BYTES: usize = 1568;

/// Error returned by the checked byte parsers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvalidKey {
    /// The byte string does not have the length required by the parameter set.
    WrongLength {
        /// Required length in bytes.
        expected: usize,
        /// Supplied length in bytes.
        actual: usize,
    },
    /// The FIPS 203 encapsulation key modulus check failed.
    ModulusCheckFailed,
    /// The FIPS 203 decapsulation key hash check failed.
    HashCheckFailed,
}

impl fmt::Display for InvalidKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongLength { expected, actual } => {
                write!(f, "wrong length: expected {expected} bytes, got {actual}")
            }
            Self::ModulusCheckFailed => f.write_str("encapsulation key modulus check failed"),
            Self::HashCheckFailed => f.write_str("decapsulation key hash check failed"),
        }
    }
}

/// A checked ML-KEM encapsulation (public) key.
///
/// The only way to construct one from bytes is [`EncapsKey::from_bytes`],
/// which enforces the FIPS 203 Section 7 type and modulus checks.
#[derive(Clone, Copy)]
pub struct EncapsKey<P: ParameterSet> {
    bytes: [u8; MAX_EK_BYTES],
    _marker: PhantomData<P>,
}

impl<P: ParameterSet> EncapsKey<P> {
    /// Parse and validate an encapsulation key.
    ///
    /// Performs the type check (length) and the modulus check
    /// `ByteEncode_12(ByteDecode_12(ek)) == ek` on every 384-byte chunk.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, InvalidKey> {
        if bytes.len() != P::EK_BYTES {
            return Err(InvalidKey::WrongLength {
                expected: P::EK_BYTES,
                actual: bytes.len(),
            });
        }

        let mut ok = Choice::from(1u8);
        for i in 0..P::K {
            let chunk = &bytes[i * POLY_BYTES..(i + 1) * POLY_BYTES];
            let mut reencoded = [0u8; POLY_BYTES];
            let poly = crate::poly::Poly::decode_12(chunk.try_into().expect("poly chunk length"));
            poly.encode_12(&mut reencoded);
            ok &= reencoded.as_slice().ct_eq(chunk);
        }
        if ok.unwrap_u8() == 0 {
            return Err(InvalidKey::ModulusCheckFailed);
        }

        Ok(Self::from_bytes_unchecked(bytes))
    }

    fn from_bytes_unchecked(bytes: &[u8]) -> Self {
        let mut out = [0u8; MAX_EK_BYTES];
        out[..P::EK_BYTES].copy_from_slice(&bytes[..P::EK_BYTES]);
        Self {
            bytes: out,
            _marker: PhantomData,
        }
    }

    /// The serialized encapsulation key (`384*k + 32` bytes).
    #[inline]
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..P::EK_BYTES]
    }
}

impl<P: ParameterSet> fmt::Debug for EncapsKey<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EncapsKey<{}>({} bytes)", P::NAME, P::EK_BYTES)
    }
}

/// A checked ML-KEM decapsulation (private) key.
///
/// Construction from bytes runs the FIPS 203 Section 7 hash check. The key is
/// zeroized on drop and the bytes are never exposed through a variable-time
/// formatting routine.
pub struct DecapsKey<P: ParameterSet> {
    bytes: [u8; MAX_DK_BYTES],
    _marker: PhantomData<P>,
}

impl<P: ParameterSet> DecapsKey<P> {
    /// Parse and validate a decapsulation key.
    ///
    /// Performs the type check and the hash check
    /// `H(ek) == h` against the copy of `H(ek)` embedded in the key.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, InvalidKey> {
        if bytes.len() != P::DK_BYTES {
            return Err(InvalidKey::WrongLength {
                expected: P::DK_BYTES,
                actual: bytes.len(),
            });
        }

        let ek_start = P::DK_PKE_BYTES;
        let ek_end = ek_start + P::EK_BYTES;
        let hash_start = ek_end;
        let hash_end = hash_start + 32;
        let computed = hash::h(&bytes[ek_start..ek_end]);
        if computed
            .as_slice()
            .ct_eq(&bytes[hash_start..hash_end])
            .unwrap_u8()
            == 0
        {
            return Err(InvalidKey::HashCheckFailed);
        }

        Ok(Self::from_bytes_unchecked(bytes))
    }

    fn from_bytes_unchecked(bytes: &[u8]) -> Self {
        let mut out = [0u8; MAX_DK_BYTES];
        out[..P::DK_BYTES].copy_from_slice(&bytes[..P::DK_BYTES]);
        Self {
            bytes: out,
            _marker: PhantomData,
        }
    }

    /// The serialized decapsulation key. Treat the result as key material.
    #[inline]
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..P::DK_BYTES]
    }

    #[inline]
    fn dk_pke(&self) -> &[u8] {
        &self.bytes[..P::DK_PKE_BYTES]
    }

    #[inline]
    fn ek_pke(&self) -> &[u8] {
        &self.bytes[P::DK_PKE_BYTES..P::DK_PKE_BYTES + P::EK_BYTES]
    }

    #[inline]
    fn h(&self) -> &[u8] {
        let start = P::DK_PKE_BYTES + P::EK_BYTES;
        &self.bytes[start..start + 32]
    }

    #[inline]
    fn z(&self) -> &[u8] {
        let start = P::DK_PKE_BYTES + P::EK_BYTES + 32;
        &self.bytes[start..start + 32]
    }
}

impl<P: ParameterSet> Zeroize for DecapsKey<P> {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

impl<P: ParameterSet> Drop for DecapsKey<P> {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl<P: ParameterSet> ZeroizeOnDrop for DecapsKey<P> {}

impl<P: ParameterSet> fmt::Debug for DecapsKey<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DecapsKey<{}>(<redacted>)", P::NAME)
    }
}

/// An ML-KEM ciphertext. Public data, but parsed with a length check.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Ciphertext<P: ParameterSet> {
    bytes: [u8; MAX_CT_BYTES],
    _marker: PhantomData<P>,
}

impl<P: ParameterSet> Ciphertext<P> {
    /// Parse a ciphertext, checking its length (FIPS 203 Section 7).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, InvalidKey> {
        if bytes.len() != P::CT_BYTES {
            return Err(InvalidKey::WrongLength {
                expected: P::CT_BYTES,
                actual: bytes.len(),
            });
        }
        let mut out = [0u8; MAX_CT_BYTES];
        out[..P::CT_BYTES].copy_from_slice(bytes);
        Ok(Self {
            bytes: out,
            _marker: PhantomData,
        })
    }

    fn from_bytes_unchecked(bytes: &[u8]) -> Self {
        let mut out = [0u8; MAX_CT_BYTES];
        out[..P::CT_BYTES].copy_from_slice(&bytes[..P::CT_BYTES]);
        Self {
            bytes: out,
            _marker: PhantomData,
        }
    }

    /// The serialized ciphertext (`32*(du*k + dv)` bytes).
    #[inline]
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..P::CT_BYTES]
    }
}

impl<P: ParameterSet> fmt::Debug for Ciphertext<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ciphertext<{}>({} bytes)", P::NAME, P::CT_BYTES)
    }
}

/// A 32-byte ML-KEM shared secret.
///
/// Equality is constant-time, and the bytes are zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret([u8; 32]);

impl SharedSecret {
    /// Borrow the shared secret bytes.
    #[inline]
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl AsRef<[u8]> for SharedSecret {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl ConstantTimeEq for SharedSecret {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl PartialEq for SharedSecret {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for SharedSecret {}

impl fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SharedSecret(<redacted>)")
    }
}

/// The ML-KEM API, implemented for each [`ParameterSet`].
pub trait Kem: ParameterSet {
    /// Encapsulation key type.
    type EncapsKey;
    /// Decapsulation key type.
    type DecapsKey;
    /// Ciphertext type.
    type Ciphertext;

    /// Randomized key generation (FIPS 203 Algorithm 19).
    fn keygen(rng: &mut impl CryptoRngCore) -> (Self::EncapsKey, Self::DecapsKey);

    /// Randomized encapsulation (FIPS 203 Algorithm 20).
    fn encaps(
        ek: &Self::EncapsKey,
        rng: &mut impl CryptoRngCore,
    ) -> (Self::Ciphertext, SharedSecret);

    /// Decapsulation with implicit rejection (FIPS 203 Algorithm 21).
    fn decaps(dk: &Self::DecapsKey, ct: &Self::Ciphertext) -> SharedSecret;
}

impl<P: ParameterSet> Kem for P {
    type EncapsKey = EncapsKey<P>;
    type DecapsKey = DecapsKey<P>;
    type Ciphertext = Ciphertext<P>;

    fn keygen(rng: &mut impl CryptoRngCore) -> (Self::EncapsKey, Self::DecapsKey) {
        let mut seed = [0u8; 64];
        rng.fill_bytes(&mut seed);
        let mut d = [0u8; 32];
        let mut z = [0u8; 32];
        d.copy_from_slice(&seed[..32]);
        z.copy_from_slice(&seed[32..]);
        seed.zeroize();
        let keys = keygen_internal::<P>(&d, &z);
        d.zeroize();
        z.zeroize();
        keys
    }

    fn encaps(
        ek: &Self::EncapsKey,
        rng: &mut impl CryptoRngCore,
    ) -> (Self::Ciphertext, SharedSecret) {
        let mut m = [0u8; 32];
        rng.fill_bytes(&mut m);
        let result = encaps_internal::<P>(ek, &m);
        m.zeroize();
        result
    }

    fn decaps(dk: &Self::DecapsKey, ct: &Self::Ciphertext) -> SharedSecret {
        decaps_internal::<P>(dk, ct)
    }
}

/// Deterministic key generation (FIPS 203 Algorithm 16).
///
/// `d` seeds the K-PKE key pair; `z` is the implicit-rejection secret.
#[must_use]
pub fn keygen_internal<P: ParameterSet>(
    d: &[u8; 32],
    z: &[u8; 32],
) -> (EncapsKey<P>, DecapsKey<P>) {
    let mut ek_bytes = [0u8; MAX_EK_BYTES];
    let mut dk_bytes = [0u8; MAX_DK_BYTES];
    kpke::keygen::<P>(
        d,
        &mut ek_bytes[..P::EK_BYTES],
        &mut dk_bytes[..P::DK_PKE_BYTES],
    );

    dk_bytes[P::DK_PKE_BYTES..P::DK_PKE_BYTES + P::EK_BYTES]
        .copy_from_slice(&ek_bytes[..P::EK_BYTES]);
    let h = hash::h(&ek_bytes[..P::EK_BYTES]);
    let hash_start = P::DK_PKE_BYTES + P::EK_BYTES;
    dk_bytes[hash_start..hash_start + 32].copy_from_slice(&h);
    dk_bytes[hash_start + 32..hash_start + 64].copy_from_slice(z);

    let ek = EncapsKey::<P>::from_bytes_unchecked(&ek_bytes[..P::EK_BYTES]);
    let dk = DecapsKey::<P>::from_bytes_unchecked(&dk_bytes[..P::DK_BYTES]);

    ek_bytes.zeroize();
    dk_bytes.zeroize();
    (ek, dk)
}

/// Deterministic encapsulation (FIPS 203 Algorithm 17).
///
/// `m` is the 32-byte encapsulation randomness. The caller is responsible for
/// using a cryptographically random `m` in production.
#[must_use]
pub fn encaps_internal<P: ParameterSet>(
    ek: &EncapsKey<P>,
    m: &[u8; 32],
) -> (Ciphertext<P>, SharedSecret) {
    let mut g_input = [0u8; 64];
    g_input[..32].copy_from_slice(m);
    g_input[32..].copy_from_slice(&hash::h(ek.as_bytes()));
    let (mut key, r) = hash::g(&g_input);
    g_input.zeroize();

    let mut ct_bytes = [0u8; MAX_CT_BYTES];
    kpke::encrypt::<P>(ek.as_bytes(), m, &r, &mut ct_bytes[..P::CT_BYTES]);

    let ct = Ciphertext::<P>::from_bytes_unchecked(&ct_bytes[..P::CT_BYTES]);
    ct_bytes.zeroize();
    let mut r = r;
    r.zeroize();

    let secret = SharedSecret(key);
    key.zeroize();
    (ct, secret)
}

/// Decapsulation (FIPS 203 Algorithm 18), including implicit rejection.
#[must_use]
pub fn decaps_internal<P: ParameterSet>(dk: &DecapsKey<P>, ct: &Ciphertext<P>) -> SharedSecret {
    let mut m_prime = [0u8; 32];
    kpke::decrypt::<P>(dk.dk_pke(), ct.as_bytes(), &mut m_prime);

    let mut g_input = [0u8; 64];
    g_input[..32].copy_from_slice(&m_prime);
    g_input[32..].copy_from_slice(dk.h());
    let (mut key_prime, r_prime) = hash::g(&g_input);
    g_input.zeroize();

    let mut c_prime = [0u8; MAX_CT_BYTES];
    kpke::encrypt::<P>(dk.ek_pke(), &m_prime, &r_prime, &mut c_prime[..P::CT_BYTES]);

    let mut j_input = [0u8; 32 + MAX_CT_BYTES];
    j_input[..32].copy_from_slice(dk.z());
    j_input[32..32 + P::CT_BYTES].copy_from_slice(ct.as_bytes());
    let mut key_bar = hash::j(&j_input[..32 + P::CT_BYTES]);
    j_input.zeroize();

    let matches = c_prime[..P::CT_BYTES].ct_eq(ct.as_bytes());
    // `SharedSecret` zeroizes on drop, so it cannot be `Copy`; select on the
    // copyable byte array instead, then wrap the result.
    let mut selected = <[u8; 32]>::conditional_select(&key_bar, &key_prime, matches);
    let secret = SharedSecret(selected);
    selected.zeroize();

    m_prime.zeroize();
    key_prime.zeroize();
    key_bar.zeroize();
    c_prime.zeroize();
    let mut r_prime = r_prime;
    r_prime.zeroize();
    secret
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::{MlKem1024, MlKem512, MlKem768};

    fn roundtrip<P: ParameterSet>() {
        let d = [1u8; 32];
        let z = [2u8; 32];
        let (ek, dk) = keygen_internal::<P>(&d, &z);
        assert_eq!(ek.as_bytes().len(), P::EK_BYTES);
        assert_eq!(dk.as_bytes().len(), P::DK_BYTES);

        let ek2 = EncapsKey::<P>::from_bytes(ek.as_bytes()).expect("valid ek");
        let dk2 = DecapsKey::<P>::from_bytes(dk.as_bytes()).expect("valid dk");

        let m = [3u8; 32];
        let (ct, ss1) = encaps_internal::<P>(&ek2, &m);
        let ss2 = decaps_internal::<P>(&dk2, &ct);
        assert_eq!(ss1, ss2);
    }

    #[test]
    fn kem_roundtrip_all_sets() {
        roundtrip::<MlKem512>();
        roundtrip::<MlKem768>();
        roundtrip::<MlKem1024>();
    }

    #[test]
    fn wrong_lengths_are_rejected() {
        assert!(EncapsKey::<MlKem512>::from_bytes(&[0u8; 799]).is_err());
        assert!(DecapsKey::<MlKem512>::from_bytes(&[0u8; 1631]).is_err());
        assert!(Ciphertext::<MlKem512>::from_bytes(&[0u8; 767]).is_err());
    }

    #[test]
    fn modulus_check_rejects_noncanonical_key() {
        let d = [4u8; 32];
        let z = [5u8; 32];
        let (ek, _) = keygen_internal::<MlKem512>(&d, &z);
        let mut bytes = [0u8; MAX_EK_BYTES];
        bytes[..MlKem512::EK_BYTES].copy_from_slice(ek.as_bytes());
        // Force the first 12-bit coefficient to 0xFFF, which is >= q.
        bytes[0] = 0xff;
        bytes[1] = 0x0f;
        assert_eq!(
            EncapsKey::<MlKem512>::from_bytes(&bytes[..MlKem512::EK_BYTES]).unwrap_err(),
            InvalidKey::ModulusCheckFailed
        );
    }

    #[test]
    fn hash_check_rejects_modified_decapsulation_key() {
        let d = [6u8; 32];
        let z = [7u8; 32];
        let (_, dk) = keygen_internal::<MlKem768>(&d, &z);
        let mut bytes = [0u8; MAX_DK_BYTES];
        bytes[..MlKem768::DK_BYTES].copy_from_slice(dk.as_bytes());
        let h_index = MlKem768::DK_PKE_BYTES + MlKem768::EK_BYTES;
        bytes[h_index] ^= 1;
        assert_eq!(
            DecapsKey::<MlKem768>::from_bytes(&bytes[..MlKem768::DK_BYTES]).unwrap_err(),
            InvalidKey::HashCheckFailed
        );
    }

    #[test]
    fn implicit_rejection_is_deterministic_and_different() {
        let d = [8u8; 32];
        let z = [9u8; 32];
        let (ek, dk) = keygen_internal::<MlKem512>(&d, &z);
        let m = [10u8; 32];
        let (ct, ss) = encaps_internal::<MlKem512>(&ek, &m);

        let mut bad = [0u8; MAX_CT_BYTES];
        bad[..MlKem512::CT_BYTES].copy_from_slice(ct.as_bytes());
        bad[0] ^= 1;
        let bad_ct = Ciphertext::<MlKem512>::from_bytes(&bad[..MlKem512::CT_BYTES]).unwrap();
        let rejected_1 = decaps_internal::<MlKem512>(&dk, &bad_ct);
        let rejected_2 = decaps_internal::<MlKem512>(&dk, &bad_ct);
        assert_ne!(rejected_1, ss);
        assert_eq!(rejected_1, rejected_2);
    }
}
