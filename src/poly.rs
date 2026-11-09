//! Polynomials with 256 coefficients modulo `q`, and the FIPS 203
//! byte encoding, decoding, compression and decompression algorithms.

use zeroize::Zeroize;

use crate::field::{self, Q};

/// Number of coefficients in a polynomial.
pub const N: usize = 256;
/// Serialized size of a degree-12 polynomial (`ByteEncode_12`).
pub const POLY_BYTES: usize = 384;

/// A polynomial in `R_q = Z_q[X]/(X^256 + 1)`.
///
/// Coefficients are always kept in canonical form `[0, q)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Zeroize)]
pub struct Poly(pub [u16; N]);

impl Default for Poly {
    fn default() -> Self {
        Self::zero()
    }
}

impl Poly {
    /// The zero polynomial.
    #[inline]
    #[must_use]
    pub const fn zero() -> Self {
        Self([0u16; N])
    }

    /// Construct from raw coefficients. The caller must ensure they are
    /// canonical (`< q`).
    #[inline]
    #[must_use]
    pub const fn from_coeffs(coeffs: [u16; N]) -> Self {
        Self(coeffs)
    }

    /// Borrow the coefficients.
    #[inline]
    #[must_use]
    pub const fn coeffs(&self) -> &[u16; N] {
        &self.0
    }

    /// Mutably borrow the coefficients.
    #[inline]
    #[must_use]
    pub fn coeffs_mut(&mut self) -> &mut [u16; N] {
        &mut self.0
    }

    /// Coefficient-wise addition.
    #[inline]
    pub fn add_assign(&mut self, other: &Self) {
        for i in 0..N {
            self.0[i] = field::add(self.0[i], other.0[i]);
        }
    }

    /// Coefficient-wise subtraction.
    #[inline]
    pub fn sub_assign(&mut self, other: &Self) {
        for i in 0..N {
            self.0[i] = field::sub(self.0[i], other.0[i]);
        }
    }

    /// Coefficient-wise negation.
    #[inline]
    pub fn neg_assign(&mut self) {
        for c in &mut self.0 {
            *c = field::neg(*c);
        }
    }

    /// `ByteEncode_12` from FIPS 203 Algorithm 5.
    #[inline]
    pub fn encode_12(&self, out: &mut [u8; POLY_BYTES]) {
        let mut acc: u32 = 0;
        let mut bits: u32 = 0;
        let mut index = 0usize;
        for &c in &self.0 {
            debug_assert!(c < Q);
            acc |= (c as u32) << bits;
            bits += 12;
            // 256 * 12 bits is exactly 384 bytes, so this flushes evenly.
            while bits >= 8 {
                out[index] = acc as u8;
                index += 1;
                acc >>= 8;
                bits -= 8;
            }
        }
        debug_assert_eq!(index, POLY_BYTES);
        debug_assert_eq!(bits, 0);
    }

    /// `ByteDecode_12` from FIPS 203 Algorithm 6.
    ///
    /// Values in `[q, 2^12)` are reduced modulo `q` as the standard requires.
    #[inline]
    #[must_use]
    pub fn decode_12(bytes: &[u8; POLY_BYTES]) -> Self {
        let mut out = [0u16; N];
        let mut acc: u32 = 0;
        let mut bits: u32 = 0;
        let mut index = 0usize;
        for &byte in bytes {
            acc |= (byte as u32) << bits;
            bits += 8;
            while bits >= 12 {
                let value = (acc & 0x0fff) as u16;
                out[index] = field::reduce_once(value);
                index += 1;
                acc >>= 12;
                bits -= 12;
            }
        }
        debug_assert_eq!(index, N);
        Self(out)
    }

    /// `ByteEncode_d` for `d < 12`. `out` must be exactly `32*d` bytes.
    #[inline]
    pub fn encode_d(&self, d: usize, out: &mut [u8]) {
        debug_assert!((1..12).contains(&d));
        debug_assert_eq!(out.len(), 32 * d);
        let mut acc: u32 = 0;
        let mut bits: u32 = 0;
        let mut index = 0usize;
        for &c in &self.0 {
            debug_assert!((c as usize) < (1usize << d));
            acc |= (c as u32) << bits;
            bits += d as u32;
            while bits >= 8 {
                out[index] = acc as u8;
                index += 1;
                acc >>= 8;
                bits -= 8;
            }
        }
        if bits > 0 {
            out[index] = acc as u8;
            index += 1;
        }
        debug_assert_eq!(index, out.len());
    }

    /// `ByteDecode_d` for `d < 12`. `bytes` must be exactly `32*d` bytes.
    #[inline]
    #[must_use]
    pub fn decode_d(d: usize, bytes: &[u8]) -> Self {
        debug_assert!((1..12).contains(&d));
        debug_assert_eq!(bytes.len(), 32 * d);
        let mask = (1u32 << d) - 1;
        let mut out = [0u16; N];
        let mut acc: u32 = 0;
        let mut bits: u32 = 0;
        let mut index = 0usize;
        for &byte in bytes {
            acc |= (byte as u32) << bits;
            bits += 8;
            while bits >= d as u32 {
                out[index] = (acc & mask) as u16;
                index += 1;
                acc >>= d;
                bits -= d as u32;
            }
        }
        debug_assert_eq!(index, N);
        Self(out)
    }

    /// `Compress_d` coefficient-wise (FIPS 203 Algorithm 5).
    #[inline]
    #[must_use]
    pub fn compress(&self, d: usize) -> Self {
        let mut out = [0u16; N];
        for i in 0..N {
            out[i] = field::compress(self.0[i], d as u32);
        }
        Self(out)
    }

    /// `Decompress_d` coefficient-wise (FIPS 203 Algorithm 6).
    #[inline]
    #[must_use]
    pub fn decompress(&self, d: usize) -> Self {
        let mut out = [0u16; N];
        for i in 0..N {
            out[i] = field::decompress(self.0[i], d as u32);
        }
        Self(out)
    }

    /// Encode a 1-bit message polynomial: `ByteEncode_1(Compress_1(w))`.
    #[inline]
    pub fn compress_1_encode(&self, out: &mut [u8; 32]) {
        let mut acc: u8 = 0;
        for i in 0..N {
            let bit = field::compress(self.0[i], 1) as u8;
            acc |= bit << (i & 7);
            if (i & 7) == 7 {
                out[i >> 3] = acc;
                acc = 0;
            }
        }
    }

    /// Decode a 1-bit message polynomial and decompress it to `{0, (q+1)/2}`.
    #[inline]
    #[must_use]
    pub fn decode_1_decompress(bytes: &[u8; 32]) -> Self {
        let mut out = [0u16; N];
        for i in 0..N {
            let bit = ((bytes[i >> 3] >> (i & 7)) & 1) as u16;
            out[i] = field::decompress(bit, 1);
        }
        Self(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_poly(seed: u32) -> Poly {
        let mut x = seed;
        let mut p = [0u16; N];
        for c in &mut p {
            x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            *c = (x % Q as u32) as u16;
        }
        Poly(p)
    }

    #[test]
    fn encode_decode_12_roundtrip() {
        for seed in 0..8 {
            let p = sample_poly(seed);
            let mut bytes = [0u8; POLY_BYTES];
            p.encode_12(&mut bytes);
            assert_eq!(Poly::decode_12(&bytes), p);
        }
    }

    #[test]
    fn decode_12_reduces_noncanonical_values() {
        // 0xFFF (4095) reduces to 4095 - 3329 = 766.
        let mut bytes = [0u8; POLY_BYTES];
        bytes[0] = 0xff;
        bytes[1] = 0x0f;
        let p = Poly::decode_12(&bytes);
        assert_eq!(p.0[0], 766);
    }

    #[test]
    fn encode_decode_d_roundtrip() {
        for d in [4usize, 5, 10, 11] {
            for seed in 0..4 {
                let p = sample_poly(seed).compress(d);
                let mut bytes = [0u8; 352];
                let bytes = &mut bytes[..32 * d];
                p.encode_d(d, bytes);
                assert_eq!(Poly::decode_d(d, bytes), p, "d={d} seed={seed}");
            }
        }
    }

    #[test]
    fn one_bit_message_roundtrip() {
        let mut bits = [0u8; 32];
        for (i, b) in bits.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(37);
        }
        let p = Poly::decode_1_decompress(&bits);
        let mut out = [0u8; 32];
        p.compress_1_encode(&mut out);
        assert_eq!(out, bits);
    }

    #[test]
    fn add_sub_are_inverse() {
        let a = sample_poly(1);
        let b = sample_poly(2);
        let mut c = a;
        c.add_assign(&b);
        c.sub_assign(&b);
        assert_eq!(c, a);
        for i in 0..N {
            assert!(c.0[i] < Q);
        }
    }
}
