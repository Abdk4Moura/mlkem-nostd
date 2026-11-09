//! The number-theoretic transform of FIPS 203 Section 4.3
//! (Algorithms 9 to 12), with `zeta = 17`.

use crate::field::{add, mul, sub};
use crate::poly::{Poly, N};

/// `BitRev7` from FIPS 203 Section 4.3.
const fn bitrev7(x: usize) -> usize {
    let mut result = 0usize;
    let mut i = 0;
    while i < 7 {
        result = (result << 1) | ((x >> i) & 1);
        i += 1;
    }
    result
}

/// Modular exponentiation with a public exponent, used to build the tables
/// at compile time.
const fn pow_mod(mut base: u32, mut exponent: u32) -> u16 {
    let mut result = 1u32;
    base %= 3329;
    while exponent > 0 {
        if exponent & 1 == 1 {
            result = (result * base) % 3329;
        }
        base = (base * base) % 3329;
        exponent >>= 1;
    }
    result as u16
}

const fn make_zetas() -> [u16; 128] {
    let mut table = [0u16; 128];
    let mut i = 0;
    while i < 128 {
        table[i] = pow_mod(17, bitrev7(i) as u32);
        i += 1;
    }
    table
}

const fn make_gammas() -> [u16; 128] {
    let mut table = [0u16; 128];
    let mut i = 0;
    while i < 128 {
        table[i] = pow_mod(17, (2 * bitrev7(i) + 1) as u32);
        i += 1;
    }
    table
}

/// `zeta^{BitRev7(i)} mod q`; index 0 is unused by the transform.
pub const ZETAS: [u16; 128] = make_zetas();
/// `zeta^{2*BitRev7(i)+1} mod q`, the twiddle of `BaseCaseMultiply`.
pub const GAMMAS: [u16; 128] = make_gammas();

/// `NTT` (FIPS 203 Algorithm 9), in place.
pub fn ntt(f: &mut Poly) {
    let mut i = 1usize;
    let mut len = 128usize;
    while len >= 2 {
        let mut start = 0usize;
        while start < N {
            let zeta = ZETAS[i];
            i += 1;
            for j in start..start + len {
                let t = mul(zeta, f.0[j + len]);
                f.0[j + len] = sub(f.0[j], t);
                f.0[j] = add(f.0[j], t);
            }
            start += 2 * len;
        }
        len >>= 1;
    }
}

/// `NTT^{-1}` (FIPS 203 Algorithm 10), in place.
///
/// The inverse uses the forward zeta table in reverse order, then scales by
/// `3303 = 128^{-1} mod q`, exactly as the standard specifies.
pub fn invntt(f: &mut Poly) {
    let mut i = 127usize;
    let mut len = 2usize;
    while len <= 128 {
        let mut start = 0usize;
        while start < N {
            let zeta = ZETAS[i];
            i -= 1;
            for j in start..start + len {
                let t = f.0[j];
                f.0[j] = add(t, f.0[j + len]);
                f.0[j + len] = mul(zeta, sub(f.0[j + len], t));
            }
            start += 2 * len;
        }
        len <<= 1;
    }
    for c in &mut f.0 {
        *c = mul(*c, 3303);
    }
}

/// `MultiplyNTTs` (FIPS 203 Algorithm 11).
#[must_use]
pub fn multiply_ntts(a: &Poly, b: &Poly) -> Poly {
    let mut c = Poly::zero();
    let mut i = 0usize;
    while i < 128 {
        let gamma = GAMMAS[i];
        let a0 = a.0[2 * i];
        let a1 = a.0[2 * i + 1];
        let b0 = b.0[2 * i];
        let b1 = b.0[2 * i + 1];
        c.0[2 * i] = add(mul(a0, b0), mul(mul(a1, b1), gamma));
        c.0[2 * i + 1] = add(mul(a0, b1), mul(a1, b0));
        i += 1;
    }
    c
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::Q;

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
    fn zeta_table_matches_fips() {
        assert_eq!(ZETAS[0], 1);
        assert_eq!(ZETAS[1], 1729);
        assert_eq!(ZETAS[2], 2580);
        assert_eq!(ZETAS[127], 2154);
        assert_eq!(GAMMAS[0], 17);
        assert_eq!(GAMMAS[1], 3312);
    }

    #[test]
    fn ntt_roundtrip() {
        for seed in 0..16 {
            let original = sample_poly(seed);
            let mut transformed = original;
            ntt(&mut transformed);
            invntt(&mut transformed);
            assert_eq!(transformed, original, "seed {seed}");
        }
    }

    fn naive_multiply(a: &Poly, b: &Poly) -> Poly {
        let mut out = [0u16; N];
        for i in 0..N {
            for j in 0..N {
                let product = mul(a.0[i], b.0[j]);
                let k = i + j;
                if k < N {
                    out[k] = add(out[k], product);
                } else {
                    out[k - N] = sub(out[k - N], product);
                }
            }
        }
        Poly(out)
    }

    #[test]
    fn multiply_ntts_matches_negacyclic_convolution() {
        for seed in 0..4 {
            let a = sample_poly(seed);
            let b = sample_poly(seed + 100);
            let mut a_hat = a;
            let mut b_hat = b;
            ntt(&mut a_hat);
            ntt(&mut b_hat);
            let mut product = multiply_ntts(&a_hat, &b_hat);
            invntt(&mut product);
            assert_eq!(product, naive_multiply(&a, &b), "seed {seed}");
        }
    }
}
