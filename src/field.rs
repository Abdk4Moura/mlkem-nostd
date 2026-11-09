//! Arithmetic modulo `q = 3329`.
//!
//! Every operation is branch-free and uses only fixed-time multiply/shift
//! sequences. There is no division or remainder operation on secret values;
//! see the crate-level constant-time notes.

/// The ML-KEM prime modulus.
pub const Q: u16 = 3329;
/// `q` as a `u32`, for widening expressions.
pub const Q_U32: u32 = Q as u32;
/// `ceil(2^48 / q)`, used for division-free Barrett reduction.
///
/// For any `x < q^2`, `(x * RECIP) >> 48 == x / q` exactly, and for any
/// `x < 2^24` the same holds for the rounded-compression numerator.
const RECIP48: u64 = 84_552_411_148;

/// Reduce a value in `[0, 2q)` to `[0, q)` without branching.
#[inline(always)]
#[must_use]
pub const fn reduce_once(x: u16) -> u16 {
    // If x < q, the wrapped subtraction sets bit 15 and adding q restores x.
    // If q <= x < 2q, the subtraction is exact and the mask is zero.
    let t = x.wrapping_sub(Q);
    t.wrapping_add((t >> 15) * Q)
}

/// Addition modulo `q`. Inputs must be in `[0, q)`.
#[inline(always)]
#[must_use]
pub const fn add(a: u16, b: u16) -> u16 {
    reduce_once(a + b)
}

/// Subtraction modulo `q`. Inputs must be in `[0, q)`.
#[inline(always)]
#[must_use]
pub const fn sub(a: u16, b: u16) -> u16 {
    reduce_once(a + Q - b)
}

/// Negation modulo `q` (zero maps to zero).
#[inline(always)]
#[must_use]
pub const fn neg(a: u16) -> u16 {
    reduce_once(Q - a)
}

/// Multiplication modulo `q` using Barrett reduction.
///
/// `a`, `b` must be in `[0, q)`. The result is in `[0, q)`. The reduction is
/// exact; `field::tests::mul_exhaustive` checks all `q^2` input pairs.
#[inline(always)]
#[must_use]
pub const fn mul(a: u16, b: u16) -> u16 {
    let t = (a as u64) * (b as u64);
    let quotient = (t * RECIP48) >> 48;
    (t - quotient * (Q as u64)) as u16
}

/// `Compress_d(x)` from FIPS 203 Algorithm 5, returning a `d`-bit value.
///
/// Uses a multiply-and-shift reciprocal of `q`; no division is performed.
/// `d` is a public parameter. `x` must be in `[0, q)`.
#[inline(always)]
#[must_use]
pub const fn compress(x: u16, d: u32) -> u16 {
    let numerator = ((x as u64) << d) + ((Q as u64) / 2);
    let rounded = (numerator * RECIP48) >> 48;
    (rounded as u16) & (((1u16) << d) - 1)
}

/// `Decompress_d(y)` from FIPS 203 Algorithm 6.
///
/// `y` must be a `d`-bit value and `d >= 1`. The result is in `[0, q)`.
#[inline(always)]
#[must_use]
pub const fn decompress(y: u16, d: u32) -> u16 {
    let numerator = Q_U32 * (y as u32) + (1u32 << (d - 1));
    (numerator >> d) as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_sub_exhaustive() {
        for a in 0..Q {
            for b in 0..Q {
                let sum = add(a, b);
                assert_eq!(sum as u32, (a as u32 + b as u32) % Q as u32);
                let diff = sub(a, b);
                assert_eq!(
                    diff as i32,
                    (a as i32 - b as i32).rem_euclid(Q as i32),
                    "sub({a}, {b})"
                );
            }
        }
    }

    #[test]
    fn mul_exhaustive() {
        for a in 0..Q {
            for b in 0..Q {
                assert_eq!(
                    mul(a, b) as u32,
                    (a as u32 * b as u32) % Q as u32,
                    "mul({a}, {b})"
                );
            }
        }
    }

    #[test]
    fn neg_is_inverse() {
        for a in 0..Q {
            assert_eq!(add(a, neg(a)), 0);
        }
    }

    #[test]
    fn compress_matches_fips_formula() {
        for d in [1u32, 4, 5, 10, 11] {
            for x in 0..Q {
                let expected = (((x as u32) << d) + Q as u32 / 2) / Q as u32;
                let expected = (expected & ((1 << d) - 1)) as u16;
                assert_eq!(compress(x, d), expected, "compress({x}, {d})");
            }
        }
    }

    #[test]
    fn decompress_matches_fips_formula() {
        for d in [1u32, 4, 5, 10, 11] {
            for y in 0..(1u16 << d) {
                let expected = ((Q as u32 * y as u32 + (1 << (d - 1))) >> d) as u16;
                assert_eq!(decompress(y, d), expected, "decompress({y}, {d})");
            }
        }
    }

    #[test]
    fn compression_error_bound() {
        for d in [1u32, 4, 5, 10, 11] {
            let denom = 1i64 << (d + 1);
            let period = (Q as i64) << d;
            for x in 0..Q {
                let c = compress(x, d);
                // Circular distance between x and q*c/2^d, scaled by 2^d.
                // Compress is allowed to wrap modulo 2^d, so the error must
                // be measured modulo q as FIPS 203 does.
                let diff = ((x as i64) << d) - (Q as i64) * (c as i64);
                let e = diff.rem_euclid(period);
                let centered = e.min(period - e);
                assert!(
                    centered * 2 <= Q as i64,
                    "compress error bound violated for x={x}, d={d}: {centered}"
                );

                // The integer round-trip is within one unit of the bound.
                let back = decompress(c, d);
                let diff = (x as i32 - back as i32).rem_euclid(Q as i32);
                let centered = diff.min(Q as i32 - diff) as i64;
                let bound = (Q as i64 + denom - 1) / denom;
                assert!(
                    centered <= bound,
                    "round-trip error {centered} > {bound} for x={x}, d={d}"
                );
            }
        }
    }
}
