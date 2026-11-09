//! FIPS 203 sampling algorithms: `SampleNTT` (Algorithm 7) and
//! `SamplePolyCBD` (Algorithm 8).

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake128;
use zeroize::Zeroize;

use crate::field::{self, Q};
use crate::hash;
use crate::poly::{Poly, N};

/// `SampleNTT(B)` where the XOF input is `B || col || row`.
///
/// This is `A_hat[row][col]` as defined in FIPS 203 Algorithm 13. The
/// rejection loop and the number of SHAKE blocks depend only on the public
/// seed `rho`.
#[must_use]
pub fn sample_ntt(rho: &[u8; 32], row: u8, col: u8) -> Poly {
    let mut xof = Shake128::default();
    xof.update(rho);
    xof.update(&[col, row]);
    let mut reader = xof.finalize_xof();

    // SHAKE128's rate is 168 bytes, which is divisible by 3, so each block can
    // be parsed independently into 12-bit candidate pairs.
    let mut block = [0u8; 168];
    let mut out = [0u16; N];
    let mut count = 0usize;
    while count < N {
        reader.read(&mut block);
        let mut i = 0usize;
        while i + 2 < block.len() && count < N {
            let b0 = block[i] as u16;
            let b1 = block[i + 1] as u16;
            let b2 = block[i + 2] as u16;
            let d1 = b0 | ((b1 & 0x0f) << 8);
            let d2 = (b1 >> 4) | (b2 << 4);
            if d1 < Q {
                out[count] = d1;
                count += 1;
            }
            if count < N && d2 < Q {
                out[count] = d2;
                count += 1;
            }
            i += 3;
        }
    }
    Poly(out)
}

#[inline(always)]
fn bit(buf: &[u8], index: usize) -> u16 {
    ((buf[index >> 3] >> (index & 7)) & 1) as u16
}

/// `SamplePolyCBD_eta(PRF_eta(s, b))` (FIPS 203 Algorithm 8).
///
/// The loop count is fixed and no branch depends on the seed or its bits.
/// The PRF output is zeroized before returning.
#[must_use]
pub fn sample_poly_cbd(seed: &[u8; 32], eta: usize, counter: u8) -> Poly {
    debug_assert!(eta == 2 || eta == 3);
    let mut prf_output = [0u8; 192];
    let bytes = &mut prf_output[..64 * eta];
    hash::prf(seed, counter, bytes);

    let mut out = [0u16; N];
    for (i, coefficient) in out.iter_mut().enumerate() {
        let base = 2 * eta * i;
        let mut x = 0u16;
        let mut y = 0u16;
        for j in 0..eta {
            x += bit(bytes, base + j);
            y += bit(bytes, base + eta + j);
        }
        *coefficient = field::sub(x, y);
    }
    prf_output.zeroize();
    Poly(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sample_ntt_known_answer() {
        let rho = [0u8; 32];
        assert_eq!(
            &sample_ntt(&rho, 0, 0).0[..8],
            &[2944, 3017, 340, 1184, 3243, 1708, 2458, 2285]
        );
        assert_eq!(
            &sample_ntt(&rho, 1, 2).0[..8],
            &[2215, 657, 881, 1494, 1472, 1073, 1127, 2146]
        );
    }

    #[test]
    fn sample_ntt_coefficients_are_canonical() {
        let rho = [0x42u8; 32];
        for row in 0..4u8 {
            for col in 0..4u8 {
                let p = sample_ntt(&rho, row, col);
                assert!(p.0.iter().all(|&c| c < Q));
            }
        }
    }

    #[test]
    fn sample_cbd_known_answer() {
        let seed = [0u8; 32];
        assert_eq!(
            &sample_poly_cbd(&seed, 2, 0).0[..16],
            &[0, 3327, 0, 2, 3327, 3327, 1, 3328, 1, 3328, 0, 2, 0, 0, 1, 3328]
        );
        assert_eq!(
            &sample_poly_cbd(&seed, 3, 0).0[..16],
            &[0, 0, 2, 0, 1, 0, 0, 1, 0, 3328, 3326, 1, 3328, 3328, 3327, 3328]
        );
    }

    #[test]
    fn sample_cbd_range() {
        let seed = [7u8; 32];
        for eta in [2usize, 3] {
            for counter in 0..8u8 {
                let p = sample_poly_cbd(&seed, eta, counter);
                for &c in &p.0 {
                    let centered = if c as usize > Q as usize / 2 {
                        c as i32 - Q as i32
                    } else {
                        c as i32
                    };
                    assert!(centered.abs() <= eta as i32);
                }
            }
        }
    }
}
