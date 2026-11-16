//! The K-PKE component scheme of FIPS 203 Section 5
//! (Algorithms 13, 14 and 15).

use zeroize::Zeroize;

use crate::field;
use crate::hash;
use crate::ntt::{invntt, multiply_ntts, ntt};
use crate::params::ParameterSet;
use crate::poly::{Poly, POLY_BYTES};
use crate::sample::{sample_ntt, sample_poly_cbd};

/// The largest module rank supported: ML-KEM-1024 has `k = 4`.
pub const MAX_K: usize = 4;

#[inline]
fn poly_chunk(bytes: &[u8], index: usize) -> &[u8; POLY_BYTES] {
    bytes[index * POLY_BYTES..(index + 1) * POLY_BYTES]
        .try_into()
        .expect("poly chunk length")
}

#[inline]
fn poly_chunk_mut(bytes: &mut [u8], index: usize) -> &mut [u8; POLY_BYTES] {
    let chunk: &mut [u8] = &mut bytes[index * POLY_BYTES..(index + 1) * POLY_BYTES];
    chunk.try_into().expect("poly chunk length")
}

/// `K-PKE.KeyGen` (FIPS 203 Algorithm 13).
///
/// Writes `384*k + 32` bytes to `ek` and `384*k` bytes to `dk`.
pub fn keygen<P: ParameterSet>(d: &[u8; 32], ek: &mut [u8], dk: &mut [u8]) {
    debug_assert_eq!(ek.len(), P::EK_BYTES);
    debug_assert_eq!(dk.len(), P::DK_PKE_BYTES);

    let mut g_input = [0u8; 33];
    g_input[..32].copy_from_slice(d);
    g_input[32] = P::K as u8;
    let (mut rho, mut sigma) = hash::g(&g_input);
    g_input.zeroize();

    let mut s = [Poly::zero(); MAX_K];
    let mut e = [Poly::zero(); MAX_K];
    for i in 0..P::K {
        s[i] = sample_poly_cbd(&sigma, P::ETA1, i as u8);
        e[i] = sample_poly_cbd(&sigma, P::ETA1, (P::K + i) as u8);
    }

    let mut s_hat = s;
    let mut e_hat = e;
    for i in 0..P::K {
        ntt(&mut s_hat[i]);
        ntt(&mut e_hat[i]);
    }

    for i in 0..P::K {
        let mut acc = Poly::zero();
        for j in 0..P::K {
            let a = sample_ntt(&rho, i as u8, j as u8);
            let product = multiply_ntts(&a, &s_hat[j]);
            acc.add_assign(&product);
            let mut product = product;
            product.zeroize();
        }
        acc.add_assign(&e_hat[i]);
        acc.encode_12(poly_chunk_mut(ek, i));
        acc.zeroize();
    }
    ek[P::DK_PKE_BYTES..].copy_from_slice(&rho);

    for i in 0..P::K {
        s_hat[i].encode_12(poly_chunk_mut(dk, i));
    }

    s.zeroize();
    e.zeroize();
    s_hat.zeroize();
    e_hat.zeroize();
    sigma.zeroize();
    rho.zeroize();
}

/// `K-PKE.Encrypt` (FIPS 203 Algorithm 14).
///
/// `ek` is the serialized K-PKE encryption key, `m` is the 32-byte message
/// polynomial seed, and `r` is the 32-byte encryption randomness. Writes
/// `32*(du*k + dv)` bytes to `ct`.
pub fn encrypt<P: ParameterSet>(ek: &[u8], m: &[u8; 32], r: &[u8; 32], ct: &mut [u8]) {
    debug_assert_eq!(ek.len(), P::EK_BYTES);
    debug_assert_eq!(ct.len(), P::CT_BYTES);

    let mut t_hat = [Poly::zero(); MAX_K];
    for i in 0..P::K {
        t_hat[i] = Poly::decode_12(poly_chunk(ek, i));
    }
    let rho: &[u8; 32] = ek[P::DK_PKE_BYTES..].try_into().expect("rho length");
    let _ = rho;

    let mut y = [Poly::zero(); MAX_K];
    let mut e1 = [Poly::zero(); MAX_K];
    for i in 0..P::K {
        y[i] = sample_poly_cbd(r, P::ETA1, i as u8);
        e1[i] = sample_poly_cbd(r, P::ETA2, (P::K + i) as u8);
    }
    let mut e2 = sample_poly_cbd(r, P::ETA2, (2 * P::K) as u8);

    let mut y_hat = y;
    for i in 0..P::K {
        ntt(&mut y_hat[i]);
    }

    for i in 0..P::K {
        let mut acc = Poly::zero();
        for j in 0..P::K {
            // (A^T)[i][j] = A[j][i] = SampleNTT(rho || i || j).
            let a = sample_ntt(rho, j as u8, i as u8);
            let product = multiply_ntts(&a, &y_hat[j]);
            acc.add_assign(&product);
            let mut product = product;
            product.zeroize();
        }
        invntt(&mut acc);
        acc.add_assign(&e1[i]);
        let compressed = acc.compress(P::DU);
        compressed.encode_d(P::DU, &mut ct[32 * P::DU * i..32 * P::DU * (i + 1)]);
        acc.zeroize();
    }

    let mut v = Poly::zero();
    for i in 0..P::K {
        let product = multiply_ntts(&t_hat[i], &y_hat[i]);
        v.add_assign(&product);
        let mut product = product;
        product.zeroize();
    }
    invntt(&mut v);
    v.add_assign(&e2);
    v.add_assign(&Poly::decode_1_decompress(m));

    let mut compressed = v.compress(P::DV);
    compressed.encode_d(P::DV, &mut ct[32 * P::DU * P::K..]);

    t_hat.zeroize();
    y.zeroize();
    e1.zeroize();
    y_hat.zeroize();
    e2.zeroize();
    v.zeroize();
    compressed.zeroize();
}

/// `K-PKE.Decrypt` (FIPS 203 Algorithm 15).
///
/// `dk` is the `384*k`-byte K-PKE decryption key. Writes the 32-byte message
/// into `m`.
pub fn decrypt<P: ParameterSet>(dk: &[u8], ct: &[u8], m: &mut [u8; 32]) {
    debug_assert_eq!(dk.len(), P::DK_PKE_BYTES);
    debug_assert_eq!(ct.len(), P::CT_BYTES);

    let mut s_hat = [Poly::zero(); MAX_K];
    for i in 0..P::K {
        s_hat[i] = Poly::decode_12(poly_chunk(dk, i));
    }

    let mut u_hat = [Poly::zero(); MAX_K];
    for i in 0..P::K {
        u_hat[i] =
            Poly::decode_d(P::DU, &ct[32 * P::DU * i..32 * P::DU * (i + 1)]).decompress(P::DU);
        ntt(&mut u_hat[i]);
    }
    let mut v = Poly::decode_d(P::DV, &ct[32 * P::DU * P::K..]).decompress(P::DV);

    let mut acc = Poly::zero();
    for i in 0..P::K {
        let product = multiply_ntts(&s_hat[i], &u_hat[i]);
        acc.add_assign(&product);
        let mut product = product;
        product.zeroize();
    }
    invntt(&mut acc);
    v.sub_assign(&acc);
    v.compress_1_encode(m);

    s_hat.zeroize();
    u_hat.zeroize();
    v.zeroize();
    acc.zeroize();
}

/// Compile-time check that the polynomial arithmetic is not accidentally
/// using a different modulus.
const _: () = assert!(field::Q == 3329);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::{MlKem1024, MlKem512, MlKem768};

    fn roundtrip<P: ParameterSet>(d: [u8; 32], m: [u8; 32], r: [u8; 32]) {
        let mut ek = [0u8; 1568];
        let mut dk = [0u8; 1536];
        let mut ct = [0u8; 1568];
        keygen::<P>(&d, &mut ek[..P::EK_BYTES], &mut dk[..P::DK_PKE_BYTES]);
        encrypt::<P>(&ek[..P::EK_BYTES], &m, &r, &mut ct[..P::CT_BYTES]);
        let mut recovered = [0u8; 32];
        decrypt::<P>(&dk[..P::DK_PKE_BYTES], &ct[..P::CT_BYTES], &mut recovered);
        assert_eq!(recovered, m);
    }

    #[test]
    fn kpke_roundtrip_all_sets() {
        roundtrip::<MlKem512>([1u8; 32], [2u8; 32], [3u8; 32]);
        roundtrip::<MlKem768>([4u8; 32], [5u8; 32], [6u8; 32]);
        roundtrip::<MlKem1024>([7u8; 32], [8u8; 32], [9u8; 32]);
    }
}
