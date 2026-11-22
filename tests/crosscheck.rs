//! Cross-check against the RustCrypto `ml-kem` implementation.
//!
//! For identical seeds, our deterministic key generation, encapsulation and
//! decapsulation must be byte-for-byte identical to `ml-kem` 0.3.

#![allow(deprecated)]

use ml_kem::{
    Ciphertext as RefCiphertext, Decapsulate, DecapsulationKey, ExpandedKeyEncoding, KeyExport,
    MlKem1024 as Ref1024, MlKem512 as Ref512, MlKem768 as Ref768, B32,
};

use mlkem_nostd::kem::{decaps_internal, encaps_internal, keygen_internal, Ciphertext};
use mlkem_nostd::{MlKem1024, MlKem512, MlKem768, ParameterSet};

struct XorShift(u64);

impl XorShift {
    fn fill(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(8) {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            let bytes = x.to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
    }
}

macro_rules! crosscheck {
    ($ours:ty, $reference:ty) => {{
        for round in 0..8u64 {
            let mut rng = XorShift(0x9e37_79b9_7f4a_7c15 ^ round.wrapping_mul(0x1234_5678));
            let mut d = [0u8; 32];
            let mut z = [0u8; 32];
            let mut m = [0u8; 32];
            rng.fill(&mut d);
            rng.fill(&mut z);
            rng.fill(&mut m);

            let (ek, dk) = keygen_internal::<$ours>(&d, &z);

            let mut seed = [0u8; 64];
            seed[..32].copy_from_slice(&d);
            seed[32..].copy_from_slice(&z);
            let reference_dk = DecapsulationKey::<$reference>::from_seed(seed.into());
            let reference_ek = reference_dk.encapsulation_key();

            assert_eq!(
                ek.as_bytes(),
                reference_ek.to_bytes().as_slice(),
                "{} ek round {round}",
                <$ours>::NAME
            );
            assert_eq!(
                dk.as_bytes(),
                reference_dk.to_expanded_bytes().as_slice(),
                "{} dk round {round}",
                <$ours>::NAME
            );

            let (ct, ss) = encaps_internal::<$ours>(&ek, &m);
            let (reference_ct, reference_ss) =
                reference_ek.encapsulate_deterministic(&B32::from(m));
            assert_eq!(
                ct.as_bytes(),
                reference_ct.as_slice(),
                "{} ciphertext round {round}",
                <$ours>::NAME
            );
            assert_eq!(
                ss.as_bytes(),
                reference_ss.as_slice(),
                "{} shared secret round {round}",
                <$ours>::NAME
            );

            let reference_ct = RefCiphertext::<$reference>::try_from(ct.as_bytes()).unwrap();
            let reference_decaps = reference_dk.decapsulate(&reference_ct);
            let our_decaps = decaps_internal::<$ours>(&dk, &ct);
            assert_eq!(
                our_decaps.as_bytes(),
                reference_decaps.as_slice(),
                "{} decapsulation round {round}",
                <$ours>::NAME
            );

            // Parse the reference implementation's ciphertext through our
            // checked type as an additional interoperability check.
            let our_ct = Ciphertext::<$ours>::from_bytes(reference_ct.as_slice()).unwrap();
            assert_eq!(
                decaps_internal::<$ours>(&dk, &our_ct).as_bytes(),
                reference_ss.as_slice()
            );
        }
    }};
}

#[test]
fn keys_ciphertexts_and_secrets_match_rustcrypto() {
    crosscheck!(MlKem512, Ref512);
    crosscheck!(MlKem768, Ref768);
    crosscheck!(MlKem1024, Ref1024);
}
