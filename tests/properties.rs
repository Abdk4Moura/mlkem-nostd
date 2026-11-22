//! Property tests for the ML-KEM API.
//!
//! The round-trip property is checked with 10,000 cases per parameter set.
//! Run with `cargo test --release --test properties`.

use proptest::prelude::*;

use mlkem_nostd::hash;
use mlkem_nostd::kem::{decaps_internal, encaps_internal, keygen_internal, Ciphertext};
use mlkem_nostd::{Kem, MlKem1024, MlKem512, MlKem768, ParameterSet};

/// Small deterministic RNG for exercising the public randomized API.
struct TestRng(u64);

impl rand_core::RngCore for TestRng {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(8) {
            let bytes = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl rand_core::CryptoRng for TestRng {}

fn seed32() -> impl Strategy<Value = [u8; 32]> {
    proptest::array::uniform32(any::<u8>())
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 10_000, .. ProptestConfig::default() })]

    #[test]
    fn roundtrip_512(d in seed32(), z in seed32(), m in seed32()) {
        let (ek, dk) = keygen_internal::<MlKem512>(&d, &z);
        let (ct, ss1) = encaps_internal::<MlKem512>(&ek, &m);
        let ss2 = decaps_internal::<MlKem512>(&dk, &ct);
        prop_assert_eq!(ss1.as_bytes(), ss2.as_bytes());
    }

    #[test]
    fn roundtrip_768(d in seed32(), z in seed32(), m in seed32()) {
        let (ek, dk) = keygen_internal::<MlKem768>(&d, &z);
        let (ct, ss1) = encaps_internal::<MlKem768>(&ek, &m);
        let ss2 = decaps_internal::<MlKem768>(&dk, &ct);
        prop_assert_eq!(ss1.as_bytes(), ss2.as_bytes());
    }

    #[test]
    fn roundtrip_1024(d in seed32(), z in seed32(), m in seed32()) {
        let (ek, dk) = keygen_internal::<MlKem1024>(&d, &z);
        let (ct, ss1) = encaps_internal::<MlKem1024>(&ek, &m);
        let ss2 = decaps_internal::<MlKem1024>(&dk, &ct);
        prop_assert_eq!(ss1.as_bytes(), ss2.as_bytes());
    }

    #[test]
    fn implicit_rejection_512(d in seed32(), z in seed32(), m in seed32(), flip in any::<u16>()) {
        let (ek, dk) = keygen_internal::<MlKem512>(&d, &z);
        let (ct, ss) = encaps_internal::<MlKem512>(&ek, &m);
        let mut bytes = [0u8; 768];
        bytes.copy_from_slice(ct.as_bytes());
        let index = (flip as usize) % bytes.len();
        bytes[index] ^= 1;
        let bad = Ciphertext::<MlKem512>::from_bytes(&bytes).unwrap();
        let rejected = decaps_internal::<MlKem512>(&dk, &bad);
        prop_assert_ne!(rejected.as_bytes(), ss.as_bytes());
        let mut j_input = Vec::with_capacity(32 + bytes.len());
        j_input.extend_from_slice(&z);
        j_input.extend_from_slice(bad.as_bytes());
        prop_assert_eq!(rejected.as_bytes(), &hash::j(&j_input));
    }

    #[test]
    fn implicit_rejection_768(d in seed32(), z in seed32(), m in seed32(), flip in any::<u16>()) {
        let (ek, dk) = keygen_internal::<MlKem768>(&d, &z);
        let (ct, ss) = encaps_internal::<MlKem768>(&ek, &m);
        let mut bytes = [0u8; 1088];
        bytes.copy_from_slice(ct.as_bytes());
        let index = (flip as usize) % bytes.len();
        bytes[index] ^= 1;
        let bad = Ciphertext::<MlKem768>::from_bytes(&bytes).unwrap();
        let rejected = decaps_internal::<MlKem768>(&dk, &bad);
        prop_assert_ne!(rejected.as_bytes(), ss.as_bytes());
        let mut j_input = Vec::with_capacity(32 + bytes.len());
        j_input.extend_from_slice(&z);
        j_input.extend_from_slice(bad.as_bytes());
        prop_assert_eq!(rejected.as_bytes(), &hash::j(&j_input));
    }

    #[test]
    fn implicit_rejection_1024(d in seed32(), z in seed32(), m in seed32(), flip in any::<u16>()) {
        let (ek, dk) = keygen_internal::<MlKem1024>(&d, &z);
        let (ct, ss) = encaps_internal::<MlKem1024>(&ek, &m);
        let mut bytes = [0u8; 1568];
        bytes.copy_from_slice(ct.as_bytes());
        let index = (flip as usize) % bytes.len();
        bytes[index] ^= 1;
        let bad = Ciphertext::<MlKem1024>::from_bytes(&bytes).unwrap();
        let rejected = decaps_internal::<MlKem1024>(&dk, &bad);
        prop_assert_ne!(rejected.as_bytes(), ss.as_bytes());
        let mut j_input = Vec::with_capacity(32 + bytes.len());
        j_input.extend_from_slice(&z);
        j_input.extend_from_slice(bad.as_bytes());
        prop_assert_eq!(rejected.as_bytes(), &hash::j(&j_input));
    }
}

#[test]
fn public_randomized_api() {
    let mut rng = TestRng(0x1234_5678_9abc_def0);

    let (ek, dk) = MlKem512::keygen(&mut rng);
    let (ct, k1) = MlKem512::encaps(&ek, &mut rng);
    let k2 = MlKem512::decaps(&dk, &ct);
    assert_eq!(k1, k2);
    assert_eq!(ek.as_bytes().len(), MlKem512::EK_BYTES);
    assert_eq!(dk.as_bytes().len(), MlKem512::DK_BYTES);
    assert_eq!(ct.as_bytes().len(), MlKem512::CT_BYTES);

    let (ek, dk) = MlKem768::keygen(&mut rng);
    let (ct, k1) = MlKem768::encaps(&ek, &mut rng);
    assert_eq!(k1, MlKem768::decaps(&dk, &ct));

    let (ek, dk) = MlKem1024::keygen(&mut rng);
    let (ct, k1) = MlKem1024::encaps(&ek, &mut rng);
    assert_eq!(k1, MlKem1024::decaps(&dk, &ct));
}
