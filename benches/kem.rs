//! Criterion benchmarks: ours versus RustCrypto `ml-kem` 0.3.
//!
//! Deterministic internal entry points are used on both sides so the numbers
//! exclude RNG cost and measure the ML-KEM work itself.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ml_kem::{
    Ciphertext as RefCiphertext, Decapsulate, DecapsulationKey, MlKem1024 as Ref1024,
    MlKem512 as Ref512, MlKem768 as Ref768, B32,
};

use mlkem_nostd::kem::{decaps_internal, encaps_internal, keygen_internal};
use mlkem_nostd::{MlKem1024, MlKem512, MlKem768};

macro_rules! bench_set {
    ($group:expr, $name:literal, $ours:ty, $reference:ty) => {{
        let d = [0x11u8; 32];
        let z = [0x22u8; 32];
        let m = [0x33u8; 32];

        let (ek, dk) = keygen_internal::<$ours>(&d, &z);
        let (ct, _ss) = encaps_internal::<$ours>(&ek, &m);

        let mut seed = [0u8; 64];
        seed[..32].copy_from_slice(&d);
        seed[32..].copy_from_slice(&z);
        let reference_dk = DecapsulationKey::<$reference>::from_seed(seed.into());
        let reference_ek = reference_dk.encapsulation_key().clone();
        let reference_ct = RefCiphertext::<$reference>::try_from(ct.as_bytes()).unwrap();

        $group.bench_function(concat!($name, "/keygen/ours"), |b| {
            b.iter(|| black_box(keygen_internal::<$ours>(black_box(&d), black_box(&z))))
        });
        $group.bench_function(concat!($name, "/keygen/rustcrypto"), |b| {
            b.iter(|| {
                black_box(DecapsulationKey::<$reference>::from_seed(
                    black_box(seed).into(),
                ))
            })
        });
        $group.bench_function(concat!($name, "/encaps/ours"), |b| {
            b.iter(|| black_box(encaps_internal::<$ours>(black_box(&ek), black_box(&m))))
        });
        $group.bench_function(concat!($name, "/encaps/rustcrypto"), |b| {
            b.iter(|| black_box(reference_ek.encapsulate_deterministic(black_box(&B32::from(m)))))
        });
        $group.bench_function(concat!($name, "/decaps/ours"), |b| {
            b.iter(|| black_box(decaps_internal::<$ours>(black_box(&dk), black_box(&ct))))
        });
        $group.bench_function(concat!($name, "/decaps/rustcrypto"), |b| {
            b.iter(|| black_box(reference_dk.decapsulate(black_box(&reference_ct))))
        });
    }};
}

fn benchmarks(c: &mut Criterion) {
    bench_set!(c, "ml-kem-512", MlKem512, Ref512);
    bench_set!(c, "ml-kem-768", MlKem768, Ref768);
    bench_set!(c, "ml-kem-1024", MlKem1024, Ref1024);
}

criterion_group!(benches, benchmarks);
criterion_main!(benches);
