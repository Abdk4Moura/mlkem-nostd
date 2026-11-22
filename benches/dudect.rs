//! Dudect-style timing tests.
//!
//! Run with:
//! ```text
//! DUDECT_SAMPLES=1000000 cargo bench --bench dudect -- --filter decaps
//! ```
//!
//! `DUDECT_SAMPLES` is the total number of measurements (default 1,000,000,
//! split roughly evenly between the two classes).

use std::hint::black_box;

use dudect_bencher::ctbench::{run_benches_console, BenchMetadata, BenchName, BenchOpts};
use dudect_bencher::{rand::RngExt, BenchRng, Class, CtRunner};
use mlkem_nostd::kem::{decaps_internal, encaps_internal, keygen_internal, Ciphertext};
use mlkem_nostd::poly::Poly;
use mlkem_nostd::{MlKem1024, ParameterSet};

const DEFAULT_SAMPLES: usize = 1_000_000;
const INPUTS: usize = 64;

fn sample_count() -> usize {
    std::env::var("DUDECT_SAMPLES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(DEFAULT_SAMPLES)
}

/// Valid ciphertexts versus ciphertexts with one flipped byte. This exercises
/// the implicit-rejection comparison and constant-time key selection.
fn decaps_valid_vs_rejected(runner: &mut CtRunner, rng: &mut BenchRng) {
    let d = [0x51u8; 32];
    let z = [0x52u8; 32];
    let (ek, dk) = keygen_internal::<MlKem1024>(&d, &z);

    let mut valid = Vec::with_capacity(INPUTS);
    let mut rejected = Vec::with_capacity(INPUTS);
    for i in 0..INPUTS {
        let m = [i as u8; 32];
        let (ct, _) = encaps_internal::<MlKem1024>(&ek, &m);
        let mut bad = [0u8; MlKem1024::CT_BYTES];
        bad.copy_from_slice(ct.as_bytes());
        bad[0] ^= 1;
        valid.push(ct);
        rejected.push(Ciphertext::<MlKem1024>::from_bytes(&bad).unwrap());
    }

    for _ in 0..sample_count() {
        let class = if rng.random::<bool>() {
            Class::Left
        } else {
            Class::Right
        };
        let index = (rng.random::<u32>() as usize) % INPUTS;
        let ct = match class {
            Class::Left => &valid[index],
            Class::Right => &rejected[index],
        };
        runner.run_one(class, || {
            black_box(decaps_internal::<MlKem1024>(&dk, black_box(ct)));
        });
    }
}

/// `Compress_d` on uniformly random secret coefficients versus extreme
/// coefficients. The implementation must not branch on the coefficients.
fn compress_secret_inputs(runner: &mut CtRunner, rng: &mut BenchRng) {
    let mut random = Vec::with_capacity(INPUTS);
    let mut extreme = Vec::with_capacity(INPUTS);
    for _ in 0..INPUTS {
        let mut coeffs = [0u16; 256];
        for c in &mut coeffs {
            *c = rng.random::<u16>() % 3329;
        }
        random.push(Poly(coeffs));
        extreme.push(Poly([3328u16; 256]));
    }

    for _ in 0..sample_count() {
        let class = if rng.random::<bool>() {
            Class::Left
        } else {
            Class::Right
        };
        let index = (rng.random::<u32>() as usize) % INPUTS;
        let poly = match class {
            Class::Left => &random[index],
            Class::Right => &extreme[index],
        };
        runner.run_one(class, || {
            black_box(poly.compress(10));
        });
    }
}

fn main() {
    // `cargo bench` appends `--bench` to the harness arguments; drop it.
    let mut opts = BenchOpts::default();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--bench" => {}
            "--filter" => opts.filter = args.next(),
            "--continuous" => {
                opts.continuous = true;
                opts.filter = args.next();
            }
            "--out" => opts.file_out = args.next().map(Into::into),
            other if other.starts_with("--filter=") => {
                opts.filter = Some(other["--filter=".len()..].to_string());
            }
            other => panic!("unknown argument: {other}"),
        }
    }
    let benches = vec![
        BenchMetadata {
            name: BenchName("decaps_valid_vs_rejected"),
            seed: None,
            benchfn: decaps_valid_vs_rejected,
        },
        BenchMetadata {
            name: BenchName("compress_secret_inputs"),
            seed: None,
            benchfn: compress_secret_inputs,
        },
    ];
    run_benches_console(opts, benches).unwrap();
}
