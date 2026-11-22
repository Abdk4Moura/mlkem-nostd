//! NIST ACVP known-answer tests for ML-KEM (FIPS 203).
//!
//! Run with:
//! ```text
//! cargo test --features acvp --test acvp
//! ```
//!
//! The JSON files are pinned by `scripts/fetch-vectors.sh` and checked
//! against `vectors/SHA256SUMS`.

#![cfg(feature = "acvp")]

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use serde::Deserialize;

use mlkem_nostd::kem::{
    decaps_internal, encaps_internal, keygen_internal, Ciphertext, DecapsKey, EncapsKey,
};
use mlkem_nostd::{MlKem1024, MlKem512, MlKem768, ParameterSet};

#[derive(Debug, Deserialize)]
struct PromptFile {
    #[serde(rename = "testGroups")]
    test_groups: Vec<PromptGroup>,
}

#[derive(Debug, Deserialize)]
struct PromptGroup {
    #[serde(rename = "tgId")]
    tg_id: u32,
    #[serde(rename = "parameterSet")]
    parameter_set: String,
    function: Option<String>,
    tests: Vec<PromptTest>,
}

#[derive(Debug, Deserialize)]
struct PromptTest {
    #[serde(rename = "tcId")]
    tc_id: u32,
    d: Option<String>,
    z: Option<String>,
    ek: Option<String>,
    dk: Option<String>,
    m: Option<String>,
    c: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ExpectedFile {
    #[serde(rename = "testGroups")]
    test_groups: Vec<ExpectedGroup>,
}

#[derive(Debug, Deserialize)]
struct ExpectedGroup {
    #[serde(rename = "tgId")]
    tg_id: u32,
    tests: Vec<ExpectedTest>,
}

#[derive(Debug, Deserialize)]
struct ExpectedTest {
    #[serde(rename = "tcId")]
    tc_id: u32,
    ek: Option<String>,
    dk: Option<String>,
    c: Option<String>,
    k: Option<String>,
    #[serde(rename = "testPassed")]
    test_passed: Option<bool>,
}

type ExpectedMap = BTreeMap<u32, BTreeMap<u32, ExpectedTest>>;

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("vectors")
}

fn load_expected(path: &PathBuf) -> ExpectedMap {
    let file = fs::read(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let parsed: ExpectedFile =
        serde_json::from_slice(&file).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()));
    parsed
        .test_groups
        .into_iter()
        .map(|g| (g.tg_id, g.tests.into_iter().map(|t| (t.tc_id, t)).collect()))
        .collect()
}

fn hex_bytes(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap_or_else(|e| panic!("bad hex: {e}"))
}

fn hex32(s: &str) -> [u8; 32] {
    hex_bytes(s)
        .try_into()
        .unwrap_or_else(|v: Vec<u8>| panic!("expected 32 bytes, got {}", v.len()))
}

fn expected_result(map: &ExpectedMap, tg_id: u32, tc_id: u32) -> &ExpectedTest {
    map.get(&tg_id)
        .and_then(|g| g.get(&tc_id))
        .unwrap_or_else(|| panic!("missing expected result for tg {tg_id} tc {tc_id}"))
}

fn check_keygen<P: ParameterSet>(group: &PromptGroup, expected: &ExpectedMap, count: &mut usize) {
    for test in &group.tests {
        let d = hex32(test.d.as_ref().expect("d"));
        let z = hex32(test.z.as_ref().expect("z"));
        let (ek, dk) = keygen_internal::<P>(&d, &z);
        let want = expected_result(expected, group.tg_id, test.tc_id);
        assert_eq!(
            hex::encode(ek.as_bytes()),
            want.ek.as_ref().expect("ek").to_lowercase(),
            "{} keyGen tcId {} ek",
            P::NAME,
            test.tc_id
        );
        assert_eq!(
            hex::encode(dk.as_bytes()),
            want.dk.as_ref().expect("dk").to_lowercase(),
            "{} keyGen tcId {} dk",
            P::NAME,
            test.tc_id
        );
        *count += 1;
    }
}

fn check_encap<P: ParameterSet>(group: &PromptGroup, expected: &ExpectedMap, count: &mut usize) {
    for test in &group.tests {
        let ek = EncapsKey::<P>::from_bytes(&hex_bytes(test.ek.as_ref().expect("ek")))
            .expect("encapsulation key");
        let m = hex32(test.m.as_ref().expect("m"));
        let (ct, ss) = encaps_internal::<P>(&ek, &m);
        let want = expected_result(expected, group.tg_id, test.tc_id);
        assert_eq!(
            hex::encode(ct.as_bytes()),
            want.c.as_ref().expect("c").to_lowercase(),
            "{} encaps tcId {} ciphertext",
            P::NAME,
            test.tc_id
        );
        assert_eq!(
            hex::encode(ss.as_bytes()),
            want.k.as_ref().expect("k").to_lowercase(),
            "{} encaps tcId {} shared secret",
            P::NAME,
            test.tc_id
        );
        *count += 1;
    }
}

fn check_decap<P: ParameterSet>(group: &PromptGroup, expected: &ExpectedMap, count: &mut usize) {
    for test in &group.tests {
        let dk = DecapsKey::<P>::from_bytes(&hex_bytes(test.dk.as_ref().expect("dk")))
            .expect("decapsulation key");
        let ct = Ciphertext::<P>::from_bytes(&hex_bytes(test.c.as_ref().expect("c")))
            .expect("ciphertext");
        let ss = decaps_internal::<P>(&dk, &ct);
        let want = expected_result(expected, group.tg_id, test.tc_id);
        assert_eq!(
            hex::encode(ss.as_bytes()),
            want.k.as_ref().expect("k").to_lowercase(),
            "{} decaps tcId {} shared secret",
            P::NAME,
            test.tc_id
        );
        *count += 1;
    }
}

fn check_encaps_key_check<P: ParameterSet>(
    group: &PromptGroup,
    expected: &ExpectedMap,
    count: &mut usize,
) {
    for test in &group.tests {
        let ok = EncapsKey::<P>::from_bytes(&hex_bytes(test.ek.as_ref().expect("ek"))).is_ok();
        let want = expected_result(expected, group.tg_id, test.tc_id)
            .test_passed
            .expect("testPassed");
        assert_eq!(ok, want, "{} ekCheck tcId {}", P::NAME, test.tc_id);
        *count += 1;
    }
}

fn check_decaps_key_check<P: ParameterSet>(
    group: &PromptGroup,
    expected: &ExpectedMap,
    count: &mut usize,
) {
    for test in &group.tests {
        let ok = DecapsKey::<P>::from_bytes(&hex_bytes(test.dk.as_ref().expect("dk"))).is_ok();
        let want = expected_result(expected, group.tg_id, test.tc_id)
            .test_passed
            .expect("testPassed");
        assert_eq!(ok, want, "{} dkCheck tcId {}", P::NAME, test.tc_id);
        *count += 1;
    }
}

#[test]
fn acvp_keygen_vectors() {
    let dir = vectors_dir().join("ML-KEM-keyGen-FIPS203");
    let prompt: PromptFile =
        serde_json::from_slice(&fs::read(dir.join("prompt.json")).expect("read prompt"))
            .expect("parse prompt");
    let expected = load_expected(&dir.join("expectedResults.json"));

    let mut count = 0usize;
    for group in &prompt.test_groups {
        match group.parameter_set.as_str() {
            "ML-KEM-512" => check_keygen::<MlKem512>(group, &expected, &mut count),
            "ML-KEM-768" => check_keygen::<MlKem768>(group, &expected, &mut count),
            "ML-KEM-1024" => check_keygen::<MlKem1024>(group, &expected, &mut count),
            other => panic!("unknown parameter set {other}"),
        }
    }
    assert_eq!(count, 75, "expected all 75 keyGen vectors");
    println!("ACVP keyGen: {count} vectors passed");
}

#[test]
fn acvp_encap_decap_vectors() {
    let dir = vectors_dir().join("ML-KEM-encapDecap-FIPS203");
    let prompt: PromptFile =
        serde_json::from_slice(&fs::read(dir.join("prompt.json")).expect("read prompt"))
            .expect("parse prompt");
    let expected = load_expected(&dir.join("expectedResults.json"));

    let mut count = 0usize;
    for group in &prompt.test_groups {
        let function = group.function.as_deref().expect("function");
        match group.parameter_set.as_str() {
            "ML-KEM-512" => match function {
                "encapsulation" => check_encap::<MlKem512>(group, &expected, &mut count),
                "decapsulation" => check_decap::<MlKem512>(group, &expected, &mut count),
                "encapsulationKeyCheck" => {
                    check_encaps_key_check::<MlKem512>(group, &expected, &mut count)
                }
                "decapsulationKeyCheck" => {
                    check_decaps_key_check::<MlKem512>(group, &expected, &mut count)
                }
                other => panic!("unknown function {other}"),
            },
            "ML-KEM-768" => match function {
                "encapsulation" => check_encap::<MlKem768>(group, &expected, &mut count),
                "decapsulation" => check_decap::<MlKem768>(group, &expected, &mut count),
                "encapsulationKeyCheck" => {
                    check_encaps_key_check::<MlKem768>(group, &expected, &mut count)
                }
                "decapsulationKeyCheck" => {
                    check_decaps_key_check::<MlKem768>(group, &expected, &mut count)
                }
                other => panic!("unknown function {other}"),
            },
            "ML-KEM-1024" => match function {
                "encapsulation" => check_encap::<MlKem1024>(group, &expected, &mut count),
                "decapsulation" => check_decap::<MlKem1024>(group, &expected, &mut count),
                "encapsulationKeyCheck" => {
                    check_encaps_key_check::<MlKem1024>(group, &expected, &mut count)
                }
                "decapsulationKeyCheck" => {
                    check_decaps_key_check::<MlKem1024>(group, &expected, &mut count)
                }
                other => panic!("unknown function {other}"),
            },
            other => panic!("unknown parameter set {other}"),
        }
    }
    assert_eq!(count, 165, "expected all 165 encapDecap vectors");
    println!("ACVP encapDecap: {count} vectors passed");
}
