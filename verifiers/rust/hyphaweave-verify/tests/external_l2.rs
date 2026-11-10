// SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
// SPDX-License-Identifier: Apache-2.0

//! External L2 conformance: the committed RFC 3161 test material.
//!
//! Walks the L2 cases under `vectors/integrity-levels/` whose `expected.json`
//! expects an `E_TS_*` code or `anchor_verified: true`, replays the timestamp
//! part of the case with the real `.tsr` bytes and the committed test TSA
//! material, and asserts the §12.2/§12.4/§12.5 outcome. A few
//! `vectors/key-lifecycle/` compromise cases are replayed too because they pin
//! the `genTime + accuracy` bound of §9.4 (the committed receipts use a fixed
//! `genTime` of 2026-11-01T00:00:00.000Z).
//!
//! This test is not part of the platform path: it consumes the vectors as
//! read-only external test data, exactly like the other `external_*` gates.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use hyphaweave_verify::digest;
use hyphaweave_verify::json;
use hyphaweave_verify::time::Timestamp;
use hyphaweave_verify::timestamp::{self, AttestationTimestamp, ReceiptState};
use hyphaweave_verify::value::{Object, Value};

/// Directories under `vectors/` that are replayed by this test.
const L2_CASES: &str = "integrity-levels";

/// Committed `genTime` of every crafted receipt (see the vectors README).
const COMMITTED_GEN_TIME: &str = "2026-11-01T00:00:00.000Z";

fn vectors_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../vectors")
}

fn read_bytes(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

fn read_object(path: &Path) -> Object {
    json::parse_object(&read_bytes(path))
        .unwrap_or_else(|error| panic!("parse {}: {error:?}", path.display()))
}

/// `sha256:<hex>` of the canonical `manifest.json` bytes without the optional
/// trailing LF (§2.4).
fn manifest_digest_string(container: &Path) -> String {
    let mut manifest = read_bytes(&container.join("manifest.json"));
    if manifest.last() == Some(&b'\n') {
        manifest.pop();
    }
    digest::manifest_digest(&manifest)
}

fn manifest_digest_bytes(container: &Path) -> [u8; 32] {
    let digest_string = manifest_digest_string(container);
    digest::sha256_digest_bytes(&digest_string)
        .unwrap_or_else(|| panic!("manifest digest is not sha256: {digest_string}"))
}

/// The `timestamps[]` entries of `signatures/manifest.sig.json` (§11.3).
fn attestation_entries(container: &Path) -> Vec<AttestationTimestamp> {
    let attestation = read_object(&container.join("signatures").join("manifest.sig.json"));
    let timestamps = attestation
        .get_array("timestamps")
        .unwrap_or_else(|| panic!("{}: no timestamps array", container.display()));
    timestamps
        .iter()
        .map(|value| {
            let entry = value.as_object().expect("timestamp entry object");
            AttestationTimestamp {
                digest: entry
                    .get_str("digest")
                    .expect("timestamp digest")
                    .to_string(),
                path: entry.get_str("path").expect("timestamp path").to_string(),
                renews: entry.get_str("renews").map(str::to_string),
            }
        })
        .collect()
}

fn receipt_files(container: &Path, entries: &[AttestationTimestamp]) -> BTreeMap<String, Vec<u8>> {
    entries
        .iter()
        .map(|entry| (entry.path.clone(), read_bytes(&container.join(&entry.path))))
        .collect()
}

/// Trust anchors from the case's `--tsa-trust` argument, if it has one.
fn trust_anchors(case_dir: &Path, expected: &Object) -> Vec<[u8; 32]> {
    let mut file_contents = Vec::new();
    if let Some(arguments) = expected.get_array("args") {
        let arguments: Vec<&str> = arguments.iter().filter_map(Value::as_str).collect();
        let mut index = 0;
        while index < arguments.len() {
            if arguments[index] == "--tsa-trust" {
                if let Some(path) = arguments.get(index + 1) {
                    file_contents.push(read_bytes(&case_dir.join(path)));
                }
            }
            index += 1;
        }
    }
    timestamp::load_trust_anchors(&file_contents).expect("committed trust anchor loads")
}

fn expected_errors(expected: &Object) -> Vec<String> {
    expected
        .get_array("errors")
        .map(|errors| {
            errors
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn expected_anchor_verified(expected: &Object) -> Option<bool> {
    expected
        .get_object("expected_container")
        .and_then(|container| container.get_bool("anchor_verified"))
}

struct CaseEvidence {
    evidence: timestamp::ChainEvidence,
}

/// Replays the timestamp profile of one container case.
fn replay(case_dir: &Path) -> CaseEvidence {
    let container = case_dir.join("container");
    let expected = read_object(&case_dir.join("expected.json"));
    let entries = attestation_entries(&container);
    let files = receipt_files(&container, &entries);
    let anchors = trust_anchors(case_dir, &expected);
    let evidence = timestamp::verify_chain(
        &entries,
        &manifest_digest_bytes(&container),
        &files,
        &anchors,
    );
    CaseEvidence { evidence }
}

fn all_failure_codes(evidence: &timestamp::ChainEvidence) -> BTreeSet<&'static str> {
    evidence
        .receipts
        .iter()
        .filter_map(|receipt| receipt.error)
        .chain(evidence.chain_error)
        .collect()
}

fn case_directories(root: &Path) -> Vec<PathBuf> {
    let mut directories: Vec<PathBuf> = std::fs::read_dir(root)
        .unwrap_or_else(|error| panic!("read {}: {error}", root.display()))
        .map(|entry| entry.expect("directory entry").path())
        .filter(|path| path.is_dir())
        .collect();
    directories.sort();
    directories
}

#[test]
fn external_l2_integrity_level_cases() {
    let root = vectors_root().join(L2_CASES);
    let mut checked = 0usize;
    let mut skipped = 0usize;
    for case_dir in case_directories(&root) {
        let case_name = case_dir
            .file_name()
            .expect("case name")
            .to_string_lossy()
            .to_string();
        let expected = read_object(&case_dir.join("expected.json"));
        let expected_anchor_verified = expected_anchor_verified(&expected);
        let expected_timestamp_errors: Vec<String> = expected_errors(&expected)
            .into_iter()
            .filter(|code| code.starts_with("E_TS_"))
            .collect();
        let expects_anchor = expected_anchor_verified == Some(true);
        if expected_timestamp_errors.is_empty() && !expects_anchor {
            // The case's expectation is about container-level manifest rules
            // unrelated to the timestamp profile; the container workstream
            // covers it.
            skipped += 1;
            continue;
        }

        let CaseEvidence { evidence } = replay(&case_dir);
        if let Some(expected_anchor_verified) = expected_anchor_verified {
            assert_eq!(
                evidence.anchor_verified, expected_anchor_verified,
                "{case_name}: anchor_verified"
            );
        }
        if expects_anchor {
            assert!(
                evidence
                    .receipts
                    .iter()
                    .all(|receipt| receipt.state == ReceiptState::Verified),
                "{case_name}: every receipt must be verified, got {:?}",
                evidence.receipts
            );
            assert!(
                all_failure_codes(&evidence).is_empty(),
                "{case_name}: unexpected timestamp failures {:?}",
                all_failure_codes(&evidence)
            );
            assert!(
                evidence.receipts.iter().all(|receipt| receipt.gen_time
                    == Some(Timestamp::parse(COMMITTED_GEN_TIME).expect("committed genTime"))),
                "{case_name}: genTime"
            );
        } else {
            let failures = all_failure_codes(&evidence);
            let present_unverified = evidence
                .receipts
                .iter()
                .any(|receipt| receipt.state == ReceiptState::PresentUnverified);
            for code in &expected_timestamp_errors {
                if code == "E_TS_UNTRUSTED" {
                    assert!(
                        present_unverified,
                        "{case_name}: expected a present-unverified receipt, got {:?}",
                        evidence.receipts
                    );
                } else {
                    assert!(
                        failures.contains(code.as_str()),
                        "{case_name}: expected {code}, got {failures:?}"
                    );
                }
            }
        }
        checked += 1;
    }
    assert!(
        checked >= 22,
        "expected at least 22 timestamp-relevant L2 cases, checked {checked}"
    );
    println!(
        "external_l2: {checked} integrity-levels timestamp cases matched \
         ({skipped} non-timestamp cases skipped)"
    );
}

#[test]
fn external_l2_key_lifecycle_accuracy_cases() {
    // These cases pin the §9.4 `genTime + accuracy < T` comparison through the
    // timestamp evidence only; the record-level verdict belongs to the context
    // workstream.
    let root = vectors_root().join("key-lifecycle");
    let cases = [
        ("compromise-accuracy-crossing", 1_000_000i64),
        ("compromise-accuracy-equality", 1_000_000i64),
        ("compromise-rescued-by-timestamp", 0i64),
        ("compromise-untrusted-timestamp", 0i64),
    ];
    for (case_name, expected_accuracy_us) in cases {
        let case_dir = root.join(case_name);
        let expected = read_object(&case_dir.join("expected.json"));
        let CaseEvidence { evidence } = replay(&case_dir);
        let expected_anchor_verified = expected_anchor_verified(&expected)
            .unwrap_or_else(|| panic!("{case_name}: expected_container.anchor_verified"));
        assert_eq!(
            evidence.anchor_verified, expected_anchor_verified,
            "{case_name}: anchor_verified"
        );
        assert_eq!(evidence.receipts.len(), 1, "{case_name}: receipt count");
        let receipt = &evidence.receipts[0];
        assert_eq!(
            receipt.gen_time,
            Some(Timestamp::parse(COMMITTED_GEN_TIME).expect("committed genTime")),
            "{case_name}: genTime"
        );
        if expected_anchor_verified {
            assert_eq!(receipt.state, ReceiptState::Verified, "{case_name}: state");
            assert_eq!(
                receipt.accuracy_us, expected_accuracy_us,
                "{case_name}: accuracy conversion"
            );
            // §9.4 case 1: the rescue bound is genTime_ms * 1000 + accuracy_us.
            let gen_time = receipt.gen_time.expect("verified genTime");
            assert_eq!(
                evidence.rescue_bounds_us(),
                vec![gen_time.to_unix_millis() * 1_000 + receipt.accuracy_us],
                "{case_name}: rescue bound"
            );
        } else {
            assert_eq!(
                receipt.state,
                ReceiptState::PresentUnverified,
                "{case_name}: state"
            );
            assert!(
                evidence.rescue_bounds_us().is_empty(),
                "{case_name}: untrusted receipts cannot rescue"
            );
        }
    }
    println!(
        "external_l2: {} key-lifecycle timestamp-evidence cases matched",
        cases.len()
    );
}
