// SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
// SPDX-License-Identifier: Apache-2.0

//! WR-CJ / envelope structural conformance against the committed `jcs` vectors.
//!
//! The `jcs` category exercises exactly the first two record checks (§14.5):
//! canonical JSON parsing and envelope structure. Signature verification is not
//! needed, so this test runs before the crypto workstream is integrated.

use std::fs;
use std::path::PathBuf;

use hyphaweave_verify::envelope;
use hyphaweave_verify::json;
use hyphaweave_verify::value::Value;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

fn code_strings(value: &Value) -> Vec<&str> {
    value
        .as_array()
        .unwrap_or_default()
        .iter()
        .filter_map(Value::as_str)
        .collect()
}

#[test]
fn jcs_vectors_match_envelope_classification() {
    let root = repo_root().join("vectors/jcs");
    let mut cases = 0usize;
    let mut failures: Vec<String> = Vec::new();
    for entry in fs::read_dir(&root).expect("vectors/jcs exists") {
        let case_dir = entry.expect("dir entry").path();
        if !case_dir.is_dir() {
            continue;
        }
        let expected_bytes = fs::read(case_dir.join("expected.json")).expect("expected.json");
        let expected = json::parse_object(&expected_bytes).expect("expected.json parses");
        let input = expected.get_str("input").expect("input field");
        let input_bytes = fs::read(case_dir.join(input)).expect("input file");
        let expected_errors = expected.get("errors").map(code_strings).unwrap_or_default();
        let actual = envelope::parse_record_file(&input_bytes);
        cases += 1;
        match (&actual, expected_errors.first().copied()) {
            (Ok(_), None) => {}
            (Ok(_), Some(code)) => failures.push(format!(
                "{}: expected {code} but parsed successfully",
                case_dir.display()
            )),
            (Err(actual_code), None) => failures.push(format!(
                "{}: expected no error but got {actual_code}",
                case_dir.display()
            )),
            (Err(actual_code), Some(expected_code)) => {
                if *actual_code != expected_code {
                    failures.push(format!(
                        "{}: expected {expected_code} but got {actual_code}",
                        case_dir.display()
                    ));
                }
            }
        }
    }
    assert!(cases > 0, "no jcs cases found");
    assert!(
        failures.is_empty(),
        "{} of {cases} jcs cases failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
    println!("jcs/envelope structural vectors: {cases} cases matched");
}

#[test]
fn canonical_form_round_trips() {
    let root = repo_root().join("vectors/jcs");
    let mut checked = 0usize;
    for entry in fs::read_dir(&root).expect("vectors/jcs exists") {
        let case_dir = entry.expect("dir entry").path();
        if !case_dir.is_dir() {
            continue;
        }
        let Ok(bytes) = fs::read(case_dir.join("record.json")) else {
            continue;
        };
        let Ok(object) = json::parse_object(&bytes) else {
            continue;
        };
        if envelope::parse_record_file(&bytes).is_ok() {
            assert!(
                json::is_canonical_file_form(&bytes, &object),
                "{}: accepted record bytes are not canonical file form",
                case_dir.display()
            );
            checked += 1;
        }
    }
    assert!(checked > 0);
    println!("canonical round-trip: {checked} files");
}

#[test]
fn code_registry_is_closed_for_vectors() {
    let root = repo_root().join("vectors");
    let mut seen: Vec<String> = Vec::new();
    for category in fs::read_dir(&root).expect("vectors exists") {
        let category = category.expect("entry").path();
        if !category.is_dir() {
            continue;
        }
        for case in fs::read_dir(&category).expect("category") {
            let case = case.expect("entry").path();
            let expected_path = case.join("expected.json");
            if !expected_path.is_file() {
                continue;
            }
            let bytes = fs::read(&expected_path).expect("read expected");
            let expected = json::parse_object(&bytes).expect("parse expected");
            for field in ["errors", "notices"] {
                if let Some(values) = expected.get(field) {
                    for code in code_strings(values) {
                        let registered = if field == "errors" {
                            hyphaweave_verify::error_codes::is_error_code(code)
                        } else {
                            hyphaweave_verify::error_codes::is_notice(code)
                        };
                        assert!(registered, "{code} is not in the closed registry");
                        seen.push(code.to_owned());
                    }
                }
            }
        }
    }
    assert!(!seen.is_empty());
    println!("vector registry codes: {} prefixes checked", seen.len());
}
