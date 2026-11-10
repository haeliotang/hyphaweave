// SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
// SPDX-License-Identifier: Apache-2.0

//! Vector-driven tests for the registered-kind body schemas (`kinds.rs`).
//!
//! The tests walk the conformance vectors in `vectors/` (read-only test input)
//! and assert the two context-free facts this module owns:
//!
//! - check (6) of §14.5: a registered kind's body is validated with the code
//!   the kind page names, and unknown kinds are opaque (§7.3);
//! - the §4.4 per-record signing obligation: the seven signer-constrained kinds
//!   get their dedicated signer code, ordinary records require `actor.key` when
//!   `accepted` and nothing otherwise.
//!
//! Cases whose defect needs the verification context (an owner declaration's
//! class, a grant chain, signer key classes) are the record pipeline's later
//! steps and are only checked for what `parse_body` can decide.

use std::fs;
use std::path::{Path, PathBuf};

use hyphaweave_verify::envelope;
use hyphaweave_verify::error_codes::Code;
use hyphaweave_verify::json;
use hyphaweave_verify::kinds::{self, GrantActionKind, KindBody, Obligation};
use hyphaweave_verify::value::{Object, Value};

/// Error codes that a kind body can produce without context (§14.5 check (6))
/// plus the context-free kind semantic codes of the kind pages.
const KIND_CODES: [&str; 10] = [
    "E_KIND_BODY_SCHEMA",
    "E_GRANT_SCHEMA",
    "E_KEY_PUBLIC_KEY",
    "E_KEY_ID_MISMATCH",
    "E_KEY_OWNER_MISSING",
    "E_KEY_VALIDITY",
    "E_KEY_ROTATION_KEYS",
    "E_KEY_REVOKE_EFFECTIVE",
    "E_CONSENT_VALIDITY",
    "E_ACTOR_KEY_TYPE_MISMATCH",
];

fn vectors_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../vectors")
}

/// Collects every `<category>/<case>` directory that carries an
/// `expected.json`, in sorted order. The `external/` cross-check data, the
/// `keys/` keyset and the frozen-candidate copies are not case directories.
fn collect_cases() -> Vec<PathBuf> {
    let root = vectors_root();
    let mut categories: Vec<PathBuf> = fs::read_dir(&root)
        .expect("vectors directory")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .collect();
    categories.sort();
    let mut cases = Vec::new();
    for category in categories {
        let name = category
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        if matches!(name, "external" | "keys" | "frozen") {
            continue;
        }
        collect_below(&category, &mut cases);
    }
    cases
}

fn collect_below(directory: &Path, cases: &mut Vec<PathBuf>) {
    let mut entries: Vec<PathBuf> = fs::read_dir(directory)
        .expect("vector directory")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .collect();
    entries.sort();
    for entry in entries {
        if entry.join("expected.json").is_file() {
            cases.push(entry);
        } else {
            collect_below(&entry, cases);
        }
    }
}

fn read_expected(case: &Path) -> Object {
    let bytes = fs::read(case.join("expected.json")).expect("read expected.json");
    json::parse_object(&bytes).expect("expected.json is ordinary canonical JSON")
}

fn expected_errors(expected: &Object) -> Vec<String> {
    expected
        .get_array("errors")
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn read_record(case: &Path, input: &str) -> envelope::RecordFile {
    let bytes = fs::read(case.join(input)).expect("read vector record");
    envelope::parse_record_file(&bytes).expect("vector record parses at the envelope level")
}

/// Every record-target case whose expected error is a kind-level code must be
/// rejected by `parse_body` with exactly that code, unless the defect is one
/// the context-free layer cannot see (the owner declaration's class).
#[test]
fn kinds_record_target_kind_level_errors() {
    let mut checked = 0usize;
    let mut deferred = 0usize;
    for case in collect_cases() {
        let expected = read_expected(&case);
        if expected.get_str("target") != Some("record") {
            continue;
        }
        let errors = expected_errors(&expected);
        if !errors
            .iter()
            .any(|code| KIND_CODES.contains(&code.as_str()))
        {
            continue;
        }
        let input = expected.get_str("input").unwrap_or("record.json");
        let file = read_record(&case, input);
        let id = expected.get_str("id").unwrap_or("<unnamed>");
        match kinds::parse_body(&file) {
            Ok(_) => {
                // Kind-level defects left to the pipeline need the verification
                // context: the resolving owner declaration's class (R5) and the
                // class of the actor key (§5.1).
                assert!(
                    errors.iter().any(|code| {
                        code == "E_KEY_OWNER_MISSING" || code == "E_ACTOR_KEY_TYPE_MISMATCH"
                    }),
                    "{id}: parse_body accepted the body but {errors:?} is expected"
                );
                deferred += 1;
            }
            Err(code) => {
                assert!(
                    errors.contains(&code.to_owned()),
                    "{id}: parse_body returned {code}, expected {errors:?}"
                );
                checked += 1;
            }
        }
    }
    println!(
        "kind bodies: {checked} record-target kind-code vectors rejected as expected, \
         {deferred} deferred to the context stage"
    );
    assert!(checked >= 9, "expected the record-target kind-code vectors");
    assert!(deferred >= 1, "expected the owner-class vector to defer");
}

/// Every record-target case that must verify (`valid` or `erased`) has a body
/// that passes check (6) unchanged.
#[test]
fn kinds_positive_record_target_bodies_parse() {
    let mut parsed = 0usize;
    let mut opaque = 0usize;
    let mut placeholders = 0usize;
    for case in collect_cases() {
        let expected = read_expected(&case);
        if expected.get_str("target") != Some("record") {
            continue;
        }
        let verdict = expected.get_str("verdict").unwrap_or_default();
        if !matches!(verdict, "valid" | "erased") {
            continue;
        }
        let input = expected.get_str("input").unwrap_or("record.json");
        let id = expected.get_str("id").unwrap_or("<unnamed>");
        let file = read_record(&case, input);
        match kinds::parse_body(&file) {
            Ok(KindBody::Opaque) => {
                assert!(
                    file.envelope().is_none() || !envelope::is_registered_kind(file.kind()),
                    "{id}: a registered kind must not be opaque"
                );
                if file.envelope().is_none() {
                    placeholders += 1;
                }
                opaque += 1;
            }
            Ok(_) => parsed += 1,
            Err(code) => panic!("{id}: expected a valid body, parse_body returned {code}"),
        }
    }
    println!(
        "kind bodies: {parsed} positive record-target bodies parsed, \
         {opaque} opaque ({placeholders} placeholders)"
    );
    assert!(
        parsed >= 5,
        "expected the positive record-target registered-kind bodies"
    );
}

/// The `labels/consent-validity` container vector is the only case pinning
/// `E_CONSENT_VALIDITY`: its `weave.consent.granted` record must be rejected at
/// the body stage while the other record in the container parses.
#[test]
fn kinds_consent_validity_container_vector() {
    let root = vectors_root();
    let case = root.join("labels/consent-validity");
    let expected = read_expected(&case);
    assert_eq!(
        expected_errors(&expected),
        vec!["E_CONSENT_VALIDITY".to_owned()]
    );
    let records = case.join("container/records");
    let mut files: Vec<PathBuf> = fs::read_dir(&records)
        .expect("consent-validity container records")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .collect();
    files.sort();
    assert_eq!(
        files.len(),
        1,
        "expected the consent record in the container"
    );
    let mut validity_errors = 0usize;
    for file in files {
        let bytes = fs::read(&file).expect("read container record");
        let record = envelope::parse_record_file(&bytes).expect("container record envelope");
        match kinds::parse_body(&record) {
            Ok(_) => {}
            Err(code) => {
                assert_eq!(code, "E_CONSENT_VALIDITY", "{}: {code}", file.display());
                validity_errors += 1;
            }
        }
    }
    println!("kind bodies: consent-validity container pins E_CONSENT_VALIDITY");
    assert_eq!(validity_errors, 1);
}

/// Walks every record that parses in the vector tree and checks that the §4.4
/// obligation matches the kind: the seven signer-constrained kinds carry their
/// dedicated obligation (and thus a dedicated signer code), ordinary records
/// require `actor.key` exactly when `accepted`.
#[test]
fn kinds_obligation_matches_every_vector_record() {
    let mut records = 0usize;
    let mut bodies = 0usize;
    let mut seen_kinds: Vec<&'static str> = Vec::new();
    for case in collect_cases() {
        let expected = read_expected(&case);
        let target = expected.get_str("target").unwrap_or_default();
        let input = expected.get_str("input").unwrap_or_default();
        let mut files: Vec<PathBuf> = Vec::new();
        if target == "record" {
            files.push(case.join(input));
        } else {
            let container = case.join(input);
            let records_dir = container.join("records");
            if container.is_dir() && records_dir.is_dir() {
                for entry in fs::read_dir(&records_dir).expect("container records dir") {
                    let path = entry.expect("container record entry").path();
                    if path
                        .extension()
                        .is_some_and(|extension| extension == "json")
                    {
                        files.push(path);
                    }
                }
            }
        }
        files.sort();
        for file in files {
            let Ok(bytes) = fs::read(&file) else {
                continue;
            };
            let Ok(record) = envelope::parse_record_file(&bytes) else {
                continue; // malformed on purpose for an earlier check
            };
            records += 1;
            let Ok(body) = kinds::parse_body(&record) else {
                continue; // malformed on purpose: rejected by this module's own test
            };
            bodies += 1;
            let obligation = kinds::obligation(&record, &body);
            match &body {
                KindBody::KeyDeclared(_) => {
                    assert!(
                        matches!(obligation, Obligation::DeclaredKey { .. }),
                        "{}: wrong obligation for weave.key.declared",
                        file.display()
                    );
                    seen_kinds.push("weave.key.declared");
                }
                KindBody::KeyRotated(_) => {
                    assert!(
                        matches!(obligation, Obligation::RotationBoth { .. }),
                        "{}: wrong obligation for weave.key.rotated",
                        file.display()
                    );
                    seen_kinds.push("weave.key.rotated");
                }
                KindBody::KeyRevoked(_) => {
                    assert!(
                        matches!(obligation, Obligation::RevokedKey { .. }),
                        "{}: wrong obligation for weave.key.revoked",
                        file.display()
                    );
                    seen_kinds.push("weave.key.revoked");
                }
                KindBody::Grant(_) => {
                    assert!(
                        matches!(obligation, Obligation::Grant { .. }),
                        "{}: wrong obligation for weave.grant",
                        file.display()
                    );
                    seen_kinds.push("weave.grant");
                }
                KindBody::ConsentGranted(_) => {
                    assert_eq!(obligation, Obligation::Consent);
                    seen_kinds.push("weave.consent.granted");
                }
                KindBody::ConsentRevoked(_) => {
                    assert_eq!(obligation, Obligation::Consent);
                    seen_kinds.push("weave.consent.revoked");
                }
                KindBody::Erasure(_) => {
                    assert_eq!(obligation, Obligation::Erasure);
                    seen_kinds.push("weave.erasure");
                }
                KindBody::Opaque => {
                    let accepted = record
                        .envelope()
                        .is_some_and(|envelope| envelope.stage == "accepted");
                    let expected = if accepted {
                        Obligation::ActorKey
                    } else {
                        Obligation::None
                    };
                    assert_eq!(
                        obligation,
                        expected,
                        "{}: wrong ordinary obligation",
                        file.display()
                    );
                }
            }
            if let Some(envelope) = record.envelope() {
                if envelope::SIGNER_CONSTRAINED_KINDS.contains(&envelope.kind.as_str()) {
                    assert!(
                        obligation.dedicated_code().is_some(),
                        "{}: signer-constrained kind without a dedicated code",
                        file.display()
                    );
                } else {
                    assert_eq!(
                        obligation.dedicated_code(),
                        None,
                        "{}: ordinary kind with a dedicated code",
                        file.display()
                    );
                }
            }
        }
    }
    let expected_kinds = [
        "weave.key.declared",
        "weave.key.rotated",
        "weave.key.revoked",
        "weave.grant",
        "weave.consent.granted",
        "weave.consent.revoked",
        "weave.erasure",
    ];
    for kind in expected_kinds {
        assert!(
            seen_kinds.contains(&kind),
            "no parsed vector record of kind {kind}"
        );
    }
    println!(
        "kind obligation: {bodies} bodies ({records} parseable records) across all seven \
         signer-constrained kinds"
    );
}

/// Explicit obligation checks pinned by the named positive vectors.
#[test]
fn kinds_obligation_pinned_by_vectors() {
    let root = vectors_root();
    let declared = read_record(&root.join("key-lifecycle/declared-valid"), "record.json");
    let body = kinds::parse_body(&declared).expect("declared-valid body");
    assert_eq!(
        kinds::obligation(&declared, &body),
        Obligation::DeclaredKey {
            declared_key: "ed25519:928a1e1dbe45a5d298ce5f6b5ce2eabe".to_owned(),
            // An optional `owner` on a human declaration needs no cosignature.
            owner_key: None,
        }
    );

    let rotated = read_record(&root.join("key-lifecycle/rotated-valid"), "record.json");
    let body = kinds::parse_body(&rotated).expect("rotated-valid body");
    assert_eq!(
        kinds::obligation(&rotated, &body),
        Obligation::RotationBoth {
            old_key: "ed25519:f6a2edbfb48098da6eb9018c5ee78673".to_owned(),
            new_key: "ed25519:bbecfa632505e9d2df3c49b3e70e613f".to_owned(),
        }
    );

    let root_grant = read_record(&root.join("grant/valid-root"), "record.json");
    let body = kinds::parse_body(&root_grant).expect("valid-root body");
    assert_eq!(
        kinds::obligation(&root_grant, &body),
        Obligation::Grant {
            action: GrantActionKind::Grant,
        }
    );

    let accepted = read_record(&root.join("stage/accepted-signed"), "record.json");
    let body = kinds::parse_body(&accepted).expect("accepted-signed body");
    assert_eq!(body, KindBody::Opaque);
    assert_eq!(kinds::obligation(&accepted, &body), Obligation::ActorKey);

    let proposed = read_record(&root.join("stage/valid-proposed-unsigned"), "record.json");
    let body = kinds::parse_body(&proposed).expect("proposed body");
    assert_eq!(kinds::obligation(&proposed, &body), Obligation::None);

    println!("kind obligation: named positive vectors match the §4.4 split");
}

/// `parse_body` reports only kind-level codes; every expected error in the
/// vector tree that this module reports must be one of [`KIND_CODES`].
#[test]
fn kinds_reported_codes_stay_in_registry() {
    let mut reported: Vec<Code> = Vec::new();
    for case in collect_cases() {
        let expected = read_expected(&case);
        if expected.get_str("target") != Some("record") {
            continue;
        }
        let input = expected.get_str("input").unwrap_or("record.json");
        let Ok(bytes) = fs::read(case.join(input)) else {
            continue;
        };
        let Ok(record) = envelope::parse_record_file(&bytes) else {
            continue;
        };
        if let Err(code) = kinds::parse_body(&record) {
            reported.push(code);
        }
    }
    reported.sort_unstable();
    reported.dedup();
    for code in &reported {
        assert!(
            KIND_CODES.contains(code),
            "parse_body reported a non-kind code: {code}"
        );
    }
    println!("kind bodies: parse_body reported codes {reported:?}");
}
