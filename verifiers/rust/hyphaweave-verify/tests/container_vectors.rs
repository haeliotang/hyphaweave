// SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
// SPDX-License-Identifier: Apache-2.0

//! Container conformance vectors: runs [`hyphaweave_verify::container`] over
//! every container-target case under `vectors/`.
//!
//! The runner reproduces each case's `args` (`@keyset` -> `vectors/keys/keyset`,
//! `@case` -> the case directory, anything else relative to the case
//! directory), verifies the input, and compares the conclusion with
//! `expected.json` exactly as `vectors/README.md` defines:
//!
//! - `verdict` exact;
//! - `errors` as a set over `container.errors ∪ every records[].errors`;
//! - `notices` as a subset over the same union;
//! - `expected_container` as a recursive subset match of the `container` object;
//! - `records` as per-id subset matches (`verdict`/`errors` when present).
//!
//! Paths are resolved relative to `env!("CARGO_MANIFEST_DIR")`. The frozen
//! candidate corpus is a separate run (`frozen_container_corpus`) because the
//! published vector corpus excludes `frozen/` from its own catalog.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use hyphaweave_verify::container;
use hyphaweave_verify::json;
use hyphaweave_verify::options::{ContainerInput, VerifyOptions};
use hyphaweave_verify::report::{ContainerReport, Report, Verdict};
use hyphaweave_verify::value::{Object, Value};

/// The repository's published vector corpus.
fn vectors_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../vectors")
}

/// Finds `keys/keyset` by walking up from a corpus root (§vectors README).
fn keyset_for(corpus: &Path) -> PathBuf {
    let mut current = Some(corpus);
    while let Some(directory) = current {
        let candidate = directory.join("keys/keyset");
        if candidate.is_dir() {
            return candidate;
        }
        current = directory.parent();
    }
    panic!("no keys/keyset above {}", corpus.display());
}

/// One discovered case: its directory and parsed `expected.json`.
struct Case {
    directory: PathBuf,
    id: String,
    expected: Object,
    target: String,
}

/// Deterministically discovers `<category>/<case>/expected.json`.
fn discover_corpus(corpus: &Path, include_frozen: bool) -> Vec<Case> {
    let mut cases = Vec::new();
    let mut categories: Vec<PathBuf> = std::fs::read_dir(corpus)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", corpus.display()))
        .map(|entry| entry.expect("directory entry").path())
        .filter(|path| path.is_dir())
        .collect();
    categories.sort();
    for category in categories {
        let Some(name) = category.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        // `external/` holds third-party test data and `keys/` the key inventory;
        // `frozen/` is a separate corpus run.
        if matches!(name, "external" | "keys") || (name == "frozen" && !include_frozen) {
            continue;
        }
        let mut case_dirs: Vec<PathBuf> = std::fs::read_dir(&category)
            .expect("category readable")
            .map(|entry| entry.expect("case entry").path())
            .filter(|path| path.is_dir() && path.join("expected.json").is_file())
            .collect();
        case_dirs.sort();
        for directory in case_dirs {
            let bytes = std::fs::read(directory.join("expected.json"))
                .unwrap_or_else(|error| panic!("cannot read expected.json: {error}"));
            let expected = match json::parse_object(&bytes) {
                Ok(object) => object,
                Err(error) => panic!(
                    "{}: expected.json is not parseable: {} at {}",
                    directory.display(),
                    error.code,
                    error.offset
                ),
            };
            let id = expected.get_str("id").unwrap_or_default().to_owned();
            let target = expected.get_str("target").unwrap_or_default().to_owned();
            cases.push(Case {
                directory,
                id,
                expected,
                target,
            });
        }
    }
    cases
}

/// Resolves an `expected.json` `args` token (§vectors README).
fn resolve_token(corpus: &Path, case_directory: &Path, token: &str) -> PathBuf {
    match token {
        "@keyset" => keyset_for(corpus),
        "@case" => case_directory.to_path_buf(),
        other => case_directory.join(other),
    }
}

/// Loads a `--keys` directory: top-level `*.json` files sorted by file name.
fn load_keyset(directory: &Path) -> Vec<Vec<u8>> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("cannot read keyset dir {}: {error}", directory.display()))
        .map(|entry| entry.expect("keyset entry").path())
        .filter(|path| path.is_file() && path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    files.sort();
    files
        .into_iter()
        .map(|path| std::fs::read(&path).expect("keyset file readable"))
        .collect()
}

/// Reproduces one case's verification inputs from `expected.json`.
fn build_case(corpus: &Path, case: &Case) -> (ContainerInput, VerifyOptions) {
    let mut options = VerifyOptions::new();
    if let Some(arguments) = case.expected.get_array("args") {
        let tokens: Vec<String> = arguments
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .unwrap_or_else(|| panic!("{}: non-string arg token", case.id))
                    .to_owned()
            })
            .collect();
        let mut index = 0;
        while index < tokens.len() {
            match tokens[index].as_str() {
                "--keys" => {
                    index += 1;
                    let directory = resolve_token(corpus, &case.directory, &tokens[index]);
                    options.keyset = load_keyset(&directory);
                }
                "--tsa-trust" => {
                    index += 1;
                    let path = resolve_token(corpus, &case.directory, &tokens[index]);
                    options.tsa_trust = vec![std::fs::read(&path)
                        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()))];
                }
                "--previous" => {
                    index += 1;
                    let directory = resolve_token(corpus, &case.directory, &tokens[index]);
                    options.previous = Some(ContainerInput::Directory(directory));
                }
                other => panic!("{}: unsupported arg token {other}", case.id),
            }
            index += 1;
        }
    }
    let relative = case
        .expected
        .get_str("input")
        .unwrap_or_else(|| panic!("{}: input member missing", case.id));
    let path = case.directory.join(relative);
    let input = if relative.ends_with(".zip") {
        ContainerInput::Zip(std::fs::read(&path).expect("zip input readable"))
    } else {
        ContainerInput::Directory(path)
    };
    (input, options)
}

/// The set of reported error codes over `container.errors ∪ records[].errors`.
fn reported_errors(report: &Report) -> BTreeSet<String> {
    let mut codes = BTreeSet::new();
    if let Some(container) = &report.container {
        for code in &container.errors {
            codes.insert((*code).to_owned());
        }
    }
    for record in &report.records {
        for code in &record.errors {
            codes.insert((*code).to_owned());
        }
    }
    codes
}

/// The set of reported notices over the same union.
fn reported_notices(report: &Report) -> BTreeSet<String> {
    let mut notices = BTreeSet::new();
    if let Some(container) = &report.container {
        for code in &container.notices {
            notices.insert((*code).to_owned());
        }
    }
    for record in &report.records {
        for code in &record.notices {
            notices.insert((*code).to_owned());
        }
    }
    notices
}

fn expected_codes(expected: &Object, member: &str) -> BTreeSet<String> {
    expected
        .get_array(member)
        .unwrap_or(&[])
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect()
}

/// Serializes the `container` report object into the §14.6 value shape so the
/// recursive subset matcher can compare it with `expected_container`.
fn container_value(container: &ContainerReport) -> Value {
    let mut object = Object::new();
    object.insert("created_at", container.created_at.clone());
    object.insert("manifest_digest", container.manifest_digest.clone());
    object.insert("level_claimed", container.level_claimed.clone());
    object.insert("level_verified", container.level_verified.clone());
    object.insert("anchor_verified", container.anchor_verified);
    object.insert(
        "chain",
        container.chain.as_ref().map(|chain| {
            let mut chain_object = Object::new();
            chain_object.insert("status", chain.status.clone());
            Value::Object(chain_object)
        }),
    );
    object.insert(
        "previous_manifest_digest",
        container.previous_manifest_digest.clone(),
    );
    object.insert(
        "record_count",
        container
            .record_count
            .map(|count| i64::try_from(count).unwrap_or(i64::MAX)),
    );
    object.insert(
        "errors",
        Value::Array(
            container
                .errors
                .iter()
                .map(|code| Value::Str((*code).to_owned()))
                .collect(),
        ),
    );
    object.insert(
        "notices",
        Value::Array(
            container
                .notices
                .iter()
                .map(|code| Value::Str((*code).to_owned()))
                .collect(),
        ),
    );
    object.insert(
        "timestamps",
        Value::Array(
            container
                .timestamps
                .iter()
                .map(|timestamp| {
                    let mut entry = Object::new();
                    entry.insert("index", Some(timestamp.index));
                    entry.insert("path", timestamp.path.clone());
                    entry.insert("state", timestamp.state.clone());
                    entry.insert("gen_time", timestamp.gen_time.clone());
                    Value::Object(entry)
                })
                .collect(),
        ),
    );
    Value::Object(object)
}

/// Recursive subset match: every member of `expected` must be present in
/// `actual` with an equal (or recursively matching) value.
fn subset_match(expected: &Value, actual: &Value, path: &str) -> Result<(), String> {
    match (expected, actual) {
        (Value::Object(expected_object), Value::Object(actual_object)) => {
            for (name, expected_value) in expected_object.iter() {
                let Some(actual_value) = actual_object.get(name) else {
                    return Err(format!("{path}/{name}: missing"));
                };
                subset_match(expected_value, actual_value, &format!("{path}/{name}"))?;
            }
            Ok(())
        }
        _ => {
            if expected == actual {
                Ok(())
            } else {
                Err(format!(
                    "{path}: expected {}, actual {}",
                    render(expected),
                    render(actual)
                ))
            }
        }
    }
}

fn render(value: &Value) -> String {
    match value {
        Value::Null => "null".to_owned(),
        Value::Bool(flag) => flag.to_string(),
        Value::Int(number) => number.to_string(),
        Value::Str(text) => format!("\"{text}\""),
        _ => json::canonical_value_bytes(value)
            .iter()
            .map(|byte| char::from(*byte))
            .collect(),
    }
}

/// Compares one report with one case's `expected.json`; returns every mismatch.
fn compare(case: &Case, report: &Report) -> Vec<String> {
    let mut mismatches = Vec::new();
    let expected_verdict = case.expected.get_str("verdict").unwrap_or_default();
    if report.verdict.as_str() != expected_verdict {
        mismatches.push(format!(
            "verdict: expected {expected_verdict}, actual {}",
            report.verdict.as_str()
        ));
    }
    let expected_errors = expected_codes(&case.expected, "errors");
    let actual_errors = reported_errors(report);
    if expected_errors != actual_errors {
        mismatches.push(format!(
            "errors: expected {expected_errors:?}, actual {actual_errors:?}"
        ));
    }
    let expected_notices = expected_codes(&case.expected, "notices");
    let actual_notices = reported_notices(report);
    let missing_notices: Vec<&String> = expected_notices.difference(&actual_notices).collect();
    if !missing_notices.is_empty() {
        mismatches.push(format!(
            "notices: missing {missing_notices:?} (reported {actual_notices:?})"
        ));
    }
    if let Some(expected_container) = case.expected.get("expected_container") {
        let actual = container_value(
            report
                .container
                .as_ref()
                .expect("container target always reports a container object"),
        );
        if let Err(mismatch) = subset_match(expected_container, &actual, "container") {
            mismatches.push(format!("expected_container: {mismatch}"));
        }
    }
    if let Some(expected_digest) = case.expected.get_str("expected_digest") {
        let actual = report
            .records
            .first()
            .and_then(|record| record.digest.clone());
        if actual.as_deref() != Some(expected_digest) {
            mismatches.push(format!(
                "expected_digest: expected {expected_digest}, actual {actual:?}"
            ));
        }
    }
    if let Some(expected_records) = case.expected.get_array("records") {
        for expectation in expected_records {
            let Some(expectation) = expectation.as_object() else {
                mismatches.push("records: non-object expectation".to_owned());
                continue;
            };
            let Some(id) = expectation.get_str("id") else {
                mismatches.push("records: expectation without id".to_owned());
                continue;
            };
            let Some(actual) = report
                .records
                .iter()
                .find(|record| record.id.as_deref() == Some(id))
            else {
                mismatches.push(format!("records[{id}]: not reported"));
                continue;
            };
            if let Some(expected_verdict) = expectation.get_str("verdict") {
                if actual.verdict.as_str() != expected_verdict {
                    mismatches.push(format!(
                        "records[{id}].verdict: expected {expected_verdict}, actual {}",
                        actual.verdict.as_str()
                    ));
                }
            }
            if expectation.contains("errors") {
                let expected: BTreeSet<String> = expectation
                    .get_array("errors")
                    .unwrap_or(&[])
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect();
                let actual: BTreeSet<String> = actual
                    .errors
                    .iter()
                    .map(|code| (*code).to_owned())
                    .collect();
                if expected != actual {
                    mismatches.push(format!(
                        "records[{id}].errors: expected {expected:?}, actual {actual:?}"
                    ));
                }
            }
            if let Some(expected_digest) = expectation.get_str("digest") {
                if actual.digest.as_deref() != Some(expected_digest) {
                    mismatches.push(format!("records[{id}].digest: mismatch"));
                }
            }
            if let Some(expected_kind_known) = expectation.get_bool("kind_known") {
                if actual.kind_known != Some(expected_kind_known) {
                    mismatches.push(format!("records[{id}].kind_known: mismatch"));
                }
            }
        }
    }
    mismatches
}

/// Runs one corpus and prints a pass/fail summary; panics when any case fails.
fn run_corpus(corpus: &Path, include_frozen: bool, label: &str) {
    let cases = discover_corpus(corpus, include_frozen);
    let mut checked = 0usize;
    let mut passed = 0usize;
    let mut failures: Vec<(String, Vec<String>)> = Vec::new();
    let previous_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    for case in &cases {
        if case.target != "container" {
            continue;
        }
        checked += 1;
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let (input, options) = build_case(corpus, case);
            container::verify_container(&input, &options)
        }));
        let mismatches = match outcome {
            Ok(Ok(report)) => compare(case, &report),
            Ok(Err(error)) => vec![format!("usage error: {error}")],
            Err(payload) => {
                let message = payload
                    .downcast_ref::<&str>()
                    .map(|message| (*message).to_owned())
                    .or_else(|| payload.downcast_ref::<String>().cloned())
                    .unwrap_or_else(|| "panic".to_owned());
                vec![format!("panic: {message}")]
            }
        };
        if mismatches.is_empty() {
            passed += 1;
        } else {
            failures.push((case.id.clone(), mismatches));
        }
    }
    std::panic::set_hook(previous_hook);
    println!("{label}: {passed}/{checked} container cases passed");
    for (id, mismatches) in &failures {
        println!("FAIL {id}");
        for mismatch in mismatches {
            println!("     {mismatch}");
        }
    }
    assert!(
        failures.is_empty(),
        "{label}: {} of {checked} container cases failed",
        failures.len()
    );
}

/// The published conformance corpus.
#[test]
fn container_corpus() {
    run_corpus(&vectors_root(), false, "container vectors");
}

/// The frozen candidate regression set (`vectors/frozen/v0.1-candidate`).
#[test]
fn frozen_container_corpus() {
    run_corpus(
        &vectors_root().join("frozen/v0.1-candidate"),
        true,
        "frozen container vectors",
    );
}

/// The candidate regression set copies the published corpus, so both must
/// agree on every container-target case.
#[test]
fn frozen_matches_published() {
    let published = discover_corpus(&vectors_root(), false);
    let frozen = discover_corpus(&vectors_root().join("frozen/v0.1-candidate"), true);
    let published_ids: BTreeSet<&str> = published
        .iter()
        .filter(|case| case.target == "container")
        .map(|case| case.id.as_str())
        .collect();
    let frozen_ids: BTreeSet<&str> = frozen
        .iter()
        .filter(|case| case.target == "container")
        .map(|case| case.id.as_str())
        .collect();
    assert!(
        frozen_ids.is_subset(&published_ids),
        "frozen-only container cases: {:?}",
        frozen_ids.difference(&published_ids).collect::<Vec<_>>()
    );
}

/// A `weave.erased` verdict is a record-level outcome; the container verdict is
/// never `erased` (§14.3).
#[test]
fn container_verdict_is_never_erased() {
    for case in discover_corpus(&vectors_root(), false)
        .into_iter()
        .filter(|case| case.target == "container")
    {
        let (input, options) = build_case(&vectors_root(), &case);
        if let Ok(report) = container::verify_container(&input, &options) {
            assert_ne!(
                report.verdict,
                Verdict::Erased,
                "{}: container verdict erased",
                case.id
            );
        }
    }
}

/// §14.7 ablation for the container workstream: for every container-level code
/// a case expects (`E_MANIFEST_*`, `E_CONTAINER_*`, `E_TS_*`), re-running with
/// that check skipped must not panic and must remove the code from the report.
/// The same hook drives the H0 ablation gate, so a container check that ignores
/// `options.skipped` is a defect even when the normal corpus passes.
#[test]
fn container_level_ablation() {
    let corpus = vectors_root();
    let mut checked = 0usize;
    let mut passed = 0usize;
    let mut failures: Vec<(String, String)> = Vec::new();
    let previous_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    for case in discover_corpus(&corpus, false)
        .into_iter()
        .filter(|case| case.target == "container")
    {
        for code in expected_codes(&case.expected, "errors") {
            let container_level = code.starts_with("E_MANIFEST_")
                || code.starts_with("E_CONTAINER_")
                || code.starts_with("E_TS_");
            if !container_level {
                continue;
            }
            checked += 1;
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let (input, mut options) = build_case(&corpus, &case);
                options.skip_checks.insert(code.clone());
                container::verify_container(&input, &options)
            }));
            let problem = match outcome {
                Ok(Ok(report)) => {
                    if reported_errors(&report).contains(&code) {
                        Some(format!("skipped code {code} still reported"))
                    } else {
                        None
                    }
                }
                Ok(Err(error)) => Some(format!("usage error: {error}")),
                Err(payload) => {
                    let message = payload
                        .downcast_ref::<&str>()
                        .map(|message| (*message).to_owned())
                        .or_else(|| payload.downcast_ref::<String>().cloned())
                        .unwrap_or_else(|| "panic".to_owned());
                    Some(format!("panic: {message}"))
                }
            };
            if let Some(problem) = problem {
                failures.push((case.id.clone(), problem));
            } else {
                passed += 1;
            }
        }
    }
    std::panic::set_hook(previous_hook);
    println!("container-level ablation: {passed}/{checked} checks ablatable");
    for (id, problem) in &failures {
        println!("FAIL {id}: {problem}");
    }
    assert!(
        failures.is_empty(),
        "{} of {checked} container-level checks ignored options.skipped",
        failures.len()
    );
}

/// Report-shape semantics for container targets (§14.5/§14.6), pinned by the
/// black-box reference reports: undetermined fields are their honest defaults,
/// a records-listing inconsistency stops before record evaluation, and receipt
/// files are checked in the timestamps stage.
#[test]
fn container_report_stages_and_defaults() {
    use hyphaweave_verify::report::{Summary, VerdictCounts};

    let corpus = vectors_root();
    let cases = discover_corpus(&corpus, false);
    let find = |id: &str| -> &Case {
        cases
            .iter()
            .find(|case| case.id == id)
            .unwrap_or_else(|| panic!("missing case {id}"))
    };

    // Early invalid container: every container field is present with the
    // undetermined default, and no record report is invented.
    let case = find("container/manifest-missing");
    let (input, options) = build_case(&corpus, case);
    let report = container::verify_container(&input, &options).expect("report");
    let container_report = report.container.as_ref().expect("container object");
    assert_eq!(container_report.level_verified.as_deref(), Some("L0"));
    assert_eq!(container_report.anchor_verified, Some(false));
    assert_eq!(
        container_report
            .chain
            .as_ref()
            .map(|chain| chain.status.as_str()),
        Some("absent")
    );
    assert_eq!(container_report.record_count, Some(0));
    assert_eq!(container_report.created_at, None);
    assert_eq!(container_report.manifest_digest, None);
    assert!(report.records.is_empty());
    assert_eq!(report.summary, Summary::Verdicts(VerdictCounts::default()));

    // A records-listing inconsistency makes the container invalid without
    // claiming any per-record result.
    let case = find("container/record-extra");
    let (input, options) = build_case(&corpus, case);
    let report = container::verify_container(&input, &options).expect("report");
    assert!(report.records.is_empty());
    assert_eq!(
        report.container.as_ref().expect("container").errors,
        vec!["E_MANIFEST_RECORD_EXTRA"]
    );

    // Receipt-file problems are timestamp-stage errors: the listed record is
    // still evaluated, the listed receipt is reported invalid without a
    // genTime, and the chain claim stays unverified.
    let case = find("integrity-levels/l2-ts-file-digest");
    let (input, options) = build_case(&corpus, case);
    let report = container::verify_container(&input, &options).expect("report");
    let container_report = report.container.as_ref().expect("container object");
    assert_eq!(report.records.len(), 1);
    assert_eq!(report.records[0].verdict, Verdict::Valid);
    assert_eq!(container_report.errors, vec!["E_TS_FILE"]);
    assert!(container_report
        .notices
        .contains(&"N_CHAIN_CLAIM_UNVERIFIED"));
    assert_eq!(container_report.timestamps.len(), 1);
    assert_eq!(container_report.timestamps[0].state, "invalid");
    assert_eq!(container_report.timestamps[0].gen_time, None);
    assert_eq!(
        container_report
            .chain
            .as_ref()
            .map(|chain| chain.status.as_str()),
        Some("unverified")
    );
}
