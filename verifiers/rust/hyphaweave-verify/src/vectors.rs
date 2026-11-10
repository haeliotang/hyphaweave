// SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
// SPDX-License-Identifier: Apache-2.0

//! Conformance-vector runner (§14.10, `vectors/README.md`).
//!
//! The runner discovers case directories in deterministic sorted order, reads
//! each `expected.json`, reproduces the case's command arguments, verifies the
//! case, and checks the conclusion:
//!
//! - `verdict` exact;
//! - `errors` as a set over the container's top-level and per-record errors;
//! - `notices` as a subset of the reported notices over the same union;
//! - `expected_digest` against `records[0].digest` for record targets;
//! - `expected_resolution` against `records[0].refs[]` states;
//! - `expected_container` as a recursive subset match of the container object;
//! - `records` as per-id subset matches of record reports.
//!
//! Argument tokens in `expected.json`: `@keyset` -> the `keys/keyset` directory
//! of the enclosing vectors corpus (found by walking up from the vectors
//! directory until a `keys/keyset` directory exists); `@case` -> the case
//! directory; anything else is a path relative to the case directory. There is
//! no network access and the runner reads only the vector directory tree plus
//! the resolved keyset directory.
//!
//! The caller's [`VerifyOptions`] are the base for every case, so a caller that
//! supplies `--tsa-trust` on the `vectors` command provides default anchors for
//! the whole run (the other local inputs are normally supplied per case). A
//! case whose `args` name `--keys`, `--tsa-trust` or `--previous` replaces that
//! input for itself only; a case without `args` keeps the caller's inputs, so a
//! case that documents its conclusion *without* `--keys` really is verified with
//! no local trust input.
//!
//! Discovery is `<category>/<case>/expected.json`, two directory levels below
//! the given directory, in sorted relative-path order. That shape is the same
//! for the main corpus and for `vectors/frozen/v0.1-candidate`, so the frozen
//! set is a separate run, never a nested part of the main run.
//!
//! The returned report is path-free and deterministic. Its `input` identity
//! (PROVISIONAL, Appendix A P7) is the SHA-256 and byte size of the sorted
//! case-id list joined with a single `\n` and no trailing newline; per-case
//! results are sorted by case id. The case-id list is the `id` member of each
//! case's `expected.json`.

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs;
use std::io::Error;
use std::path::{Path, PathBuf};

use crate::digest;
use crate::error_codes::{self, Code};
use crate::json;
use crate::options::{ContainerInput, UsageError, VerifyOptions};
use crate::report::{
    ContainerReport, InputIdentity, RecordReport, Report, Summary, Target, VectorCaseReport,
    VectorCounts, Verdict, VerifierInfo,
};
use crate::value::{Object, Value};
use crate::{REPORT_VERSION, SPEC, VERIFIER_NAME, VERIFIER_VERSION};

/// Runs every conformance case under `directory` and returns the `vectors`
/// report.
///
/// # Errors
/// Returns a [`UsageError`] when the directory or a case file cannot be read, or
/// when a case's `expected.json` is malformed.
pub fn verify_vectors(directory: &Path, options: &VerifyOptions) -> Result<Report, UsageError> {
    let cases = discover_cases(directory)?;
    let mut keyset_cache: Option<PathBuf> = None;
    let mut case_reports: Vec<VectorCaseReport> = Vec::with_capacity(cases.len());
    let mut case_ids: Vec<String> = Vec::with_capacity(cases.len());
    let mut matched: u64 = 0;
    for case in &cases {
        let expectation = CaseExpectation::parse(&case.directory, &case.expected)?;
        let case_options = case_options(
            &case.directory,
            &case.expected,
            directory,
            options,
            &mut keyset_cache,
        )?;
        let report = verify_case(&case.directory, &expectation, &case_options)?;
        let succeeded = case_matches(&expectation, &report);
        if succeeded {
            matched += 1;
        }
        case_ids.push(expectation.id.clone());
        case_reports.push(VectorCaseReport {
            id: expectation.id.clone(),
            matched: succeeded,
            expected: expectation.verdict.clone(),
            actual: report.verdict.as_str().to_owned(),
        });
    }
    case_reports.sort_by(|left, right| left.id.cmp(&right.id));
    case_ids.sort();
    let case_count = u64::try_from(cases.len()).unwrap_or(u64::MAX);
    let mismatched = case_count.saturating_sub(matched);
    let identity_text = case_ids.join("\n");
    let identity_bytes = identity_text.as_bytes();
    let verdict = if mismatched == 0 {
        Verdict::Valid
    } else {
        Verdict::Invalid
    };
    Ok(Report {
        checks_disabled: checks_disabled(options),
        report_version: REPORT_VERSION.to_owned(),
        spec: SPEC.to_owned(),
        target: Target::Vectors,
        verdict,
        input: InputIdentity {
            sha256: digest::sha256_digest_string(identity_bytes),
            size: u64::try_from(identity_bytes.len()).unwrap_or(u64::MAX),
        },
        records: Vec::new(),
        container: None,
        summary: Summary::Vectors(VectorCounts {
            case_count,
            matched,
            mismatched,
        }),
        limitations: Vec::new(),
        cases: case_reports,
        verifier: VerifierInfo {
            name: VERIFIER_NAME.to_owned(),
            version: VERIFIER_VERSION.to_owned(),
        },
    })
}

/// One discovered case directory and its parsed `expected.json`.
struct Case {
    directory: PathBuf,
    expected: Object,
}

/// The checked conclusion of one `expected.json` (§14.10, `vectors/README.md`).
struct CaseExpectation {
    id: String,
    target: String,
    input: String,
    verdict: String,
    errors: BTreeSet<String>,
    notices: Vec<String>,
    expected_digest: Option<String>,
    expected_resolution: Option<Vec<String>>,
    expected_container: Option<Value>,
    records: Vec<Object>,
}

impl CaseExpectation {
    fn parse(directory: &Path, expected: &Object) -> Result<Self, UsageError> {
        let id = required_string(directory, expected, "id")?.to_owned();
        let target = required_string(directory, expected, "target")?.to_owned();
        let input = required_string(directory, expected, "input")?.to_owned();
        let verdict = required_string(directory, expected, "verdict")?.to_owned();
        let errors = required_string_list(directory, expected, "errors")?
            .into_iter()
            .collect();
        let notices = optional_string_list(directory, expected, "notices")?.unwrap_or_default();
        let expected_digest = optional_string(directory, expected, "expected_digest")?;
        let expected_resolution = optional_string_list(directory, expected, "expected_resolution")?;
        let expected_container = expected.get("expected_container").cloned();
        let records = match expected.get("records") {
            None => Vec::new(),
            Some(Value::Array(items)) => {
                let mut records = Vec::with_capacity(items.len());
                for item in items {
                    let object = item.as_object().ok_or_else(|| {
                        expectation_error(directory, "\"records\" entries must be objects")
                    })?;
                    records.push(object.clone());
                }
                records
            }
            Some(_) => {
                return Err(expectation_error(directory, "\"records\" must be an array"));
            }
        };
        Ok(Self {
            id,
            target,
            input,
            verdict,
            errors,
            notices,
            expected_digest,
            expected_resolution,
            expected_container,
            records,
        })
    }
}

fn discover_cases(directory: &Path) -> Result<Vec<Case>, UsageError> {
    let mut cases = Vec::new();
    for category in sorted_subdirectories(directory)? {
        for case_directory in sorted_subdirectories(&category)? {
            let expected_path = case_directory.join("expected.json");
            if !expected_path.is_file() {
                continue;
            }
            let bytes =
                fs::read(&expected_path).map_err(|error| io_error(&expected_path, &error))?;
            let expected = json::parse_object(&bytes).map_err(|_| {
                expectation_error(&case_directory, "expected.json is not valid JSON")
            })?;
            cases.push(Case {
                directory: case_directory,
                expected,
            });
        }
    }
    Ok(cases)
}

fn sorted_subdirectories(directory: &Path) -> Result<Vec<PathBuf>, UsageError> {
    let entries = fs::read_dir(directory).map_err(|error| io_error(directory, &error))?;
    let mut paths = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| io_error(directory, &error))?;
        let path = entry.path();
        if path.is_dir() {
            paths.push(path);
        }
    }
    paths.sort_by(|left, right| left.file_name().cmp(&right.file_name()));
    Ok(paths)
}

fn verify_case(
    directory: &Path,
    expectation: &CaseExpectation,
    options: &VerifyOptions,
) -> Result<Report, UsageError> {
    let input_path = directory.join(&expectation.input);
    match expectation.target.as_str() {
        "record" => {
            let bytes = fs::read(&input_path).map_err(|error| io_error(&input_path, &error))?;
            crate::verify_record(&bytes, options)
        }
        "container" => {
            let input = if input_path.is_dir() {
                ContainerInput::Directory(input_path)
            } else {
                let bytes = fs::read(&input_path).map_err(|error| io_error(&input_path, &error))?;
                ContainerInput::Zip(bytes)
            };
            crate::verify_container(input, options)
        }
        other => Err(expectation_error(
            directory,
            format!("unsupported target \"{other}\""),
        )),
    }
}

/// Builds the options for one case from its `args` member (§14.1).
///
/// The caller's options are the base: a case that names `--keys`,
/// `--tsa-trust` or `--previous` replaces that input for this case only.
fn case_options(
    directory: &Path,
    expected: &Object,
    vectors_directory: &Path,
    base: &VerifyOptions,
    keyset_cache: &mut Option<PathBuf>,
) -> Result<VerifyOptions, UsageError> {
    let mut options = base.clone();
    let Some(args) = expected.get_array("args") else {
        return Ok(options);
    };
    let mut index = 0;
    while index < args.len() {
        let arg = args[index]
            .as_str()
            .ok_or_else(|| expectation_error(directory, "\"args\" entries must be strings"))?;
        match arg {
            "--json" => index += 1,
            "--keys" | "--tsa-trust" | "--previous" => {
                let token = args
                    .get(index + 1)
                    .and_then(Value::as_str)
                    .ok_or_else(|| expectation_error(directory, format!("{arg} needs a value")))?;
                let path = resolve_token(directory, vectors_directory, token, keyset_cache)?;
                match arg {
                    "--keys" => options.keyset = load_keyset(&path)?,
                    "--tsa-trust" => {
                        let bytes = fs::read(&path).map_err(|error| io_error(&path, &error))?;
                        options.tsa_trust = vec![bytes];
                    }
                    _ => options.previous = Some(previous_input(&path)?),
                }
                index += 2;
            }
            other => {
                return Err(expectation_error(
                    directory,
                    format!("unsupported args token \"{other}\""),
                ));
            }
        }
    }
    Ok(options)
}

fn resolve_token(
    directory: &Path,
    vectors_directory: &Path,
    token: &str,
    keyset_cache: &mut Option<PathBuf>,
) -> Result<PathBuf, UsageError> {
    match token {
        "@case" => Ok(directory.to_path_buf()),
        "@keyset" => {
            if let Some(path) = keyset_cache {
                return Ok(path.clone());
            }
            let path = resolve_keyset(vectors_directory)?;
            *keyset_cache = Some(path.clone());
            Ok(path)
        }
        other if other.starts_with('@') => Err(expectation_error(
            directory,
            format!("unsupported argument token \"{other}\""),
        )),
        relative => Ok(directory.join(relative)),
    }
}

/// Finds `keys/keyset` by walking up from the vectors directory (§14.10).
fn resolve_keyset(vectors_directory: &Path) -> Result<PathBuf, UsageError> {
    for ancestor in vectors_directory.ancestors() {
        let candidate = ancestor.join("keys").join("keyset");
        if candidate.is_dir() {
            return Ok(candidate);
        }
    }
    Err(UsageError(format!(
        "cannot resolve @keyset: no keys/keyset directory above {}",
        vectors_directory.display()
    )))
}

fn previous_input(path: &Path) -> Result<ContainerInput, UsageError> {
    if path.is_dir() {
        Ok(ContainerInput::Directory(path.to_path_buf()))
    } else {
        let bytes = fs::read(path).map_err(|error| io_error(path, &error))?;
        Ok(ContainerInput::Zip(bytes))
    }
}

/// Loads the top-level `*.json` files of a keyset directory, sorted by file name
/// (§14.1).
fn load_keyset(directory: &Path) -> Result<Vec<Vec<u8>>, UsageError> {
    let entries = fs::read_dir(directory).map_err(|error| io_error(directory, &error))?;
    let mut files: Vec<PathBuf> = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| io_error(directory, &error))?;
        let path = entry.path();
        if path.is_file() && path.extension() == Some(OsStr::new("json")) {
            files.push(path);
        }
    }
    files.sort_by(|left, right| left.file_name().cmp(&right.file_name()));
    let mut records = Vec::with_capacity(files.len());
    for path in files {
        let bytes = fs::read(&path).map_err(|error| io_error(&path, &error))?;
        records.push(bytes);
    }
    Ok(records)
}

/// The sorted skip list echoed in `checks_disabled` (§14.7).
fn checks_disabled(options: &VerifyOptions) -> Vec<Code> {
    options
        .skip_checks
        .iter()
        .filter_map(|skip| {
            error_codes::ALL_ERROR_CODES
                .iter()
                .copied()
                .find(|code| code == &skip.as_str())
        })
        .collect()
}

fn expectation_error(directory: &Path, message: impl AsRef<str>) -> UsageError {
    UsageError(format!("{}: {}", directory.display(), message.as_ref()))
}

fn io_error(path: &Path, error: &Error) -> UsageError {
    UsageError(format!("{}: {error}", path.display()))
}

fn required_string<'a>(
    directory: &Path,
    expected: &'a Object,
    name: &str,
) -> Result<&'a str, UsageError> {
    expected.get_str(name).ok_or_else(|| {
        expectation_error(
            directory,
            format!("expected.json: missing or non-string \"{name}\""),
        )
    })
}

fn optional_string(
    directory: &Path,
    expected: &Object,
    name: &str,
) -> Result<Option<String>, UsageError> {
    match expected.get(name) {
        None => Ok(None),
        Some(Value::Str(text)) => Ok(Some(text.clone())),
        Some(_) => Err(expectation_error(
            directory,
            format!("expected.json: \"{name}\" must be a string"),
        )),
    }
}

fn string_list(value: &Value) -> Option<Vec<String>> {
    let items = value.as_array()?;
    let mut list = Vec::with_capacity(items.len());
    for item in items {
        list.push(item.as_str()?.to_owned());
    }
    Some(list)
}

fn required_string_list(
    directory: &Path,
    expected: &Object,
    name: &str,
) -> Result<Vec<String>, UsageError> {
    optional_string_list(directory, expected, name)?.ok_or_else(|| {
        expectation_error(
            directory,
            format!("expected.json: missing \"{name}\" array"),
        )
    })
}

fn optional_string_list(
    directory: &Path,
    expected: &Object,
    name: &str,
) -> Result<Option<Vec<String>>, UsageError> {
    match expected.get(name) {
        None => Ok(None),
        Some(value) => string_list(value).map(Some).ok_or_else(|| {
            expectation_error(
                directory,
                format!("expected.json: \"{name}\" must be an array of strings"),
            )
        }),
    }
}

fn case_matches(expectation: &CaseExpectation, report: &Report) -> bool {
    // §14.3: the verdict is exact.
    if report.target.as_str() != expectation.target
        || report.verdict.as_str() != expectation.verdict
    {
        return false;
    }
    // The expected error set is a set over `container.errors` and every
    // `records[].errors` (§14.6).
    let reported_errors = reported_error_set(report);
    let expected_errors: BTreeSet<&str> = expectation.errors.iter().map(String::as_str).collect();
    if reported_errors != expected_errors {
        return false;
    }
    // Notices are a subset of the reported notice set.
    let reported_notices = reported_notice_set(report);
    if !expectation
        .notices
        .iter()
        .all(|notice| reported_notices.contains(notice.as_str()))
    {
        return false;
    }
    if let Some(expected_digest) = &expectation.expected_digest {
        if report
            .records
            .first()
            .and_then(|record| record.digest.as_deref())
            != Some(expected_digest.as_str())
        {
            return false;
        }
    }
    if let Some(expected_resolution) = &expectation.expected_resolution {
        let Some(record) = report.records.first() else {
            return false;
        };
        if expected_resolution.len() > record.refs.len() {
            return false;
        }
        for (state, reference) in expected_resolution.iter().zip(record.refs.iter()) {
            if reference.state != *state {
                return false;
            }
        }
    }
    if let Some(expected_container) = &expectation.expected_container {
        let Some(container) = report.container.as_ref() else {
            return false;
        };
        if !subset_match(expected_container, &container_report_value(container)) {
            return false;
        }
    }
    records_expectations_match(&expectation.records, report)
}

fn reported_error_set(report: &Report) -> BTreeSet<&str> {
    let mut set = BTreeSet::new();
    if let Some(container) = &report.container {
        set.extend(container.errors.iter().copied());
    }
    for record in &report.records {
        set.extend(record.errors.iter().copied());
    }
    set
}

fn reported_notice_set(report: &Report) -> BTreeSet<&str> {
    let mut set = BTreeSet::new();
    if let Some(container) = &report.container {
        set.extend(container.notices.iter().copied());
    }
    for record in &report.records {
        set.extend(record.notices.iter().copied());
    }
    set
}

/// Recursive subset match: nested objects are matched member by member, arrays
/// and scalar values are compared exactly (§14.10, `vectors/README.md`).
fn subset_match(expected: &Value, actual: &Value) -> bool {
    match (expected, actual) {
        (Value::Object(expected_object), Value::Object(actual_object)) => {
            expected_object.iter().all(|(name, value)| {
                actual_object
                    .get(name)
                    .is_some_and(|actual_value| subset_match(value, actual_value))
            })
        }
        (Value::Array(expected_items), Value::Array(actual_items)) => {
            expected_items.len() == actual_items.len()
                && expected_items
                    .iter()
                    .zip(actual_items.iter())
                    .all(|(expected_item, actual_item)| subset_match(expected_item, actual_item))
        }
        _ => expected == actual,
    }
}

fn records_expectations_match(expected_records: &[Object], report: &Report) -> bool {
    expected_records.iter().all(|expected| {
        let Some(id) = expected.get_str("id") else {
            return false;
        };
        report.records.iter().any(|actual| {
            actual.id.as_deref() == Some(id) && record_expectation_matches(expected, actual)
        })
    })
}

fn record_expectation_matches(expected: &Object, actual: &RecordReport) -> bool {
    expected.iter().all(|(name, value)| match name {
        "id" => value.as_str() == actual.id.as_deref(),
        "verdict" => value.as_str() == Some(actual.verdict.as_str()),
        "kind_known" => value.as_bool() == actual.kind_known,
        "errors" => {
            let reported: BTreeSet<&str> = actual.errors.iter().copied().collect();
            expected_string_set(value).is_some_and(|expected_codes| expected_codes == reported)
        }
        "notices" => {
            let reported: BTreeSet<&str> = actual.notices.iter().copied().collect();
            expected_string_set(value)
                .is_some_and(|expected_notices| expected_notices.is_subset(&reported))
        }
        _ => subset_match(value, &record_report_value(actual)),
    })
}

fn expected_string_set(value: &Value) -> Option<BTreeSet<&str>> {
    let items = value.as_array()?;
    let mut set = BTreeSet::new();
    for item in items {
        set.insert(item.as_str()?);
    }
    Some(set)
}

/// The container report projection used for `expected_container` matching.
fn container_report_value(container: &ContainerReport) -> Value {
    crate::report_json::container_value(container)
}

/// The record report projection used for `records[]` fallback matching.
fn record_report_value(record: &RecordReport) -> Value {
    crate::report_json::record_value(record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error_codes::{e, n};
    use crate::report::{ChainReport, ContainerReport, RefReport, VerdictCounts};

    fn expectation(target: &str, verdict: &str) -> CaseExpectation {
        CaseExpectation {
            id: "test/case".to_owned(),
            target: target.to_owned(),
            input: "record.json".to_owned(),
            verdict: verdict.to_owned(),
            errors: BTreeSet::new(),
            notices: Vec::new(),
            expected_digest: None,
            expected_resolution: None,
            expected_container: None,
            records: Vec::new(),
        }
    }

    fn record(id: &str, verdict: Verdict, errors: Vec<Code>) -> RecordReport {
        RecordReport {
            digest: Some("sha256:0000".to_owned()),
            id: Some(id.to_owned()),
            kind: Some("weave.note".to_owned()),
            stage: Some("accepted".to_owned()),
            origin: None,
            kind_known: Some(true),
            verdict,
            errors,
            notices: Vec::new(),
            refs: Vec::new(),
            sigs: Vec::new(),
            attestation: None,
        }
    }

    fn container(errors: Vec<Code>) -> ContainerReport {
        ContainerReport {
            created_at: Some("2026-01-01T00:00:00Z".to_owned()),
            manifest_digest: Some("sha256:1111".to_owned()),
            level_claimed: Some("L0".to_owned()),
            level_verified: Some("L0".to_owned()),
            anchor_verified: Some(false),
            chain: Some(ChainReport {
                status: "absent".to_owned(),
            }),
            previous_manifest_digest: None,
            record_count: Some(1),
            errors,
            notices: Vec::new(),
            timestamps: Vec::new(),
        }
    }

    fn report(
        target: Target,
        verdict: Verdict,
        records: Vec<RecordReport>,
        container: Option<ContainerReport>,
    ) -> Report {
        Report {
            checks_disabled: Vec::new(),
            report_version: "1".to_owned(),
            spec: "weave-record/1".to_owned(),
            target,
            verdict,
            input: InputIdentity {
                sha256: "sha256:2222".to_owned(),
                size: 2,
            },
            records,
            container,
            summary: Summary::Verdicts(VerdictCounts::default()),
            limitations: Vec::new(),
            cases: Vec::new(),
            verifier: VerifierInfo {
                name: "test".to_owned(),
                version: "0".to_owned(),
            },
        }
    }

    #[test]
    fn verdict_is_exact() {
        let expectation = expectation("record", "valid");
        let valid = report(
            Target::Record,
            Verdict::Valid,
            vec![record("a", Verdict::Valid, vec![])],
            None,
        );
        assert!(case_matches(&expectation, &valid));
        let erased = report(
            Target::Record,
            Verdict::Erased,
            vec![record("a", Verdict::Erased, vec![])],
            None,
        );
        assert!(!case_matches(&expectation, &erased));
    }

    #[test]
    fn errors_are_compared_as_an_unsorted_set_over_container_and_records() {
        let mut expectation = expectation("container", "invalid");
        expectation.errors = ["E_SIG_REQUIRED", "E_MANIFEST_DIGEST"]
            .iter()
            .map(|code| (*code).to_owned())
            .collect();
        let mut expected_records = vec![record("a", Verdict::Invalid, vec![e::SIG_REQUIRED])];
        expected_records[0].errors = vec![e::SIG_REQUIRED];
        let unmatched = report(
            Target::Container,
            Verdict::Invalid,
            expected_records.clone(),
            Some(container(vec![e::MANIFEST_DIGEST])),
        );
        assert!(case_matches(&expectation, &unmatched));
        // An extra reported error breaks the set equality.
        expected_records[0].errors = vec![e::SIG_REQUIRED, e::SIG_INVALID];
        let extra = report(
            Target::Container,
            Verdict::Invalid,
            expected_records,
            Some(container(vec![e::MANIFEST_DIGEST])),
        );
        assert!(!case_matches(&expectation, &extra));
    }

    #[test]
    fn notices_are_a_subset() {
        let mut expectation = expectation("record", "valid");
        expectation.notices = vec![n::REF_MISSING.to_owned()];
        let mut actual = record("a", Verdict::Valid, vec![]);
        actual.notices = vec![n::REF_MISSING, n::REF_MOVED];
        let matched = report(Target::Record, Verdict::Valid, vec![actual], None);
        assert!(case_matches(&expectation, &matched));
        let missing = report(
            Target::Record,
            Verdict::Valid,
            vec![record("a", Verdict::Valid, vec![])],
            None,
        );
        assert!(!case_matches(&expectation, &missing));
    }

    #[test]
    fn expected_digest_must_equal_records_zero_digest() {
        let mut expectation = expectation("record", "erased");
        expectation.expected_digest = Some("sha256:0000".to_owned());
        let matched = report(
            Target::Record,
            Verdict::Erased,
            vec![record("a", Verdict::Erased, vec![])],
            None,
        );
        assert!(case_matches(&expectation, &matched));
        expectation.expected_digest = Some("sha256:ffff".to_owned());
        assert!(!case_matches(&expectation, &matched));
    }

    #[test]
    fn expected_resolution_matches_by_reference_index() {
        let mut expectation = expectation("record", "valid");
        expectation.expected_resolution = Some(vec!["missing".to_owned(), "erased".to_owned()]);
        let mut actual = record("a", Verdict::Valid, vec![]);
        actual.refs = vec![
            RefReport {
                index: 0,
                rel: "derived_from".to_owned(),
                state: "missing".to_owned(),
            },
            RefReport {
                index: 1,
                rel: "supersedes".to_owned(),
                state: "erased".to_owned(),
            },
        ];
        let matched = report(Target::Record, Verdict::Valid, vec![actual.clone()], None);
        assert!(case_matches(&expectation, &matched));
        actual.refs[1].state = "found".to_owned();
        let moved = report(Target::Record, Verdict::Valid, vec![actual], None);
        assert!(!case_matches(&expectation, &moved));
    }

    #[test]
    fn expected_container_is_a_recursive_subset() {
        let mut expectation = expectation("container", "valid");
        let mut chain = Object::new();
        chain.insert("status", Value::Str("absent".to_owned()));
        let mut expected_container = Object::new();
        expected_container.insert("level_claimed", Value::Str("L0".to_owned()));
        expected_container.insert("previous_manifest_digest", Value::Null);
        expected_container.insert("chain", Value::Object(chain));
        expectation.expected_container = Some(Value::Object(expected_container));
        let actual = report(
            Target::Container,
            Verdict::Valid,
            vec![],
            Some(container(vec![])),
        );
        assert!(case_matches(&expectation, &actual));
        // `null` is an exact value, not a wildcard.
        let mut actual_container = container(vec![]);
        actual_container.previous_manifest_digest = Some("sha256:3333".to_owned());
        let rewritten = report(
            Target::Container,
            Verdict::Valid,
            vec![],
            Some(actual_container),
        );
        assert!(!case_matches(&expectation, &rewritten));
        // A missing nested member is a mismatch.
        let mut broken = container(vec![]);
        broken.chain = None;
        let broken = report(Target::Container, Verdict::Valid, vec![], Some(broken));
        assert!(!case_matches(&expectation, &broken));
    }

    #[test]
    fn records_are_matched_by_id_and_flag_values() {
        let mut expectation = expectation("record", "valid");
        let mut expected_record = Object::new();
        expected_record.insert("id", Value::Str("a".to_owned()));
        expected_record.insert("kind_known", Value::Bool(false));
        expected_record.insert("verdict", Value::Str("valid".to_owned()));
        mock_errors(&mut expected_record, &[]);
        expectation.records = vec![expected_record];
        let mut actual = record("a", Verdict::Valid, vec![]);
        actual.kind_known = Some(false);
        let matched = report(Target::Record, Verdict::Valid, vec![actual.clone()], None);
        assert!(case_matches(&expectation, &matched));
        actual.kind_known = Some(true);
        let wrong = report(Target::Record, Verdict::Valid, vec![actual], None);
        assert!(!case_matches(&expectation, &wrong));
        let absent = report(Target::Record, Verdict::Valid, vec![], None);
        assert!(!case_matches(&expectation, &absent));
    }

    fn mock_errors(object: &mut Object, codes: &[&'static str]) {
        object.insert(
            "errors",
            Value::Array(
                codes
                    .iter()
                    .map(|code| Value::Str((*code).to_owned()))
                    .collect(),
            ),
        );
    }

    /// The committed corpus discovers exactly the two documented sets, and
    /// `@keyset` resolves for both (from inside the frozen candidate directory
    /// it must find the enclosing corpus keyset).
    #[test]
    fn discovers_the_committed_corpus_and_resolves_the_keyset() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../vectors");
        let cases = discover_cases(&root).expect("main corpus discovery");
        assert_eq!(cases.len(), 294);
        let frozen = root.join("frozen/v0.1-candidate");
        let frozen_cases = discover_cases(&frozen).expect("frozen corpus discovery");
        assert_eq!(frozen_cases.len(), 179);
        let keyset = resolve_keyset(&root).expect("main corpus keyset");
        assert!(keyset.is_dir());
        assert_eq!(
            keyset,
            root.join("keys/keyset"),
            "@keyset resolves to <vectors>/keys/keyset"
        );
        assert_eq!(
            resolve_keyset(&frozen).expect("frozen corpus keyset"),
            keyset,
            "walking up from the frozen set finds the same keyset"
        );
        // Case discovery order and ids are deterministic and path-free.
        let mut previous = String::new();
        for case in &cases {
            let expectation = CaseExpectation::parse(&case.directory, &case.expected)
                .expect("committed expected.json parses");
            assert!(!expectation.id.is_empty());
            assert!(!expectation.id.contains('/') || expectation.id.matches('/').count() == 1);
            assert!(expectation.id > previous || previous.is_empty());
            previous = expectation.id;
        }
    }

    /// A committed case's `args` reproduce the expected verifier options.
    #[test]
    fn case_options_load_the_keyset_directory() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../vectors");
        let case = root.join("jcs/canonical-tricky");
        let bytes = fs::read(case.join("expected.json")).expect("case expected.json");
        let expected = json::parse_object(&bytes).expect("case expected.json parses");
        let mut keyset_cache = None;
        let options = case_options(
            &case,
            &expected,
            &root,
            &VerifyOptions::new(),
            &mut keyset_cache,
        )
        .expect("case options");
        assert_eq!(options.keyset.len(), 10, "keyset has the ten declarations");
        assert_eq!(keyset_cache, Some(root.join("keys/keyset")));
        assert!(options.tsa_trust.is_empty());
        assert!(options.previous.is_none());
    }

    /// A case with no `args` keeps the caller's options (no implicit keyset).
    #[test]
    fn case_without_args_inherits_base_options() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../vectors");
        let case = root.join("container/self-attested-root-untrusted");
        let bytes = fs::read(case.join("expected.json")).expect("case expected.json");
        let expected = json::parse_object(&bytes).expect("case expected.json parses");
        let mut keyset_cache = None;
        let options = case_options(
            &case,
            &expected,
            &root,
            &VerifyOptions::new(),
            &mut keyset_cache,
        )
        .expect("case options");
        assert!(options.keyset.is_empty());
        assert!(keyset_cache.is_none());
    }
}
