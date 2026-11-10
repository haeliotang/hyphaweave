// SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
// SPDX-License-Identifier: Apache-2.0

//! Ablation / byte-flip gate harness (gate 5 of the H1 task).
//!
//! **Byte-flip gate.** For every positive case (expected verdict `valid` or
//! `erased`), flip one bit of every input byte in turn and require that the
//! verifier never reports `valid`/`erased` again, except for bytes that are
//! documented as *not cryptographically covered*. The exemptions and their
//! reasons are printed with their byte counts; anything else is a violation:
//!
//! - a byte of a `sigs[].alg` value whose flip keeps a **grammar-valid unknown**
//!   algorithm name: §3.6/Q13 makes such an entry *ignored*, so a flip inside
//!   `"ed25519"` (or a manifest attestation's `signatures[].alg`) can create an
//!   inert signature entry and leave the verdict unchanged (the record and
//!   manifest digests exclude the signature structures, and an auxiliary
//!   counter-signature is not load-bearing). A flip that breaks the algorithm
//!   name grammar, or that cannot be read back as UTF-8, is **not** exempt;
//! - the two deliberately unsigned positive records and the ignored-entry cases
//!   of `vectors/GATE-3-EXCEPTIONS.md`;
//! - `weave.erased` placeholders: a structurally sound placeholder is `erased`
//!   by design and carries no signature;
//! - container `readable/` files (§11.8: never parsed or hashed) and
//!   `signatures/tsa-cert-<n>.pem` files (§12.3: never trusted on their own);
//! - for zip-form containers the *materialised entry contents* are flipped; the
//!   archive metadata (headers, CRCs, comments) is not semantic input.
//!
//! **Ablation gate.** Every registered error code's check is disabled in turn
//! through the test-only §14.7 hook and the committed corpus must mismatch. The
//! runner then requires that every surviving code is either pinned by a targeted
//! probe (a crafted input whose reported code changes when the check is
//! disabled) or documented as never emitted by this verifier.
//!
//! These tests are `#[ignore]`d because they take minutes: run them with
//! `cargo test --release --test gates -- --include-ignored --nocapture`.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::ops::Range;
use std::path::{Path, PathBuf};

use hyphaweave_verify::error_codes::{e, ALL_ERROR_CODES};
use hyphaweave_verify::options::ContainerInput;
use hyphaweave_verify::report::{Report, Verdict};
use hyphaweave_verify::value::{Object, Value};
use hyphaweave_verify::{
    b64, digest, ed25519, json, verify_container, verify_record, VerifyOptions,
};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

fn vectors_root() -> PathBuf {
    repo_root().join("vectors")
}

fn keyset_dir() -> PathBuf {
    vectors_root().join("keys/keyset")
}

fn load_keyset(dir: &Path) -> Vec<Vec<u8>> {
    let mut entries: Vec<PathBuf> = fs::read_dir(dir)
        .expect("keyset dir")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    entries.sort();
    entries
        .iter()
        .map(|path| fs::read(path).expect("keyset file"))
        .collect()
}

/// Every committed case directory (main corpus, not the frozen copy).
fn cases() -> Vec<PathBuf> {
    let mut out = Vec::new();
    let root = vectors_root();
    for category in fs::read_dir(&root).expect("vectors dir") {
        let category = category.expect("entry").path();
        if !category.is_dir() {
            continue;
        }
        let name = category.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if matches!(name, "frozen" | "external" | "keys") {
            continue;
        }
        for case in fs::read_dir(&category).expect("category") {
            let case = case.expect("entry").path();
            if case.join("expected.json").is_file() {
                out.push(case);
            }
        }
    }
    out.sort();
    out
}

fn expected_json(case: &Path) -> Object {
    let bytes = fs::read(case.join("expected.json")).expect("expected.json");
    json::parse_object(&bytes).expect("expected parses")
}

fn expected_verdict(expected: &Object) -> &str {
    expected.get_str("verdict").unwrap_or("")
}

fn is_positive(expected: &Object) -> bool {
    matches!(expected_verdict(expected), "valid" | "erased")
}

fn case_id(case: &Path) -> String {
    let category = case
        .parent()
        .and_then(Path::file_name)
        .and_then(|name| name.to_str())
        .unwrap_or("");
    let name = case
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    format!("{category}/{name}")
}

fn input_path(case: &Path, expected: &Object) -> PathBuf {
    let input = expected.get_str("input").unwrap_or("record.json");
    case.join(input)
}

fn options_from_args(case: &Path, expected: &Object) -> VerifyOptions {
    let mut options = VerifyOptions::new();
    let keyset = keyset_dir();
    let args = expected
        .get("args")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_owned))
                .collect::<Vec<String>>()
        })
        .unwrap_or_default();
    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--keys" => {
                let target = args.get(index + 1).cloned().unwrap_or_default();
                let dir = if target == "@keyset" {
                    keyset.clone()
                } else {
                    case.join(target)
                };
                options.keyset = load_keyset(&dir);
                index += 2;
            }
            "--tsa-trust" => {
                let target = args.get(index + 1).cloned().unwrap_or_default();
                let path = if target == "@keyset" {
                    keyset.join(target)
                } else {
                    case.join(target)
                };
                options.tsa_trust = vec![fs::read(path).expect("tsa trust file")];
                index += 2;
            }
            _ => index += 1,
        }
    }
    options
}

fn report_has_terminal_verdict(report: &Report) -> bool {
    matches!(report.verdict, Verdict::Valid | Verdict::Erased)
}

// ---------------------------------------------------------------------------
// Byte ranges of Q13 unknown-algorithm-exempt bytes
// ---------------------------------------------------------------------------

/// Range of a top-level member's value in canonical JSON bytes.
fn top_level_member_value_range(bytes: &[u8], member: &str) -> Option<Range<usize>> {
    let mut index = 0usize;
    if bytes.get(index) != Some(&b'{') {
        return None;
    }
    index += 1;
    loop {
        // Key.
        if bytes.get(index) != Some(&b'"') {
            return None;
        }
        let key_start = index + 1;
        index += 1;
        while index < bytes.len() && bytes[index] != b'"' {
            index += 1;
        }
        let key = std::str::from_utf8(&bytes[key_start..index]).ok()?;
        index += 1;
        if bytes.get(index) != Some(&b':') {
            return None;
        }
        index += 1;
        // Value.
        let value_start = index;
        let mut depth = 0usize;
        let mut in_string = false;
        let mut next_member = false;
        while index < bytes.len() {
            let byte = bytes[index];
            if in_string {
                if byte == b'\\' {
                    index += 2;
                    continue;
                }
                if byte == b'"' {
                    in_string = false;
                }
                index += 1;
                continue;
            }
            match byte {
                b'"' => in_string = true,
                b'{' | b'[' => depth += 1,
                b'}' | b']' => {
                    if depth == 0 {
                        return if key == member {
                            Some(value_start..index)
                        } else {
                            None
                        };
                    }
                    depth -= 1;
                }
                b',' if depth == 0 => {
                    if key == member {
                        return Some(value_start..index);
                    }
                    // Another top-level member follows: leave the value scanner
                    // and continue with the next member instead of giving up.
                    index += 1;
                    next_member = true;
                    break;
                }
                _ => {}
            }
            index += 1;
        }
        if !next_member {
            return None;
        }
    }
}

/// Byte ranges of every `<member>[].alg` *value* in a canonical JSON object.
///
/// A flip inside these bytes can turn the known `ed25519` algorithm into a
/// grammar-valid unknown algorithm, which §3.6/Q13 treats as an ignored
/// signature entry; the record digest excludes `sigs` (§2.2) and the manifest
/// digest excludes the attestation file (§2.4), so such bytes are not
/// cryptographically covered.
fn alg_value_ranges(bytes: &[u8], member: &str) -> Vec<Range<usize>> {
    let Some(array) = top_level_member_value_range(bytes, member) else {
        return Vec::new();
    };
    let mut ranges = Vec::new();
    let mut cursor = array.start;
    while let Some(found) = find_subslice(&bytes[cursor..array.end], b"\"alg\":\"") {
        let value_start = cursor + found + b"\"alg\":\"".len();
        let Some(end_rel) = bytes[value_start..array.end]
            .iter()
            .position(|byte| *byte == b'"')
        else {
            break;
        };
        let value_end = value_start + end_rel;
        ranges.push(value_start..value_end);
        cursor = value_end;
    }
    ranges
}

/// Byte ranges of every `sigs[].alg` value in a canonical record file.
fn sig_alg_value_ranges(bytes: &[u8]) -> Vec<Range<usize>> {
    alg_value_ranges(bytes, "sigs")
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// True when flipping `index` inside one of the `alg` value ranges turns the
/// text into a *different, grammar-valid* algorithm name — exactly the Q13
/// ignored-entry class. A flip that breaks the name grammar (the signature
/// structure is then rejected) or that cannot be read back as UTF-8 is not
/// exempt.
fn creates_ignored_alg(bytes: &[u8], index: usize, ranges: &[Range<usize>]) -> bool {
    let Some(range) = ranges.iter().find(|range| range.contains(&index)) else {
        return false;
    };
    let mut name = bytes[range.clone()].to_vec();
    name[index - range.start] ^= 0x01;
    match std::str::from_utf8(&name) {
        Ok(text) => is_alg_name(text) && text != "ed25519",
        Err(_) => false,
    }
}

/// `^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$`, at most 32 bytes (§4.3).
fn is_alg_name(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.is_empty() || bytes.len() > 32 || !bytes[0].is_ascii_lowercase() {
        return false;
    }
    let mut previous_dash = false;
    for &byte in &bytes[1..] {
        if byte.is_ascii_lowercase() || byte.is_ascii_digit() {
            previous_dash = false;
        } else if byte == b'-' && !previous_dash {
            previous_dash = true;
        } else {
            return false;
        }
    }
    !previous_dash
}

// ---------------------------------------------------------------------------
// Record byte-flip gate
// ---------------------------------------------------------------------------

/// Cases documented in `vectors/GATE-3-EXCEPTIONS.md` whose bytes are not
/// cryptographically bound (deliberately unsigned positives and ignored
/// unknown-algorithm signature entries).
const BYTE_FLIP_EXCEPTIONS: [&str; 5] = [
    "digest/record-unsigned",
    "stage/valid-proposed-unsigned",
    "sig/unknown-alg-optional",
    "sig/unknown-alg-with-known-valid",
    "sig/unknown-alg",
];

#[test]
#[ignore = "gate run: slow; execute with --release --include-ignored"]
fn byte_flip_record_positives() {
    let mut flips = 0u64;
    let mut rejected = 0u64;
    let mut exempt = BTreeMap::<&'static str, u64>::new();
    let mut violations: Vec<String> = Vec::new();
    for case in cases() {
        let expected = expected_json(&case);
        if !is_positive(&expected) || expected.get_str("target") != Some("record") {
            continue;
        }
        let id = case_id(&case);
        let whole_case_exempt = BYTE_FLIP_EXCEPTIONS.contains(&id.as_str());
        let input = input_path(&case, &expected);
        let bytes = fs::read(&input).expect("record input");
        let options = options_from_args(&case, &expected);
        let placeholder = hyphaweave_verify::envelope::parse_record_file(&bytes)
            .map(|record| record.erased().is_some())
            .unwrap_or(false);
        let alg_ranges = sig_alg_value_ranges(&bytes);
        for index in 0..bytes.len() {
            let mut mutated = bytes.clone();
            mutated[index] ^= 0x01;
            let report = verify_record(&mutated, &options).expect("verify");
            flips += 1;
            if !report_has_terminal_verdict(&report) {
                rejected += 1;
                continue;
            }
            let reason = if whole_case_exempt {
                Some("documented GATE-3-EXCEPTIONS case")
            } else if creates_ignored_alg(&bytes, index, &alg_ranges) {
                Some("sigs[].alg value: Q13 ignored entry, digest excludes sigs")
            } else if placeholder && report.verdict == Verdict::Erased {
                Some("weave.erased placeholder: no signature by design")
            } else {
                None
            };
            match reason {
                Some(reason) => *exempt.entry(reason).or_default() += 1,
                None => violations.push(format!(
                    "{id}: byte {index} flip still yields {:?}",
                    report.verdict
                )),
            }
        }
    }
    println!(
        "byte-flip record positives: {flips} flips, {rejected} rejected, {} documented exemptions",
        exempt.values().sum::<u64>()
    );
    for (reason, count) in &exempt {
        println!("  exemption: {count} flips — {reason}");
    }
    assert!(
        violations.is_empty(),
        "byte-flip violations ({}):\n{}",
        violations.len(),
        violations.join("\n")
    );
    assert!(flips > 10_000, "unexpectedly few flips: {flips}");
}

// ---------------------------------------------------------------------------
// Container byte-flip gate
// ---------------------------------------------------------------------------

fn read_directory_files(root: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut files = BTreeMap::new();
    fn walk(root: &Path, current: &Path, files: &mut BTreeMap<String, Vec<u8>>) {
        let mut entries: Vec<PathBuf> = fs::read_dir(current)
            .map(|entry| {
                entry
                    .filter_map(Result::ok)
                    .map(|entry| entry.path())
                    .collect()
            })
            .unwrap_or_default();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                walk(root, &path, files);
            } else if path.is_file() {
                let relative = path
                    .strip_prefix(root)
                    .expect("inside root")
                    .to_string_lossy()
                    .replace('\\', "/");
                files.insert(relative, fs::read(&path).expect("read container file"));
            }
        }
    }
    walk(root, root, &mut files);
    files
}

/// Files whose bytes are deliberately not cryptographically bound by the
/// format: `readable/` is ignored entirely (§11.8) and `tsa-cert-<n>.pem` files
/// are never trusted on their own (§12.3).
fn unbound_container_file(path: &str) -> bool {
    path.starts_with("readable/")
        || (path.starts_with("signatures/tsa-cert-") && path.ends_with(".pem"))
}

fn is_record_file(path: &str) -> bool {
    path.starts_with("records/") && path.ends_with(".json")
}

/// Q13-exempt `alg` value ranges for a container file: `records/*.json` carry
/// `sigs`, and the attestation file carries `signatures`. Neither signature
/// structure is covered by the manifest digest (§2.4), so a flip that creates a
/// grammar-valid unknown algorithm is inert in the same way as for a standalone
/// record.
fn container_alg_ranges(path: &str, bytes: &[u8]) -> Vec<Range<usize>> {
    if is_record_file(path) {
        alg_value_ranges(bytes, "sigs")
    } else if path == "signatures/manifest.sig.json" {
        alg_value_ranges(bytes, "signatures")
    } else {
        Vec::new()
    }
}

#[test]
#[ignore = "gate run: minutes in release mode; execute with --release --include-ignored"]
fn byte_flip_container_positives() {
    let mut flips = 0u64;
    let mut rejected = 0u64;
    let mut exempt = BTreeMap::<&'static str, u64>::new();
    let mut violations: Vec<String> = Vec::new();
    for case in cases() {
        let expected = expected_json(&case);
        if !is_positive(&expected) || expected.get_str("target") != Some("container") {
            continue;
        }
        let id = case_id(&case);
        let input = input_path(&case, &expected);
        let options = options_from_args(&case, &expected);
        let files: BTreeMap<String, Vec<u8>> = if input.is_dir() {
            read_directory_files(&input)
        } else {
            let bytes = fs::read(&input).expect("zip container");
            hyphaweave_verify::zip::read_zip(&bytes).expect("zip parses")
        };
        for (path, data) in &files {
            if unbound_container_file(path) {
                *exempt
                    .entry("readable/ or tsa-cert pem (§11.8/§12.3)")
                    .or_default() += data.len() as u64;
                continue;
            }
            let alg_ranges = container_alg_ranges(path, data);
            for index in 0..data.len() {
                let mut mutated = files.clone();
                let mut changed = data.clone();
                changed[index] ^= 0x01;
                mutated.insert(path.clone(), changed);
                let report = verify_container(ContainerInput::Files(mutated), &options)
                    .expect("container verifies");
                flips += 1;
                if !report_has_terminal_verdict(&report) {
                    rejected += 1;
                    continue;
                }
                if creates_ignored_alg(data, index, &alg_ranges) {
                    let reason = if is_record_file(path) {
                        "record sigs[].alg value: Q13 ignored entry, digest excludes sigs"
                    } else {
                        "attestation signatures[].alg value: Q13 ignored entry"
                    };
                    *exempt.entry(reason).or_default() += 1;
                } else {
                    violations.push(format!(
                        "{id}: {path} byte {index} flip still yields {:?}",
                        report.verdict
                    ));
                }
            }
        }
    }
    println!(
        "byte-flip container positives: {flips} flips ({rejected} rejected), {} documented exemptions",
        exempt.values().sum::<u64>()
    );
    for (reason, count) in &exempt {
        println!("  exemption: {count} bytes — {reason}");
    }
    assert!(
        violations.is_empty(),
        "byte-flip violations ({}):\n{}",
        violations.len(),
        violations.join("\n")
    );
    assert!(flips > 10_000, "unexpectedly few flips: {flips}");
}

// ---------------------------------------------------------------------------
// Ablation gate
// ---------------------------------------------------------------------------

fn vectors_report_with_skip(code: &str) -> hyphaweave_verify::VectorCounts {
    let mut options = VerifyOptions::new();
    options.skip_checks.insert(code.to_owned());
    let report = hyphaweave_verify::verify_vectors(&vectors_root(), &options)
        .expect("vectors corpus verifies");
    match report.summary {
        hyphaweave_verify::Summary::Vectors(counts) => counts,
        hyphaweave_verify::Summary::Verdicts(_) => panic!("expected vector counts"),
    }
}

/// Builds one Ed25519-signed record from an object skeleton (test helper).
fn signed_record(mut object: Object, signer: &str, key_id: &str) -> Vec<u8> {
    let digest_string = digest::record_digest(&object);
    let message = digest::record_signature_message(&digest_string);
    let seed_path = vectors_root().join("keys").join(format!("{signer}.seed"));
    let seed_hex = fs::read_to_string(seed_path).expect("seed");
    let mut seed = [0u8; 32];
    for (index, pair) in seed_hex.trim().as_bytes().chunks(2).enumerate() {
        let byte = u8::from_str_radix(std::str::from_utf8(pair).expect("hex"), 16).expect("hex");
        seed[index] = byte;
    }
    let signature = ed25519::sign(&seed, &message);
    let mut entry = Object::new();
    entry.insert("alg", "ed25519");
    entry.insert("key", key_id);
    entry.insert("value", b64::encode(&signature));
    object.insert("sigs", Value::Array(vec![Value::Object(entry)]));
    json::canonical_object_bytes(&object)
}

/// The conclusion-relevant outcome of a report: verdict, error codes (container
/// and record level) and notices. Probes compare this with and without the
/// disabled check.
fn outcome(report: &Report) -> (Verdict, Vec<&'static str>) {
    let mut errors: Vec<&'static str> = report
        .records
        .iter()
        .flat_map(|record| record.errors.clone())
        .collect();
    let mut notices: Vec<&'static str> = report
        .records
        .iter()
        .flat_map(|record| record.notices.clone())
        .collect();
    if let Some(container) = &report.container {
        errors.extend(container.errors.iter().copied());
        notices.extend(container.notices.iter().copied());
    }
    errors.sort_unstable();
    notices.sort_unstable();
    (report.verdict, errors)
}

fn json_size_probe() -> bool {
    let mut options = VerifyOptions::new();
    options.keyset = load_keyset(&keyset_dir());
    let bytes = fs::read(vectors_root().join("sig/valid-single/record.json")).expect("record");
    let mut padded = bytes.clone();
    padded.extend(std::iter::repeat_n(b' ', 1_048_576));
    let plain = verify_record(&padded, &options).expect("record");
    let mut skipped_options = options.clone();
    skipped_options.skip_checks.insert(e::JSON_SIZE.to_owned());
    let skipped = verify_record(&padded, &skipped_options).expect("record");
    outcome(&plain) != outcome(&skipped)
}

fn grant_schema_probe() -> bool {
    let mut options = VerifyOptions::new();
    options.keyset = load_keyset(&keyset_dir());
    let key_id = "ed25519:333f90d1d9dfb653b78df977b9b13ff2";
    let mut origin = Object::new();
    origin.insert("project", "example");
    origin.insert("instance", key_id);
    let mut actor = Object::new();
    actor.insert("type", "human");
    actor.insert("key", key_id);
    let mut grant = Object::new();
    let mut grantee = Object::new();
    grantee.insert("key", "ed25519:b6190071e4bbc7c82afc702fa9ffa6f5");
    grant.insert("grantee", Value::Object(grantee));
    grant.insert("kinds", Value::Array(vec![Value::from("example.note")]));
    // Invalid action token: the closed vocabulary requires E_GRANT_SCHEMA.
    grant.insert("actions", Value::Array(vec![Value::from("bogus")]));
    grant.insert("scope", Value::Array(vec![Value::from("example")]));
    grant.insert("valid_from", "2026-11-01T00:00:00.000Z");
    grant.insert("valid_until", Value::Null);
    grant.insert("transferable", false);
    grant.insert("evidence", Value::Null);
    grant.insert("remedy", Value::Null);
    let mut body = Object::new();
    body.insert("action", "grant");
    body.insert("grant", Value::Object(grant));
    let mut record = Object::new();
    record.insert("actor", Value::Object(actor));
    record.insert("body", Value::Object(body));
    record.insert("format", "weave-record/1");
    record.insert("id", "grant-schema-probe");
    record.insert("kind", "weave.grant");
    record.insert("origin", Value::Object(origin));
    record.insert("recorded_at", "2026-11-01T00:00:00.000Z");
    record.insert("stage", "accepted");
    let bytes = signed_record(record, "human-1", key_id);
    let plain = verify_record(&bytes, &options).expect("record");
    let mut skipped_options = options.clone();
    skipped_options
        .skip_checks
        .insert(e::GRANT_SCHEMA.to_owned());
    let skipped = verify_record(&bytes, &skipped_options).expect("record");
    let pinned = plain
        .records
        .iter()
        .any(|record| record.errors.contains(&e::GRANT_SCHEMA));
    pinned && outcome(&plain) != outcome(&skipped)
}

fn minimal_manifest(extra: Option<(&str, Value)>) -> Vec<u8> {
    let key_id = "ed25519:333f90d1d9dfb653b78df977b9b13ff2";
    let mut origin = Object::new();
    origin.insert("project", "example");
    origin.insert("instance", key_id);
    let mut manifest = Object::new();
    manifest.insert("created_at", "2026-11-01T00:00:00.000Z");
    manifest.insert("format", "weave-record/1");
    manifest.insert("level", "L0");
    manifest.insert("manifest_version", 1);
    manifest.insert("origin", Value::Object(origin));
    manifest.insert("previous_manifest", Value::Null);
    manifest.insert("records", Value::Array(Vec::new()));
    if let Some((name, value)) = extra {
        manifest.insert(name, value);
    }
    json::canonical_object_bytes(&manifest)
}

fn container_files(manifest: Vec<u8>) -> BTreeMap<String, Vec<u8>> {
    let mut files = BTreeMap::new();
    files.insert("manifest.json".to_owned(), manifest);
    files
}

fn manifest_schema_probe() -> bool {
    let manifest = minimal_manifest(Some(("bogus_member", Value::Int(1))));
    let files = container_files(manifest);
    let plain = verify_container(ContainerInput::Files(files.clone()), &VerifyOptions::new())
        .expect("container");
    let mut options = VerifyOptions::new();
    options.skip_checks.insert(e::MANIFEST_SCHEMA.to_owned());
    let skipped = verify_container(ContainerInput::Files(files), &options).expect("container");
    outcome(&plain) != outcome(&skipped)
}

fn container_zip_probe() -> bool {
    let input = ContainerInput::Zip(vec![0u8; 64]);
    let plain = verify_container(input.clone(), &VerifyOptions::new()).expect("container");
    let mut options = VerifyOptions::new();
    options.skip_checks.insert(e::CONTAINER_ZIP.to_owned());
    let skipped = verify_container(input, &options).expect("container");
    outcome(&plain) != outcome(&skipped)
}

fn container_size_probe() -> bool {
    let manifest = minimal_manifest(None);
    let mut files = container_files(manifest);
    for index in 0..=200_000usize {
        files.insert(format!("readable/{index}"), Vec::new());
    }
    let input = ContainerInput::Files(files);
    let plain = verify_container(input.clone(), &VerifyOptions::new()).expect("container");
    let mut options = VerifyOptions::new();
    options.skip_checks.insert(e::CONTAINER_SIZE.to_owned());
    let skipped = verify_container(input, &options).expect("container");
    outcome(&plain) != outcome(&skipped)
}

#[test]
#[ignore = "gate run: minutes; execute with --release --include-ignored"]
fn ablation_every_code_turns_corpus_red() {
    let mut killed = 0u64;
    let mut survivors: Vec<&'static str> = Vec::new();
    for code in ALL_ERROR_CODES {
        let counts = vectors_report_with_skip(code);
        if counts.mismatched > 0 {
            killed += 1;
        } else {
            survivors.push(code);
        }
    }
    println!(
        "ablation: {} codes, {killed} killed by the corpus, {} survivors",
        ALL_ERROR_CODES.len(),
        survivors.len()
    );
    // Codes never emitted by this verifier are documented survivors; every other
    // survivor must be pinned by a targeted probe whose outcome changes when the
    // check is disabled.
    let never_emitted: BTreeSet<&str> = [e::ENV_SIG_ALG].into_iter().collect();
    let probes: BTreeMap<&str, fn() -> bool> = [
        (e::JSON_SIZE, json_size_probe as fn() -> bool),
        (e::GRANT_SCHEMA, grant_schema_probe as fn() -> bool),
        (e::MANIFEST_SCHEMA, manifest_schema_probe as fn() -> bool),
        (e::CONTAINER_ZIP, container_zip_probe as fn() -> bool),
        (e::CONTAINER_SIZE, container_size_probe as fn() -> bool),
    ]
    .into_iter()
    .collect();
    let mut unpinned: Vec<&str> = Vec::new();
    for code in &survivors {
        if never_emitted.contains(code) {
            println!("  documented survivor (never emitted by H1): {code}");
            continue;
        }
        match probes.get(code) {
            Some(probe) => {
                if probe() {
                    println!("  survivor pinned by probe: {code}");
                } else {
                    unpinned.push(code);
                }
            }
            None => unpinned.push(code),
        }
    }
    assert!(
        unpinned.is_empty(),
        "unpinned ablation survivors: {unpinned:?}"
    );
    assert!(killed + survivors.len() as u64 == ALL_ERROR_CODES.len() as u64);
}
