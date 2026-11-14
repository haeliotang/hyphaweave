// SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
// SPDX-License-Identifier: Apache-2.0

//! Record identity is the full `(origin.project, origin.instance, id)` triple
//! (H1-FIX2 Y1). §6.3 resolves references against "a record with that `origin`
//! and `id`", and §10.3 matches placeholders by "the same `origin` and `id`";
//! `origin` is the `{project, instance}` pair of §4.1. A placeholder's own
//! `origin` is not covered by the digest it carries, so an implementation that
//! keys the context by `(project, id)` alone lets a record or placeholder of
//! another instance stand in for the referenced one.
//!
//! Each test builds a directory-less container (`ContainerInput::Files`) from
//! a committed vector, changes one instance, recomputes every digest and
//! re-signs the records and the manifest with the committed test keys. No
//! committed vector covers these cases; `docs/h1-findings.md` F58 asks the
//! specification side for vectors.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use hyphaweave_verify::error_codes::e;
use hyphaweave_verify::options::ContainerInput;
use hyphaweave_verify::report::Report;
use hyphaweave_verify::value::{Object, Value};
use hyphaweave_verify::{b64, digest, ed25519, json, operator, verify_container, VerifyOptions};
use hyphaweave_verify::{Target, Verdict};

const HUMAN_1: &str = "ed25519:333f90d1d9dfb653b78df977b9b13ff2";
const HUMAN_2: &str = "ed25519:928a1e1dbe45a5d298ce5f6b5ce2eabe";

fn vectors_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../vectors")
}

fn keyset_options() -> VerifyOptions {
    let mut options = VerifyOptions::new();
    options.keyset = operator::load_keyset(&vectors_root().join("keys/keyset")).expect("keyset");
    options
}

fn seed(name: &str) -> [u8; 32] {
    let seed_hex =
        fs::read_to_string(vectors_root().join("keys").join(format!("{name}.seed"))).expect("seed");
    let mut seed = [0u8; 32];
    for (index, pair) in seed_hex.trim().as_bytes().chunks(2).enumerate() {
        seed[index] = u8::from_str_radix(std::str::from_utf8(pair).expect("hex"), 16).expect("hex");
    }
    seed
}

fn read_object(path: &Path) -> Object {
    json::parse_object(&fs::read(path).expect("read")).expect("json object")
}

/// Replaces (or adds) one member.
fn set(object: &Object, name: &str, value: impl Into<Value>) -> Object {
    let mut out = object.without(name);
    out.insert(name, value);
    out
}

fn origin(instance: &str) -> Object {
    let mut origin = Object::new();
    origin.insert("instance", instance);
    origin.insert("project", "example");
    origin
}

/// Re-signs a record with `human-1` (§2.3), replacing any `sigs`.
fn sign_record(object: &Object) -> Object {
    let digest_string = digest::record_digest(object);
    let signature = ed25519::sign(
        &seed("human-1"),
        &digest::record_signature_message(&digest_string),
    );
    let mut entry = Object::new();
    entry.insert("alg", "ed25519");
    entry.insert("key", HUMAN_1);
    entry.insert("value", b64::encode(&signature));
    set(object, "sigs", Value::Array(vec![Value::Object(entry)]))
}

/// A reference object `{origin, id, digest, kind}` (§6.1).
fn reference(instance: &str, id: &str, digest_string: &str, kind: &str) -> Object {
    let mut reference = Object::new();
    reference.insert("digest", digest_string);
    reference.insert("id", id);
    reference.insert("kind", kind);
    reference.insert("origin", Value::Object(origin(instance)));
    reference
}

/// Builds an L0 container from records: file names and the manifest listing
/// follow the record digests (§11.2.1), and the manifest is signed by
/// `human-1` (§11.3).
fn container(records: &[Object]) -> ContainerInput {
    let mut entries: Vec<(String, Object)> = records
        .iter()
        .map(|record| (digest::record_digest(record), record.clone()))
        .collect();
    entries.sort_by(|left, right| json::utf16_cmp(&left.0, &right.0));
    let mut files = BTreeMap::new();
    let mut listing = Vec::new();
    for (digest_string, record) in &entries {
        let hex = digest_string.strip_prefix("sha256:").expect("sha256");
        files.insert(
            format!("records/{hex}.json"),
            json::canonical_object_bytes(record),
        );
        let mut entry = Object::new();
        entry.insert("digest", digest_string.as_str());
        entry.insert("id", record.get_str("id").expect("id"));
        entry.insert("kind", record.get_str("kind").expect("kind"));
        listing.push(Value::Object(entry));
    }
    let mut manifest = Object::new();
    manifest.insert("created_at", "2026-11-01T00:00:00.000Z");
    manifest.insert("format", "weave-record/1");
    manifest.insert("level", "L0");
    manifest.insert("manifest_version", 1);
    manifest.insert("origin", Value::Object(origin(HUMAN_1)));
    manifest.insert("previous_manifest", Value::Null);
    manifest.insert("records", Value::Array(listing));
    let manifest_bytes = json::canonical_object_bytes(&manifest);
    let manifest_digest = digest::manifest_digest(&manifest_bytes);
    let signature = ed25519::sign(
        &seed("human-1"),
        &digest::manifest_signature_message(&manifest_digest),
    );
    let mut sig_entry = Object::new();
    sig_entry.insert("alg", "ed25519");
    sig_entry.insert("key", HUMAN_1);
    sig_entry.insert("value", b64::encode(&signature));
    let mut attestation = Object::new();
    attestation.insert("digest", manifest_digest.as_str());
    attestation.insert("format", "weave-record/1");
    attestation.insert("signatures", Value::Array(vec![Value::Object(sig_entry)]));
    attestation.insert("timestamps", Value::Array(Vec::new()));
    files.insert("manifest.json".to_owned(), manifest_bytes);
    files.insert(
        "signatures/manifest.sig.json".to_owned(),
        json::canonical_object_bytes(&attestation),
    );
    ContainerInput::Files(files)
}

fn container_errors(report: &Report) -> Vec<&'static str> {
    report
        .container
        .as_ref()
        .map(|container| container.errors.clone())
        .unwrap_or_default()
}

fn all_errors(report: &Report) -> Vec<&'static str> {
    let mut out: Vec<&'static str> = report
        .records
        .iter()
        .flat_map(|record| record.errors.clone())
        .collect();
    out.extend(container_errors(report));
    out.sort_unstable();
    out.dedup();
    out
}

/// The records of `erasure/valid-container`: (placeholder, erasure record).
fn erasure_vector_records() -> (Object, Object) {
    let records = vectors_root().join("erasure/valid-container/container/records");
    let mut placeholder = None;
    let mut erasure = None;
    for entry in fs::read_dir(&records).expect("records") {
        let object = read_object(&entry.expect("entry").path());
        match object.get_str("kind") {
            Some("weave.erased") => placeholder = Some(object),
            Some("weave.erasure") => erasure = Some(object),
            other => panic!("unexpected kind {other:?}"),
        }
    }
    (
        placeholder.expect("placeholder"),
        erasure.expect("erasure record"),
    )
}

/// Sanity check of the builder: the committed valid erasure container,
/// rebuilt from its records, verifies valid with no errors.
#[test]
fn rebuilt_erasure_container_is_valid() {
    let (placeholder, erasure) = erasure_vector_records();
    let report =
        verify_container(container(&[placeholder, erasure]), &keyset_options()).expect("container");
    assert_eq!(all_errors(&report), Vec::<&str>::new());
    assert_eq!(report.verdict, Verdict::Valid);
    assert_eq!(report.target, Target::Container);
}

/// §6.3: a reference to `(example, human-1, X, D)` where the context only has
/// `(example, human-2, X)` is `missing` ("no record with that `origin` and
/// `id` exists"), not `unverifiable` (which needs a record with that `origin`
/// and `id` whose digest does not match).
#[test]
fn reference_across_instances_is_missing_not_unverifiable() {
    let base = read_object(
        &vectors_root()
            .join("ref/found/container/records")
            .join("d21a9cf7c6f9f7d20c1ba1fa1366df842bf5bff61137ac527931aea016cb2bea.json"),
    );
    // The target: same project and id as the reference, another instance.
    let target = set(&base, "origin", Value::Object(origin(HUMAN_2)));
    // The reference names instance human-1 and a digest no record carries.
    let absent_digest = format!("sha256:{}", "11".repeat(32));
    let mut entry = Object::new();
    entry.insert(
        "ref",
        Value::Object(reference(
            HUMAN_1,
            "ref-target",
            &absent_digest,
            "example.note",
        )),
    );
    entry.insert("rel", "supersedes");
    let source = set(
        &set(&base, "id", "ref-source"),
        "refs",
        Value::Array(vec![Value::Object(entry)]),
    );
    let report =
        verify_container(container(&[source, target]), &keyset_options()).expect("container");
    let source_report = report
        .records
        .iter()
        .find(|record| record.id.as_deref() == Some("ref-source"))
        .expect("source record");
    let states: Vec<&str> = source_report
        .refs
        .iter()
        .map(|reference| reference.state.as_str())
        .collect();
    assert_eq!(states, vec!["missing"]);
    assert!(source_report.notices.contains(&"N_REF_MISSING"));
}

/// §10.3 rule 1: the erasure record's `erased` reference must resolve to a
/// placeholder "with the same `origin` and `id`"; a placeholder of another
/// instance carrying the right digest is an `origin`/`id` mismatch, so
/// `E_ERASE_DIGEST_MISMATCH` (container invalid).
#[test]
fn placeholder_of_another_instance_is_not_the_erased_target() {
    let (placeholder, erasure) = erasure_vector_records();
    let foreign = set(&placeholder, "origin", Value::Object(origin(HUMAN_2)));
    let report =
        verify_container(container(&[foreign, erasure]), &keyset_options()).expect("container");
    assert!(
        container_errors(&report).contains(&e::ERASE_DIGEST_MISMATCH),
        "errors: {:?}",
        all_errors(&report)
    );
    assert_eq!(report.verdict, Verdict::Invalid);
}

/// §10.3 rule 3: "Two placeholders for the same target" — two placeholders
/// with the same project and id but different instances are two targets, not
/// a contradiction. Each has its own signed erasure record; the container is
/// valid.
#[test]
fn placeholders_of_two_instances_do_not_contradict() {
    let (placeholder_a, erasure_a) = erasure_vector_records();
    // A second erasure of `(example, human-2, erasure-original-1, D2)`.
    let erased_digest_b = format!("sha256:{}", "22".repeat(32));
    let erasure_body = erasure_a.get_object("body").expect("body").clone();
    let erasure_body_b = set(
        &erasure_body,
        "erased",
        Value::Object(reference(
            HUMAN_2,
            "erasure-original-1",
            &erased_digest_b,
            "example.note",
        )),
    );
    let erasure_b = sign_record(&set(
        &set(&erasure_a, "id", "erasure-attestation-2"),
        "body",
        Value::Object(erasure_body_b),
    ));
    let erasure_b_digest = digest::record_digest(&erasure_b);
    let placeholder_b = set(
        &set(
            &set(&placeholder_a, "origin", Value::Object(origin(HUMAN_2))),
            "digest",
            erased_digest_b.as_str(),
        ),
        "attestation",
        Value::Object(reference(
            HUMAN_1,
            "erasure-attestation-2",
            &erasure_b_digest,
            "weave.erasure",
        )),
    );
    let report = verify_container(
        container(&[placeholder_a, erasure_a, placeholder_b, erasure_b]),
        &keyset_options(),
    )
    .expect("container");
    assert_eq!(all_errors(&report), Vec::<&str>::new());
    assert_eq!(report.verdict, Verdict::Valid);
}
