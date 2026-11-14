// SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
// SPDX-License-Identifier: Apache-2.0

//! Check-order cases found by the H1-FIX2 differential fuzzing (gate 5) that
//! no committed vector reaches. Each test edits one record of a committed
//! container, re-signs it with the committed test seed, rewrites the record
//! listing and re-signs the manifest (`ContainerInput::Files`).

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use hyphaweave_verify::options::ContainerInput;
use hyphaweave_verify::report::Report;
use hyphaweave_verify::value::{Object, Value};
use hyphaweave_verify::{b64, digest, ed25519, json, operator, verify_container, VerifyOptions};

const HUMAN_1: &str = "ed25519:333f90d1d9dfb653b78df977b9b13ff2";

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

fn set(object: &Object, name: &str, value: impl Into<Value>) -> Object {
    let mut out = object.without(name);
    out.insert(name, value);
    out
}

/// Re-signs every `sigs` entry whose key is `key_id` with `signer`'s seed.
fn resign(record: &Object, signer: &str, key_id: &str) -> Object {
    let digest_string = digest::record_digest(record);
    let message = digest::record_signature_message(&digest_string);
    let sigs: Vec<Value> = record
        .get_array("sigs")
        .expect("sigs")
        .iter()
        .map(|entry| {
            let entry = entry.as_object().expect("entry");
            if entry.get_str("key") == Some(key_id) {
                let signature = ed25519::sign(&seed(signer), &message);
                Value::Object(set(entry, "value", b64::encode(&signature)))
            } else {
                Value::Object(entry.clone())
            }
        })
        .collect();
    set(record, "sigs", Value::Array(sigs))
}

/// The records of a committed directory container.
fn records(container: &Path) -> Vec<Object> {
    let mut out = Vec::new();
    for entry in fs::read_dir(container.join("records")).expect("records") {
        let bytes = fs::read(entry.expect("entry").path()).expect("read");
        out.push(json::parse_object(&bytes).expect("record"));
    }
    out
}

/// An L0 container of `records` with the manifest signed by `human-1`;
/// the manifest's other members are copied from `template`.
fn container(template: &Path, records: &[Object]) -> ContainerInput {
    let template_manifest =
        json::parse_object(&fs::read(template.join("manifest.json")).expect("manifest"))
            .expect("manifest object");
    let mut entries: Vec<(String, &Object)> = records
        .iter()
        .map(|record| (digest::record_digest(record), record))
        .collect();
    entries.sort_by(|left, right| json::utf16_cmp(&left.0, &right.0));
    let mut files = BTreeMap::new();
    let mut listing = Vec::new();
    for (digest_string, record) in entries {
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
    let manifest = set(&template_manifest, "records", Value::Array(listing));
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

fn record_errors(report: &Report, id: &str) -> Vec<&'static str> {
    report
        .records
        .iter()
        .find(|record| record.id.as_deref() == Some(id))
        .map(|record| record.errors.clone())
        .expect("record in report")
}

/// §5.5.2 evaluates the chain "in the following order, and the first failing
/// check determines the error": step 6 (every grant of the chain inside its
/// window at the verification time) comes before step 7 (at most 8 links).
/// `grant/chain-depth-9-links`' note, whose cited grant needs a 9th link, is
/// `E_GRANT_UNRESOLVED`; with its `recorded_at` moved after every grant's
/// `valid_until` (and re-signed), step 6 fails first: `E_GRANT_EXPIRED`
/// (docs/h1-findings.md F68).
#[test]
fn grant_chain_validity_is_judged_before_depth() {
    let case = vectors_root().join("grant/chain-depth-9-links/container");
    let original = records(&case);
    let baseline =
        verify_container(container(&case, &original), &keyset_options()).expect("container");
    assert_eq!(
        record_errors(&baseline, "grant-depth-9-note"),
        vec!["E_GRANT_UNRESOLVED"]
    );
    let edited: Vec<Object> = original
        .iter()
        .map(|record| {
            if record.get_str("id") == Some("grant-depth-9-note") {
                let key = record
                    .get_object("actor")
                    .and_then(|actor| actor.get_str("key"))
                    .expect("actor key")
                    .to_owned();
                resign(
                    &set(record, "recorded_at", "2026-12-01T00:00:00.000Z"),
                    "agent-2",
                    &key,
                )
            } else {
                record.clone()
            }
        })
        .collect();
    let report = verify_container(container(&case, &edited), &keyset_options()).expect("container");
    assert_eq!(
        record_errors(&report, "grant-depth-9-note"),
        vec!["E_GRANT_EXPIRED"]
    );
}
