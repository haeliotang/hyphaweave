// SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
// SPDX-License-Identifier: Apache-2.0

//! Targeted probes for the checks that the committed vectors do not pin on
//! their own (R4, H1-FIX1). They run in the default `cargo test`, so CI runs
//! them. Each probe crafts an input that must report one specific code, and
//! also checks that the §14.7 hook changes that outcome; deleting the check
//! from the verifier turns the probe red. The slow corpus-wide ablation that
//! found these survivors is in `tests/gates.rs`.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use hyphaweave_verify::error_codes::e;
use hyphaweave_verify::options::ContainerInput;
use hyphaweave_verify::report::Report;
use hyphaweave_verify::value::{Object, Value};
use hyphaweave_verify::{
    b64, digest, ed25519, json, operator, verify_container, verify_record, VerifyOptions,
};

fn vectors_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../vectors")
}

fn keyset_options() -> VerifyOptions {
    let mut options = VerifyOptions::new();
    options.keyset = operator::load_keyset(&vectors_root().join("keys/keyset")).expect("keyset");
    options
}

/// Every error code of a report (container and records).
fn errors(report: &Report) -> Vec<&'static str> {
    let mut out: Vec<&'static str> = report
        .records
        .iter()
        .flat_map(|record| record.errors.clone())
        .collect();
    if let Some(container) = &report.container {
        out.extend(container.errors.iter().copied());
    }
    out.sort_unstable();
    out.dedup();
    out
}

/// The conclusion of a report: its verdict and its error codes.
fn conclusion(report: &Report) -> (hyphaweave_verify::Verdict, Vec<&'static str>) {
    (report.verdict, errors(report))
}

fn skipping(mut options: VerifyOptions, code: &str) -> VerifyOptions {
    options.skip_checks.insert(code.to_owned());
    options
}

fn signed_record(mut object: Object, signer: &str, key_id: &str) -> Vec<u8> {
    let digest_string = digest::record_digest(&object);
    let message = digest::record_signature_message(&digest_string);
    let seed_hex = fs::read_to_string(vectors_root().join("keys").join(format!("{signer}.seed")))
        .expect("seed");
    let mut seed = [0u8; 32];
    for (index, pair) in seed_hex.trim().as_bytes().chunks(2).enumerate() {
        seed[index] = u8::from_str_radix(std::str::from_utf8(pair).expect("hex"), 16).expect("hex");
    }
    let signature = ed25519::sign(&seed, &message);
    let mut entry = Object::new();
    entry.insert("alg", "ed25519");
    entry.insert("key", key_id);
    entry.insert("value", b64::encode(&signature));
    object.insert("sigs", Value::Array(vec![Value::Object(entry)]));
    json::canonical_object_bytes(&object)
}

#[test]
fn probe_json_size_record_target() {
    let options = keyset_options();
    let mut padded = fs::read(vectors_root().join("sig/valid-single/record.json")).expect("record");
    padded.extend(std::iter::repeat_n(b' ', 1_048_576));
    let plain = verify_record(&padded, &options).expect("record");
    assert_eq!(errors(&plain), vec![e::JSON_SIZE]);
    assert_eq!(
        plain.input.sha256, None,
        "§14.6 T16: oversize record input is null"
    );
    let skipped = verify_record(&padded, &skipping(options, e::JSON_SIZE)).expect("record");
    assert_ne!(conclusion(&plain), conclusion(&skipped));
}

#[test]
fn probe_grant_schema_action_vocabulary() {
    let options = keyset_options();
    let key_id = "ed25519:333f90d1d9dfb653b78df977b9b13ff2";
    let mut origin = Object::new();
    origin.insert("project", "example");
    origin.insert("instance", key_id);
    let mut actor = Object::new();
    actor.insert("type", "human");
    actor.insert("key", key_id);
    let mut grantee = Object::new();
    grantee.insert("key", "ed25519:b6190071e4bbc7c82afc702fa9ffa6f5");
    let mut grant = Object::new();
    grant.insert("grantee", Value::Object(grantee));
    grant.insert("kinds", Value::Array(vec![Value::from("example.note")]));
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
    assert_eq!(errors(&plain), vec![e::GRANT_SCHEMA]);
    let skipped = verify_record(&bytes, &skipping(options, e::GRANT_SCHEMA)).expect("record");
    assert_ne!(conclusion(&plain), conclusion(&skipped));
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

#[test]
fn probe_manifest_schema_unknown_member() {
    let mut files = BTreeMap::new();
    files.insert(
        "manifest.json".to_owned(),
        minimal_manifest(Some(("bogus_member", Value::Int(1)))),
    );
    let input = ContainerInput::Files(files);
    let plain = verify_container(input.clone(), &VerifyOptions::new()).expect("container");
    assert_eq!(errors(&plain), vec![e::MANIFEST_SCHEMA]);
    assert!(plain.records.is_empty());
    let skipped = verify_container(input, &skipping(VerifyOptions::new(), e::MANIFEST_SCHEMA))
        .expect("container");
    assert_ne!(conclusion(&plain), conclusion(&skipped));
}

/// `container/zip-valid` with general-purpose bit 0 (encryption) set on its
/// first entry, in both the local header and the central directory: rule 4 of
/// §11.9 (encrypted entries are `E_CONTAINER_ZIP`), with every other rule
/// intact.
fn encrypted_zip() -> Vec<u8> {
    let mut bytes =
        fs::read(vectors_root().join("container/zip-valid/container.zip")).expect("zip");
    let central = bytes
        .windows(4)
        .position(|window| window == [0x50, 0x4b, 0x01, 0x02])
        .expect("central header");
    let local = u32::from_le_bytes([
        bytes[central + 42],
        bytes[central + 43],
        bytes[central + 44],
        bytes[central + 45],
    ]) as usize;
    // The same entry in both places, so rule 1 (local/central agreement)
    // still holds and only the encryption rule can reject it.
    bytes[central + 8] |= 0x01;
    bytes[local + 6] |= 0x01;
    bytes
}

#[test]
fn probe_container_zip_encrypted_entry() {
    let options = keyset_options();
    let input = ContainerInput::Zip(encrypted_zip());
    let plain = verify_container(input.clone(), &options).expect("container");
    assert_eq!(errors(&plain), vec![e::CONTAINER_ZIP]);
    let skipped = verify_container(input, &skipping(options, e::CONTAINER_ZIP)).expect("container");
    assert_ne!(conclusion(&plain), conclusion(&skipped));
}

#[test]
fn probe_container_zip_unsupported_method() {
    let mut bytes =
        fs::read(vectors_root().join("container/zip-valid/container.zip")).expect("zip");
    let central = bytes
        .windows(4)
        .position(|window| window == [0x50, 0x4b, 0x01, 0x02])
        .expect("central header");
    let local = u32::from_le_bytes([
        bytes[central + 42],
        bytes[central + 43],
        bytes[central + 44],
        bytes[central + 45],
    ]) as usize;
    // Method 12 (bzip2) for the same entry in both headers.
    bytes[central + 10] = 12;
    bytes[central + 11] = 0;
    bytes[local + 8] = 12;
    bytes[local + 9] = 0;
    let report =
        verify_container(ContainerInput::Zip(bytes), &keyset_options()).expect("container");
    assert_eq!(errors(&report), vec![e::CONTAINER_ZIP]);
}

#[test]
fn probe_container_size_directory_entry_count() {
    let mut files = BTreeMap::new();
    files.insert("manifest.json".to_owned(), minimal_manifest(None));
    for index in 0..200_000usize {
        files.insert(format!("blobs/x{index}"), Vec::new());
    }
    let input = ContainerInput::Files(files);
    let plain = verify_container(input.clone(), &VerifyOptions::new()).expect("container");
    assert_eq!(errors(&plain), vec![e::CONTAINER_SIZE]);
    let skipped = verify_container(input, &skipping(VerifyOptions::new(), e::CONTAINER_SIZE))
        .expect("container");
    assert_ne!(conclusion(&plain), conclusion(&skipped));
}

/// Copies a directory tree (test fixtures only).
fn copy_tree(from: &std::path::Path, to: &std::path::Path) {
    fs::create_dir_all(to).expect("mkdir");
    for entry in fs::read_dir(from).expect("read_dir") {
        let entry = entry.expect("entry");
        let destination = to.join(entry.file_name());
        if entry.path().is_dir() {
            copy_tree(&entry.path(), &destination);
        } else {
            fs::copy(entry.path(), &destination).expect("copy");
        }
    }
}

/// A scratch copy of `container/l0-minimal` under the system temporary
/// directory, unique per process and call site.
fn l0_minimal_copy(tag: u32) -> PathBuf {
    let source = vectors_root().join("container/l0-minimal/container");
    let target = std::env::temp_dir().join(format!("h1-probe-{}-{tag}", std::process::id()));
    copy_tree(&source, &target);
    target
}

/// Regression (H1-FIX1 differential fuzzing): §11.7 requires a non-empty
/// `manifest.blobs` whenever a `blobs/` directory is present, even an empty
/// one. Built from `container/l0-minimal` plus an empty `blobs/sha256/`.
#[test]
fn empty_blobs_directory_without_listing_is_manifest_blob() {
    let target = l0_minimal_copy(line!());
    let plain = verify_container(ContainerInput::Directory(target.clone()), &keyset_options())
        .expect("container");
    fs::create_dir_all(target.join("blobs/sha256")).expect("blobs dir");
    let with_empty_blobs =
        verify_container(ContainerInput::Directory(target.clone()), &keyset_options())
            .expect("container");
    fs::remove_dir_all(&target).expect("cleanup");
    assert_eq!(errors(&plain), Vec::<&str>::new());
    assert_eq!(errors(&with_empty_blobs), vec![e::MANIFEST_BLOB]);
}

/// F55 (H1-FIX1 replays): an unlisted `records/` file above
/// `MAX_RECORD_BYTES` is an extra file and an oversize record file; the
/// records-listing phase reports both (§14.5, U8, T16). The committed
/// `oversize-record-*` vectors only have listed oversize files.
#[test]
fn unlisted_oversize_record_file_reports_both_listing_violations() {
    let target = l0_minimal_copy(line!());
    let name = format!("records/{}.json", "0".repeat(64));
    fs::write(target.join(&name), vec![b' '; 1_048_577]).expect("oversize file");
    let report = verify_container(ContainerInput::Directory(target.clone()), &keyset_options())
        .expect("container");
    fs::remove_dir_all(&target).expect("cleanup");
    assert_eq!(
        errors(&report),
        vec![e::JSON_SIZE, e::MANIFEST_RECORD_EXTRA]
    );
    assert!(report.records.is_empty());
}
