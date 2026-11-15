// SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
// SPDX-License-Identifier: Apache-2.0

//! H1-S2 (decision 2026-11-15 #20): the three deviations the S2 review
//! (review A low-1) found by differential fuzzing and no committed vector
//! pins. Each test goes through `verify_container` or `verify_record`, the
//! entry points of the CLI, on an input derived from a committed vector.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use hyphaweave_verify::error_codes::{e, l};
use hyphaweave_verify::options::ContainerInput;
use hyphaweave_verify::report::Report;
use hyphaweave_verify::value::{Object, Value};
use hyphaweave_verify::{
    b64, digest, ed25519, json, verify_container, verify_record, Verdict, VerifyOptions,
};

fn vectors_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../vectors")
}

/// The files of a directory tree, by `/`-separated relative path.
fn read_tree(root: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut files = BTreeMap::new();
    let mut work = vec![root.to_path_buf()];
    while let Some(directory) = work.pop() {
        for entry in fs::read_dir(&directory).expect("read_dir") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                work.push(path);
            } else {
                let relative = path
                    .strip_prefix(root)
                    .expect("prefix")
                    .to_str()
                    .expect("utf-8 path")
                    .replace('\\', "/");
                files.insert(relative, fs::read(&path).expect("read"));
            }
        }
    }
    files
}

/// The committed keyset, file bytes in name order, with one file's bytes
/// optionally replaced.
fn keyset_with(replace: Option<(&str, Vec<u8>)>) -> VerifyOptions {
    let directory = vectors_root().join("keys/keyset");
    let mut names: Vec<String> = fs::read_dir(&directory)
        .expect("keyset")
        .map(|entry| {
            entry
                .expect("entry")
                .file_name()
                .into_string()
                .expect("name")
        })
        .filter(|name| name.ends_with(".json"))
        .collect();
    names.sort();
    let mut options = VerifyOptions::new();
    for name in names {
        let bytes = match &replace {
            Some((target, bytes)) if *target == name => bytes.clone(),
            _ => fs::read(directory.join(&name)).expect("keyset file"),
        };
        options.keyset.push(bytes);
    }
    options
}

fn container_errors(report: &Report) -> Vec<&'static str> {
    report
        .container
        .as_ref()
        .map(|container| container.errors.clone())
        .unwrap_or_default()
}

/// `'[' * 33 + ']' * 33`: an array nested one level deeper than
/// `MAX_JSON_DEPTH`.
fn deep_array() -> Vec<u8> {
    let mut bytes = vec![b'['; 33];
    bytes.extend(std::iter::repeat_n(b']', 33));
    bytes
}

/// §1.9, §13 (review A low-1, first item): a 33-level array is a depth
/// violation, `E_JSON_SIZE`, although its top-level value is not the object a
/// record or a manifest requires — that shape is judged once the value has
/// been read. Record target, container manifest and attestation file.
#[test]
fn deep_top_level_array_is_json_size() {
    let options = keyset_with(None);
    let record = verify_record(&deep_array(), &options).expect("record");
    assert_eq!(record.verdict, Verdict::Invalid);
    assert_eq!(record.records[0].errors, vec![e::JSON_SIZE]);

    let source = vectors_root().join("container/l0-minimal/container");
    for member in ["manifest.json", "signatures/manifest.sig.json"] {
        let mut files = read_tree(&source);
        assert!(files.contains_key(member), "{member}");
        files.insert(member.to_owned(), deep_array());
        let report = verify_container(ContainerInput::Files(files), &options).expect("container");
        assert_eq!(report.verdict, Verdict::Invalid, "{member}");
        assert_eq!(container_errors(&report), vec![e::JSON_SIZE], "{member}");
    }
    // The same nesting one level shallower is no depth violation: the
    // top-level value is then judged, and it is not an object.
    let mut shallow = vec![b'['; 32];
    shallow.extend(std::iter::repeat_n(b']', 32));
    let record = verify_record(&shallow, &options).expect("record");
    assert_eq!(record.records[0].errors, vec![e::JSON_INVALID]);
}

/// §1.6, §1.9 (review A low-1, second item): a top-level integer outside
/// `[-(2^53-1), 2^53-1]` is `E_JSON_NUMBER_RANGE` at its token, before the
/// top-level shape is judged; the same number inside an object already was.
#[test]
fn top_level_out_of_range_integer_is_number_range() {
    let options = keyset_with(None);
    let record = verify_record(b"18446744073709551616", &options).expect("record");
    assert_eq!(record.verdict, Verdict::Invalid);
    assert_eq!(record.records[0].errors, vec![e::JSON_NUMBER_RANGE]);
    let nested = verify_record(br#"{"a":18446744073709551616}"#, &options).expect("record");
    assert_eq!(nested.records[0].errors, vec![e::JSON_NUMBER_RANGE]);
    // An in-range top-level integer is still not an object.
    let small = verify_record(b"1", &options).expect("record");
    assert_eq!(small.records[0].errors, vec![e::JSON_INVALID]);

    let mut files = read_tree(&vectors_root().join("container/l0-minimal/container"));
    files.insert("manifest.json".to_owned(), b"18446744073709551616".to_vec());
    let report = verify_container(ContainerInput::Files(files), &options).expect("container");
    assert_eq!(container_errors(&report), vec![e::JSON_NUMBER_RANGE]);
}

/// The keyset declaration of human-1 with one character of its
/// self-signature changed: still a structurally valid record (§14.1), but its
/// own self-signature check fails.
fn broken_human_1_declaration() -> Vec<u8> {
    let path = vectors_root().join("keys/keyset/key-declared-human-1.json");
    let text = fs::read_to_string(path).expect("declaration");
    let marker = "\"value\":\"";
    let start = text.find(marker).expect("signature value") + marker.len() + 10;
    let mut bytes = text.into_bytes();
    bytes[start] = if bytes[start] == b'A' { b'B' } else { b'A' };
    bytes
}

/// §14.1 (review A low-1, third item): a keyset declaration that fails its
/// own checks "does not establish trust and is ignored", so it supplies no
/// key material either. The manifest of `actor/agent-accepted-valid` is
/// signed by human-1, which nothing else in that context declares: with the
/// keyset declaration broken the manifest key is unknown (`E_KEY_UNKNOWN`,
/// unverifiable) instead of being verified with the ignored declaration.
#[test]
fn failing_keyset_declaration_supplies_no_material() {
    let source = vectors_root().join("actor/agent-accepted-valid/container");
    let intact = verify_container(
        ContainerInput::Directory(source.clone()),
        &keyset_with(None),
    )
    .expect("container");
    assert_eq!(intact.verdict, Verdict::Valid);
    let broken = keyset_with(Some((
        "key-declared-human-1.json",
        broken_human_1_declaration(),
    )));
    let report = verify_container(ContainerInput::Directory(source), &broken).expect("container");
    assert_eq!(report.verdict, Verdict::Unverifiable);
    assert!(
        container_errors(&report).contains(&e::KEY_UNKNOWN),
        "{:?}",
        container_errors(&report)
    );
}

/// §14.1, §14.9 (review A low-1, third item, second form): when the ignored
/// keyset declaration's key is also declared inside the container, the
/// manifest signature's material comes from the container — context
/// material, so the report carries `L_KEY_TRUST_TOFU`; with the intact
/// keyset the material is the keyset's and it does not.
#[test]
fn failing_keyset_declaration_leaves_context_material_tofu() {
    let zip = fs::read(vectors_root().join("container/zip-valid/container.zip")).expect("zip");
    let intact =
        verify_container(ContainerInput::Zip(zip.clone()), &keyset_with(None)).expect("container");
    assert!(!intact
        .limitations
        .iter()
        .any(|limitation| limitation == l::KEY_TRUST_TOFU));
    let broken = keyset_with(Some((
        "key-declared-human-1.json",
        broken_human_1_declaration(),
    )));
    let report = verify_container(ContainerInput::Zip(zip), &broken).expect("container");
    assert!(
        report
            .limitations
            .iter()
            .any(|limitation| limitation == l::KEY_TRUST_TOFU),
        "{:?}",
        report.limitations
    );
}

/// A published test seed (`vectors/keys/<name>.seed`).
fn seed(name: &str) -> [u8; 32] {
    let text = fs::read_to_string(vectors_root().join(format!("keys/{name}.seed"))).expect("seed");
    let mut out = [0u8; 32];
    for (index, pair) in text.trim().as_bytes().chunks(2).enumerate() {
        out[index] = u8::from_str_radix(std::str::from_utf8(pair).expect("hex"), 16).expect("hex");
    }
    out
}

fn key_id(name: &str) -> String {
    digest::derive_key_id(&ed25519::public_key_from_seed(&seed(name)))
}

/// Signs `object` with every named seed (entries sorted by key id).
fn signed(mut object: Object, signers: &[&str]) -> Vec<u8> {
    let message = digest::record_signature_message(&digest::record_digest(&object));
    let mut entries: Vec<(String, Value)> = signers
        .iter()
        .map(|name| {
            let mut entry = Object::new();
            entry.insert("alg", "ed25519");
            entry.insert("key", key_id(name));
            entry.insert("value", b64::encode(&ed25519::sign(&seed(name), &message)));
            (key_id(name), Value::Object(entry))
        })
        .collect();
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    object.insert(
        "sigs",
        Value::Array(entries.into_iter().map(|(_, entry)| entry).collect()),
    );
    json::canonical_object_bytes(&object)
}

fn envelope(id: &str, kind: &str, actor: &str, recorded_at: &str, body: Object) -> Object {
    let mut origin = Object::new();
    origin.insert("project", "example");
    origin.insert("instance", key_id(actor));
    let mut actor_object = Object::new();
    actor_object.insert("key", key_id(actor));
    actor_object.insert("type", "human");
    let mut object = Object::new();
    object.insert("actor", Value::Object(actor_object));
    object.insert("body", Value::Object(body));
    object.insert("format", "weave-record/1");
    object.insert("id", id);
    object.insert("kind", kind);
    object.insert("origin", Value::Object(origin));
    object.insert("recorded_at", recorded_at);
    object.insert("stage", "accepted");
    object
}

fn human_declaration(id: &str, key: &str, recorded_at: &str, cosigner: &str) -> Vec<u8> {
    let mut body = Object::new();
    body.insert("algorithm", "ed25519");
    body.insert("key", key_id(key));
    body.insert("key_type", "human");
    body.insert(
        "public_key",
        b64::encode(&ed25519::public_key_from_seed(&seed(key))),
    );
    signed(
        envelope(id, "weave.key.declared", key, recorded_at, body),
        &[key, cosigner],
    )
}

/// An L0 container of `records`, its manifest signed by human-1.
fn l0_container(records: &[Vec<u8>]) -> BTreeMap<String, Vec<u8>> {
    let mut files = BTreeMap::new();
    let mut listed = Vec::new();
    let mut records: Vec<(String, &Vec<u8>)> = records
        .iter()
        .map(|bytes| {
            let object = json::parse_object(bytes).expect("record");
            (digest::record_digest(&object), bytes)
        })
        .collect();
    // §11.6: `manifest.records` is sorted by digest ascending.
    records.sort();
    for (_, bytes) in records {
        let object = json::parse_object(bytes).expect("record");
        let digest_string = digest::record_digest(&object);
        let mut entry = Object::new();
        entry.insert("digest", digest_string.clone());
        entry.insert("id", object.get_str("id").expect("id"));
        entry.insert("kind", object.get_str("kind").expect("kind"));
        listed.push(Value::Object(entry));
        let hex = digest_string.trim_start_matches("sha256:");
        files.insert(format!("records/{hex}.json"), bytes.clone());
    }
    let mut origin = Object::new();
    origin.insert("project", "example");
    origin.insert("instance", key_id("human-1"));
    let mut manifest = Object::new();
    manifest.insert("created_at", "2026-11-01T12:00:00.000Z");
    manifest.insert("format", "weave-record/1");
    manifest.insert("level", "L0");
    manifest.insert("manifest_version", 1);
    manifest.insert("origin", Value::Object(origin));
    manifest.insert("previous_manifest", Value::Null);
    manifest.insert("records", Value::Array(listed));
    let manifest_bytes = json::canonical_object_bytes(&manifest);
    let manifest_digest = digest::manifest_digest(&manifest_bytes);
    let message = digest::manifest_signature_message(&manifest_digest);
    let mut entry = Object::new();
    entry.insert("alg", "ed25519");
    entry.insert("key", key_id("human-1"));
    entry.insert(
        "value",
        b64::encode(&ed25519::sign(&seed("human-1"), &message)),
    );
    let mut attestation = Object::new();
    attestation.insert("digest", manifest_digest);
    attestation.insert("format", "weave-record/1");
    attestation.insert("signatures", Value::Array(vec![Value::Object(entry)]));
    attestation.insert("timestamps", Value::Array(Vec::new()));
    files.insert("manifest.json".to_owned(), manifest_bytes);
    files.insert(
        "signatures/manifest.sig.json".to_owned(),
        json::canonical_object_bytes(&attestation),
    );
    files
}

/// §5.3 (S2-FIX1/Q2), docs/h1-findings.md F72: a declaration whose
/// cosignature fails §9.4 "establishes no trust", so a key trusted only
/// through it cannot hand trust on. human-1 (the only keyset root) is
/// retired at T1; human-2 is declared at T2 with human-1's cosignature
/// (fails §9.4, `E_KEY_REVOKED`); key-old is declared human at T3 with
/// human-2's cosignature; a note signed by key-old at T4 has no key material
/// (`E_KEY_UNKNOWN`). Without the second-order rule the key-old declaration
/// would be admitted through human-2's closure trust and the note valid.
#[test]
fn trust_is_not_handed_on_through_a_declaration_that_supplies_no_material() {
    let mut revoke = Object::new();
    revoke.insert("effective_at", "2026-11-02T00:00:00.000Z");
    revoke.insert("key", key_id("human-1"));
    revoke.insert("reason", "retired");
    let revocation = signed(
        envelope(
            "s2-f72-retire-human-1",
            "weave.key.revoked",
            "human-1",
            "2026-11-02T00:00:00.000Z",
            revoke,
        ),
        &["human-1"],
    );
    let human_2 = human_declaration(
        "s2-f72-human-2",
        "human-2",
        "2026-11-03T00:00:00.000Z",
        "human-1",
    );
    let key_old = human_declaration(
        "s2-f72-key-old",
        "key-old",
        "2026-11-04T00:00:00.000Z",
        "human-2",
    );
    let mut text = Object::new();
    text.insert(
        "text",
        "signed by a key trusted through a failed cosignature",
    );
    let note = signed(
        envelope(
            "s2-f72-note",
            "example.note",
            "key-old",
            "2026-11-05T00:00:00.000Z",
            text,
        ),
        &["key-old"],
    );
    let files = l0_container(&[revocation, human_2, key_old, note]);
    if let Some(directory) = std::env::var_os("H1_S2_DUMP_DIR") {
        // Probe aid: write the container out for the reference black box.
        let directory = PathBuf::from(directory);
        for (path, bytes) in &files {
            let target = directory.join(path);
            fs::create_dir_all(target.parent().expect("parent")).expect("mkdir");
            fs::write(target, bytes).expect("write");
        }
    }
    let mut options = VerifyOptions::new();
    options.keyset.push(
        fs::read(vectors_root().join("keys/keyset/key-declared-human-1.json")).expect("root"),
    );
    let report = verify_container(ContainerInput::Files(files), &options).expect("container");
    let by_id = |id: &str| {
        report
            .records
            .iter()
            .find(|record| record.id.as_deref() == Some(id))
            .expect("record")
    };
    assert_eq!(by_id("s2-f72-retire-human-1").errors, Vec::<&str>::new());
    assert_eq!(by_id("s2-f72-human-2").errors, vec![e::KEY_REVOKED]);
    assert_eq!(by_id("s2-f72-note").errors, vec![e::KEY_UNKNOWN]);
}

/// §4.5 (H1-S2 differential fuzzing): every structural violation of a
/// placeholder is `E_KIND_BODY_SCHEMA`, a `format` of another JSON type
/// ("wrong member type") or another string included.
#[test]
fn placeholder_format_of_another_type_is_body_schema() {
    let options = keyset_with(None);
    let source = vectors_root().join("digest/record-erased-placeholder/record.json");
    let object = json::parse_object(&fs::read(source).expect("placeholder")).expect("json");
    let with_format = |format: Value| {
        let mut entries = Object::new();
        for (name, value) in object.iter() {
            if name == "format" {
                entries.insert(name, format.clone());
            } else {
                entries.insert(name, value.clone());
            }
        }
        verify_record(&json::canonical_object_bytes(&entries), &options).expect("record")
    };
    assert_eq!(
        with_format(Value::Int(2)).records[0].errors,
        vec![e::KIND_BODY_SCHEMA]
    );
    assert_eq!(
        with_format(Value::Str("weave-record/2".to_owned())).records[0].errors,
        vec![e::KIND_BODY_SCHEMA]
    );
}

/// §10.3 (H1-S2 differential fuzzing): the cross-checks apply "when both
/// the placeholder and its erasure record are present". The container of
/// `erasure/actor-agent-grant-absent` without its placeholder has no §10.3
/// code; with the placeholder (the committed case) rule 1 holds as well.
#[test]
fn erasure_without_placeholder_has_no_cross_check_code() {
    let source = vectors_root().join("erasure/actor-agent-grant-absent/container/records");
    let mut records = Vec::new();
    for entry in fs::read_dir(&source).expect("records") {
        let bytes = fs::read(entry.expect("entry").path()).expect("record");
        let object = json::parse_object(&bytes).expect("json");
        if object.get_str("kind") != Some("weave.erased") {
            records.push(bytes);
        }
    }
    assert_eq!(records.len(), 1);
    let report = verify_container(
        ContainerInput::Files(l0_container(&records)),
        &keyset_with(None),
    )
    .expect("container");
    assert!(
        !container_errors(&report).contains(&e::ERASE_DIGEST_MISMATCH),
        "{:?}",
        container_errors(&report)
    );
}

/// §11.3, §12.2 step 1, §9.4 (S2/F54; H1-S2 differential fuzzing): an
/// unlisted `.tsr` is `E_TS_FILE`, and with no receipt listed there is still
/// no timestamp evidence at all, so a signature by a compromised key stays
/// `E_KEY_COMPROMISED` (not the `E_TS_UNTRUSTED` of present but unusable
/// receipts).
#[test]
fn unlisted_receipt_is_no_evidence_for_the_compromise_rule() {
    let mut files =
        read_tree(&vectors_root().join("key-lifecycle/compromise-retroactive/container"));
    let plain = verify_container(ContainerInput::Files(files.clone()), &keyset_with(None))
        .expect("container");
    let codes = |report: &Report| {
        let mut out: Vec<&str> = report
            .records
            .iter()
            .flat_map(|record| record.errors.clone())
            .chain(container_errors(report))
            .collect();
        out.sort_unstable();
        out.dedup();
        out
    };
    assert_eq!(codes(&plain), vec![e::KEY_COMPROMISED]);
    files.insert("signatures/timestamp-9.tsr".to_owned(), vec![0x30, 0x00]);
    let report =
        verify_container(ContainerInput::Files(files), &keyset_with(None)).expect("container");
    assert_eq!(codes(&report), vec![e::KEY_COMPROMISED, e::TS_FILE]);
}

/// §10.3 with S2/F48 read symmetrically (H1-S2 differential fuzzing): an
/// erasure record that fails the structural group (here its `sigs` format,
/// `E_ENV_SIGS`) is not "its erasure record", so the placeholder's
/// attestation does not resolve to one (`E_ERASE_ATTESTATION`).
#[test]
fn structurally_failed_erasure_record_is_not_attested() {
    let mut files = read_tree(&vectors_root().join("erasure/valid-container/container"));
    let erasure_path = files
        .iter()
        .find(|(_, bytes)| {
            json::parse_object(bytes)
                .is_ok_and(|object| object.get_str("kind") == Some("weave.erasure"))
        })
        .map(|(path, _)| path.clone())
        .expect("erasure record");
    let plain = verify_container(ContainerInput::Files(files.clone()), &keyset_with(None))
        .expect("container");
    assert!(container_errors(&plain).is_empty());
    let mut object = json::parse_object(&files[&erasure_path]).expect("json");
    let mut entries = Object::new();
    for (name, value) in object.iter() {
        if name == "sigs" {
            entries.insert(name, Value::Int(1));
        } else {
            entries.insert(name, value.clone());
        }
    }
    object = entries;
    files.insert(erasure_path, json::canonical_object_bytes(&object));
    let report =
        verify_container(ContainerInput::Files(files), &keyset_with(None)).expect("container");
    assert_eq!(container_errors(&report), vec![e::ERASE_ATTESTATION]);
}

/// §11.3 (S2-FIX2/U5 and its §9.4 half, decided with it by principle): the
/// manifest signature entries are judged invalid-first. human-1 is retired
/// before the manifest's `created_at`, so its manifest signature is invalid
/// `E_KEY_REVOKED` (§9.4); an entry by an undeclared key that sorts first does
/// not lower that to `E_KEY_UNKNOWN`.
#[test]
fn manifest_lifecycle_failure_beats_an_undeclared_entry() {
    let mut retire = Object::new();
    retire.insert("effective_at", "2026-11-01T06:00:00.000Z");
    retire.insert("key", key_id("human-1"));
    retire.insert("reason", "retired");
    let revocation = signed(
        envelope(
            "s2-u5-retire-human-1",
            "weave.key.revoked",
            "human-1",
            "2026-11-01T06:00:00.000Z",
            retire,
        ),
        &["human-1"],
    );
    let mut files = l0_container(&[revocation]);
    let single = verify_container(ContainerInput::Files(files.clone()), &keyset_with(None))
        .expect("container");
    assert_eq!(container_errors(&single), vec![e::KEY_REVOKED]);
    let attestation_path = "signatures/manifest.sig.json".to_owned();
    let mut attestation = json::parse_object(&files[&attestation_path]).expect("attestation");
    let mut entries = vec![{
        let mut entry = Object::new();
        entry.insert("alg", "ed25519");
        entry.insert("key", format!("ed25519:{}", "0".repeat(32)));
        entry.insert("value", b64::encode(&[0u8; 64]));
        Value::Object(entry)
    }];
    if let Some(Value::Array(existing)) = attestation.get("signatures") {
        entries.extend(existing.iter().cloned());
    }
    let mut rebuilt = Object::new();
    for (name, value) in attestation.iter() {
        if name == "signatures" {
            rebuilt.insert(name, Value::Array(entries.clone()));
        } else {
            rebuilt.insert(name, value.clone());
        }
    }
    attestation = rebuilt;
    files.insert(attestation_path, json::canonical_object_bytes(&attestation));
    let report =
        verify_container(ContainerInput::Files(files), &keyset_with(None)).expect("container");
    assert_eq!(report.verdict, Verdict::Invalid);
    assert_eq!(container_errors(&report), vec![e::KEY_REVOKED]);
}

/// §11.3 (S2-FIX2b): an entry that fails the equation decides
/// `E_MANIFEST_SIG_INVALID` before another entry's invalid §9.4 outcome,
/// whatever the order: human-1 (retired, first in key order) beside a
/// human-2 entry whose signature does not verify.
#[test]
fn manifest_equation_failure_beats_a_lifecycle_failure() {
    let mut retire = Object::new();
    retire.insert("effective_at", "2026-11-01T06:00:00.000Z");
    retire.insert("key", key_id("human-1"));
    retire.insert("reason", "retired");
    let revocation = signed(
        envelope(
            "s2-fix2b-retire-human-1",
            "weave.key.revoked",
            "human-1",
            "2026-11-01T06:00:00.000Z",
            retire,
        ),
        &["human-1"],
    );
    let mut files = l0_container(&[revocation]);
    let attestation_path = "signatures/manifest.sig.json".to_owned();
    let attestation = json::parse_object(&files[&attestation_path]).expect("attestation");
    let mut entries: Vec<Value> = match attestation.get("signatures") {
        Some(Value::Array(existing)) => existing.clone(),
        _ => Vec::new(),
    };
    let mut forged = Object::new();
    forged.insert("alg", "ed25519");
    forged.insert("key", key_id("human-2"));
    forged.insert(
        "value",
        b64::encode(&ed25519::sign(&seed("human-2"), b"other")),
    );
    entries.push(Value::Object(forged));
    let mut rebuilt = Object::new();
    for (name, value) in attestation.iter() {
        if name == "signatures" {
            rebuilt.insert(name, Value::Array(entries.clone()));
        } else {
            rebuilt.insert(name, value.clone());
        }
    }
    files.insert(attestation_path, json::canonical_object_bytes(&rebuilt));
    let report =
        verify_container(ContainerInput::Files(files), &keyset_with(None)).expect("container");
    assert_eq!(container_errors(&report), vec![e::MANIFEST_SIG_INVALID]);
}
