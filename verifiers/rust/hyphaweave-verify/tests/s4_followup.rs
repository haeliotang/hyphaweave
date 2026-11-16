// SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
// SPDX-License-Identifier: Apache-2.0

//! H1-S4 (decision 2026-11-16 #13): the two defects the pre-merge reviews
//! of H1-S3 found. A declaration that §5.3 does not admit governs no
//! validity window; and the §5.3 admission of declarations is settled once,
//! without recursion along cosignature chains, so a branching or a long
//! chain costs neither exponential time nor call stack. Every test goes
//! through `verify_container`, the CLI's entry point, on an L0 container
//! built here (set `H1_S4_DUMP_DIR` to write the containers out for the
//! reference black box).

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use hyphaweave_verify::error_codes::{e, n};
use hyphaweave_verify::options::ContainerInput;
use hyphaweave_verify::report::Report;
use hyphaweave_verify::value::{Object, Value};
use hyphaweave_verify::{b64, digest, ed25519, json, verify_container, Verdict, VerifyOptions};

const T0: &str = "2026-11-01T00:00:00.000Z";
const T1: &str = "2026-11-02T00:00:00.000Z";
const T2: &str = "2026-11-03T00:00:00.000Z";
const T3: &str = "2026-11-04T00:00:00.000Z";

fn vectors_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../vectors")
}

/// A published test seed (`vectors/keys/<name>.seed`).
fn published_seed(name: &str) -> [u8; 32] {
    let text = fs::read_to_string(vectors_root().join(format!("keys/{name}.seed"))).expect("seed");
    let mut out = [0u8; 32];
    for (index, pair) in text.trim().as_bytes().chunks(2).enumerate() {
        out[index] = u8::from_str_radix(std::str::from_utf8(pair).expect("hex"), 16).expect("hex");
    }
    out
}

/// A key of these tests: a published seed by name, or a derived one.
#[derive(Clone, Copy)]
struct Key {
    seed: [u8; 32],
}

impl Key {
    fn published(name: &str) -> Self {
        Self {
            seed: published_seed(name),
        }
    }

    fn derived(label: &str, number: usize) -> Self {
        Self {
            seed: digest::sha256(format!("h1-s4/{label}/{number}").as_bytes()),
        }
    }

    fn public(self) -> [u8; 32] {
        ed25519::public_key_from_seed(&self.seed)
    }

    fn id(self) -> String {
        digest::derive_key_id(&self.public())
    }
}

/// Signs `object` with every key (entries sorted by key id).
fn signed(mut object: Object, signers: &[Key]) -> Vec<u8> {
    let message = digest::record_signature_message(&digest::record_digest(&object));
    let mut entries: Vec<(String, Value)> = signers
        .iter()
        .map(|key| {
            let mut entry = Object::new();
            entry.insert("alg", "ed25519");
            entry.insert("key", key.id());
            entry.insert("value", b64::encode(&ed25519::sign(&key.seed, &message)));
            (key.id(), Value::Object(entry))
        })
        .collect();
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    object.insert(
        "sigs",
        Value::Array(entries.into_iter().map(|(_, entry)| entry).collect()),
    );
    json::canonical_object_bytes(&object)
}

fn envelope(
    id: &str,
    kind: &str,
    actor: Key,
    actor_type: &str,
    recorded_at: &str,
    body: Object,
) -> Object {
    let mut origin = Object::new();
    origin.insert("project", "example");
    origin.insert("instance", actor.id());
    let mut actor_object = Object::new();
    actor_object.insert("key", actor.id());
    actor_object.insert("type", actor_type);
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

/// A `weave.key.declared` record of `key`, signed by it and by `cosigners`.
fn declaration(
    id: &str,
    key: Key,
    class: &str,
    owner: Option<Key>,
    recorded_at: &str,
    valid_until: Option<&str>,
    cosigners: &[Key],
) -> Vec<u8> {
    let mut body = Object::new();
    body.insert("algorithm", "ed25519");
    body.insert("key", key.id());
    body.insert("key_type", class);
    if let Some(owner) = owner {
        body.insert("owner", owner.id());
    }
    body.insert("public_key", b64::encode(&key.public()));
    if let Some(until) = valid_until {
        body.insert("valid_until", until);
    }
    let mut signers = vec![key];
    signers.extend_from_slice(cosigners);
    signed(
        envelope(id, "weave.key.declared", key, class, recorded_at, body),
        &signers,
    )
}

fn note(id: &str, key: Key, actor_type: &str, recorded_at: &str) -> Vec<u8> {
    let mut body = Object::new();
    body.insert("text", "H1-S4");
    signed(
        envelope(id, "example.note", key, actor_type, recorded_at, body),
        &[key],
    )
}

/// An L0 container of `records`, its manifest signed by human-1.
fn l0_container(records: &[Vec<u8>]) -> BTreeMap<String, Vec<u8>> {
    let human_1 = Key::published("human-1");
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
    for (digest_string, bytes) in records {
        let object = json::parse_object(bytes).expect("record");
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
    origin.insert("instance", human_1.id());
    let mut manifest = Object::new();
    manifest.insert("created_at", "2026-11-05T00:00:00.000Z");
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
    entry.insert("key", human_1.id());
    entry.insert(
        "value",
        b64::encode(&ed25519::sign(&human_1.seed, &message)),
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

/// Verifies `records` as an L0 container with human-1's keyset declaration.
fn verify(name: &str, records: &[Vec<u8>]) -> Report {
    let files = l0_container(records);
    if let Some(directory) = std::env::var_os("H1_S4_DUMP_DIR") {
        let directory = PathBuf::from(directory).join(name);
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
    verify_container(ContainerInput::Files(files), &options).expect("container")
}

fn record_outcome<'a>(report: &'a Report, id: &str) -> (Verdict, &'a [&'static str]) {
    let record = report
        .records
        .iter()
        .find(|record| record.id.as_deref() == Some(id))
        .unwrap_or_else(|| panic!("record {id}"));
    (record.verdict, &record.errors)
}

/// §5.3: a declaration that is not semantically valid "governs no window".
/// Trusted keys: device D1 (T0, `valid_until` T1) carries, besides the
/// owner's cosignature, a cosignature by key-old, which nothing declares,
/// so §5.3 does not admit it; D2 (T2, no window) of the same key is
/// admitted, so the key has no window and D2 and the note at T3 are valid.
/// Without key-old's cosignature D1 is admitted, governs, and both are
/// `E_KEY_EXPIRED` (the review's probes w1 and w1c).
#[test]
fn a_declaration_that_is_not_admitted_governs_no_window_trusted_key() {
    let human_1 = Key::published("human-1");
    let device = Key::published("device-1");
    let undeclared = Key::published("key-old");
    for (extra, expected) in [
        (Some(undeclared), (Verdict::Valid, Vec::<&str>::new())),
        (None, (Verdict::Invalid, vec![e::KEY_EXPIRED])),
    ] {
        let mut cosigners = vec![human_1];
        cosigners.extend(extra);
        let d1 = declaration(
            "s4-w-d1",
            device,
            "device",
            Some(human_1),
            T0,
            Some(T1),
            &cosigners,
        );
        let d2 = declaration(
            "s4-w-d2",
            device,
            "device",
            Some(human_1),
            T2,
            None,
            &[human_1],
        );
        let name = format!("window-trusted-extra-{}", extra.is_some());
        let report = verify(&name, &[d1, d2, note("s4-w-note", device, "device", T3)]);
        for id in ["s4-w-d2", "s4-w-note"] {
            let (verdict, errors) = record_outcome(&report, id);
            assert_eq!((verdict, errors.to_vec()), expected.clone(), "{name}: {id}");
        }
    }
}

/// §9.1 rule 4: "an untrusted declaration MUST NOT make any other
/// declaration invalid", so it is not semantically valid and governs no
/// window either (found while writing the test above: the Rust verifier
/// used to let untrusted declarations govern). Two self-attested `human`
/// declarations of human-2, D1 at T0 with `valid_until` T1 (with and
/// without key-old's cosignature) and D2 at T2: D2 is `E_KEY_UNTRUSTED`
/// with `N_SELF_ATTESTED_ROOT_KEY`, never `E_KEY_EXPIRED`.
#[test]
fn an_untrusted_declaration_governs_no_window() {
    let human_2 = Key::published("human-2");
    let undeclared = Key::published("key-old");
    for extra in [Some(undeclared), None] {
        let cosigners: Vec<Key> = extra.into_iter().collect();
        let d1 = declaration("s4-u-d1", human_2, "human", None, T0, Some(T1), &cosigners);
        let d2 = declaration("s4-u-d2", human_2, "human", None, T2, None, &[]);
        let name = format!("window-untrusted-extra-{}", extra.is_some());
        let report = verify(&name, &[d1, d2]);
        let record = report
            .records
            .iter()
            .find(|record| record.id.as_deref() == Some("s4-u-d2"))
            .expect("d2");
        assert_eq!(record.errors, vec![e::KEY_UNTRUSTED], "{name}");
        assert_eq!(record.notices, vec![n::SELF_ATTESTED_ROOT_KEY], "{name}");
    }
}

/// Declarations of derived human keys: number 0 cosigned by human-1, every
/// later one by the keys of `previous(number)`; a note by the last key.
fn cosignature_graph(
    label: &str,
    count: usize,
    previous: impl Fn(usize) -> Vec<usize>,
) -> Vec<Vec<u8>> {
    let human_1 = Key::published("human-1");
    let mut records: Vec<Vec<u8>> = (0..count)
        .map(|number| {
            let cosigners: Vec<Key> = if number == 0 {
                vec![human_1]
            } else {
                previous(number)
                    .into_iter()
                    .map(|other| Key::derived(label, other))
                    .collect()
            };
            declaration(
                &format!("s4-{label}-{number:05}"),
                Key::derived(label, number),
                "human",
                None,
                T0,
                None,
                &cosigners,
            )
        })
        .collect();
    records.push(note(
        &format!("s4-{label}-note"),
        Key::derived(label, count - 1),
        "human",
        T2,
    ));
    records
}

/// Review A high 2: every declaration cosigned by the two before it took
/// time exponential in their number (about ×1.6 per declaration; 22 took
/// 26.7 s in a release build, 40 would take days). Admission is now settled
/// once per declaration, so 40 take a fraction of a second even unoptimised.
#[test]
fn branching_cosignature_graph_is_verified_in_bounded_time() {
    let records = cosignature_graph("branch", 40, |number| {
        if number == 1 {
            vec![0]
        } else {
            vec![number - 1, number - 2]
        }
    });
    let started = Instant::now();
    let report = verify("branch-40", &records);
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(60),
        "branch-40 took {elapsed:?}"
    );
    assert_eq!(report.verdict, Verdict::Valid, "{:?}", report.records);
    assert_eq!(report.records.len(), 41);
}

/// A cosignature cycle with chords and no grounding: number 0 is cosigned
/// by the last two keys instead of human-1, so no declaration is admitted
/// (S2-FIX3/F72, least fixed point) and the note's key has no material. The
/// strongly connected component is settled with a worklist, not by
/// exploring its paths.
#[test]
fn ungrounded_cosignature_cycle_is_settled_in_bounded_time() {
    let count = 40;
    let mut records = cosignature_graph("ring", count, |number| {
        if number == 1 {
            vec![0]
        } else {
            vec![number - 1, number - 2]
        }
    });
    let ring = |number: usize| Key::derived("ring", number);
    records[0] = declaration(
        "s4-ring-00000",
        ring(0),
        "human",
        None,
        T0,
        None,
        &[ring(count - 1), ring(count - 2)],
    );
    let started = Instant::now();
    let report = verify("ring-40", &records);
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(60),
        "ring-40 took {elapsed:?}"
    );
    for record in &report.records {
        assert_eq!(record.errors, vec![e::KEY_UNKNOWN], "{:?}", record.id);
        assert!(
            record.notices.contains(&n::KEY_UNDECLARED),
            "{:?}",
            record.id
        );
    }
}

/// Stack size of the long-chain test: CI runs on Linux, where a spawned
/// thread (as libtest uses) gets 2 MiB; a quarter of that leaves the
/// verifier's fixed cost (about 73 KiB on x86_64 debug, see
/// `tests/small_stack.rs`) plenty of room and is far too small for any
/// recursion along a chain of `CHAIN` declarations.
const CHAIN_STACK: usize = 256 * 1024;
const CHAIN: usize = 300;

/// A chain of `CHAIN` declarations, each cosigned by the one before it,
/// verified on a `CHAIN_STACK` thread. Before H1-S4 admission recursed once
/// per link (a stack overflow aborts the whole test process) and took time
/// quadratic in the chain (600 links took 52 s in a release build).
#[test]
fn long_cosignature_chain_on_a_small_stack() {
    let records = cosignature_graph("chain", CHAIN, |number| vec![number - 1]);
    let started = Instant::now();
    let report = std::thread::Builder::new()
        .stack_size(CHAIN_STACK)
        .spawn(move || verify("chain", &records))
        .expect("spawn")
        .join()
        .expect("no panic");
    let elapsed = started.elapsed();
    assert!(elapsed < Duration::from_secs(120), "chain took {elapsed:?}");
    assert_eq!(report.verdict, Verdict::Valid, "{:?}", report.records);
    assert_eq!(report.records.len(), CHAIN + 1);
}
