// SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
// SPDX-License-Identifier: Apache-2.0

//! External Ed25519 conformance checks (the material behind gate 4).
//!
//! Everything is read from the committed third-party data, resolved relative to
//! `env!("CARGO_MANIFEST_DIR")`; no network access and no Python code:
//!
//! - `vectors/external/rfc8032/rfc8032.txt`: every RFC 8032 §7.1 vector must
//!   pass — the derived public key equals the published one, the deterministic
//!   signature equals the published one, and the published signature verifies.
//! - `vectors/external/wycheproof/testvectors_v1/ed25519_test.json` together
//!   with `EXPECTED_OUTCOMES.json`: every Wycheproof Ed25519 case mapped by
//!   §3.7 — `valid` accepted, `invalid` rejected, `acceptable` rejected, with
//!   `E_SIG_SMALL_ORDER_A` / `E_SIG_MIXED_ORDER_A` for the two defect classes
//!   present in the corpus.
//! - `vectors/keys/edge-points/`: the hostile edge public-key encodings (eight
//!   canonical small-order points, `x0-sign-bit`, `noncanonical-y-p`,
//!   `mixed-order-a`), used both as public keys and as `R`.
//! - `vectors/sig/`: the crafted record-signature cases whose pinned defect is
//!   inside §3.4, verified over the real §2.3 signature message so the identity
//!   and mixed-order forgeries are exercised end-to-end.
//!
//! Run with `--nocapture` for the per-section counts.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use hyphaweave_verify::ed25519;
use hyphaweave_verify::error_codes::{e, Code};
use hyphaweave_verify::json;
use hyphaweave_verify::value::{Object, Value};
use hyphaweave_verify::{b64, digest, limits};

/// The repository's `vectors/` directory, from the crate root.
fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../vectors")
}

fn read_bytes(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()))
}

fn read_json_object(path: &Path) -> Object {
    let bytes = read_bytes(path);
    json::parse_object(&bytes)
        .unwrap_or_else(|error| panic!("cannot parse {}: {error:?}", path.display()))
}

fn hex(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0, "hex string has an even length");
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| (hex_digit(pair[0]) << 4) | hex_digit(pair[1]))
        .collect()
}

fn hex_digit(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => panic!("invalid hexadecimal digit"),
    }
}

fn hex32(text: &str) -> [u8; 32] {
    hex(text).as_slice().try_into().expect("32 bytes")
}

fn is_hex_line(line: &str) -> bool {
    line.len() % 2 == 0 && line.bytes().all(|byte| byte.is_ascii_hexdigit())
}

// ---------------------------------------------------------------------------
// RFC 8032 §7.1
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct RfcVector {
    name: String,
    algorithm: String,
    seed: Vec<u8>,
    public_key: Vec<u8>,
    message: Vec<u8>,
    signature: Vec<u8>,
    declared_message_len: usize,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RfcField {
    None,
    Algorithm,
    Seed,
    Public,
    Message,
    Signature,
}

/// Extracts the five RFC 8032 §7.1 Ed25519 vectors from the stored RFC text.
///
/// The text is paginated, so page footers and form feeds interrupt the
/// hexadecimal runs; the parser collects only hexadecimal lines under the
/// current label and ignores everything else.
fn parse_rfc8032_vectors(text: &str) -> Vec<RfcVector> {
    let heading = "\n7.1.  Test Vectors for Ed25519\n";
    let start = text.find(heading).expect("RFC 8032 §7.1 heading") + heading.len();
    let body = &text[start..];
    let next_heading = "\n7.2.  Test Vectors for Ed25519ctx\n";
    let end = body.find(next_heading).expect("RFC 8032 §7.2 heading");
    let section = &body[..end];

    let mut vectors: Vec<RfcVector> = Vec::new();
    let mut current: Option<RfcVector> = None;
    let mut field = RfcField::None;

    for raw_line in section.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(name) = line.strip_prefix("-----") {
            if let Some(vector) = current.take() {
                vectors.push(vector);
            }
            if name.trim().is_empty() {
                field = RfcField::None;
                continue;
            }
            current = Some(RfcVector {
                name: name.trim().to_string(),
                algorithm: String::new(),
                seed: Vec::new(),
                public_key: Vec::new(),
                message: Vec::new(),
                signature: Vec::new(),
                declared_message_len: 0,
            });
            field = RfcField::None;
            continue;
        }
        if line == "ALGORITHM:" {
            field = RfcField::Algorithm;
            continue;
        }
        if line == "SECRET KEY:" {
            field = RfcField::Seed;
            continue;
        }
        if line == "PUBLIC KEY:" {
            field = RfcField::Public;
            continue;
        }
        if line == "SIGNATURE:" {
            field = RfcField::Signature;
            continue;
        }
        if let Some(rest) = line.strip_prefix("MESSAGE (length ") {
            let rest = rest.strip_suffix("):").expect("message label suffix");
            let number = rest
                .strip_suffix(" bytes")
                .or_else(|| rest.strip_suffix(" byte"))
                .expect("message length unit");
            let vector = current.as_mut().expect("message label before test header");
            vector.declared_message_len = number.parse().expect("message length digits");
            field = RfcField::Message;
            continue;
        }
        if field == RfcField::Algorithm {
            current
                .as_mut()
                .expect("algorithm before test header")
                .algorithm = line.to_string();
            field = RfcField::None;
            continue;
        }
        if !is_hex_line(line) {
            continue; // Page footer, form feed or padding.
        }
        let bytes = hex(line);
        let vector = current.as_mut().expect("hexadecimal line before test header");
        match field {
            RfcField::Seed => vector.seed.extend_from_slice(&bytes),
            RfcField::Public => vector.public_key.extend_from_slice(&bytes),
            RfcField::Message => vector.message.extend_from_slice(&bytes),
            RfcField::Signature => vector.signature.extend_from_slice(&bytes),
            RfcField::None | RfcField::Algorithm => {}
        }
    }
    if let Some(vector) = current {
        vectors.push(vector);
    }
    vectors
}

fn check_rfc8032() -> usize {
    let path = vectors_dir().join("external/rfc8032/rfc8032.txt");
    let text = String::from_utf8(read_bytes(&path))
        .unwrap_or_else(|error| panic!("{} is not UTF-8: {error}", path.display()));
    let vectors = parse_rfc8032_vectors(&text);
    assert_eq!(vectors.len(), 5, "RFC 8032 §7.1 has five Ed25519 vectors");

    for vector in &vectors {
        assert_eq!(vector.algorithm, "Ed25519", "{}: algorithm", vector.name);
        assert_eq!(vector.seed.len(), 32, "{}: secret key length", vector.name);
        assert_eq!(
            vector.public_key.len(),
            32,
            "{}: public key length",
            vector.name
        );
        assert_eq!(
            vector.message.len(),
            vector.declared_message_len,
            "{}: message length",
            vector.name
        );
        assert_eq!(vector.signature.len(), 64, "{}: signature length", vector.name);

        let seed: [u8; 32] = vector.seed.as_slice().try_into().expect("32-byte seed");
        let derived = ed25519::public_key_from_seed(&seed);
        assert_eq!(
            derived.as_slice(),
            vector.public_key.as_slice(),
            "{}: derived public key",
            vector.name
        );
        assert_eq!(
            ed25519::sign(&seed, &vector.message).as_slice(),
            vector.signature.as_slice(),
            "{}: deterministic signature",
            vector.name
        );
        ed25519::verify(&vector.public_key, &vector.signature, &vector.message)
            .unwrap_or_else(|code| {
                panic!("{}: published signature rejected with {code}", vector.name)
            });
    }
    vectors.len()
}

// ---------------------------------------------------------------------------
// Wycheproof Ed25519
// ---------------------------------------------------------------------------

struct WycheproofCase {
    tc_id: i64,
    public_key: Vec<u8>,
    message: Vec<u8>,
    signature: Vec<u8>,
    result: String,
    flags: Vec<String>,
    comment: String,
}

fn parse_wycheproof_corpus(path: &Path) -> Vec<WycheproofCase> {
    let document = read_json_object(path);
    let groups = document.get_array("testGroups").expect("testGroups array");
    let mut cases = Vec::new();
    for group in groups {
        let group = group.as_object().expect("test group object");
        let public_key_hex = group
            .get_object("publicKey")
            .expect("publicKey object")
            .get_str("pk")
            .expect("publicKey.pk");
        let public_key = hex(public_key_hex);
        assert_eq!(public_key.len(), 32, "Wycheproof public key length");
        for test in group.get_array("tests").expect("tests array") {
            let test = test.as_object().expect("test object");
            cases.push(WycheproofCase {
                tc_id: test.get_i64("tcId").expect("tcId"),
                public_key: public_key.clone(),
                message: hex(test.get_str("msg").expect("msg")),
                signature: hex(test.get_str("sig").expect("sig")),
                result: test.get_str("result").expect("result").to_string(),
                flags: test
                    .get_array("flags")
                    .expect("flags array")
                    .iter()
                    .map(|flag| flag.as_str().expect("flag string").to_string())
                    .collect(),
                comment: test.get_str("comment").unwrap_or("").to_string(),
            });
        }
    }
    cases
}

fn verify_wycheproof(case: &WycheproofCase) -> Result<(), Code> {
    // §3.4 step 1 is the caller's structural check: the signature octets must be
    // exactly 64. Several Wycheproof cases (`TruncatedSignature`,
    // `SignatureWithGarbage`, `CompressedSignature`) exercise it directly.
    if case.signature.len() != 64 {
        return Err(e::ENV_SIG_VALUE);
    }
    ed25519::verify(&case.public_key, &case.signature, &case.message)
}

/// Returns `(valid accepted, invalid rejected, acceptable rejected,
/// small-order acceptable, mixed-order acceptable)`.
fn check_wycheproof() -> (usize, usize, usize, usize, usize) {
    let directory = vectors_dir().join("external/wycheproof");
    let cases = parse_wycheproof_corpus(&directory.join("testvectors_v1/ed25519_test.json"));
    assert_eq!(cases.len(), 210, "Wycheproof Ed25519 corpus size");

    let expected_document = read_json_object(&directory.join("EXPECTED_OUTCOMES.json"));
    assert_eq!(
        expected_document.get_str("file"),
        Some("testvectors_v1/ed25519_test.json"),
        "EXPECTED_OUTCOMES file identity"
    );
    let mut outcomes: BTreeMap<i64, (String, String)> = BTreeMap::new();
    for value in expected_document
        .get_array("outcomes")
        .expect("outcomes array")
    {
        let outcome = value.as_object().expect("outcome object");
        let tc_id = outcome.get_i64("tcId").expect("tcId");
        let action = outcome.get_str("expected").expect("expected").to_string();
        let result = outcome.get_str("result").expect("result").to_string();
        assert!(
            outcomes.insert(tc_id, (action, result)).is_none(),
            "duplicate tcId {tc_id} in EXPECTED_OUTCOMES"
        );
    }
    assert_eq!(
        outcomes.len(),
        cases.len(),
        "EXPECTED_OUTCOMES covers every Wycheproof case"
    );

    let mut valid_accepted = 0;
    let mut invalid_rejected = 0;
    let mut acceptable_rejected = 0;
    let mut small_order_a = 0;
    let mut mixed_order_a = 0;

    for case in &cases {
        let (action, result) = outcomes
            .get(&case.tc_id)
            .unwrap_or_else(|| panic!("tcId {} missing from EXPECTED_OUTCOMES", case.tc_id));
        assert_eq!(
            result, &case.result,
            "tcId {}: outcome table and corpus disagree",
            case.tc_id
        );
        let accept_expected = match action.as_str() {
            "accept" => {
                assert_eq!(
                    case.result, "valid",
                    "tcId {}: accept implies valid",
                    case.tc_id
                );
                true
            }
            "reject" => {
                assert!(
                    case.result == "invalid" || case.result == "acceptable",
                    "tcId {}: reject implies invalid or acceptable",
                    case.tc_id
                );
                false
            }
            other => panic!("tcId {}: unknown expected outcome {other}", case.tc_id),
        };

        let verdict = verify_wycheproof(case);
        if accept_expected {
            assert_eq!(
                verdict,
                Ok(()),
                "tcId {} ({}): expected accept: {}",
                case.tc_id,
                case.result,
                case.comment
            );
            valid_accepted += 1;
            continue;
        }
        let code = match verdict {
            Ok(()) => panic!(
                "tcId {} ({}): expected reject but was accepted: {}",
                case.tc_id, case.result, case.comment
            ),
            Err(code) => code,
        };
        if case.result == "invalid" {
            invalid_rejected += 1;
            continue;
        }
        // §3.7: `acceptable` cases are rejected by this profile; the two defect
        // classes present in the corpus have dedicated codes.
        if case.flags.iter().any(|flag| flag == "SmallOrderPublicKey") {
            assert_eq!(
                code,
                e::SIG_SMALL_ORDER_A,
                "tcId {}: small-order public key code",
                case.tc_id
            );
            small_order_a += 1;
        } else if case.flags.iter().any(|flag| flag == "MixedOrderPublicKey") {
            assert_eq!(
                code,
                e::SIG_MIXED_ORDER_A,
                "tcId {}: mixed-order public key code",
                case.tc_id
            );
            mixed_order_a += 1;
        } else {
            panic!(
                "tcId {}: acceptable case has no mapped defect class",
                case.tc_id
            );
        }
        acceptable_rejected += 1;
    }

    assert_eq!(valid_accepted, 117, "Wycheproof valid cases accepted");
    assert_eq!(invalid_rejected, 64, "Wycheproof invalid cases rejected");
    assert_eq!(
        acceptable_rejected, 29,
        "Wycheproof acceptable cases rejected"
    );
    assert_eq!(small_order_a, 8, "small-order acceptable cases");
    assert_eq!(mixed_order_a, 21, "mixed-order acceptable cases");
    (
        valid_accepted,
        invalid_rejected,
        acceptable_rejected,
        small_order_a,
        mixed_order_a,
    )
}

// ---------------------------------------------------------------------------
// Hostile edge-point encodings
// ---------------------------------------------------------------------------

/// Returns `(public keys classified, R encodings classified)`.
fn check_edge_points() -> (usize, usize) {
    let directory = vectors_dir().join("keys/edge-points");
    let index = read_json_object(&directory.join("index.json"));
    let points = index.get_array("points").expect("edge-points points array");
    assert_eq!(points.len(), 11, "edge-points fixture size");

    // A valid prime-order public key (RFC 8032 §7.1 TEST 1) for the `R` checks.
    let valid_public_key = hex32("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");

    let mut classified_keys = 0;
    let mut classified_r = 0;
    for value in points {
        let point = value.as_object().expect("edge point object");
        let name = point.get_str("name").expect("name");
        let class = point.get_str("class").expect("class");
        let encoding = hex(point.get_str("encoding").expect("encoding"));
        assert_eq!(encoding.len(), 32, "{name}: encoding length");

        let stored_path = directory.join(format!("{name}.pub.bin"));
        assert_eq!(
            read_bytes(&stored_path),
            encoding,
            "{name}: index.json encoding and {name}.pub.bin disagree"
        );

        let public_key: [u8; 32] = encoding.as_slice().try_into().expect("32-byte key");
        let expected_key_code = match class {
            "small-order" => e::SIG_SMALL_ORDER_A,
            "x0-sign-bit" | "noncanonical" => e::SIG_NONCANONICAL_A,
            "mixed-order" => e::SIG_MIXED_ORDER_A,
            other => panic!("{name}: unknown edge class {other}"),
        };
        assert_eq!(
            ed25519::verify(&public_key, &[0u8; 64], b"hostile edge"),
            Err(expected_key_code),
            "{name} as public key"
        );
        classified_keys += 1;

        // The same encoding used as `R` with a valid prime-order public key.
        let mut signature = [0u8; 64];
        signature[..32].copy_from_slice(&public_key);
        let expected_r_code = match class {
            "small-order" => e::SIG_SMALL_ORDER_R,
            "x0-sign-bit" | "noncanonical" => e::SIG_NONCANONICAL_R,
            // A mixed-order `R` is not itself forbidden; the cofactorless
            // equation decides, and with S = 0 and a prime-order A it fails.
            "mixed-order" => e::SIG_INVALID,
            other => panic!("{name}: unknown edge class {other}"),
        };
        assert_eq!(
            ed25519::verify(&valid_public_key, &signature, b"hostile edge"),
            Err(expected_r_code),
            "{name} as R"
        );
        classified_r += 1;
    }
    (classified_keys, classified_r)
}

// ---------------------------------------------------------------------------
// Project sig vectors: the crafted-signature cases pinned by their own vectors
// ---------------------------------------------------------------------------

/// The §3.4 crypto-stage code that each `vectors/sig/` case pins. Only the
/// cases whose defect is inside §3.4 are listed; the remaining sig vectors fail
/// at the envelope or signature-obligation stage owned by other modules.
const SIG_VECTOR_CODES: [(&str, Code); 24] = [
    ("S-equals-L", e::SIG_S_OUT_OF_RANGE),
    ("S-L-plus-1", e::SIG_S_OUT_OF_RANGE),
    ("noncanonical-A", e::SIG_NONCANONICAL_A),
    ("noncanonical-R", e::SIG_NONCANONICAL_R),
    ("x0-sign-bit-A", e::SIG_NONCANONICAL_A),
    ("x0-sign-bit-R", e::SIG_NONCANONICAL_R),
    ("mixed-order-A", e::SIG_MIXED_ORDER_A),
    ("small-order-A-00", e::SIG_SMALL_ORDER_A),
    ("small-order-A-01", e::SIG_SMALL_ORDER_A),
    ("small-order-A-02", e::SIG_SMALL_ORDER_A),
    ("small-order-A-03", e::SIG_SMALL_ORDER_A),
    ("small-order-A-04", e::SIG_SMALL_ORDER_A),
    ("small-order-A-05", e::SIG_SMALL_ORDER_A),
    ("small-order-A-06", e::SIG_SMALL_ORDER_A),
    ("small-order-A-07", e::SIG_SMALL_ORDER_A),
    ("small-order-R-00", e::SIG_SMALL_ORDER_R),
    ("small-order-R-01", e::SIG_SMALL_ORDER_R),
    ("small-order-R-02", e::SIG_SMALL_ORDER_R),
    ("small-order-R-03", e::SIG_SMALL_ORDER_R),
    ("small-order-R-04", e::SIG_SMALL_ORDER_R),
    ("small-order-R-05", e::SIG_SMALL_ORDER_R),
    ("small-order-R-06", e::SIG_SMALL_ORDER_R),
    ("small-order-R-07", e::SIG_SMALL_ORDER_R),
    ("invalid-value", e::SIG_INVALID),
];

fn decode_public_key(text: &str) -> [u8; 32] {
    b64::decode_exact(text, 32)
        .expect("32-byte unpadded base64url public key")
        .as_slice()
        .try_into()
        .expect("32-byte public key")
}

fn read_canonical_record(path: &Path) -> Object {
    let bytes = read_bytes(path);
    json::parse_canonical_object(&bytes, limits::MAX_RECORD_BYTES)
        .unwrap_or_else(|code| panic!("cannot parse canonical record {}: {code}", path.display()))
}

/// Loads `key_id -> public key` from the `@keyset` key-declaration records that
/// the record vectors use for signatures by an external (non-declared) key.
fn load_keyset() -> BTreeMap<String, [u8; 32]> {
    let directory = vectors_dir().join("keys/keyset");
    let mut paths: Vec<PathBuf> = std::fs::read_dir(&directory)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", directory.display()))
        .map(|entry| entry.expect("keyset directory entry").path())
        .collect();
    paths.sort();
    let mut keys = BTreeMap::new();
    for path in paths {
        if path.extension().and_then(|extension| extension.to_str()) != Some("json") {
            continue;
        }
        let record = read_canonical_record(&path);
        let body = record
            .get_object("body")
            .unwrap_or_else(|| panic!("{}: keyset record body", path.display()));
        if body.get_str("algorithm") != Some("ed25519") {
            continue;
        }
        let key_id = body
            .get_str("key")
            .unwrap_or_else(|| panic!("{}: keyset record key", path.display()));
        let public_key = decode_public_key(
            body.get_str("public_key")
                .unwrap_or_else(|| panic!("{}: keyset record public_key", path.display())),
        );
        keys.insert(key_id.to_string(), public_key);
    }
    keys
}

/// Verifies the record-signature bytes of the crafted `vectors/sig/` cases with
/// the real §2.3 message construction. This exercises the identity-point
/// forgery, the mixed-order forgery (whose crafted signature satisfies the
/// cofactorless equation, so only step 6 rejects it) and the non-canonical
/// `R`/`A` encodings end-to-end.
fn check_project_sig_vectors() -> usize {
    let directory = vectors_dir().join("sig");
    let keyset = load_keyset();
    let mut checked = 0;
    for (case, expected) in SIG_VECTOR_CODES {
        let path = directory.join(case).join("record.json");
        let record = read_canonical_record(&path);
        let actor_key = record
            .get_object("actor")
            .unwrap_or_else(|| panic!("{case}: actor object"))
            .get_str("key")
            .unwrap_or_else(|| panic!("{case}: actor.key"));
        let body = record
            .get_object("body")
            .unwrap_or_else(|| panic!("{case}: body object"));
        // Hostile-encoding cases declare the hostile key in the record body;
        // the other cases sign with a key from the keyset.
        let public_key = match body.get_str("public_key") {
            Some(declared) => decode_public_key(declared),
            None => *keyset
                .get(actor_key)
                .unwrap_or_else(|| panic!("{case}: key {actor_key} not in the keyset")),
        };
        let signature_entry = record
            .get_array("sigs")
            .unwrap_or_else(|| panic!("{case}: sigs array"))
            .iter()
            .filter_map(Value::as_object)
            .find(|entry| entry.get_str("key") == Some(actor_key))
            .unwrap_or_else(|| panic!("{case}: no signature by {actor_key}"));
        let signature = b64::decode_exact(
            signature_entry
                .get_str("value")
                .unwrap_or_else(|| panic!("{case}: signature value")),
            64,
        )
        .unwrap_or_else(|()| panic!("{case}: signature is not 64 base64url bytes"));
        let message = digest::record_signature_message(&digest::record_digest(&record));
        assert_eq!(
            ed25519::verify(&public_key, &signature, &message),
            Err(expected),
            "{case}: pinned §3.4 code"
        );
        checked += 1;
    }
    checked
}

// ---------------------------------------------------------------------------
// The combined external check
// ---------------------------------------------------------------------------

#[test]
fn external_ed25519_vectors() {
    let rfc_vectors = check_rfc8032();
    let (valid, invalid, acceptable, small_order, mixed_order) = check_wycheproof();
    let (edge_keys, edge_r) = check_edge_points();
    let project_vectors = check_project_sig_vectors();

    println!(
        "RFC 8032 §7.1: {rfc_vectors}/5 vectors pass \
         (public-key derivation, deterministic signing, verification)"
    );
    println!(
        "Wycheproof Ed25519: {}/210 outcomes match \
         ({valid} valid accepted, {invalid} invalid rejected, \
         {acceptable} acceptable rejected: {small_order} small-order A, \
         {mixed_order} mixed-order A)",
        valid + invalid + acceptable
    );
    println!(
        "hostile edge-points: {edge_keys}/11 public keys classified, \
         {edge_r}/11 R encodings classified"
    );
    println!(
        "project sig vectors: {project_vectors}/24 crafted signatures rejected \
         with their pinned §3.4 code"
    );
    println!("ALL ED25519 EXTERNAL CHECKS PASSED");
}
