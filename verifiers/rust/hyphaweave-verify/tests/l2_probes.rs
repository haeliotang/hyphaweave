// SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
// SPDX-License-Identifier: Apache-2.0

//! Two L2 checks that no committed vector reaches (H1-FIX2 Y2, recheck A
//! M-2): the `Extension.critical` row of the §12.2 check 1 DEFAULT table, and
//! the chain-head rule of §11.3/§12.4 (`renews` is `null` for the first
//! receipt). Both tests run `verify_container` on a copy of
//! `integrity-levels/l2-valid`; removing either check turns its test red.
//!
//! The DEFAULT probe changes the timestamp token, so it rebuilds the receipt:
//! the TSTInfo gains one extension, the signed `messageDigest` attribute is
//! recomputed, and the SignerInfo is re-signed with the committed test TSA key
//! (`vectors/keys/tsa/tsa.key.pem`, RSA PKCS#1 v1.5 with SHA-256). The receipt
//! digest in the attestation file is updated to match, so the DEFAULT encoding
//! is the only defect. `docs/h1-findings.md` F59 asks the specification side
//! for vectors.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use hyphaweave_verify::options::ContainerInput;
use hyphaweave_verify::report::Report;
use hyphaweave_verify::value::{Object, Value};
use hyphaweave_verify::{digest, json, operator, verify_container, Verdict, VerifyOptions};
use rsa::pkcs8::DecodePrivateKey;

const RECEIPT: &str = "signatures/timestamp-1.tsr";
const SIGFILE: &str = "signatures/manifest.sig.json";

fn vectors_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../vectors")
}

fn case_dir() -> PathBuf {
    vectors_root().join("integrity-levels/l2-valid")
}

fn options() -> VerifyOptions {
    let mut options = VerifyOptions::new();
    options.keyset = operator::load_keyset(&vectors_root().join("keys/keyset")).expect("keyset");
    options.tsa_trust = vec![fs::read(case_dir().join("tsa.crt.pem")).expect("anchor")];
    options
}

/// The committed `l2-valid` container as relative path -> bytes.
fn l2_valid_files() -> BTreeMap<String, Vec<u8>> {
    fn walk(root: &std::path::Path, dir: &std::path::Path, out: &mut BTreeMap<String, Vec<u8>>) {
        for entry in fs::read_dir(dir).expect("read_dir") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                walk(root, &path, out);
            } else {
                let relative = path
                    .strip_prefix(root)
                    .expect("relative")
                    .to_string_lossy()
                    .replace('\\', "/");
                out.insert(relative, fs::read(&path).expect("read"));
            }
        }
    }
    let root = case_dir().join("container");
    let mut files = BTreeMap::new();
    walk(&root, &root, &mut files);
    files
}

/// Rewrites `timestamps[0]` of the attestation file with `edit`.
fn edit_timestamp_entry(files: &mut BTreeMap<String, Vec<u8>>, edit: impl Fn(&Object) -> Object) {
    let attestation = json::parse_object(&files[SIGFILE]).expect("attestation");
    let entries = attestation.get_array("timestamps").expect("timestamps");
    let mut rewritten: Vec<Value> = entries.to_vec();
    rewritten[0] = Value::Object(edit(entries[0].as_object().expect("entry")));
    let mut out = attestation.without("timestamps");
    out.insert("timestamps", Value::Array(rewritten));
    files.insert(SIGFILE.to_owned(), json::canonical_object_bytes(&out));
}

fn set(object: &Object, name: &str, value: impl Into<Value>) -> Object {
    let mut out = object.without(name);
    out.insert(name, value);
    out
}

fn verify(files: BTreeMap<String, Vec<u8>>) -> Report {
    verify_container(ContainerInput::Files(files), &options()).expect("container")
}

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

// ---------------------------------------------------------------------------
// A minimal DER tree, enough to edit a well-formed receipt (test only).
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
enum Content {
    Primitive(Vec<u8>),
    Constructed(Vec<Node>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Node {
    tag: u8,
    content: Content,
}

impl Node {
    fn children(&self) -> &[Node] {
        match &self.content {
            Content::Constructed(children) => children,
            Content::Primitive(_) => panic!("primitive node has no children"),
        }
    }

    fn children_mut(&mut self) -> &mut Vec<Node> {
        match &mut self.content {
            Content::Constructed(children) => children,
            Content::Primitive(_) => panic!("primitive node has no children"),
        }
    }

    fn bytes(&self) -> &[u8] {
        match &self.content {
            Content::Primitive(bytes) => bytes,
            Content::Constructed(_) => panic!("constructed node has no bytes"),
        }
    }
}

/// Parses one TLV (single-octet tags, definite lengths: the committed
/// receipts are DER).
fn parse_one(input: &[u8]) -> (Node, &[u8]) {
    let tag = input[0];
    assert_ne!(tag & 0x1f, 0x1f, "high tag numbers are not used here");
    let (length, header) = if input[1] < 0x80 {
        (usize::from(input[1]), 2)
    } else {
        let count = usize::from(input[1] & 0x7f);
        let mut length = 0usize;
        for byte in &input[2..2 + count] {
            length = (length << 8) | usize::from(*byte);
        }
        (length, 2 + count)
    };
    let body = &input[header..header + length];
    let content = if tag & 0x20 != 0 {
        let mut children = Vec::new();
        let mut rest = body;
        while !rest.is_empty() {
            let (child, tail) = parse_one(rest);
            children.push(child);
            rest = tail;
        }
        Content::Constructed(children)
    } else {
        Content::Primitive(body.to_vec())
    };
    (Node { tag, content }, &input[header + length..])
}

fn parse(input: &[u8]) -> Node {
    let (node, rest) = parse_one(input);
    assert!(rest.is_empty());
    node
}

fn encode_length(length: usize, out: &mut Vec<u8>) {
    if length < 0x80 {
        out.push(u8::try_from(length).expect("short length"));
    } else {
        let bytes: Vec<u8> = length
            .to_be_bytes()
            .into_iter()
            .skip_while(|byte| *byte == 0)
            .collect();
        out.push(0x80 | u8::try_from(bytes.len()).expect("length octets"));
        out.extend(bytes);
    }
}

fn encode(node: &Node) -> Vec<u8> {
    let body = match &node.content {
        Content::Primitive(bytes) => bytes.clone(),
        Content::Constructed(children) => children.iter().flat_map(encode).collect(),
    };
    let mut out = vec![node.tag];
    encode_length(body.len(), &mut out);
    out.extend(body);
    out
}

/// Standard base64 (PEM bodies), test only.
fn base64_standard(text: &str) -> Vec<u8> {
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut bits = 0u32;
    let mut count = 0;
    let mut out = Vec::new();
    for byte in text.bytes().filter(|byte| !byte.is_ascii_whitespace()) {
        if byte == b'=' {
            break;
        }
        let value = alphabet
            .iter()
            .position(|candidate| *candidate == byte)
            .expect("base64 digit");
        bits = (bits << 6) | u32::try_from(value).expect("6 bits");
        count += 6;
        if count >= 8 {
            count -= 8;
            out.push(u8::try_from((bits >> count) & 0xff).expect("byte"));
        }
    }
    out
}

fn tsa_private_key() -> rsa::PrivateKey {
    let pem = fs::read_to_string(vectors_root().join("keys/tsa/tsa.key.pem")).expect("tsa key");
    let body: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    rsa::PrivateKey::from_pkcs8_der(&base64_standard(&body)).expect("pkcs8 key")
}

const OID_MESSAGE_DIGEST: [u8; 9] = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04];
const OID_RSA_ENCRYPTION: [u8; 9] = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
/// `DigestInfo` prefix for SHA-256 (RFC 8017 §9.2 note 1).
const SHA256_DIGEST_INFO: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

/// Rebuilds `receipt` with its TSTInfo replaced by `edit(tstinfo)`, the
/// `messageDigest` signed attribute recomputed, and the SignerInfo re-signed
/// with the test TSA key.
fn rebuild_receipt(receipt: &[u8], edit: impl Fn(Node) -> Node) -> Vec<u8> {
    let mut response = parse(receipt);
    // TimeStampResp.timeStampToken -> ContentInfo.content [0] -> SignedData.
    let signed_data = &mut response.children_mut()[1].children_mut()[1].children_mut()[0];
    let encap = &mut signed_data.children_mut()[2];
    let econtent = &mut encap.children_mut()[1].children_mut()[0];
    let tst_info = encode(&edit(parse(econtent.bytes())));
    econtent.content = Content::Primitive(tst_info.clone());
    let signer_infos = signed_data.children_mut().last_mut().expect("signerInfos");
    assert_eq!(signer_infos.tag, 0x31);
    let signer_info = &mut signer_infos.children_mut()[0];
    let signed_attrs = signer_info
        .children_mut()
        .iter_mut()
        .find(|node| node.tag == 0xa0)
        .expect("signedAttrs");
    let message_digest = signed_attrs
        .children_mut()
        .iter_mut()
        .find(|attribute| attribute.children()[0].bytes() == OID_MESSAGE_DIGEST)
        .expect("messageDigest attribute");
    message_digest.children_mut()[1].children_mut()[0].content =
        Content::Primitive(digest::sha256(&tst_info).to_vec());
    // The signature covers the DER of the attributes as a SET OF (RFC 5652
    // §5.4): the IMPLICIT [0] tag replaced by 0x31.
    let mut to_sign = encode(signed_attrs);
    to_sign[0] = 0x31;
    let signature_algorithm = &signer_info.children()[4];
    assert_eq!(
        signature_algorithm.children()[0].bytes(),
        OID_RSA_ENCRYPTION
    );
    let mut digest_info = SHA256_DIGEST_INFO.to_vec();
    digest_info.extend(digest::sha256(&to_sign));
    let signature = tsa_private_key()
        .sign(rsa::Pkcs1v15Sign::new_unprefixed(), &digest_info)
        .expect("rsa sign");
    let signature_node = signer_info
        .children_mut()
        .iter_mut()
        .find(|node| node.tag == 0x04)
        .expect("signature");
    signature_node.content = Content::Primitive(signature);
    encode(&response)
}

/// The `l2-valid` container with its receipt replaced by `receipt` and the
/// attestation entry's digest updated to match.
fn with_receipt(receipt: Vec<u8>) -> BTreeMap<String, Vec<u8>> {
    let mut files = l2_valid_files();
    let digest_string = digest::sha256_digest_string(&receipt);
    files.insert(RECEIPT.to_owned(), receipt);
    edit_timestamp_entry(&mut files, |entry| {
        set(entry, "digest", digest_string.as_str())
    });
    files
}

/// Appends `extensions [1] IMPLICIT Extensions` with one extension to a
/// TSTInfo that has none. `critical` is encoded only when `Some`.
fn add_tstinfo_extension(critical: Option<u8>) -> impl Fn(Node) -> Node {
    move |mut tst_info: Node| {
        assert!(
            tst_info.children().iter().all(|node| node.tag != 0xa1),
            "base TSTInfo has no extensions"
        );
        let mut extension = vec![Node {
            tag: 0x06,
            // 1.3.6.1.4.1.99999.1, an arbitrary private OID.
            content: Content::Primitive(vec![0x2b, 0x06, 0x01, 0x04, 0x01, 0x86, 0x8d, 0x1f, 0x01]),
        }];
        if let Some(value) = critical {
            extension.push(Node {
                tag: 0x01,
                content: Content::Primitive(vec![value]),
            });
        }
        extension.push(Node {
            tag: 0x04,
            content: Content::Primitive(vec![0x05, 0x00]),
        });
        tst_info.children_mut().push(Node {
            tag: 0xa1,
            content: Content::Constructed(vec![Node {
                tag: 0x30,
                content: Content::Constructed(extension),
            }]),
        });
        tst_info
    }
}

/// Builder sanity check: rebuilding the committed receipt without changes
/// reproduces it byte for byte (PKCS#1 v1.5 signing is deterministic).
#[test]
fn rebuilt_receipt_is_byte_identical() {
    let receipt = &l2_valid_files()[RECEIPT];
    assert_eq!(&rebuild_receipt(receipt, |tst_info| tst_info), receipt);
}

/// §12.2 check 1 (1c, DEFAULT table): `Extension.critical` is `BOOLEAN
/// DEFAULT FALSE`, so DER omits it when FALSE; an explicit `01 01 00` is
/// `E_TS_SCHEMA`. Shown on a TSTInfo extension, which uses the same
/// `Extension` type as certificate, CRL and CRL-entry extensions. The twin
/// without the `critical` member, and the twin with `critical TRUE` on this
/// unknown extension, show that the re-signed receipt is otherwise valid.
#[test]
fn extension_critical_false_encoded_is_ts_schema() {
    let receipt = l2_valid_files()[RECEIPT].clone();

    let omitted = verify(with_receipt(rebuild_receipt(
        &receipt,
        add_tstinfo_extension(None),
    )));
    assert_eq!(errors(&omitted), Vec::<&str>::new());
    assert_eq!(omitted.verdict, Verdict::Valid);

    let explicit_true = verify(with_receipt(rebuild_receipt(
        &receipt,
        add_tstinfo_extension(Some(0xff)),
    )));
    assert_eq!(errors(&explicit_true), Vec::<&str>::new());
    assert_eq!(explicit_true.verdict, Verdict::Valid);

    let explicit_false = verify(with_receipt(rebuild_receipt(
        &receipt,
        add_tstinfo_extension(Some(0x00)),
    )));
    assert_eq!(errors(&explicit_false), vec!["E_TS_SCHEMA"]);
    assert_eq!(explicit_false.verdict, Verdict::Invalid);
}

/// §11.3 / §12.4 check 14: `renews` is `null` for the first receipt of the
/// timestamp chain. A single receipt whose `renews` names itself, or a path
/// that is not listed, is `E_TS_RENEWAL`.
#[test]
fn chain_head_renews_must_be_null() {
    let baseline = verify(l2_valid_files());
    assert_eq!(errors(&baseline), Vec::<&str>::new());
    assert_eq!(baseline.verdict, Verdict::Valid);
    for target in [RECEIPT, "signatures/timestamp-2.tsr"] {
        let mut files = l2_valid_files();
        edit_timestamp_entry(&mut files, |entry| set(entry, "renews", target));
        let report = verify(files);
        assert_eq!(errors(&report), vec!["E_TS_RENEWAL"], "renews = {target}");
        assert_eq!(report.verdict, Verdict::Invalid, "renews = {target}");
    }
}
