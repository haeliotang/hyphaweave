// SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
// SPDX-License-Identifier: Apache-2.0

//! RFC 3161 timestamp receipts and the renewal chain of §12.
//!
//! This module is implemented from the specification only (§12.2 check table,
//! §12.3 trust anchors, §12.4 renewal chain, §9.4 compromise rescue). It parses
//! DER `TimeStampResp` / CMS `SignedData` / X.509 structures with the pure-Rust
//! RustCrypto crates and verifies the CMS signature under the fixed algorithm
//! allowlist. No network access and no certificate-chain building (H0 compares
//! the leaf certificate against the supplied anchors exactly).
//!
//! The §12.2 MUST table is applied in order; the code of the first failing
//! check is reported. A receipt that passes checks 1–14 but whose signer leaf
//! certificate does not match a `--tsa-trust` anchor (check 15) is reported
//! `present-unverified`, which makes the container `unverifiable`
//! (`E_TS_UNTRUSTED`), never `valid` (§12.3, §12.5).

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use cms::cert::CertificateChoices;
use cms::content_info::ContentInfo;
use cms::signed_data::{SignedData, SignerIdentifier};
use const_oid::ObjectIdentifier;
use der::asn1::{OctetString, Uint};
use der::{Any, Decode, Encode, Sequence, Tag, Tagged};
use sha2::{Digest, Sha256, Sha384, Sha512};
use signature::hazmat::PrehashVerifier;
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::attr::{Attribute, Attributes};
use x509_cert::ext::pkix::{ExtendedKeyUsage, KeyUsage, SubjectKeyIdentifier};
use x509_cert::Certificate;

use crate::digest;
use crate::error_codes::{e, Code};
use crate::options::UsageError;
use crate::time::Timestamp;

// Object identifiers used by the archive profile. The literals are written out
// so that their provenance is visible: RFC 3161 (id-ct-TSTInfo), RFC 5652
// (SignedData, content-type, messageDigest), RFC 5035 (signingCertificateV2),
// RFC 8017 (RSA PKCS#1 v1.5), RFC 5758 (ECDSA), RFC 5280 (extensions).

/// `id-ct-TSTInfo` (RFC 3161 §2.4.2).
const OID_ID_CT_TSTINFO: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");
/// `id-signedData` (RFC 5652 §4).
const OID_ID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
/// `id-sha256` (RFC 5754).
const OID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
/// `id-sha384` (RFC 5754).
const OID_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");
/// `id-sha512` (RFC 5754).
const OID_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3");
/// `rsaEncryption` (RFC 8017) — RSASSA-PKCS1-v1_5 with the signer digest.
const OID_RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
/// `sha256WithRSAEncryption` (RFC 8017).
const OID_SHA256_WITH_RSA: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
/// `sha384WithRSAEncryption` (RFC 8017).
const OID_SHA384_WITH_RSA: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");
/// `sha512WithRSAEncryption` (RFC 8017).
const OID_SHA512_WITH_RSA: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");
/// `ecdsa-with-SHA256` (RFC 5758).
const OID_ECDSA_WITH_SHA256: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
/// `ecdsa-with-SHA384` (RFC 5758).
const OID_ECDSA_WITH_SHA384: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
/// `id-aa-signingCertificateV2` (RFC 5035 §3).
const OID_SIGNING_CERTIFICATE_V2: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.47");
/// `id-aa-signingCertificateV2` is required; the legacy v1 attribute below is
/// only inspected to make the rejection unambiguous.
const OID_SIGNING_CERTIFICATE_V1: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.12");
/// `contentType` signed attribute (RFC 5652 §11.1).
const OID_CONTENT_TYPE_ATTRIBUTE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");
/// `messageDigest` signed attribute (RFC 5652 §11.2).
const OID_MESSAGE_DIGEST_ATTRIBUTE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");
/// `id-ecPublicKey` (RFC 5480 §2.1.1).
const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
/// `prime256v1` / NIST P-256 (RFC 5480 §2.1.1.1).
const OID_PRIME256V1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
/// `secp384r1` / NIST P-384 (RFC 5480 §2.1.1.1).
const OID_SECP384R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
/// `id-kp-timeStamping` (RFC 5280 §4.2.1.12).
const OID_ID_KP_TIMESTAMPING: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.8");

/// State of one timestamp receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiptState {
    /// Checks 1–15 of §12.2 passed (including a matching trust anchor).
    Verified,
    /// Checks 1–14 passed but check 15 (trust anchor) did not match.
    PresentUnverified,
    /// At least one of checks 1–14 failed.
    Invalid,
}

/// Outcome of verifying one receipt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiptOutcome {
    /// Receipt state.
    pub state: ReceiptState,
    /// `genTime` converted to a timestamp literal (millisecond precision).
    pub gen_time: Option<Timestamp>,
    /// `accuracy` converted to integer microseconds (absent = 0).
    pub accuracy_us: i64,
    /// First failing §12.2 check, when [`ReceiptState::Invalid`].
    pub error: Option<Code>,
}

/// One `timestamps[]` entry of the attestation file (§11.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttestationTimestamp {
    /// `sha256:<hex>` of the raw receipt bytes.
    pub digest: String,
    /// Container-relative receipt path.
    pub path: String,
    /// Path of the previous receipt in the renewal chain, or `None` for the
    /// first receipt.
    pub renews: Option<String>,
}

/// Result of verifying the whole renewal chain of one manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainEvidence {
    /// One outcome per `timestamps[]` entry, in attestation order.
    pub receipts: Vec<ReceiptOutcome>,
    /// First failing §12.2 check 14 (renewal-chain structure), when present.
    pub chain_error: Option<Code>,
    /// True only when every receipt is verified and the chain is complete.
    pub anchor_verified: bool,
}

impl ChainEvidence {
    /// Empty evidence, used when a target has no timestamp chain (record target,
    /// L0/L1 container).
    #[must_use]
    pub fn none() -> Self {
        Self {
            receipts: Vec::new(),
            chain_error: None,
            anchor_verified: false,
        }
    }

    /// True when any receipt is present (for the §9.4 case-2/case-3 split).
    #[must_use]
    pub fn has_receipts(&self) -> bool {
        !self.receipts.is_empty()
    }

    /// The `genTime + accuracy` bound in integer microseconds for every
    /// verified-and-trusted receipt (§9.4 case 1). A signature by a compromised
    /// key is rescued when one bound is strictly below `T`.
    #[must_use]
    pub fn rescue_bounds_us(&self) -> Vec<i64> {
        self.receipts
            .iter()
            .filter(|receipt| receipt.state == ReceiptState::Verified)
            .filter_map(|receipt| {
                receipt
                    .gen_time
                    .map(|time| time.to_unix_millis() * 1_000 + receipt.accuracy_us)
            })
            .collect()
    }
}

/// Verifies the renewal chain (§12.4) over one manifest digest.
///
/// `files` maps container-relative paths to file bytes; the caller has already
/// checked that every listed `.tsr` exists and matches its listed digest. The
/// presence/digest check is repeated defensively so that a caller mistake is
/// reported as `E_TS_FILE` instead of silently accepting a receipt for another
/// path.
/// `trust_anchors` holds the SHA-256 digests of the DER encodings of the
/// `--tsa-trust` certificates.
#[must_use]
pub fn verify_chain(
    entries: &[AttestationTimestamp],
    manifest_digest: &[u8; 32],
    files: &BTreeMap<String, Vec<u8>>,
    trust_anchors: &[[u8; 32]],
) -> ChainEvidence {
    // Check 14 describes the `timestamps[]` array as a whole, not one receipt.
    let chain_error = renewal_chain_error(entries);
    let path_index: BTreeMap<&str, usize> = entries
        .iter()
        .enumerate()
        .map(|(index, entry)| (entry.path.as_str(), index))
        .collect();
    let mut receipts = Vec::with_capacity(entries.len());
    for (index, entry) in entries.iter().enumerate() {
        let outcome = match expected_imprint(index, entries, &path_index, manifest_digest, files) {
            Ok(imprint) => verify_receipt(entry, &imprint, files, trust_anchors),
            // The renewal link cannot be resolved, so check 4 cannot be
            // evaluated for this receipt; the chain-defect code applies.
            Err(code) => invalid_receipt(code),
        };
        receipts.push(outcome);
    }
    let anchor_verified = chain_error.is_none()
        && !receipts.is_empty()
        && receipts
            .iter()
            .all(|receipt| receipt.state == ReceiptState::Verified);
    ChainEvidence {
        receipts,
        chain_error,
        anchor_verified,
    }
}

/// Maps a receipt error to the §12.5 container effect:
/// checks 1–14 are invalid; check 15 is unverifiable.
#[must_use]
pub fn receipt_effect(error: Code) -> &'static str {
    if error == e::TS_UNTRUSTED {
        "unverifiable"
    } else {
        "invalid"
    }
}

/// Loads `--tsa-trust` anchors: one or more PEM certificates, or raw DER.
/// Returns the SHA-256 digests of the DER encodings (§12.3).
///
/// # Errors
/// Returns a [`UsageError`] when a file contains no certificate, an unterminated
/// or non-certificate PEM block, or DER that does not parse as an X.509
/// certificate.
pub fn load_trust_anchors(file_contents: &[Vec<u8>]) -> Result<Vec<[u8; 32]>, UsageError> {
    let mut anchors = Vec::new();
    for (index, contents) in file_contents.iter().enumerate() {
        let label = format!("--tsa-trust file #{}", index + 1);
        let certificates = decode_anchor_certificates(contents)
            .map_err(|reason| UsageError(format!("{label}: {reason}")))?;
        if certificates.is_empty() {
            return Err(UsageError(format!("{label}: no certificate found")));
        }
        for certificate_der in certificates {
            Certificate::from_der(&certificate_der).map_err(|error| {
                UsageError(format!("{label}: not an X.509 certificate: {error}"))
            })?;
            anchors.push(digest::sha256(&certificate_der));
        }
    }
    Ok(anchors)
}

// --------------------------------------------------------------------------
// §12.4 renewal chain structure
// --------------------------------------------------------------------------

/// Returns the §12.2 check-14 code when `entries` is not exactly one complete
/// renewal chain: one `renews == null` head, each later entry renewing the
/// immediately preceding receipt, no duplicate paths or digests.
fn renewal_chain_error(entries: &[AttestationTimestamp]) -> Option<Code> {
    if entries.is_empty() {
        return None;
    }
    let mut paths = BTreeSet::new();
    let mut digests = BTreeSet::new();
    for entry in entries {
        if !paths.insert(entry.path.as_str()) || !digests.insert(entry.digest.as_str()) {
            return Some(e::TS_RENEWAL);
        }
    }
    if entries[0].renews.is_some() {
        return Some(e::TS_RENEWAL);
    }
    for index in 1..entries.len() {
        match entries[index].renews.as_deref() {
            Some(previous) if previous == entries[index - 1].path => {}
            _ => return Some(e::TS_RENEWAL),
        }
    }
    None
}

/// Expected `messageImprint.hashedMessage` of `entries[index]` (§12.4).
fn expected_imprint(
    index: usize,
    entries: &[AttestationTimestamp],
    path_index: &BTreeMap<&str, usize>,
    manifest_digest: &[u8; 32],
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<[u8; 32], Code> {
    let Some(previous) = entries[index].renews.as_deref() else {
        // Chain head: the raw 32 bytes of the manifest digest.
        return Ok(*manifest_digest);
    };
    let Some(&previous_index) = path_index.get(previous) else {
        return Err(e::TS_RENEWAL);
    };
    if previous_index >= index {
        return Err(e::TS_RENEWAL);
    }
    let Some(previous_bytes) = files.get(previous) else {
        return Err(e::TS_FILE);
    };
    // SHA-256(previous receipt bytes ‖ raw manifest digest).
    Ok(digest::sha256_concat(&[
        previous_bytes.as_slice(),
        manifest_digest.as_slice(),
    ]))
}

// --------------------------------------------------------------------------
// Per-receipt verification (§12.2 checks 1–15)
// --------------------------------------------------------------------------

/// Facts extracted from a receipt that passed checks 1–13.
struct ReceiptFacts {
    gen_time: Timestamp,
    accuracy_us: i64,
    certificate_der_sha256: [u8; 32],
}

fn invalid_receipt(error: Code) -> ReceiptOutcome {
    ReceiptOutcome {
        state: ReceiptState::Invalid,
        gen_time: None,
        accuracy_us: 0,
        error: Some(error),
    }
}

fn verify_receipt(
    entry: &AttestationTimestamp,
    expected_imprint: &[u8; 32],
    files: &BTreeMap<String, Vec<u8>>,
    trust_anchors: &[[u8; 32]],
) -> ReceiptOutcome {
    // Defensive caller-precondition check: the container layer reports a
    // missing or digest-mismatched receipt as `E_TS_FILE` (§11.3).
    let Some(bytes) = files.get(&entry.path) else {
        return invalid_receipt(e::TS_FILE);
    };
    if digest::sha256_digest_string(bytes) != entry.digest {
        return invalid_receipt(e::TS_FILE);
    }
    let facts = match verify_receipt_checks(bytes, expected_imprint) {
        Ok(facts) => facts,
        Err(code) => return invalid_receipt(code),
    };
    // Check 15: the signer leaf certificate is trusted iff its DER SHA-256 is
    // one of the supplied anchors (§12.3). No chain building.
    let trusted = trust_anchors
        .iter()
        .any(|anchor| *anchor == facts.certificate_der_sha256);
    ReceiptOutcome {
        state: if trusted {
            ReceiptState::Verified
        } else {
            ReceiptState::PresentUnverified
        },
        gen_time: Some(facts.gen_time),
        accuracy_us: facts.accuracy_us,
        error: None,
    }
}

/// Applies the §12.2 MUST table checks 1–14 of one receipt.
fn verify_receipt_checks(bytes: &[u8], expected_imprint: &[u8; 32]) -> Result<ReceiptFacts, Code> {
    // Check 1: DER TimeStampResp with PKIStatusInfo.status == granted (0).
    let response = TimeStampResp::from_der(bytes).map_err(|_| e::TS_SCHEMA)?;
    if response.status.status != 0 {
        return Err(e::TS_SCHEMA);
    }
    let content_info = response.token.ok_or(e::TS_SCHEMA)?;

    // Check 2: the token is a CMS ContentInfo of type `id-signedData`
    // (RFC 3161 §2.4.2), the SignedData content type is `id-ct-TSTInfo`, and
    // the encapsulated TSTInfo parses as DER with version 1.
    if content_info.content_type != OID_ID_SIGNED_DATA {
        return Err(e::TS_SCHEMA);
    }
    let signed_data_der = content_info.content.to_der().map_err(|_| e::TS_SCHEMA)?;
    let signed_data = SignedData::from_der(&signed_data_der).map_err(|_| e::TS_SCHEMA)?;
    if signed_data.encap_content_info.econtent_type != OID_ID_CT_TSTINFO {
        return Err(e::TS_SCHEMA);
    }
    let econtent = signed_data
        .encap_content_info
        .econtent
        .as_ref()
        .ok_or(e::TS_SCHEMA)?;
    if econtent.tag() != Tag::OctetString {
        return Err(e::TS_SCHEMA);
    }
    let tstinfo_bytes = econtent.value();
    let tstinfo = TstInfo::from_der(tstinfo_bytes).map_err(|_| e::TS_SCHEMA)?;
    if tstinfo.version != 1 {
        return Err(e::TS_SCHEMA);
    }
    // RFC 3161 §2.4.2: the token carries exactly the TSA signature.
    if signed_data.signer_infos.0.len() != 1 {
        return Err(e::TS_SCHEMA);
    }
    let signer_info = signed_data
        .signer_infos
        .0
        .iter()
        .next()
        .ok_or(e::TS_SCHEMA)?;

    // Check 3: messageImprint.hashAlgorithm is sha256.
    if tstinfo.message_imprint.hash_algorithm.oid != OID_SHA256 {
        return Err(e::TS_SCHEMA);
    }

    // Check 4: messageImprint.hashedMessage equals the expected imprint.
    if tstinfo.message_imprint.hashed_message.as_bytes() != expected_imprint {
        return Err(e::TS_IMPRINT);
    }

    // Check 5: signerInfo.digestAlgorithm is sha256.
    if signer_info.digest_alg.oid != OID_SHA256 {
        return Err(e::TS_SCHEMA);
    }

    // Check 6: signature algorithm allowlist (RSA PKCS#1 v1.5 or ECDSA).
    let scheme = signature_scheme(
        &signer_info.signature_algorithm.oid,
        &signer_info.digest_alg.oid,
    )?;

    // Check 7: the signer certificate is carried in the token.
    let certificate = find_signer_certificate(&signed_data, &signer_info.sid)
        .ok_or(e::TS_CMS)?;
    let certificate_der = certificate.to_der().map_err(|_| e::TS_CMS)?;

    // Checks 8 and 9 use the signed attributes.
    let signed_attributes = signer_info.signed_attrs.as_ref().ok_or(e::TS_CMS)?;

    // Check 8: ESS signingCertificateV2 matches the signer certificate; the
    // legacy v1 attribute or a missing attribute is rejected.
    check_ess_signing_certificate_v2(signed_attributes, &certificate_der)?;

    // Check 9: the signed attributes' messageDigest equals SHA-256(eContent);
    // the profile also requires the content-type attribute to name TSTInfo.
    check_signed_attributes(signed_attributes, tstinfo_bytes)?;

    // Check 10: the CMS signature verifies over
    // DER(SET OF SignedAttributes) with the signer certificate's public key.
    verify_cms_signature(
        scheme,
        &certificate.tbs_certificate.subject_public_key_info,
        signed_attributes,
        signer_info.signature.as_bytes(),
    )?;

    // Check 11: timeStamping EKU and (when present) digitalSignature key usage.
    check_certificate_profile(&certificate)?;

    // Check 13 owns genTime validation, but check 12 needs the instant. Parse
    // it here; when it is malformed check 12 cannot be evaluated and the
    // schema failure is reported at its table position below.
    let gen_time = parse_gen_time(&tstinfo.gen_time);

    // Check 12: the certificate validity window contains genTime.
    if let Some(gen_time) = gen_time {
        if !certificate_validity_contains(&certificate, gen_time) {
            return Err(e::TS_CERT);
        }
    }

    // Check 13: genTime and accuracy conversion to integer ms/µs.
    let gen_time = gen_time.ok_or(e::TS_SCHEMA)?;
    let accuracy_us = accuracy_micros(tstinfo.accuracy.as_ref())?;

    Ok(ReceiptFacts {
        gen_time,
        accuracy_us,
        certificate_der_sha256: digest::sha256(&certificate_der),
    })
}

// --------------------------------------------------------------------------
// ASN.1 definitions (RFC 3161 §2.4, RFC 5652 §5, RFC 5035 §3)
// --------------------------------------------------------------------------

/// `PKIStatusInfo ::= SEQUENCE { status PKIStatus, statusString PKIFreeText
/// OPTIONAL, failInfo PKIFailureInfo OPTIONAL }` (RFC 3161 §2.4.2).
#[derive(Sequence)]
struct PkiStatusInfo {
    status: u8,
    #[asn1(optional = "true")]
    status_string: Option<Any>,
    #[asn1(optional = "true")]
    fail_info: Option<Any>,
}

/// `TimeStampResp ::= SEQUENCE { status PKIStatusInfo, timeStampToken
/// TimeStampToken OPTIONAL }` (RFC 3161 §2.4.2).
#[derive(Sequence)]
struct TimeStampResp {
    status: PkiStatusInfo,
    #[asn1(optional = "true")]
    token: Option<ContentInfo>,
}

/// `MessageImprint ::= SEQUENCE { hashAlgorithm AlgorithmIdentifier,
/// hashedMessage OCTET STRING }` (RFC 3161 §2.4.1).
#[derive(Sequence)]
struct MessageImprint {
    hash_algorithm: AlgorithmIdentifierOwned,
    hashed_message: OctetString,
}

/// `Accuracy ::= SEQUENCE { seconds INTEGER OPTIONAL, millis [0] INTEGER
/// (1..999) OPTIONAL, micros [1] INTEGER (1..999) OPTIONAL }` (RFC 3161 §2.4.1).
#[derive(Sequence)]
struct Accuracy {
    #[asn1(optional = "true")]
    seconds: Option<Uint>,
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    millis: Option<Uint>,
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    micros: Option<Uint>,
}

/// `TSTInfo ::= SEQUENCE { version INTEGER, policy TSAPolicyId, messageImprint
/// MessageImprint, serialNumber INTEGER, genTime GeneralizedTime, accuracy
/// Accuracy OPTIONAL, ordering BOOLEAN DEFAULT FALSE, nonce INTEGER OPTIONAL,
/// tsa [0] GeneralName OPTIONAL, extensions [1] IMPLICIT Extensions OPTIONAL }`
/// (RFC 3161 §2.4.1). `genTime` is kept as a raw `Any` so that the §12.2
/// check-13 conversion can accept fractional seconds; `der`'s `GeneralizedTime`
/// decoder does not.
#[derive(Sequence)]
struct TstInfo {
    version: u8,
    policy: ObjectIdentifier,
    message_imprint: MessageImprint,
    serial_number: Uint,
    gen_time: Any,
    #[asn1(optional = "true")]
    accuracy: Option<Accuracy>,
    #[asn1(default = "Default::default")]
    ordering: bool,
    #[asn1(optional = "true")]
    nonce: Option<Uint>,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    tsa: Option<Any>,
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    extensions: Option<Any>,
}

/// `ESSCertIDv2 ::= SEQUENCE { hashAlgorithm AlgorithmIdentifier DEFAULT
/// {algorithm id-sha256}, certHash Hash, issuerSerial IssuerSerial OPTIONAL }`
/// (RFC 5035 §3). The ASN.1 DEFAULT is modelled as an `Option`: absent means
/// SHA-256, as checked in [`check_ess_signing_certificate_v2`].
#[derive(Sequence)]
struct EssCertIdV2 {
    #[asn1(optional = "true")]
    hash_algorithm: Option<AlgorithmIdentifierOwned>,
    cert_hash: OctetString,
    #[asn1(optional = "true")]
    issuer_serial: Option<Any>,
}

/// `SigningCertificateV2 ::= SEQUENCE { certs SEQUENCE OF ESSCertIDv2,
/// policies SEQUENCE OF PolicyInformation OPTIONAL }` (RFC 5035 §3).
#[derive(Sequence)]
struct SigningCertificateV2 {
    certs: Vec<EssCertIdV2>,
    #[asn1(optional = "true")]
    policies: Option<Vec<Any>>,
}

// --------------------------------------------------------------------------
// Check helpers
// --------------------------------------------------------------------------

/// Hash algorithms that the archive profile may use (§12.2 checks 5, 6, 9).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

/// Signature schemes on the §12.2 check-6 allowlist.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SignatureScheme {
    RsaPkcs1V15(HashAlgorithm),
    Ecdsa(HashAlgorithm),
}

fn hash_algorithm(oid: &ObjectIdentifier) -> Option<HashAlgorithm> {
    if *oid == OID_SHA256 {
        Some(HashAlgorithm::Sha256)
    } else if *oid == OID_SHA384 {
        Some(HashAlgorithm::Sha384)
    } else if *oid == OID_SHA512 {
        Some(HashAlgorithm::Sha512)
    } else {
        None
    }
}

/// Check 6: RSA PKCS#1 v1.5 with SHA-256/384/512 or ECDSA with SHA-256/384.
/// RSA-PSS and every other algorithm are rejected with `E_TS_CERT`.
fn signature_scheme(
    signature_oid: &ObjectIdentifier,
    digest_oid: &ObjectIdentifier,
) -> Result<SignatureScheme, Code> {
    if *signature_oid == OID_RSA_ENCRYPTION {
        // rsaEncryption carries PKCS#1 v1.5 with the signer digest, which
        // check 5 already pinned to SHA-256.
        return Ok(SignatureScheme::RsaPkcs1V15(
            hash_algorithm(digest_oid).ok_or(e::TS_CERT)?,
        ));
    }
    if *signature_oid == OID_SHA256_WITH_RSA {
        return Ok(SignatureScheme::RsaPkcs1V15(HashAlgorithm::Sha256));
    }
    if *signature_oid == OID_SHA384_WITH_RSA {
        return Ok(SignatureScheme::RsaPkcs1V15(HashAlgorithm::Sha384));
    }
    if *signature_oid == OID_SHA512_WITH_RSA {
        return Ok(SignatureScheme::RsaPkcs1V15(HashAlgorithm::Sha512));
    }
    if *signature_oid == OID_ECDSA_WITH_SHA256 {
        return Ok(SignatureScheme::Ecdsa(HashAlgorithm::Sha256));
    }
    if *signature_oid == OID_ECDSA_WITH_SHA384 {
        return Ok(SignatureScheme::Ecdsa(HashAlgorithm::Sha384));
    }
    Err(e::TS_CERT)
}

/// Check 7: the certificate matching `signerInfo.sid`, carried by the token.
fn find_signer_certificate(
    signed_data: &SignedData,
    signer_identifier: &SignerIdentifier,
) -> Option<Certificate> {
    let certificates = signed_data.certificates.as_ref()?;
    for choice in certificates.0.iter() {
        let CertificateChoices::Certificate(certificate) = choice else {
            continue;
        };
        if signer_identifier_matches(signer_identifier, certificate) {
            return Some(certificate.clone());
        }
    }
    None
}

fn signer_identifier_matches(
    signer_identifier: &SignerIdentifier,
    certificate: &Certificate,
) -> bool {
    match signer_identifier {
        SignerIdentifier::IssuerAndSerialNumber(issuer_serial) => {
            names_equal(
                &issuer_serial.issuer,
                &certificate.tbs_certificate.issuer,
            ) && issuer_serial.serial_number == certificate.tbs_certificate.serial_number
        }
        SignerIdentifier::SubjectKeyIdentifier(subject_key_identifier) => certificate
            .tbs_certificate
            .get::<SubjectKeyIdentifier>()
            .ok()
            .flatten()
            .is_some_and(|(_, certificate_key_identifier)| {
                &certificate_key_identifier == subject_key_identifier
            }),
    }
}

/// Byte-exact issuer comparison (avoid depending on `Name`'s comparison rules).
fn names_equal(left: &x509_cert::name::Name, right: &x509_cert::name::Name) -> bool {
    match (left.to_der(), right.to_der()) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

fn find_attribute(attributes: &Attributes, oid: ObjectIdentifier) -> Option<&Attribute> {
    attributes.iter().find(|attribute| attribute.oid == oid)
}

/// Check 8: ESS `signingCertificateV2` whose cert hash matches the signer leaf
/// certificate DER (§12.2 row 8). A v1-only `signingCertificate` or a missing
/// ESS attribute is rejected with `E_TS_CMS`.
fn check_ess_signing_certificate_v2(
    attributes: &Attributes,
    certificate_der: &[u8],
) -> Result<(), Code> {
    if find_attribute(attributes, OID_SIGNING_CERTIFICATE_V1).is_some()
        && find_attribute(attributes, OID_SIGNING_CERTIFICATE_V2).is_none()
    {
        // Explicitly rejected v1-only form; the generic branch below yields
        // the same code, this branch documents the table row.
        return Err(e::TS_CMS);
    }
    let attribute =
        find_attribute(attributes, OID_SIGNING_CERTIFICATE_V2).ok_or(e::TS_CMS)?;
    let value = attribute.values.iter().next().ok_or(e::TS_CMS)?;
    let value_der = value.to_der().map_err(|_| e::TS_CMS)?;
    let signing_certificate =
        SigningCertificateV2::from_der(&value_der).map_err(|_| e::TS_CMS)?;
    let certificate_id = signing_certificate.certs.first().ok_or(e::TS_CMS)?;
    // RFC 5035 §3: an omitted hashAlgorithm means SHA-256.
    let hash = match &certificate_id.hash_algorithm {
        Some(algorithm_identifier) => hash_algorithm(&algorithm_identifier.oid),
        None => Some(HashAlgorithm::Sha256),
    }
    .ok_or(e::TS_CMS)?;
    let expected = digest_with(hash, certificate_der);
    if certificate_id.cert_hash.as_bytes() != expected.as_slice() {
        return Err(e::TS_CMS);
    }
    Ok(())
}

/// Check 9: the signed attributes are about the encapsulated TSTInfo:
/// `contentType` names `id-ct-TSTInfo` (RFC 3161 §2.4.2) and `messageDigest`
/// equals SHA-256 of the eContent bytes.
fn check_signed_attributes(
    attributes: &Attributes,
    encapsulated_content: &[u8],
) -> Result<(), Code> {
    let content_type_attribute =
        find_attribute(attributes, OID_CONTENT_TYPE_ATTRIBUTE).ok_or(e::TS_CMS)?;
    let content_type_value = content_type_attribute
        .values
        .iter()
        .next()
        .ok_or(e::TS_CMS)?;
    if content_type_value.tag() != Tag::ObjectIdentifier {
        return Err(e::TS_CMS);
    }
    let content_type_der = content_type_value.to_der().map_err(|_| e::TS_CMS)?;
    let content_type =
        ObjectIdentifier::from_der(&content_type_der).map_err(|_| e::TS_CMS)?;
    if content_type != OID_ID_CT_TSTINFO {
        return Err(e::TS_CMS);
    }
    let message_digest_attribute =
        find_attribute(attributes, OID_MESSAGE_DIGEST_ATTRIBUTE).ok_or(e::TS_CMS)?;
    let message_digest_value = message_digest_attribute
        .values
        .iter()
        .next()
        .ok_or(e::TS_CMS)?;
    if message_digest_value.tag() != Tag::OctetString {
        return Err(e::TS_CMS);
    }
    if message_digest_value.value() != digest::sha256(encapsulated_content).as_slice() {
        return Err(e::TS_CMS);
    }
    Ok(())
}

/// Check 10: verifies the CMS signature over `DER(SET OF SignedAttributes)`
/// with the signer certificate's public key.
fn verify_cms_signature(
    scheme: SignatureScheme,
    subject_public_key_info: &SubjectPublicKeyInfoOwned,
    attributes: &Attributes,
    signature: &[u8],
) -> Result<(), Code> {
    // RFC 5652 §5.4: the signature is computed over the universal `SET OF
    // SignedAttributes` encoding, not the implicit [0] form carried in the
    // token.
    let signed = attributes.to_der().map_err(|_| e::TS_CMS)?;
    let subject_public_key_info_der =
        subject_public_key_info.to_der().map_err(|_| e::TS_CMS)?;
    let verified = match scheme {
        SignatureScheme::RsaPkcs1V15(hash) => verify_rsa_pkcs1_v15(
            &subject_public_key_info_der,
            hash,
            &signed,
            signature,
        ),
        SignatureScheme::Ecdsa(hash) => {
            verify_ecdsa(subject_public_key_info, hash, &signed, signature)
        }
    };
    if verified {
        Ok(())
    } else {
        Err(e::TS_CMS)
    }
}

/// DigestInfo prefixes from RFC 8017 §9.2 (`EMSA-PKCS1-v1_5`).
const SHA256_DIGEST_INFO_PREFIX: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];
const SHA384_DIGEST_INFO_PREFIX: [u8; 19] = [
    0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
    0x00, 0x04, 0x30,
];
const SHA512_DIGEST_INFO_PREFIX: [u8; 19] = [
    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
    0x00, 0x04, 0x40,
];

fn rsa_pkcs1_v15_digest_info(algorithm: HashAlgorithm) -> (usize, &'static [u8]) {
    match algorithm {
        HashAlgorithm::Sha256 => (32, &SHA256_DIGEST_INFO_PREFIX),
        HashAlgorithm::Sha384 => (48, &SHA384_DIGEST_INFO_PREFIX),
        HashAlgorithm::Sha512 => (64, &SHA512_DIGEST_INFO_PREFIX),
    }
}

fn digest_with(algorithm: HashAlgorithm, data: &[u8]) -> Vec<u8> {
    match algorithm {
        HashAlgorithm::Sha256 => Sha256::digest(data).to_vec(),
        HashAlgorithm::Sha384 => Sha384::digest(data).to_vec(),
        HashAlgorithm::Sha512 => Sha512::digest(data).to_vec(),
    }
}

fn verify_rsa_pkcs1_v15(
    subject_public_key_info_der: &[u8],
    hash: HashAlgorithm,
    message: &[u8],
    signature: &[u8],
) -> bool {
    use rsa::pkcs8::DecodePublicKey;
    let Ok(public_key) = rsa::RsaPublicKey::from_public_key_der(subject_public_key_info_der) else {
        return false;
    };
    let digest = digest_with(hash, message);
    let (hash_len, prefix) = rsa_pkcs1_v15_digest_info(hash);
    let scheme = rsa::Pkcs1v15Sign {
        hash_len: Some(hash_len),
        prefix: prefix.to_vec().into_boxed_slice(),
    };
    public_key.verify(scheme, &digest, signature).is_ok()
}

fn verify_ecdsa(
    subject_public_key_info: &SubjectPublicKeyInfoOwned,
    hash: HashAlgorithm,
    message: &[u8],
    signature: &[u8],
) -> bool {
    let digest = digest_with(hash, message);
    let Some(curve) = ec_curve_oid(subject_public_key_info) else {
        return false;
    };
    let point = subject_public_key_info.subject_public_key.raw_bytes();
    if curve == OID_PRIME256V1 {
        let Ok(public_key) = p256::ecdsa::VerifyingKey::from_sec1_bytes(point) else {
            return false;
        };
        let Ok(signature) = p256::ecdsa::Signature::from_der(signature) else {
            return false;
        };
        public_key.verify_prehash(&digest, &signature).is_ok()
    } else if curve == OID_SECP384R1 {
        let Ok(public_key) = p384::ecdsa::VerifyingKey::from_sec1_bytes(point) else {
            return false;
        };
        let Ok(signature) = p384::ecdsa::Signature::from_der(signature) else {
            return false;
        };
        public_key.verify_prehash(&digest, &signature).is_ok()
    } else {
        false
    }
}

/// Curve OID from an EC `SubjectPublicKeyInfo` (RFC 5480 §2.1.1).
fn ec_curve_oid(subject_public_key_info: &SubjectPublicKeyInfoOwned) -> Option<ObjectIdentifier> {
    if subject_public_key_info.algorithm.oid != OID_EC_PUBLIC_KEY {
        return None;
    }
    let parameters = subject_public_key_info.algorithm.parameters.as_ref()?;
    if parameters.tag() != Tag::ObjectIdentifier {
        return None;
    }
    let encoded = parameters.to_der().ok()?;
    ObjectIdentifier::from_der(&encoded).ok()
}

/// Check 11: `id-kp-timeStamping` EKU is required; when a KeyUsage extension is
/// present it must contain `digitalSignature` (§12.2 row 11).
fn check_certificate_profile(certificate: &Certificate) -> Result<(), Code> {
    let extended_key_usage = certificate
        .tbs_certificate
        .get::<ExtendedKeyUsage>()
        .map_err(|_| e::TS_CERT)?;
    let Some((_critical, extended_key_usage)) = extended_key_usage else {
        return Err(e::TS_CERT);
    };
    if !extended_key_usage
        .0
        .iter()
        .any(|oid| *oid == OID_ID_KP_TIMESTAMPING)
    {
        return Err(e::TS_CERT);
    }
    let key_usage = certificate
        .tbs_certificate
        .get::<KeyUsage>()
        .map_err(|_| e::TS_CERT)?;
    if let Some((_critical, key_usage)) = key_usage {
        if !key_usage.digital_signature() {
            return Err(e::TS_CERT);
        }
    }
    Ok(())
}

/// Check 12: the signer certificate validity window contains `genTime`
/// (claimed time, never the wall clock).
fn certificate_validity_contains(certificate: &Certificate, gen_time: Timestamp) -> bool {
    let not_before = certificate_time_millis(&certificate.tbs_certificate.validity.not_before);
    let not_after = certificate_time_millis(&certificate.tbs_certificate.validity.not_after);
    let gen_time = gen_time.to_unix_millis();
    not_before <= gen_time && gen_time <= not_after
}

fn certificate_time_millis(time: &x509_cert::time::Time) -> i64 {
    let duration = time.to_unix_duration();
    i64::try_from(duration.as_secs())
        .unwrap_or(i64::MAX)
        .saturating_mul(1_000)
        .saturating_add(i64::from(duration.subsec_millis()))
}

/// Check 13: parses `genTime` as a DER `GeneralizedTime`
/// (`YYYYMMDDHHMMSS[.fraction]Z`) and converts it to millisecond precision by
/// flooring sub-millisecond digits. The `Z` form is required by DER.
fn parse_gen_time(value: &Any) -> Option<Timestamp> {
    if value.tag() != Tag::GeneralizedTime {
        return None;
    }
    parse_generalized_time_text(value.value())
}

fn parse_generalized_time_text(bytes: &[u8]) -> Option<Timestamp> {
    // 14 ASCII digits: YYYYMMDDHHMMSS.
    if bytes.len() < 15 {
        return None;
    }
    let digits = bytes.get(..14)?;
    if !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let number = |range: std::ops::Range<usize>| -> Option<u16> {
        let mut value = 0u16;
        for &byte in &bytes[range] {
            if !byte.is_ascii_digit() {
                return None;
            }
            value = value * 10 + u16::from(byte - b'0');
        }
        Some(value)
    };
    let year = number(0..4)?;
    let month = u8::try_from(number(4..6)?).ok()?;
    let day = u8::try_from(number(6..8)?).ok()?;
    let hour = u8::try_from(number(8..10)?).ok()?;
    let minute = u8::try_from(number(10..12)?).ok()?;
    let second = u8::try_from(number(12..14)?).ok()?;

    // Optional fractional seconds followed by the mandatory `Z` (DER).
    let rest = bytes.get(14..)?;
    let millisecond = if rest == b"Z" {
        0u16
    } else {
        if rest.len() < 3 || rest.first() != Some(&b'.') || rest.last() != Some(&b'Z') {
            return None;
        }
        let fraction = rest.get(1..rest.len() - 1)?;
        if fraction.is_empty() || !fraction.iter().all(u8::is_ascii_digit) {
            return None;
        }
        // Floor to milliseconds: only the first three fractional digits count.
        let mut millisecond = 0u16;
        if let Some(digit) = fraction.first() {
            millisecond += u16::from(digit - b'0') * 100;
        }
        if let Some(digit) = fraction.get(1) {
            millisecond += u16::from(digit - b'0') * 10;
        }
        if let Some(digit) = fraction.get(2) {
            millisecond += u16::from(digit - b'0');
        }
        millisecond
    };

    // Reuse the strict timestamp literal grammar/calendar validation (§2.8).
    let canonical = format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millisecond:03}Z"
    );
    Timestamp::parse(&canonical)
}

/// Check 13: converts `accuracy` to integer microseconds; absent components
/// count as 0 and an absent `accuracy` field means 0 (§9.4 case 1).
fn accuracy_micros(accuracy: Option<&Accuracy>) -> Result<i64, Code> {
    let Some(accuracy) = accuracy else {
        return Ok(0);
    };
    let seconds = match &accuracy.seconds {
        Some(value) => uint_to_u64(value).ok_or(e::TS_SCHEMA)?,
        None => 0,
    };
    let milliseconds = match &accuracy.millis {
        Some(value) => accuracy_component(value)?,
        None => 0,
    };
    let microseconds = match &accuracy.micros {
        Some(value) => accuracy_component(value)?,
        None => 0,
    };
    let seconds_microseconds = i64::try_from(seconds)
        .ok()
        .and_then(|seconds| seconds.checked_mul(1_000_000))
        .ok_or(e::TS_SCHEMA)?;
    Ok(seconds_microseconds + milliseconds * 1_000 + microseconds)
}

/// `millis`/`micros` present values must be in 1–999 (§12.2 row 13).
fn accuracy_component(value: &Uint) -> Result<i64, Code> {
    let value = uint_to_u64(value).ok_or(e::TS_SCHEMA)?;
    if !(1..=999).contains(&value) {
        return Err(e::TS_SCHEMA);
    }
    i64::try_from(value).map_err(|_| e::TS_SCHEMA)
}

fn uint_to_u64(value: &Uint) -> Option<u64> {
    let bytes = value.as_bytes();
    if bytes.len() > 8 {
        return None;
    }
    Some(
        bytes
            .iter()
            .fold(0u64, |accumulator, &byte| (accumulator << 8) | u64::from(byte)),
    )
}

// --------------------------------------------------------------------------
// `--tsa-trust` loading (§12.3)
// --------------------------------------------------------------------------

const PEM_BEGIN_CERTIFICATE: &[u8] = b"-----BEGIN CERTIFICATE-----";
const PEM_END_CERTIFICATE: &[u8] = b"-----END CERTIFICATE-----";

/// Decodes the DER of every certificate in one `--tsa-trust` file: either one
/// or more PEM `CERTIFICATE` blocks or a single raw DER certificate.
fn decode_anchor_certificates(contents: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    if find_subslice(contents, PEM_BEGIN_CERTIFICATE).is_none() {
        return Ok(vec![contents.to_vec()]);
    }
    let mut certificates = Vec::new();
    let mut cursor = 0usize;
    while let Some(relative_begin) = find_subslice(&contents[cursor..], PEM_BEGIN_CERTIFICATE) {
        let begin = cursor + relative_begin;
        if !contents[cursor..begin].iter().all(u8::is_ascii_whitespace) {
            return Err("unexpected data outside PEM certificate blocks".to_string());
        }
        let Some(relative_end) = find_subslice(&contents[begin..], PEM_END_CERTIFICATE) else {
            return Err("unterminated PEM certificate block".to_string());
        };
        let end = begin + relative_end + PEM_END_CERTIFICATE.len();
        let (label, der) = der::pem::decode_vec(&contents[begin..end])
            .map_err(|error| format!("invalid PEM certificate: {error}"))?;
        if label != "CERTIFICATE" {
            return Err(format!("unexpected PEM label `{label}`"));
        }
        certificates.push(der);
        cursor = end;
    }
    if !contents[cursor..].iter().all(u8::is_ascii_whitespace) {
        return Err("unexpected trailing data after PEM certificates".to_string());
    }
    Ok(certificates)
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

// --------------------------------------------------------------------------
// Tests
// --------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const SOLID_TRUST_ANCHOR_PEM_FINGERPRINT: &str =
        "2cd592e2ecd4c9f3ba4271eeeb446e7d1248704d3cd65cd8d033b2cf2c64300c";
    const TSA_CERTIFICATE: &str = "../../../vectors/keys/tsa/tsa.crt.pem";
    const VALID_RECEIPT: &str =
        "../../../vectors/integrity-levels/l2-valid/container/signatures/timestamp-1.tsr";
    const RENEWAL_RECEIPT_1: &str =
        "../../../vectors/integrity-levels/l2-renewal-chain-valid/container/signatures/timestamp-1.tsr";
    const RENEWAL_RECEIPT_2: &str =
        "../../../vectors/integrity-levels/l2-renewal-chain-valid/container/signatures/timestamp-2.tsr";
    const EXPIRED_CERTIFICATE: &str =
        "../../../vectors/integrity-levels/l2-cert-expired/tsa-crafted.pem";
    const VALID_RECEIPT_DIGEST: &str =
        "sha256:516dfb1189be80c659361932e044622b5071666769fe505c132bfae4c516d83d";
    const RENEWAL_RECEIPT_DIGEST: &str =
        "sha256:6cbd8b4490a5c5cbeca1fa8fbb1fd8bdf7584d0601f99572b4457a46731d81cf";
    const MANIFEST_DIGEST_BYTES: [u8; 32] = [
        0xcd, 0x87, 0x9a, 0xa3, 0xe7, 0xc2, 0xe9, 0xdf, 0x1f, 0xd3, 0xa1, 0x01, 0x01, 0x81, 0x1b,
        0x09, 0xaf, 0xba, 0xa6, 0x1a, 0xfb, 0x7f, 0xb2, 0xb9, 0xe1, 0xd8, 0x7b, 0x5a, 0x00, 0x85,
        0x61, 0xa1,
    ];

    fn vector_bytes(relative: &str) -> Vec<u8> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(relative);
        std::fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
    }

    fn valid_receipt_files() -> BTreeMap<String, Vec<u8>> {
        let mut files = BTreeMap::new();
        files.insert(
            "signatures/timestamp-1.tsr".to_string(),
            vector_bytes(VALID_RECEIPT),
        );
        files
    }

    fn valid_trust_anchors() -> Vec<[u8; 32]> {
        load_trust_anchors(&[vector_bytes(TSA_CERTIFICATE)])
            .expect("test TSA certificate loads")
    }

    fn valid_entry() -> AttestationTimestamp {
        AttestationTimestamp {
            digest: VALID_RECEIPT_DIGEST.to_string(),
            path: "signatures/timestamp-1.tsr".to_string(),
            renews: None,
        }
    }

    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn receipt_effect_maps_check_15_to_unverifiable() {
        assert_eq!(receipt_effect(e::TS_UNTRUSTED), "unverifiable");
        for code in [
            e::TS_SCHEMA,
            e::TS_IMPRINT,
            e::TS_CMS,
            e::TS_CERT,
            e::TS_RENEWAL,
            e::TS_FILE,
        ] {
            assert_eq!(receipt_effect(code), "invalid", "{code}");
        }
    }

    #[test]
    fn load_trust_anchors_reads_pem_certificate() {
        let anchors = valid_trust_anchors();
        assert_eq!(anchors.len(), 1);
        assert_eq!(to_hex(&anchors[0]), SOLID_TRUST_ANCHOR_PEM_FINGERPRINT);
    }

    #[test]
    fn load_trust_anchors_reads_multiple_pem_certificates_in_order() {
        let first = vector_bytes(TSA_CERTIFICATE);
        let second = vector_bytes(EXPIRED_CERTIFICATE);
        let mut concatenated = first.clone();
        concatenated.push(b'\n');
        concatenated.extend_from_slice(&second);
        let anchors = load_trust_anchors(&[concatenated]).expect("two PEM blocks load");
        assert_eq!(anchors.len(), 2);
        assert_eq!(to_hex(&anchors[0]), SOLID_TRUST_ANCHOR_PEM_FINGERPRINT);
        assert_ne!(to_hex(&anchors[1]), SOLID_TRUST_ANCHOR_PEM_FINGERPRINT);
    }

    #[test]
    fn load_trust_anchors_reads_raw_der_certificate() {
        let pem = vector_bytes(TSA_CERTIFICATE);
        let (_, der) = der::pem::decode_vec(&pem).expect("test certificate PEM decodes");
        let anchors = load_trust_anchors(&[der]).expect("raw DER certificate loads");
        assert_eq!(anchors.len(), 1);
        assert_eq!(to_hex(&anchors[0]), SOLID_TRUST_ANCHOR_PEM_FINGERPRINT);
    }

    #[test]
    fn load_trust_anchors_rejects_non_certificate_input() {
        let truncated_pem = b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
        assert!(load_trust_anchors(&[truncated_pem.to_vec()]).is_err());
        assert!(load_trust_anchors(&[b"not a certificate".to_vec()]).is_err());
        assert!(load_trust_anchors(&[Vec::new()]).is_err());
    }

    #[test]
    fn generalized_time_conversion_floors_sub_millisecond_digits() {
        let millis = |text: &str| {
            parse_generalized_time_text(text.as_bytes())
                .unwrap_or_else(|| panic!("{text} parses"))
                .to_unix_millis()
        };
        let whole = millis("20261101000000Z");
        assert_eq!(whole, 1_793_491_200_000);
        assert_eq!(millis("20261101000000.5Z"), whole + 500);
        assert_eq!(millis("20261101000000.123Z"), whole + 123);
        assert_eq!(millis("20261101000000.123456Z"), whole + 123);
        assert_eq!(millis("20261101000000.000999Z"), whole);
        // Calendrical validation is done by the strict TS grammar of §2.8.
        assert!(parse_generalized_time_text(b"20260230000000Z").is_none());
        assert!(parse_generalized_time_text(b"20261101000000").is_none());
        assert!(parse_generalized_time_text(b"20261101000000+0000").is_none());
        assert!(parse_generalized_time_text(b"2026110100000Z").is_none());
        assert!(parse_generalized_time_text(b"20261101000000.Z").is_none());
    }

    #[test]
    fn accuracy_conversion_uses_seconds_millis_micros() {
        let accuracy = |seconds: Option<u64>, millis: Option<u64>, micros: Option<u64>| {
            let uint = |value: Option<u64>| {
                value.map(|value| {
                    let bytes = value.to_be_bytes();
                    let start = bytes.iter().position(|byte| *byte != 0).unwrap_or(7);
                    Uint::new(&bytes[start..]).expect("test integer encodes")
                })
            };
            Accuracy {
                seconds: uint(seconds),
                millis: uint(millis),
                micros: uint(micros),
            }
        };
        assert_eq!(accuracy_micros(None).expect("absent accuracy"), 0);
        assert_eq!(
            accuracy_micros(Some(&accuracy(Some(1), None, None))).expect("seconds"),
            1_000_000
        );
        assert_eq!(
            accuracy_micros(Some(&accuracy(Some(2), Some(3), Some(4)))).expect("all components"),
            2_003_004
        );
        assert_eq!(
            accuracy_micros(Some(&accuracy(None, Some(999), Some(999)))).expect("max components"),
            999_999
        );
        assert_eq!(
            accuracy_micros(Some(&accuracy(None, Some(0), None))),
            Err(e::TS_SCHEMA)
        );
        assert_eq!(
            accuracy_micros(Some(&accuracy(None, None, Some(1000)))),
            Err(e::TS_SCHEMA)
        );
        let oversized = Uint::new(&[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
            .expect("oversized integer encodes");
        assert_eq!(
            accuracy_micros(Some(&Accuracy {
                seconds: Some(oversized),
                millis: None,
                micros: None,
            })),
            Err(e::TS_SCHEMA)
        );
    }

    #[test]
    fn valid_receipt_passes_every_check_and_is_trusted() {
        let files = valid_receipt_files();
        let evidence = verify_chain(
            &[valid_entry()],
            &MANIFEST_DIGEST_BYTES,
            &files,
            &valid_trust_anchors(),
        );
        assert_eq!(evidence.chain_error, None);
        assert!(evidence.anchor_verified);
        assert_eq!(evidence.receipts.len(), 1);
        let receipt = &evidence.receipts[0];
        assert_eq!(receipt.state, ReceiptState::Verified);
        assert_eq!(receipt.error, None);
        assert_eq!(receipt.accuracy_us, 0);
        assert_eq!(
            receipt.gen_time,
            Timestamp::parse("2026-11-01T00:00:00.000Z")
        );
    }

    #[test]
    fn receipt_without_matching_anchor_is_present_unverified() {
        let files = valid_receipt_files();
        let evidence = verify_chain(&[valid_entry()], &MANIFEST_DIGEST_BYTES, &files, &[]);
        assert!(!evidence.anchor_verified);
        assert_eq!(evidence.receipts[0].state, ReceiptState::PresentUnverified);
        assert_eq!(evidence.receipts[0].error, None);
        assert!(evidence.rescue_bounds_us().is_empty());

        let other = valid_trust_anchors()[0];
        let mut other_anchor = other;
        other_anchor[0] ^= 0xff;
        let evidence = verify_chain(
            &[valid_entry()],
            &MANIFEST_DIGEST_BYTES,
            &files,
            &[other_anchor],
        );
        assert_eq!(evidence.receipts[0].state, ReceiptState::PresentUnverified);
    }

    #[test]
    fn receipt_with_wrong_imprint_is_invalid() {
        let mut wrong = MANIFEST_DIGEST_BYTES;
        wrong[0] ^= 0xff;
        let evidence = verify_chain(
            &[valid_entry()],
            &wrong,
            &valid_receipt_files(),
            &valid_trust_anchors(),
        );
        assert!(!evidence.anchor_verified);
        assert_eq!(evidence.receipts[0].state, ReceiptState::Invalid);
        assert_eq!(evidence.receipts[0].error, Some(e::TS_IMPRINT));
    }

    #[test]
    fn receipt_with_mismatched_file_digest_is_invalid() {
        let mut entry = valid_entry();
        entry.digest =
            "sha256:9999999999999999999999999999999999999999999999999999999999999999"
                .to_string();
        let evidence = verify_chain(
            &[entry],
            &MANIFEST_DIGEST_BYTES,
            &valid_receipt_files(),
            &valid_trust_anchors(),
        );
        assert_eq!(evidence.receipts[0].state, ReceiptState::Invalid);
        assert_eq!(evidence.receipts[0].error, Some(e::TS_FILE));
    }

    #[test]
    fn receipt_with_tampered_signature_is_invalid() {
        let mut files = valid_receipt_files();
        let bytes = files
            .get_mut("signatures/timestamp-1.tsr")
            .expect("receipt present");
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        // Keep the listed digest consistent so that the CMS check decides.
        let tampered = bytes.clone();
        let entry = AttestationTimestamp {
            digest: digest::sha256_digest_string(&tampered),
            path: "signatures/timestamp-1.tsr".to_string(),
            renews: None,
        };
        let evidence = verify_chain(
            &[entry],
            &MANIFEST_DIGEST_BYTES,
            &files,
            &valid_trust_anchors(),
        );
        assert_eq!(evidence.receipts[0].state, ReceiptState::Invalid);
        assert_eq!(evidence.receipts[0].error, Some(e::TS_CMS));
    }

    #[test]
    fn renewal_chain_uses_previous_receipt_bytes_and_manifest_digest() {
        let mut files = BTreeMap::new();
        files.insert(
            "signatures/timestamp-1.tsr".to_string(),
            vector_bytes(RENEWAL_RECEIPT_1),
        );
        files.insert(
            "signatures/timestamp-2.tsr".to_string(),
            vector_bytes(RENEWAL_RECEIPT_2),
        );
        let entries = vec![
            AttestationTimestamp {
                digest: VALID_RECEIPT_DIGEST.to_string(),
                path: "signatures/timestamp-1.tsr".to_string(),
                renews: None,
            },
            AttestationTimestamp {
                digest: RENEWAL_RECEIPT_DIGEST.to_string(),
                path: "signatures/timestamp-2.tsr".to_string(),
                renews: Some("signatures/timestamp-1.tsr".to_string()),
            },
        ];
        let evidence = verify_chain(
            &entries,
            &MANIFEST_DIGEST_BYTES,
            &files,
            &valid_trust_anchors(),
        );
        assert_eq!(evidence.chain_error, None);
        assert!(evidence.anchor_verified);
        assert!(evidence
            .receipts
            .iter()
            .all(|receipt| receipt.state == ReceiptState::Verified));
        assert_eq!(evidence.rescue_bounds_us().len(), 2);
    }

    #[test]
    fn renewal_chain_structure_errors_are_detected() {
        let manifest = MANIFEST_DIGEST_BYTES;
        let base = AttestationTimestamp {
            digest: VALID_RECEIPT_DIGEST.to_string(),
            path: "signatures/timestamp-1.tsr".to_string(),
            renews: None,
        };

        // Missing head.
        let second = AttestationTimestamp {
            digest: RENEWAL_RECEIPT_DIGEST.to_string(),
            path: "signatures/timestamp-2.tsr".to_string(),
            renews: Some("signatures/timestamp-1.tsr".to_string()),
        };
        let evidence = verify_chain(&[second.clone()], &manifest, &BTreeMap::new(), &[]);
        assert_eq!(evidence.chain_error, Some(e::TS_RENEWAL));

        // Dangling link.
        let dangling = AttestationTimestamp {
            renews: Some("signatures/timestamp-3.tsr".to_string()),
            ..second.clone()
        };
        let evidence = verify_chain(
            &[base.clone(), dangling],
            &manifest,
            &BTreeMap::new(),
            &[],
        );
        assert_eq!(evidence.chain_error, Some(e::TS_RENEWAL));
        assert_eq!(evidence.receipts[1].error, Some(e::TS_RENEWAL));

        // Two chain heads.
        let two_heads = [
            base.clone(),
            AttestationTimestamp {
                path: "signatures/timestamp-2.tsr".to_string(),
                ..base.clone()
            },
        ];
        let evidence = verify_chain(&two_heads, &manifest, &BTreeMap::new(), &[]);
        assert_eq!(evidence.chain_error, Some(e::TS_RENEWAL));

        // Duplicate path.
        let duplicate = [base.clone(), base.clone()];
        let evidence = verify_chain(&duplicate, &manifest, &BTreeMap::new(), &[]);
        assert_eq!(evidence.chain_error, Some(e::TS_RENEWAL));

        // Out-of-order listing: head not first.
        let out_of_order = [second.clone(), base.clone()];
        let evidence = verify_chain(&out_of_order, &manifest, &BTreeMap::new(), &[]);
        assert_eq!(evidence.chain_error, Some(e::TS_RENEWAL));
    }

    #[test]
    fn empty_chain_has_no_evidence() {
        let evidence = verify_chain(&[], &MANIFEST_DIGEST_BYTES, &BTreeMap::new(), &[]);
        assert_eq!(evidence, ChainEvidence::none());
        assert!(!evidence.has_receipts());
    }
}
