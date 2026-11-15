// SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
// SPDX-License-Identifier: Apache-2.0

//! RFC 3161 timestamp verification (§12).
//!
//! The renewal chain of one manifest is verified in the complete check order of
//! §12.2 (W6): the file checks of every listed receipt, then the chain shape
//! (check 14), then checks 1–13 and 15 per receipt in chain order. The first
//! failing check is that receipt's only code.
//!
//! Check 1 is a real strict-DER check (W3, X1, X6, X7). Its rules come from
//! X.690 and the ASN.1 module definitions of RFC 3161, RFC 5652, RFC 5280 and
//! RFC 5035/5816 only; no parsing library decides it:
//!
//! - **1a** — [`crate::der::check_universal_rules`] applies the universal DER
//!   rules to every TLV of the file (iteratively, so nesting cannot overflow
//!   the stack);
//! - **1b/1c** — the schema walker below decodes the `TimeStampResp` against
//!   the module definitions. "Re-encoding yields the input" is checked
//!   constructively: every component must be present in the defined order with
//!   no extra components, every SET OF (implicitly tagged ones included) is in
//!   DER order, no component equal to its DEFAULT is encoded (the four DEFAULT
//!   components of §12.2 1c, compared by DER encoding), implicitly tagged
//!   primitives obey the content rules of their type, the signer's algorithm
//!   parameters have the form fixed per algorithm (X6/X7), and open-type values
//!   are judged by their framing only;
//! - **1d** — status, content type, `SignedData.version`, exactly one
//!   `SignerInfo` whose version matches its `sid`;
//! - **1e** — the signer certificate named by the `sid` is walked under the
//!   RFC 5280 `Certificate` definition and its extension values are single DER
//!   TLVs; every other certificate is an open type.
//!
//! Only the cryptographic primitives are rented: SHA-2 from `sha2`, RSA
//! PKCS#1 v1.5 from `rsa`, ECDSA P-256/P-384 from `p256`/`p384`.

use std::collections::{BTreeMap, BTreeSet};

use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::der::{self, universal, Class, DerError, Tlv};
use crate::digest;
use crate::error_codes::{e, Code};
use crate::limits;
use crate::options::UsageError;
use crate::time::Timestamp;

// --------------------------------------------------------------------------
// Object identifiers (dotted; encoded with `der::oid`)
// --------------------------------------------------------------------------

const ID_SIGNED_DATA: &str = "1.2.840.113549.1.7.2";
const ID_CT_TSTINFO: &str = "1.2.840.113549.1.9.16.1.4";
const ID_CONTENT_TYPE: &str = "1.2.840.113549.1.9.3";
const ID_MESSAGE_DIGEST: &str = "1.2.840.113549.1.9.4";
const ID_SIGNING_CERTIFICATE_V2: &str = "1.2.840.113549.1.9.16.2.47";
const ID_SHA224: &str = "2.16.840.1.101.3.4.2.4";
const ID_SHA256: &str = "2.16.840.1.101.3.4.2.1";
const ID_SHA384: &str = "2.16.840.1.101.3.4.2.2";
const ID_SHA512: &str = "2.16.840.1.101.3.4.2.3";
const RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
const SHA224_WITH_RSA: &str = "1.2.840.113549.1.1.14";
const SHA256_WITH_RSA: &str = "1.2.840.113549.1.1.11";
const SHA384_WITH_RSA: &str = "1.2.840.113549.1.1.12";
const SHA512_WITH_RSA: &str = "1.2.840.113549.1.1.13";
const ECDSA_WITH_SHA224: &str = "1.2.840.10045.4.3.1";
const ECDSA_WITH_SHA256: &str = "1.2.840.10045.4.3.2";
const ECDSA_WITH_SHA384: &str = "1.2.840.10045.4.3.3";
const ECDSA_WITH_SHA512: &str = "1.2.840.10045.4.3.4";
const ID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
const PRIME256V1: &str = "1.2.840.10045.3.1.7";
const SECP384R1: &str = "1.3.132.0.34";
const ID_KP_TIME_STAMPING: &str = "1.3.6.1.5.5.7.3.8";
const ID_CE_KEY_USAGE: &str = "2.5.29.15";
const ID_CE_EXT_KEY_USAGE: &str = "2.5.29.37";
const ID_CE_SUBJECT_KEY_IDENTIFIER: &str = "2.5.29.14";

/// DER encoding of the ESSCertIDv2 `hashAlgorithm` DEFAULT `{id-sha256}`
/// (parameters absent, §12.2 1c).
const ESS_DEFAULT_HASH_ALGORITHM: [u8; 13] = [
    0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
];

fn is_oid(content: &[u8], dotted: &str) -> bool {
    content == der::oid(dotted).as_slice()
}

// --------------------------------------------------------------------------
// Public model
// --------------------------------------------------------------------------

/// State of one timestamp receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiptState {
    /// Checks 1–15 of §12.2 passed, with usable accuracy.
    Verified,
    /// Structure and CMS pass, but the receipt is not verified-and-trusted (no
    /// matching anchor) or its accuracy is unusable evidence (T3).
    PresentUnverified,
    /// A file, chain, format or cryptographic check failed.
    Invalid,
}

/// Outcome of verifying one receipt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiptOutcome {
    /// Receipt state.
    pub state: ReceiptState,
    /// `genTime` truncated to whole milliseconds, filled once checks 1–4 passed
    /// (§14.6).
    pub gen_time: Option<Timestamp>,
    /// `accuracy` in integer microseconds when it is usable evidence (absent
    /// `accuracy` = 0); `None` when unusable or not established.
    pub accuracy_us: Option<i64>,
    /// The receipt's only reported code (§12.2 W6): the first failing check, or
    /// `E_TS_UNTRUSTED` for a present-unverified receipt.
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

/// Result of the timestamp phase of one manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainEvidence {
    /// One outcome per `timestamps[]` entry, in attestation order.
    pub receipts: Vec<ReceiptOutcome>,
    /// `E_TS_RENEWAL` when the chain shape (check 14) failed.
    pub chain_error: Option<Code>,
    /// True only when every receipt is verified, trusted and usable.
    pub anchor_verified: bool,
}

/// The three §9.4 outcomes of the compromise rescue rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rescue {
    /// A verified, trusted, usable receipt satisfies `genTime + accuracy < T`.
    Rescued,
    /// Receipts are present, but none is verified, trusted and usable (case 2).
    Untrusted,
    /// No evidence at all, or the trusted usable evidence does not rescue
    /// (case 3).
    Fails,
}

impl ChainEvidence {
    /// Empty evidence, used when a target has no timestamp chain (record
    /// target, L0/L1 container).
    #[must_use]
    pub fn none() -> Self {
        Self {
            receipts: Vec::new(),
            chain_error: None,
            anchor_verified: false,
        }
    }

    /// True when any receipt is listed.
    #[must_use]
    pub fn has_receipts(&self) -> bool {
        !self.receipts.is_empty()
    }

    /// The §9.4 compromise rule for a revocation effective at `t_ms` (Unix
    /// milliseconds): `genTime_ms × 1000 + accuracy_us < T_ms × 1000`, with
    /// checked fixed-width arithmetic (S11, T3). An overflow never rescues.
    #[must_use]
    pub fn rescue(&self, t_ms: i64) -> Rescue {
        if self.receipts.is_empty() {
            return Rescue::Fails;
        }
        let Some(boundary) = t_ms.checked_mul(1_000) else {
            return Rescue::Fails;
        };
        let mut any_usable_trusted = false;
        for receipt in &self.receipts {
            if receipt.state != ReceiptState::Verified {
                continue;
            }
            let (Some(gen_time), Some(accuracy_us)) = (receipt.gen_time, receipt.accuracy_us)
            else {
                continue;
            };
            any_usable_trusted = true;
            let bound = gen_time
                .to_unix_millis()
                .checked_mul(1_000)
                .and_then(|value| value.checked_add(accuracy_us));
            if bound.is_some_and(|bound| bound < boundary) {
                return Rescue::Rescued;
            }
        }
        if any_usable_trusted {
            Rescue::Fails
        } else {
            Rescue::Untrusted
        }
    }

    /// The timestamp phase's reported codes: the codes of every failing
    /// receipt together (§12.2 W6), sorted and unique.
    #[must_use]
    pub fn reported_codes(&self) -> Vec<Code> {
        if let Some(code) = self.chain_error {
            return vec![code];
        }
        let mut codes: Vec<Code> = self
            .receipts
            .iter()
            .filter_map(|receipt| receipt.error)
            .collect();
        codes.sort_unstable();
        codes.dedup();
        codes
    }
}

/// Runs the whole timestamp phase over one manifest digest (§12.2 W6).
///
/// `files` maps container-relative paths to receipt bytes. `trust_anchors`
/// holds the SHA-256 digests of the DER encodings of the `--tsa-trust`
/// certificates (§12.3).
#[must_use]
pub fn verify_chain(
    entries: &[AttestationTimestamp],
    manifest_digest: &[u8; 32],
    files: &BTreeMap<String, Vec<u8>>,
    trust_anchors: &[[u8; 32]],
) -> ChainEvidence {
    if entries.is_empty() {
        return ChainEvidence::none();
    }
    // (1) File checks for every listed receipt.
    let mut file_errors: Vec<Option<Code>> = Vec::with_capacity(entries.len());
    for entry in entries {
        let error = match files.get(&entry.path) {
            None => Some(e::TS_FILE),
            Some(bytes) if bytes.len() > limits::MAX_TIMESTAMP_BYTES => Some(e::JSON_SIZE),
            Some(bytes) if digest::sha256_digest_string(bytes) != entry.digest => Some(e::TS_FILE),
            Some(_) => None,
        };
        file_errors.push(error);
    }
    if file_errors.iter().any(Option::is_some) {
        return ChainEvidence {
            receipts: file_errors
                .into_iter()
                .map(|error| ReceiptOutcome {
                    state: ReceiptState::Invalid,
                    gen_time: None,
                    accuracy_us: None,
                    error,
                })
                .collect(),
            chain_error: None,
            anchor_verified: false,
        };
    }
    // (2) Chain shape (check 14), from the array alone.
    if let Some(code) = renewal_chain_error(entries) {
        return ChainEvidence {
            receipts: entries
                .iter()
                .map(|_| ReceiptOutcome {
                    state: ReceiptState::Invalid,
                    gen_time: None,
                    accuracy_us: None,
                    error: None,
                })
                .collect(),
            chain_error: Some(code),
            anchor_verified: false,
        };
    }
    // (3) Per receipt, in chain order (check 14 pinned the attestation order
    // to the chain order).
    let mut receipts = Vec::with_capacity(entries.len());
    for (index, entry) in entries.iter().enumerate() {
        let bytes = files
            .get(&entry.path)
            .map(Vec::as_slice)
            .unwrap_or_default();
        let imprint = if index == 0 {
            *manifest_digest
        } else {
            let previous = files
                .get(&entries[index - 1].path)
                .map(Vec::as_slice)
                .unwrap_or_default();
            digest::sha256_concat(&[previous, manifest_digest.as_slice()])
        };
        receipts.push(verify_receipt(bytes, &imprint, trust_anchors));
    }
    let anchor_verified = receipts
        .iter()
        .all(|receipt| receipt.state == ReceiptState::Verified);
    ChainEvidence {
        receipts,
        chain_error: None,
        anchor_verified,
    }
}

/// Check 14: exactly one renewal chain, listed in chain order, one head, each
/// later entry renewing the immediately preceding receipt, no duplicate paths
/// or digests.
fn renewal_chain_error(entries: &[AttestationTimestamp]) -> Option<Code> {
    let mut paths = BTreeSet::new();
    let mut digests = BTreeSet::new();
    for entry in entries {
        if !paths.insert(entry.path.as_str()) || !digests.insert(entry.digest.as_str()) {
            return Some(e::TS_RENEWAL);
        }
    }
    if entries.first().is_some_and(|first| first.renews.is_some()) {
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

// --------------------------------------------------------------------------
// Per-receipt checks 1–13 and 15
// --------------------------------------------------------------------------

fn invalid(error: Code, gen_time: Option<Timestamp>) -> ReceiptOutcome {
    ReceiptOutcome {
        state: ReceiptState::Invalid,
        gen_time,
        accuracy_us: None,
        error: Some(error),
    }
}

/// Verifies one receipt against the §12.2 table in its fixed order.
#[must_use]
pub fn verify_receipt(
    bytes: &[u8],
    expected_imprint: &[u8; 32],
    trust_anchors: &[[u8; 32]],
) -> ReceiptOutcome {
    // Check 1 (1a–1e).
    let Ok(token) = check_one(bytes) else {
        return invalid(e::TS_SCHEMA, None);
    };
    // Check 2: content type and the TSTInfo (1a–1c on its own, version 1).
    if !is_oid(token.econtent_type, ID_CT_TSTINFO) {
        return invalid(e::TS_SCHEMA, None);
    }
    let Some(econtent) = token.econtent else {
        return invalid(e::TS_SCHEMA, None);
    };
    let Ok(tst) = decode_tst_info(econtent) else {
        return invalid(e::TS_SCHEMA, None);
    };
    if tst.version != [0x01] {
        return invalid(e::TS_SCHEMA, None);
    }
    // Check 3.
    if !is_oid(tst.imprint_algorithm, ID_SHA256) {
        return invalid(e::TS_SCHEMA, None);
    }
    // Check 4.
    if tst.hashed_message != expected_imprint.as_slice() {
        return invalid(e::TS_IMPRINT, None);
    }
    // Checks 1–4 passed: genTime is reported from here on (§14.6).
    let gen_time = parse_generalized_time(tst.gen_time);
    // Check 5.
    if !is_oid(token.signer.digest_algorithm, ID_SHA256) {
        return invalid(e::TS_SCHEMA, gen_time);
    }
    // Check 6.
    let Some(scheme) = signature_scheme(token.signer.signature_algorithm) else {
        return invalid(e::TS_CERT, gen_time);
    };
    // Check 7.
    let Some(certificate) = token.signer_certificate.as_ref() else {
        return invalid(e::TS_CMS, gen_time);
    };
    // Checks 8 and 9.
    let Some(signed_attributes) = token.signer.signed_attributes else {
        return invalid(e::TS_CMS, gen_time);
    };
    if let Err(code) = check_signed_attributes(&token, certificate, econtent) {
        return invalid(code, gen_time);
    }
    // Check 10: the signature over DER(SET OF SignedAttributes) (RFC 5652
    // §5.4): the implicit [0] tag is replaced by the universal SET tag.
    let signed = der::encode(0x31, signed_attributes);
    if !verify_signature(scheme, certificate.spki, &signed, token.signer.signature) {
        return invalid(e::TS_CMS, gen_time);
    }
    // Check 11.
    if !certificate_profile_ok(certificate) {
        return invalid(e::TS_CERT, gen_time);
    }
    // Check 12 (genTime itself is check 13; an invalid genTime fails there).
    if let Some(gen_time) = gen_time {
        let millis = gen_time.to_unix_millis();
        let (Some(not_before), Some(not_after)) = (
            certificate_time_millis(certificate.not_before),
            certificate_time_millis(certificate.not_after),
        ) else {
            return invalid(e::TS_CERT, Some(gen_time));
        };
        if millis < not_before || millis > not_after {
            return invalid(e::TS_CERT, Some(gen_time));
        }
    }
    // Check 13: genTime and the accuracy format; an over-bound or overflowing
    // total is unusable evidence, not a format error (T3).
    let Some(gen_time) = gen_time else {
        return invalid(e::TS_SCHEMA, None);
    };
    let accuracy = match accuracy_micros(tst.accuracy) {
        Ok(accuracy) => accuracy,
        Err(()) => return invalid(e::TS_SCHEMA, Some(gen_time)),
    };
    let Some(accuracy_us) = accuracy else {
        return ReceiptOutcome {
            state: ReceiptState::PresentUnverified,
            gen_time: Some(gen_time),
            accuracy_us: None,
            error: Some(e::TS_UNTRUSTED),
        };
    };
    // Check 15: trust (§12.3).
    let leaf = digest::sha256(certificate.raw);
    if !trust_anchors.contains(&leaf) {
        return ReceiptOutcome {
            state: ReceiptState::PresentUnverified,
            gen_time: Some(gen_time),
            accuracy_us: Some(accuracy_us),
            error: Some(e::TS_UNTRUSTED),
        };
    }
    ReceiptOutcome {
        state: ReceiptState::Verified,
        gen_time: Some(gen_time),
        accuracy_us: Some(accuracy_us),
        error: None,
    }
}

/// One accuracy component: `Err(())` format error, `Ok(None)` too large for a
/// fixed-width value (unusable), `Ok(Some(v))` its value.
fn accuracy_component(content: Option<&[u8]>, ranged: bool) -> Result<Option<i64>, ()> {
    let Some(content) = content else {
        return Ok(Some(0));
    };
    if content.first().is_some_and(|byte| byte & 0x80 != 0) {
        // A negative component is a format error.
        return Err(());
    }
    let significant = content.iter().skip_while(|byte| **byte == 0).count();
    if significant > 8 {
        return if ranged { Err(()) } else { Ok(None) };
    }
    let value = content.iter().fold(0u64, |accumulator, &byte| {
        (accumulator << 8) | u64::from(byte)
    });
    if ranged && !(1..=999).contains(&value) {
        return Err(());
    }
    Ok(i64::try_from(value).ok())
}

/// §12.2 check 13 accuracy: `Ok(Some(us))` usable, `Ok(None)` unusable
/// (above `MAX_TS_ACCURACY` or overflowing in checked arithmetic), `Err(())` a
/// format error.
fn accuracy_micros(accuracy: Option<Accuracy<'_>>) -> Result<Option<i64>, ()> {
    let Some(accuracy) = accuracy else {
        return Ok(Some(0));
    };
    let seconds = accuracy_component(accuracy.seconds, false)?;
    let millis = accuracy_component(accuracy.millis, true)?;
    let micros = accuracy_component(accuracy.micros, true)?;
    let total = (|| {
        seconds?
            .checked_mul(1_000_000)?
            .checked_add(millis?.checked_mul(1_000)?)?
            .checked_add(micros?)
    })();
    let limit = limits::MAX_TS_ACCURACY_SECONDS * 1_000_000;
    Ok(total.filter(|total| *total <= limit))
}

// --------------------------------------------------------------------------
// Check 1: schema walk (1b/1c), status and versions (1d), signer certificate (1e)
// --------------------------------------------------------------------------

type DerResult<T> = Result<T, DerError>;

/// A cursor over the components of a SEQUENCE.
struct Seq<'a> {
    items: Vec<Tlv<'a>>,
    position: usize,
}

impl<'a> Seq<'a> {
    /// A universal, constructed SEQUENCE.
    fn new(tlv: &Tlv<'a>) -> DerResult<Self> {
        if !tlv.is_universal(universal::SEQUENCE) || !tlv.tag.constructed {
            return Err(DerError("expected SEQUENCE"));
        }
        Self::of_content(tlv.content)
    }

    /// The components of an implicitly tagged SEQUENCE (constructed).
    fn implicit(tlv: &Tlv<'a>) -> DerResult<Self> {
        if !tlv.tag.constructed {
            return Err(DerError("expected constructed"));
        }
        Self::of_content(tlv.content)
    }

    fn of_content(content: &'a [u8]) -> DerResult<Self> {
        Ok(Self {
            items: der::children(content)?,
            position: 0,
        })
    }

    fn next(&mut self) -> DerResult<Tlv<'a>> {
        let item = *self
            .items
            .get(self.position)
            .ok_or(DerError("missing component"))?;
        self.position += 1;
        Ok(item)
    }

    /// Takes the next component when `predicate` accepts it.
    fn optional(&mut self, predicate: impl Fn(&Tlv<'a>) -> bool) -> Option<Tlv<'a>> {
        let item = *self.items.get(self.position)?;
        if predicate(&item) {
            self.position += 1;
            Some(item)
        } else {
            None
        }
    }

    fn finish(&self) -> DerResult<()> {
        if self.position == self.items.len() {
            Ok(())
        } else {
            Err(DerError("unexpected component"))
        }
    }
}

/// A universally tagged primitive of the schema. Its content obeys the
/// canonical-content rules of its type (§12.2 1c: "every typed primitive ...
/// is rebuilt from its content octets by the X.690 rules for its type"). In a
/// receipt 1a has already judged every TLV; for a `--tsa-trust` anchor, which
/// gets 1a on its `extnValue`s only (§14.1), this is where they are judged.
fn universal_primitive<'a>(tlv: &Tlv<'a>, number: u64) -> DerResult<&'a [u8]> {
    if tlv.is_universal(number) && !tlv.tag.constructed {
        der::check_typed_content(number, tlv.content)?;
        Ok(tlv.content)
    } else {
        Err(DerError("unexpected type"))
    }
}

/// An implicitly tagged primitive: content rules of the underlying type (1c).
fn implicit_primitive<'a>(tlv: &Tlv<'a>, number: u64) -> DerResult<&'a [u8]> {
    if tlv.tag.constructed {
        return Err(DerError("implicit primitive in constructed form"));
    }
    der::check_primitive_content(number, tlv.content)?;
    Ok(tlv.content)
}

/// The components of a SET OF (universal or implicitly tagged), in DER order.
fn set_of<'a>(tlv: &Tlv<'a>) -> DerResult<Vec<Tlv<'a>>> {
    if !tlv.tag.constructed {
        return Err(DerError("SET OF in primitive form"));
    }
    let components = der::children(tlv.content)?;
    if !der::is_der_sorted(&components) {
        return Err(DerError("SET OF not in DER order"));
    }
    Ok(components)
}

/// The components of a SEQUENCE OF.
fn sequence_of<'a>(tlv: &Tlv<'a>) -> DerResult<Vec<Tlv<'a>>> {
    if !tlv.is_universal(universal::SEQUENCE) || !tlv.tag.constructed {
        return Err(DerError("expected SEQUENCE OF"));
    }
    der::children(tlv.content)
}

fn oid_value<'a>(tlv: &Tlv<'a>) -> DerResult<&'a [u8]> {
    universal_primitive(tlv, universal::OID)
}

fn integer_value<'a>(tlv: &Tlv<'a>) -> DerResult<&'a [u8]> {
    universal_primitive(tlv, universal::INTEGER)
}

fn octet_string<'a>(tlv: &Tlv<'a>) -> DerResult<&'a [u8]> {
    universal_primitive(tlv, universal::OCTET_STRING)
}

fn is_time(tlv: &Tlv<'_>) -> bool {
    (tlv.is_universal(universal::UTC_TIME) || tlv.is_universal(universal::GENERALIZED_TIME))
        && !tlv.tag.constructed
}

fn time_value<'a>(tlv: &Tlv<'a>) -> DerResult<Tlv<'a>> {
    if is_time(tlv) {
        // §12.2 1c: times are compared as their raw content in the DER form.
        der::check_typed_content(tlv.tag.number.unwrap_or_default(), tlv.content)?;
        Ok(*tlv)
    } else {
        Err(DerError("expected Time"))
    }
}

fn explicit_single<'a>(tlv: &Tlv<'a>) -> DerResult<Tlv<'a>> {
    if !tlv.tag.constructed {
        return Err(DerError("explicit tag in primitive form"));
    }
    let inner = der::children(tlv.content)?;
    if inner.len() != 1 {
        return Err(DerError("explicit tag content"));
    }
    Ok(inner[0])
}

/// `AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters ANY OPTIONAL }`
/// with an open-type `parameters`.
struct AlgorithmId<'a> {
    oid: &'a [u8],
    parameters: Option<Tlv<'a>>,
}

fn algorithm_identifier<'a>(tlv: &Tlv<'a>) -> DerResult<AlgorithmId<'a>> {
    let mut seq = Seq::new(tlv)?;
    let oid = oid_value(&seq.next()?)?;
    let parameters = seq.optional(|_| true);
    seq.finish()?;
    Ok(AlgorithmId { oid, parameters })
}

/// `Name ::= SEQUENCE OF RelativeDistinguishedName`, each a SET OF
/// `AttributeTypeAndValue { type OID, value ANY }` (value open type).
fn name(tlv: &Tlv<'_>) -> DerResult<()> {
    for rdn in sequence_of(tlv)? {
        if !rdn.is_universal(universal::SET) {
            return Err(DerError("expected RDN SET"));
        }
        for attribute in set_of(&rdn)? {
            let mut seq = Seq::new(&attribute)?;
            oid_value(&seq.next()?)?;
            seq.next()?;
            seq.finish()?;
        }
    }
    Ok(())
}

/// `Extensions ::= SEQUENCE SIZE (1..MAX) OF Extension`; returns
/// `(extnID, extnValue)` pairs. `critical` DEFAULT FALSE must not be encoded
/// as FALSE.
fn extensions_content(content: &[u8]) -> DerResult<Vec<(&[u8], &[u8])>> {
    let items = der::children(content)?;
    if items.is_empty() {
        return Err(DerError("empty Extensions"));
    }
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let mut seq = Seq::new(&item)?;
        let id = oid_value(&seq.next()?)?;
        if let Some(critical) = seq.optional(|tlv| tlv.is_universal(universal::BOOLEAN)) {
            universal_primitive(&critical, universal::BOOLEAN)?;
            if critical.content == [0x00] {
                return Err(DerError("critical DEFAULT FALSE encoded"));
            }
        }
        let value = octet_string(&seq.next()?)?;
        seq.finish()?;
        out.push((id, value));
    }
    Ok(out)
}

fn extensions<'a>(tlv: &Tlv<'a>) -> DerResult<Vec<(&'a [u8], &'a [u8])>> {
    if !tlv.is_universal(universal::SEQUENCE) || !tlv.tag.constructed {
        return Err(DerError("expected Extensions"));
    }
    extensions_content(tlv.content)
}

/// `DirectoryString` CHOICE: one universal string type.
fn directory_string(tlv: &Tlv<'_>) -> DerResult<()> {
    match (tlv.tag.class, tlv.tag.number) {
        (Class::Universal, Some(12 | 19 | 20 | 28 | 30)) if !tlv.tag.constructed => Ok(()),
        _ => Err(DerError("expected DirectoryString")),
    }
}

fn explicit_directory_string(tlv: &Tlv<'_>) -> DerResult<()> {
    directory_string(&explicit_single(tlv)?)
}

/// `GeneralName` (RFC 5280, implicit tags; `directoryName` is explicit because
/// `Name` is a CHOICE; `x400Address` is an open type). Returns the raw `Name`
/// of a `directoryName`.
fn general_name<'a>(tlv: &Tlv<'a>) -> DerResult<Option<&'a [u8]>> {
    if tlv.tag.class != Class::Context {
        return Err(DerError("expected GeneralName"));
    }
    match tlv.tag.number {
        Some(0) => {
            // otherName: [0] IMPLICIT SEQUENCE { type-id OID, value [0] EXPLICIT ANY }
            let mut seq = Seq::implicit(tlv)?;
            oid_value(&seq.next()?)?;
            let value = seq.next()?;
            if !value.is_context(0) {
                return Err(DerError("otherName value"));
            }
            explicit_single(&value)?;
            seq.finish()?;
            Ok(None)
        }
        Some(1 | 2 | 6) => {
            if tlv.tag.constructed {
                return Err(DerError("IA5String constructed"));
            }
            Ok(None)
        }
        Some(3) => Ok(None),
        Some(4) => {
            let inner = explicit_single(tlv)?;
            name(&inner)?;
            Ok(Some(inner.raw))
        }
        Some(5) => {
            let mut seq = Seq::implicit(tlv)?;
            if let Some(assigner) = seq.optional(|tlv| tlv.is_context(0)) {
                explicit_directory_string(&assigner)?;
            }
            let party = seq.next()?;
            if !party.is_context(1) {
                return Err(DerError("ediPartyName"));
            }
            explicit_directory_string(&party)?;
            seq.finish()?;
            Ok(None)
        }
        Some(7) => {
            implicit_primitive(tlv, universal::OCTET_STRING)?;
            Ok(None)
        }
        Some(8) => {
            implicit_primitive(tlv, universal::OID)?;
            Ok(None)
        }
        _ => Err(DerError("unknown GeneralName")),
    }
}

/// `PolicyInformation ::= SEQUENCE { policyIdentifier OID, policyQualifiers
/// SEQUENCE OF PolicyQualifierInfo OPTIONAL }` (qualifier open type).
fn policy_information(tlv: &Tlv<'_>) -> DerResult<()> {
    let mut seq = Seq::new(tlv)?;
    oid_value(&seq.next()?)?;
    if let Some(qualifiers) = seq.optional(|_| true) {
        for qualifier in sequence_of(&qualifiers)? {
            let mut inner = Seq::new(&qualifier)?;
            oid_value(&inner.next()?)?;
            inner.next()?;
            inner.finish()?;
        }
    }
    seq.finish()
}

/// One decoded `ESSCertIDv2`.
struct EssCertId<'a> {
    hash_algorithm: Option<&'a [u8]>,
    cert_hash: &'a [u8],
    issuer_serial: Option<(Vec<&'a [u8]>, &'a [u8])>,
}

/// `SigningCertificateV2 ::= SEQUENCE { certs SEQUENCE OF ESSCertIDv2,
/// policies SEQUENCE OF PolicyInformation OPTIONAL }`.
fn signing_certificate_v2<'a>(tlv: &Tlv<'a>) -> DerResult<Vec<EssCertId<'a>>> {
    let mut seq = Seq::new(tlv)?;
    let mut ids = Vec::new();
    for item in sequence_of(&seq.next()?)? {
        let mut cert_id = Seq::new(&item)?;
        let hash_algorithm = match cert_id.optional(|tlv| tlv.is_universal(universal::SEQUENCE)) {
            Some(algorithm) => {
                // §12.2 1c: `{id-sha256}` without parameters is the DEFAULT
                // and must not be encoded; `{id-sha256, NULL}` is another value.
                if algorithm.raw == ESS_DEFAULT_HASH_ALGORITHM {
                    return Err(DerError("ESSCertIDv2 DEFAULT encoded"));
                }
                Some(algorithm_identifier(&algorithm)?.oid)
            }
            None => None,
        };
        let cert_hash = octet_string(&cert_id.next()?)?;
        let issuer_serial = match cert_id.optional(|_| true) {
            Some(issuer_serial) => {
                let mut inner = Seq::new(&issuer_serial)?;
                let mut directory_names = Vec::new();
                for general in sequence_of(&inner.next()?)? {
                    if let Some(raw) = general_name(&general)? {
                        directory_names.push(raw);
                    }
                }
                let serial = integer_value(&inner.next()?)?;
                inner.finish()?;
                Some((directory_names, serial))
            }
            None => None,
        };
        cert_id.finish()?;
        ids.push(EssCertId {
            hash_algorithm,
            cert_hash,
            issuer_serial,
        });
    }
    if let Some(policies) = seq.optional(|_| true) {
        for policy in sequence_of(&policies)? {
            policy_information(&policy)?;
        }
    }
    seq.finish()?;
    Ok(ids)
}

/// One decoded attribute: type and values.
struct Attribute<'a> {
    attribute_type: &'a [u8],
    values: Vec<Tlv<'a>>,
}

/// `Attribute ::= SEQUENCE { attrType OID, attrValues SET OF AttributeValue }`;
/// the values of `id-contentType`, `id-messageDigest` and
/// `id-aa-signingCertificateV2` are decoded, every other value is an open type.
fn attribute<'a>(tlv: &Tlv<'a>) -> DerResult<Attribute<'a>> {
    let mut seq = Seq::new(tlv)?;
    let attribute_type = oid_value(&seq.next()?)?;
    let values_tlv = seq.next()?;
    if !values_tlv.is_universal(universal::SET) {
        return Err(DerError("attrValues"));
    }
    let values = set_of(&values_tlv)?;
    seq.finish()?;
    for value in &values {
        if is_oid(attribute_type, ID_CONTENT_TYPE) {
            oid_value(value)?;
        } else if is_oid(attribute_type, ID_MESSAGE_DIGEST) {
            octet_string(value)?;
        } else if is_oid(attribute_type, ID_SIGNING_CERTIFICATE_V2) {
            signing_certificate_v2(value)?;
        }
    }
    Ok(Attribute {
        attribute_type,
        values,
    })
}

fn attributes<'a>(tlv: &Tlv<'a>) -> DerResult<Vec<Attribute<'a>>> {
    set_of(tlv)?.iter().map(attribute).collect()
}

/// The signer identifier: issuer and serial, or a subject key identifier.
#[derive(Clone, Copy)]
enum SignerId<'a> {
    IssuerSerial { issuer: &'a [u8], serial: &'a [u8] },
    KeyIdentifier(&'a [u8]),
}

/// The signer of the token.
struct SignerInfo<'a> {
    version: &'a [u8],
    sid: SignerId<'a>,
    digest_algorithm: &'a [u8],
    /// Content of the `[0] IMPLICIT SignedAttributes` (the SET OF components).
    signed_attributes: Option<&'a [u8]>,
    signed_attribute_list: Vec<Attribute<'a>>,
    signature_algorithm: &'a [u8],
    signature: &'a [u8],
}

/// §12.2 1c (X6, X7): the form of the signer's algorithm parameters. The
/// parameters of an algorithm outside the table are an open type.
fn check_signer_parameters(digest: &AlgorithmId<'_>, signature: &AlgorithmId<'_>) -> DerResult<()> {
    let is_null = |parameters: &Option<Tlv<'_>>| {
        parameters
            .as_ref()
            .is_some_and(|tlv| tlv.raw == [0x05, 0x00])
    };
    let any = |oid: &[u8], list: &[&str]| list.iter().any(|dotted| is_oid(oid, dotted));
    if any(digest.oid, &[ID_SHA224, ID_SHA256, ID_SHA384, ID_SHA512])
        && !(digest.parameters.is_none() || is_null(&digest.parameters))
    {
        return Err(DerError("digestAlgorithm parameters"));
    }
    if is_oid(signature.oid, RSA_ENCRYPTION) && !is_null(&signature.parameters) {
        return Err(DerError("rsaEncryption parameters"));
    }
    if any(
        signature.oid,
        &[
            SHA224_WITH_RSA,
            SHA256_WITH_RSA,
            SHA384_WITH_RSA,
            SHA512_WITH_RSA,
        ],
    ) && !(signature.parameters.is_none() || is_null(&signature.parameters))
    {
        return Err(DerError("sha*WithRSAEncryption parameters"));
    }
    if any(
        signature.oid,
        &[
            ECDSA_WITH_SHA224,
            ECDSA_WITH_SHA256,
            ECDSA_WITH_SHA384,
            ECDSA_WITH_SHA512,
        ],
    ) && signature.parameters.is_some()
    {
        return Err(DerError("ecdsa parameters"));
    }
    Ok(())
}

fn signer_info<'a>(tlv: &Tlv<'a>) -> DerResult<SignerInfo<'a>> {
    let mut seq = Seq::new(tlv)?;
    let version = integer_value(&seq.next()?)?;
    let sid_tlv = seq.next()?;
    let sid = if sid_tlv.is_universal(universal::SEQUENCE) {
        let mut inner = Seq::new(&sid_tlv)?;
        let issuer = inner.next()?;
        name(&issuer)?;
        let serial = integer_value(&inner.next()?)?;
        inner.finish()?;
        SignerId::IssuerSerial {
            issuer: issuer.raw,
            serial,
        }
    } else if sid_tlv.is_context(0) {
        SignerId::KeyIdentifier(implicit_primitive(&sid_tlv, universal::OCTET_STRING)?)
    } else {
        return Err(DerError("SignerIdentifier"));
    };
    let digest_algorithm = algorithm_identifier(&seq.next()?)?;
    let signed = seq.optional(|tlv| tlv.is_context(0));
    let signed_attribute_list = match &signed {
        Some(tlv) => attributes(tlv)?,
        None => Vec::new(),
    };
    let signature_algorithm = algorithm_identifier(&seq.next()?)?;
    check_signer_parameters(&digest_algorithm, &signature_algorithm)?;
    let signature = octet_string(&seq.next()?)?;
    if let Some(unsigned) = seq.optional(|tlv| tlv.is_context(1)) {
        attributes(&unsigned)?;
    }
    seq.finish()?;
    Ok(SignerInfo {
        version,
        sid,
        digest_algorithm: digest_algorithm.oid,
        signed_attributes: signed.map(|tlv| tlv.content),
        signed_attribute_list,
        signature_algorithm: signature_algorithm.oid,
        signature,
    })
}

/// `CertificateList` (RFC 5280 §5.1), with CRL and CRL-entry extensions.
fn certificate_list(tlv: &Tlv<'_>) -> DerResult<()> {
    let mut seq = Seq::new(tlv)?;
    let tbs = seq.next()?;
    algorithm_identifier(&seq.next()?)?;
    universal_primitive(&seq.next()?, universal::BIT_STRING)?;
    seq.finish()?;
    let mut tbs = Seq::new(&tbs)?;
    if let Some(version) = tbs.optional(|tlv| tlv.is_universal(universal::INTEGER)) {
        integer_value(&version)?;
    }
    algorithm_identifier(&tbs.next()?)?;
    name(&tbs.next()?)?;
    time_value(&tbs.next()?)?;
    tbs.optional(is_time);
    if let Some(revoked) = tbs.optional(|tlv| tlv.is_universal(universal::SEQUENCE)) {
        for entry in sequence_of(&revoked)? {
            let mut inner = Seq::new(&entry)?;
            integer_value(&inner.next()?)?;
            time_value(&inner.next()?)?;
            if let Some(entry_extensions) = inner.optional(|_| true) {
                extensions(&entry_extensions)?;
            }
            inner.finish()?;
        }
    }
    if let Some(crl_extensions) = tbs.optional(|tlv| tlv.is_context(0)) {
        extensions(&explicit_single(&crl_extensions)?)?;
    }
    tbs.finish()
}

/// The decoded signer certificate (1e).
struct Certificate<'a> {
    raw: &'a [u8],
    issuer: &'a [u8],
    serial: &'a [u8],
    not_before: Tlv<'a>,
    not_after: Tlv<'a>,
    spki: &'a [u8],
    extensions: Vec<(&'a [u8], &'a [u8])>,
}

/// §12.2 1e: the signer certificate under the RFC 5280 `Certificate`
/// definition, with its DEFAULT version, and every `extnValue` a single DER
/// TLV obeying the universal rules of 1a.
fn certificate<'a>(tlv: &Tlv<'a>) -> DerResult<Certificate<'a>> {
    let mut seq = Seq::new(tlv)?;
    let tbs = seq.next()?;
    algorithm_identifier(&seq.next()?)?;
    universal_primitive(&seq.next()?, universal::BIT_STRING)?;
    seq.finish()?;
    let mut tbs = Seq::new(&tbs)?;
    // RFC 5280 §4.1: `version [0] EXPLICIT Version DEFAULT v1` with
    // `Version ::= INTEGER { v1(0), v2(1), v3(2) }`. v1 is the absent field
    // (an explicit v1 is a DEFAULT value encoded, §12.2 1c); v2 and v3 are
    // encoded. The specification adds no version rule, so the module's
    // version set is the criterion (H1-FIX2 Y5, docs/h1-findings.md F62).
    let mut version_number = 0u8;
    if let Some(version) = tbs.optional(|tlv| tlv.is_context(0)) {
        if version.raw == [0xa0, 0x03, 0x02, 0x01, 0x00] {
            return Err(DerError("TBSCertificate.version DEFAULT encoded"));
        }
        version_number = match integer_value(&explicit_single(&version)?)? {
            // Only reachable without the DEFAULT check above; kept so that
            // check alone decides an explicit v1.
            [0x00] => 0,
            [0x01] => 1,
            [0x02] => 2,
            _ => return Err(DerError("certificate version outside v1..v3")),
        };
    }
    let serial = integer_value(&tbs.next()?)?;
    algorithm_identifier(&tbs.next()?)?;
    let issuer = tbs.next()?;
    name(&issuer)?;
    let validity_tlv = tbs.next()?;
    let mut validity = Seq::new(&validity_tlv)?;
    let not_before = time_value(&validity.next()?)?;
    let not_after = time_value(&validity.next()?)?;
    validity.finish()?;
    name(&tbs.next()?)?;
    let spki = tbs.next()?;
    let mut spki_seq = Seq::new(&spki)?;
    algorithm_identifier(&spki_seq.next()?)?;
    universal_primitive(&spki_seq.next()?, universal::BIT_STRING)?;
    spki_seq.finish()?;
    for unique in [1u64, 2] {
        if let Some(identifier) = tbs.optional(|tlv| tlv.is_context(unique)) {
            // RFC 5280 module: "If present, version MUST be v2 or v3".
            if version_number < 1 {
                return Err(DerError("unique identifier in a v1 certificate"));
            }
            implicit_primitive(&identifier, universal::BIT_STRING)?;
        }
    }
    let mut certificate_extensions = Vec::new();
    if let Some(extension_tlv) = tbs.optional(|tlv| tlv.is_context(3)) {
        // RFC 5280 module: "If present, version MUST be v3".
        if version_number != 2 {
            return Err(DerError("extensions in a certificate below v3"));
        }
        certificate_extensions = extensions(&explicit_single(&extension_tlv)?)?;
        for (_, value) in &certificate_extensions {
            der::check_universal_rules(value)?;
        }
    }
    tbs.finish()?;
    Ok(Certificate {
        raw: tlv.raw,
        issuer: issuer.raw,
        serial,
        not_before,
        not_after,
        spki: spki.raw,
        extensions: certificate_extensions,
    })
}

/// Framing-only peek used by 1e to find the component the `sid` names; a
/// component that does not have the shape of a certificate is not a match.
fn names_signer(component: &Tlv<'_>, sid: SignerId<'_>) -> bool {
    let peek = || -> DerResult<bool> {
        let mut seq = Seq::new(component)?;
        let mut tbs = Seq::new(&seq.next()?)?;
        tbs.optional(|tlv| tlv.is_context(0));
        let serial = integer_value(&tbs.next()?)?;
        tbs.next()?;
        let issuer = tbs.next()?;
        match sid {
            SignerId::IssuerSerial {
                issuer: sid_issuer,
                serial: sid_serial,
            } => Ok(issuer.raw == sid_issuer && serial == sid_serial),
            SignerId::KeyIdentifier(key_identifier) => {
                while let Some(item) = tbs.optional(|_| true) {
                    if !item.is_context(3) {
                        continue;
                    }
                    for (id, value) in extensions(&explicit_single(&item)?)? {
                        if is_oid(id, ID_CE_SUBJECT_KEY_IDENTIFIER) {
                            let inner = der::read_single(value)?;
                            if octet_string(&inner)? == key_identifier {
                                return Ok(true);
                            }
                        }
                    }
                }
                Ok(false)
            }
        }
    };
    peek().unwrap_or(false)
}

/// The decoded token, after 1a–1e.
struct Token<'a> {
    econtent_type: &'a [u8],
    econtent: Option<&'a [u8]>,
    signer: SignerInfo<'a>,
    signer_certificate: Option<Certificate<'a>>,
}

/// Check 1 (1a–1e). Any failure is `E_TS_SCHEMA`.
fn check_one(bytes: &[u8]) -> DerResult<Token<'_>> {
    // 1a.
    der::check_universal_rules(bytes)?;
    // 1b/1c: TimeStampResp ::= SEQUENCE { status PKIStatusInfo,
    // timeStampToken TimeStampToken OPTIONAL }.
    let root = der::read_single(bytes)?;
    let mut response = Seq::new(&root)?;
    let mut status_info = Seq::new(&response.next()?)?;
    let status = integer_value(&status_info.next()?)?;
    if let Some(text) = status_info.optional(|tlv| tlv.is_universal(universal::SEQUENCE)) {
        let strings = sequence_of(&text)?;
        if strings.is_empty() {
            return Err(DerError("empty PKIFreeText"));
        }
        for string in strings {
            universal_primitive(&string, universal::UTF8_STRING)?;
        }
    }
    if let Some(fail_info) = status_info.optional(|tlv| tlv.is_universal(universal::BIT_STRING)) {
        // A named bit list has no trailing zero bit (X.690 §11.2.2).
        let unused = der::check_bit_string(fail_info.content)?;
        if let Some(last) = fail_info.content.get(1..).and_then(<[u8]>::last) {
            if (last >> unused) & 1 == 0 {
                return Err(DerError("failInfo trailing zero bit"));
            }
        }
    }
    status_info.finish()?;
    let token_tlv = response.optional(|_| true);
    response.finish()?;
    // ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT ANY }.
    let token_tlv = token_tlv.ok_or(DerError("no token"))?;
    let mut content_info = Seq::new(&token_tlv)?;
    let content_type = oid_value(&content_info.next()?)?;
    let content = content_info.next()?;
    if !content.is_context(0) {
        return Err(DerError("ContentInfo.content"));
    }
    let content = explicit_single(&content)?;
    content_info.finish()?;
    // 1d: granted, and the content is SignedData (otherwise an open type).
    if status != [0x00] {
        return Err(DerError("status not granted"));
    }
    if !is_oid(content_type, ID_SIGNED_DATA) {
        return Err(DerError("not signedData"));
    }
    let mut signed_data = Seq::new(&content)?;
    let version = integer_value(&signed_data.next()?)?;
    let digest_algorithms = signed_data.next()?;
    if !digest_algorithms.is_universal(universal::SET) {
        return Err(DerError("digestAlgorithms"));
    }
    for algorithm in set_of(&digest_algorithms)? {
        algorithm_identifier(&algorithm)?;
    }
    let mut encapsulated = Seq::new(&signed_data.next()?)?;
    let econtent_type = oid_value(&encapsulated.next()?)?;
    let econtent = match encapsulated.optional(|tlv| tlv.is_context(0)) {
        Some(tlv) => Some(octet_string(&explicit_single(&tlv)?)?),
        None => None,
    };
    encapsulated.finish()?;
    // `certificates [0] IMPLICIT CertificateSet`: every component is an open
    // type here (framing only); 1e decodes the signer certificate below.
    let certificates = match signed_data.optional(|tlv| tlv.is_context(0)) {
        Some(tlv) => set_of(&tlv)?,
        None => Vec::new(),
    };
    if let Some(crls) = signed_data.optional(|tlv| tlv.is_context(1)) {
        for choice in set_of(&crls)? {
            if choice.is_universal(universal::SEQUENCE) {
                certificate_list(&choice)?;
            } else if choice.is_context(1) {
                // other [1] IMPLICIT OtherRevocationInfoFormat
                let mut other = Seq::implicit(&choice)?;
                oid_value(&other.next()?)?;
                other.next()?;
                other.finish()?;
            } else {
                return Err(DerError("RevocationInfoChoice"));
            }
        }
    }
    let signer_infos = signed_data.next()?;
    if !signer_infos.is_universal(universal::SET) {
        return Err(DerError("signerInfos"));
    }
    let signer_infos = set_of(&signer_infos)?;
    signed_data.finish()?;
    let mut decoded_signers = Vec::with_capacity(signer_infos.len());
    for signer in &signer_infos {
        decoded_signers.push(signer_info(signer)?);
    }
    // 1d: versions, and exactly one SignerInfo whose version matches its sid
    // (RFC 5652 §5.3).
    if version != [0x03] {
        return Err(DerError("SignedData.version"));
    }
    if decoded_signers.len() != 1 {
        return Err(DerError("not exactly one SignerInfo"));
    }
    let signer = decoded_signers.remove(0);
    let expected_version: &[u8] = match signer.sid {
        SignerId::IssuerSerial { .. } => &[0x01],
        SignerId::KeyIdentifier(_) => &[0x03],
    };
    if signer.version != expected_version {
        return Err(DerError("SignerInfo.version does not match sid"));
    }
    // 1e: the first component the sid names is the signer certificate.
    let signer_certificate = match certificates
        .iter()
        .find(|component| names_signer(component, signer.sid))
    {
        Some(component) => Some(certificate(component)?),
        None => None,
    };
    Ok(Token {
        econtent_type,
        econtent,
        signer,
        signer_certificate,
    })
}

/// The decoded TSTInfo fields used by checks 2–4 and 13.
struct TstInfo<'a> {
    version: &'a [u8],
    imprint_algorithm: &'a [u8],
    hashed_message: &'a [u8],
    gen_time: &'a [u8],
    accuracy: Option<Accuracy<'a>>,
}

/// `Accuracy ::= SEQUENCE { seconds INTEGER OPTIONAL, millis [0] INTEGER
/// OPTIONAL, micros [1] INTEGER OPTIONAL }` (implicit tags).
#[derive(Clone, Copy)]
struct Accuracy<'a> {
    seconds: Option<&'a [u8]>,
    millis: Option<&'a [u8]>,
    micros: Option<&'a [u8]>,
}

/// Check 2: 1a–1c on the encapsulated TSTInfo bytes on their own (W3).
fn decode_tst_info(bytes: &[u8]) -> DerResult<TstInfo<'_>> {
    der::check_universal_rules(bytes)?;
    let root = der::read_single(bytes)?;
    let mut seq = Seq::new(&root)?;
    let version = integer_value(&seq.next()?)?;
    oid_value(&seq.next()?)?;
    let mut imprint = Seq::new(&seq.next()?)?;
    let imprint_algorithm = algorithm_identifier(&imprint.next()?)?.oid;
    let hashed_message = octet_string(&imprint.next()?)?;
    imprint.finish()?;
    integer_value(&seq.next()?)?;
    let gen_time = universal_primitive(&seq.next()?, universal::GENERALIZED_TIME)?;
    let accuracy = match seq.optional(|tlv| tlv.is_universal(universal::SEQUENCE)) {
        Some(tlv) => {
            let mut inner = Seq::new(&tlv)?;
            let seconds = match inner.optional(|tlv| tlv.is_universal(universal::INTEGER)) {
                Some(tlv) => Some(integer_value(&tlv)?),
                None => None,
            };
            let millis = match inner.optional(|tlv| tlv.is_context(0)) {
                Some(tlv) => Some(implicit_primitive(&tlv, universal::INTEGER)?),
                None => None,
            };
            let micros = match inner.optional(|tlv| tlv.is_context(1)) {
                Some(tlv) => Some(implicit_primitive(&tlv, universal::INTEGER)?),
                None => None,
            };
            inner.finish()?;
            Some(Accuracy {
                seconds,
                millis,
                micros,
            })
        }
        None => None,
    };
    if let Some(ordering) = seq.optional(|tlv| tlv.is_universal(universal::BOOLEAN)) {
        if ordering.content == [0x00] {
            return Err(DerError("ordering DEFAULT FALSE encoded"));
        }
    }
    if let Some(nonce) = seq.optional(|tlv| tlv.is_universal(universal::INTEGER)) {
        integer_value(&nonce)?;
    }
    if let Some(tsa) = seq.optional(|tlv| tlv.is_context(0)) {
        general_name(&explicit_single(&tsa)?)?;
    }
    if let Some(extension_tlv) = seq.optional(|tlv| tlv.is_context(1)) {
        if !extension_tlv.tag.constructed {
            return Err(DerError("TSTInfo extensions"));
        }
        extensions_content(extension_tlv.content)?;
    }
    seq.finish()?;
    Ok(TstInfo {
        version,
        imprint_algorithm,
        hashed_message,
        gen_time,
        accuracy,
    })
}

// --------------------------------------------------------------------------
// Checks 6–12
// --------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SignatureScheme {
    RsaPkcs1V15(HashAlgorithm),
    Ecdsa(HashAlgorithm),
}

/// Check 6: RSA PKCS#1 v1.5 with SHA-256/384/512 or ECDSA with SHA-256/384.
/// `rsaEncryption` uses the signer digest, which check 5 pinned to SHA-256.
fn signature_scheme(oid: &[u8]) -> Option<SignatureScheme> {
    if is_oid(oid, RSA_ENCRYPTION) || is_oid(oid, SHA256_WITH_RSA) {
        Some(SignatureScheme::RsaPkcs1V15(HashAlgorithm::Sha256))
    } else if is_oid(oid, SHA384_WITH_RSA) {
        Some(SignatureScheme::RsaPkcs1V15(HashAlgorithm::Sha384))
    } else if is_oid(oid, SHA512_WITH_RSA) {
        Some(SignatureScheme::RsaPkcs1V15(HashAlgorithm::Sha512))
    } else if is_oid(oid, ECDSA_WITH_SHA256) {
        Some(SignatureScheme::Ecdsa(HashAlgorithm::Sha256))
    } else if is_oid(oid, ECDSA_WITH_SHA384) {
        Some(SignatureScheme::Ecdsa(HashAlgorithm::Sha384))
    } else {
        None
    }
}

/// Checks 8 and 9: content-type and `messageDigest` attributes, and an ESS
/// `signingCertificateV2` whose first `ESSCertIDv2` names the signer
/// certificate.
fn check_signed_attributes(
    token: &Token<'_>,
    certificate: &Certificate<'_>,
    econtent: &[u8],
) -> Result<(), Code> {
    let list = &token.signer.signed_attribute_list;
    let single = |dotted: &str| -> Result<Option<Tlv<'_>>, Code> {
        let matching: Vec<&Attribute<'_>> = list
            .iter()
            .filter(|attribute| is_oid(attribute.attribute_type, dotted))
            .collect();
        match matching.as_slice() {
            [] => Ok(None),
            [attribute] if attribute.values.len() == 1 => Ok(Some(attribute.values[0])),
            _ => Err(e::TS_CMS),
        }
    };
    let content_type = single(ID_CONTENT_TYPE)?.ok_or(e::TS_CMS)?;
    let message_digest = single(ID_MESSAGE_DIGEST)?.ok_or(e::TS_CMS)?;
    if !is_oid(content_type.content, ID_CT_TSTINFO) {
        return Err(e::TS_CMS);
    }
    // Check 8: ESS signingCertificateV2 (already decoded by check 1).
    let ess = single(ID_SIGNING_CERTIFICATE_V2)?.ok_or(e::TS_CMS)?;
    let ids = signing_certificate_v2(&ess).map_err(|_| e::TS_SCHEMA)?;
    let first = ids.first().ok_or(e::TS_CMS)?;
    let hash = match first.hash_algorithm {
        None => Sha256::digest(certificate.raw).to_vec(),
        Some(oid) if is_oid(oid, ID_SHA256) => Sha256::digest(certificate.raw).to_vec(),
        Some(oid) if is_oid(oid, ID_SHA384) => Sha384::digest(certificate.raw).to_vec(),
        Some(oid) if is_oid(oid, ID_SHA512) => Sha512::digest(certificate.raw).to_vec(),
        Some(_) => return Err(e::TS_CMS),
    };
    if hash != first.cert_hash {
        return Err(e::TS_CMS);
    }
    if let Some((directory_names, serial)) = &first.issuer_serial {
        if *serial != certificate.serial || !directory_names.contains(&certificate.issuer) {
            return Err(e::TS_CMS);
        }
    }
    // Check 9: messageDigest = SHA-256(eContent).
    if message_digest.content != &Sha256::digest(econtent)[..] {
        return Err(e::TS_CMS);
    }
    Ok(())
}

/// Check 10. A key the algorithm cannot use fails here (W6).
fn verify_signature(
    scheme: SignatureScheme,
    spki: &[u8],
    message: &[u8],
    signature: &[u8],
) -> bool {
    match scheme {
        SignatureScheme::RsaPkcs1V15(hash) => verify_rsa(spki, hash, message, signature),
        SignatureScheme::Ecdsa(hash) => verify_ecdsa(spki, hash, message, signature),
    }
}

fn digest_with(algorithm: HashAlgorithm, data: &[u8]) -> Vec<u8> {
    match algorithm {
        HashAlgorithm::Sha256 => Sha256::digest(data).to_vec(),
        HashAlgorithm::Sha384 => Sha384::digest(data).to_vec(),
        HashAlgorithm::Sha512 => Sha512::digest(data).to_vec(),
    }
}

/// DigestInfo prefixes of RFC 8017 §9.2 (EMSA-PKCS1-v1_5).
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

/// The unsigned big-endian magnitude of a positive DER INTEGER content
/// (leading `0x00` sign octets removed). `None` for an empty, non-minimal,
/// negative or zero INTEGER.
fn positive_integer_magnitude(content: &[u8]) -> Option<&[u8]> {
    der::check_integer(content).ok()?;
    if content[0] & 0x80 != 0 {
        return None;
    }
    let skip = content.iter().take_while(|octet| **octet == 0).count();
    let magnitude = &content[skip..];
    if magnitude.is_empty() {
        None
    } else {
        Some(magnitude)
    }
}

/// Compares two unsigned big-endian magnitudes without leading zero octets.
fn magnitude_cmp(left: &[u8], right: &[u8]) -> std::cmp::Ordering {
    left.len().cmp(&right.len()).then_with(|| left.cmp(right))
}

/// §12.2 check 10 (S2-FIX1/Q4): the RSA key bounds, judged explicitly on the
/// `RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }`
/// (RFC 8017 §A.1.1) carried in the `subjectPublicKey` BIT STRING: a modulus
/// of 2,048 to 8,192 bits and an odd public exponent `e` with
/// 65,537 <= `e` < 2^256. A key decoder's own limits are not the criterion.
fn rsa_key_within_bounds(spki: &[u8]) -> bool {
    let bounds = || -> DerResult<bool> {
        let tlv = der::read_single(spki)?;
        let mut seq = Seq::new(&tlv)?;
        algorithm_identifier(&seq.next()?)?;
        let bits = universal_primitive(&seq.next()?, universal::BIT_STRING)?;
        seq.finish()?;
        let Some((&0, key)) = bits.split_first() else {
            return Ok(false);
        };
        let key = der::read_single(key)?;
        let mut key = Seq::new(&key)?;
        let modulus = integer_value(&key.next()?)?;
        let exponent = integer_value(&key.next()?)?;
        key.finish()?;
        let (Some(modulus), Some(exponent)) = (
            positive_integer_magnitude(modulus),
            positive_integer_magnitude(exponent),
        ) else {
            return Ok(false);
        };
        // Bit length of the modulus: the leading octet is non-zero.
        let modulus_bits = (modulus.len() - 1) * 8 + (8 - modulus[0].leading_zeros() as usize);
        let modulus_ok = (2048..=8192).contains(&modulus_bits);
        // 65,537 <= e < 2^256, e odd.
        let exponent_ok = exponent.len() <= 32
            && magnitude_cmp(exponent, &[0x01, 0x00, 0x01]) != std::cmp::Ordering::Less
            && exponent.last().is_some_and(|octet| octet & 1 == 1);
        Ok(modulus_ok && exponent_ok)
    };
    bounds().unwrap_or(false)
}

/// The order `n` of P-256 (FIPS 186-4 §D.1.2.3, SEC 2 §2.4.2).
const P256_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];

/// The order `n` of P-384 (FIPS 186-4 §D.1.2.4, SEC 2 §2.5.1).
const P384_ORDER: [u8; 48] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc7, 0x63, 0x4d, 0x81, 0xf4, 0x37, 0x2d, 0xdf,
    0x58, 0x1a, 0x0d, 0xb2, 0x48, 0xb0, 0xa7, 0x7a, 0xec, 0xec, 0x19, 0x6a, 0xcc, 0xc5, 0x29, 0x73,
];

/// §12.2 check 10 (S2-FIX1/Q4): the signature value is one DER
/// `Ecdsa-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }` (RFC 5480, RFC 5758)
/// with no octet after it, `r` and `s` positive in their shortest encoding and
/// each in [1, n − 1]. Judged with this crate's X.690 reader, never by the
/// signature type's own decoder.
fn ecdsa_signature_within_bounds(signature: &[u8], order: &[u8]) -> bool {
    let bounds = || -> DerResult<bool> {
        let tlv = der::read_single(signature)?;
        let mut seq = Seq::new(&tlv)?;
        let r = integer_value(&seq.next()?)?;
        let s = integer_value(&seq.next()?)?;
        seq.finish()?;
        Ok([r, s].iter().all(|value| {
            positive_integer_magnitude(value).is_some_and(|magnitude| {
                magnitude_cmp(magnitude, order) == std::cmp::Ordering::Less
            })
        }))
    };
    bounds().unwrap_or(false)
}

fn verify_rsa(spki: &[u8], hash: HashAlgorithm, message: &[u8], signature: &[u8]) -> bool {
    use rsa::pkcs8::DecodePublicKey;
    if !rsa_key_within_bounds(spki) {
        return false;
    }
    let Ok(public_key) = rsa::PublicKey::from_public_key_der(spki) else {
        return false;
    };
    let digest = digest_with(hash, message);
    let (hash_len, prefix): (usize, &[u8]) = match hash {
        HashAlgorithm::Sha256 => (32, &SHA256_DIGEST_INFO_PREFIX),
        HashAlgorithm::Sha384 => (48, &SHA384_DIGEST_INFO_PREFIX),
        HashAlgorithm::Sha512 => (64, &SHA512_DIGEST_INFO_PREFIX),
    };
    let scheme = rsa::Pkcs1v15Sign {
        hash_len: Some(hash_len),
        prefix: prefix.to_vec().into_boxed_slice(),
    };
    public_key.verify(scheme, &digest, signature).is_ok()
}

fn verify_ecdsa(spki: &[u8], hash: HashAlgorithm, message: &[u8], signature: &[u8]) -> bool {
    use signature::hazmat::PrehashVerifier;
    let parsed = (|| -> DerResult<(Vec<u8>, Vec<u8>)> {
        let tlv = der::read_single(spki)?;
        let mut seq = Seq::new(&tlv)?;
        let algorithm = algorithm_identifier(&seq.next()?)?;
        let point = universal_primitive(&seq.next()?, universal::BIT_STRING)?;
        if !is_oid(algorithm.oid, ID_EC_PUBLIC_KEY) {
            return Err(DerError("not an EC key"));
        }
        let curve = algorithm
            .parameters
            .filter(|tlv| tlv.is_universal(universal::OID))
            .ok_or(DerError("curve"))?;
        Ok((
            curve.content.to_vec(),
            point.get(1..).unwrap_or_default().to_vec(),
        ))
    })();
    let Ok((curve, point)) = parsed else {
        return false;
    };
    let digest = digest_with(hash, message);
    if is_oid(&curve, PRIME256V1) {
        if !ecdsa_signature_within_bounds(signature, &P256_ORDER) {
            return false;
        }
        let (Ok(key), Ok(signature)) = (
            p256::ecdsa::VerifyingKey::from_sec1_bytes(&point),
            p256::ecdsa::Signature::from_der(signature),
        ) else {
            return false;
        };
        key.verify_prehash(&digest, &signature).is_ok()
    } else if is_oid(&curve, SECP384R1) {
        if !ecdsa_signature_within_bounds(signature, &P384_ORDER) {
            return false;
        }
        let (Ok(key), Ok(signature)) = (
            p384::ecdsa::VerifyingKey::from_sec1_bytes(&point),
            p384::ecdsa::Signature::from_der(signature),
        ) else {
            return false;
        };
        key.verify_prehash(&digest, &signature).is_ok()
    } else {
        false
    }
}

/// Check 11: `id-kp-timeStamping` EKU required; a present KeyUsage must
/// contain `digitalSignature`.
fn certificate_profile_ok(certificate: &Certificate<'_>) -> bool {
    let find = |dotted: &str| {
        certificate
            .extensions
            .iter()
            .find(|(id, _)| is_oid(id, dotted))
            .map(|(_, value)| *value)
    };
    let Some(eku) = find(ID_CE_EXT_KEY_USAGE) else {
        return false;
    };
    let has_time_stamping = der::read_single(eku)
        .ok()
        .and_then(|tlv| sequence_of(&tlv).ok())
        .is_some_and(|purposes| {
            purposes
                .iter()
                .any(|purpose| oid_value(purpose).is_ok_and(|oid| is_oid(oid, ID_KP_TIME_STAMPING)))
        });
    if !has_time_stamping {
        return false;
    }
    match find(ID_CE_KEY_USAGE) {
        None => true,
        Some(value) => der::read_single(value)
            .ok()
            .filter(|tlv| tlv.is_universal(universal::BIT_STRING))
            .and_then(|tlv| tlv.content.get(1).copied())
            .is_some_and(|first| first & 0x80 != 0),
    }
}

/// Converts a certificate `Time` to Unix milliseconds (RFC 5280 §4.1.2.5:
/// UTCTime years 50–99 are 19YY, 00–49 are 20YY).
fn certificate_time_millis(time: Tlv<'_>) -> Option<i64> {
    let text = std::str::from_utf8(time.content).ok()?;
    let (year, rest) = if time.is_universal(universal::UTC_TIME) {
        let short: u16 = text.get(0..2)?.parse().ok()?;
        let year = if short >= 50 {
            1900 + short
        } else {
            2000 + short
        };
        (year, text.get(2..)?)
    } else {
        (text.get(0..4)?.parse().ok()?, text.get(4..)?)
    };
    let field = |range: std::ops::Range<usize>| -> Option<u8> { rest.get(range)?.parse().ok() };
    let literal = format!(
        "{year:04}-{:02}-{:02}T{:02}:{:02}:{:02}.000Z",
        field(0..2)?,
        field(2..4)?,
        field(4..6)?,
        field(6..8)?,
        field(8..10)?
    );
    Timestamp::parse(&literal).map(Timestamp::to_unix_millis)
}

/// Check 13: a DER GeneralizedTime converted to milliseconds by truncating
/// sub-millisecond digits; `None` when it is not a valid date and time.
fn parse_generalized_time(content: &[u8]) -> Option<Timestamp> {
    if !der::is_generalized_time_form(content) {
        return None;
    }
    let text = std::str::from_utf8(content).ok()?;
    let fraction = text
        .get(14..)
        .and_then(|rest| rest.strip_prefix('.'))
        .and_then(|rest| rest.strip_suffix('Z'))
        .unwrap_or("");
    let mut millis = String::from(fraction);
    millis.truncate(3);
    while millis.len() < 3 {
        millis.push('0');
    }
    let literal = format!(
        "{}-{}-{}T{}:{}:{}.{millis}Z",
        text.get(0..4)?,
        text.get(4..6)?,
        text.get(6..8)?,
        text.get(8..10)?,
        text.get(10..12)?,
        text.get(12..14)?
    );
    Timestamp::parse(&literal)
}

// --------------------------------------------------------------------------
// `--tsa-trust` (§12.3, §14.1)
// --------------------------------------------------------------------------

const PEM_BEGIN: &str = "-----BEGIN CERTIFICATE-----";
const PEM_END: &str = "-----END CERTIFICATE-----";

/// Loads `--tsa-trust` anchors: one or more PEM certificates per file. Returns
/// the SHA-256 digests of the DER encodings (§12.3).
///
/// # Errors
/// A [`UsageError`] when a file contains no certificate, text outside PEM
/// certificate blocks, an unterminated block, or a block that does not decode
/// as an X.509 certificate (W4): it is never treated as an empty anchor set.
pub fn load_trust_anchors(file_contents: &[Vec<u8>]) -> Result<Vec<[u8; 32]>, UsageError> {
    let usage = |reason: &str| UsageError(format!("--tsa-trust: {reason}"));
    let mut anchors = Vec::new();
    for contents in file_contents {
        let text = std::str::from_utf8(contents).map_err(|_| usage("the file is not PEM text"))?;
        let mut rest = text;
        let mut count = 0usize;
        loop {
            let trimmed = rest.trim_start();
            if trimmed.is_empty() {
                break;
            }
            let Some(body) = trimmed.strip_prefix(PEM_BEGIN) else {
                return Err(usage("data outside PEM CERTIFICATE blocks"));
            };
            let Some(end) = body.find(PEM_END) else {
                return Err(usage("unterminated PEM certificate block"));
            };
            let encoded: String = body[..end]
                .chars()
                .filter(|character| !character.is_ascii_whitespace())
                .collect();
            let der_bytes = crate::b64::decode_standard_padded(&encoded)
                .ok_or_else(|| usage("a PEM block is not valid base64"))?;
            // §14.1 (S2/F62/F63): an anchor decodes as an X.509 certificate
            // under exactly the rules of §12.2 1e — the module walk with the
            // 1b/1c rules (typed primitives in their canonical content), the
            // version constraints and the 1a rules for every `extnValue`. The
            // open types (an `AttributeTypeAndValue.value`, for example) are
            // judged by their framing only, so 1a is not applied to the whole
            // certificate here.
            let decodes = der::check_framing(&der_bytes).is_ok()
                && der::read_single(&der_bytes)
                    .ok()
                    .is_some_and(|tlv| certificate(&tlv).is_ok());
            if !decodes {
                return Err(usage("a PEM block does not decode as an X.509 certificate"));
            }
            anchors.push(digest::sha256(&der_bytes));
            count += 1;
            rest = &body[end + PEM_END.len()..];
        }
        if count == 0 {
            return Err(usage("the file contains no certificate"));
        }
    }
    Ok(anchors)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn accuracy(
        seconds: Option<&'static [u8]>,
        millis: Option<&'static [u8]>,
        micros: Option<&'static [u8]>,
    ) -> Option<Accuracy<'static>> {
        Some(Accuracy {
            seconds,
            millis,
            micros,
        })
    }

    #[test]
    fn accuracy_rules() {
        assert_eq!(accuracy_micros(None), Ok(Some(0)));
        assert_eq!(
            accuracy_micros(accuracy(Some(&[1]), Some(&[2]), Some(&[3]))),
            Ok(Some(1_002_003))
        );
        // An explicit zero, a value of 1000 and a negative value are format errors.
        assert_eq!(accuracy_micros(accuracy(None, Some(&[0]), None)), Err(()));
        assert_eq!(
            accuracy_micros(accuracy(None, Some(&[0x03, 0xe8]), None)),
            Err(())
        );
        assert_eq!(
            accuracy_micros(accuracy(Some(&[0xff]), None, None)),
            Err(())
        );
        // Exactly MAX_TS_ACCURACY (86,400 s) is usable; one more microsecond is not.
        assert_eq!(
            accuracy_micros(accuracy(Some(&[0x01, 0x51, 0x80]), None, None)),
            Ok(Some(86_400_000_000))
        );
        assert_eq!(
            accuracy_micros(accuracy(Some(&[0x01, 0x51, 0x80]), None, Some(&[1]))),
            Ok(None)
        );
        // Overflowing values are unusable, never a wrap-around (S11).
        assert_eq!(
            accuracy_micros(accuracy(
                Some(&[0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
                Some(&[0x03, 0xe7]),
                Some(&[0x03, 0xe7])
            )),
            Ok(None)
        );
        assert_eq!(
            accuracy_micros(accuracy(
                Some(&[0x08, 0x63, 0x83, 0x20, 0x6c, 0x16]),
                Some(&[0x03, 0xe7]),
                Some(&[0x03, 0xe7])
            )),
            Ok(None)
        );
    }

    #[test]
    fn rescue_rule_is_strict_and_checked() {
        let receipt = |state, gen_ms: i64, accuracy_us: Option<i64>| ReceiptOutcome {
            state,
            gen_time: Timestamp::from_unix_millis(gen_ms),
            accuracy_us,
            error: None,
        };
        let evidence = |receipts| ChainEvidence {
            receipts,
            chain_error: None,
            anchor_verified: false,
        };
        assert_eq!(ChainEvidence::none().rescue(1_000), Rescue::Fails);
        let verified = evidence(vec![receipt(ReceiptState::Verified, 1_000, Some(0))]);
        assert_eq!(verified.rescue(1_001), Rescue::Rescued);
        assert_eq!(verified.rescue(1_000), Rescue::Fails);
        let untrusted = evidence(vec![receipt(
            ReceiptState::PresentUnverified,
            1_000,
            Some(0),
        )]);
        assert_eq!(untrusted.rescue(5_000), Rescue::Untrusted);
        let unusable = evidence(vec![receipt(ReceiptState::Verified, 1_000, None)]);
        assert_eq!(unusable.rescue(5_000), Rescue::Untrusted);
        let huge = evidence(vec![receipt(ReceiptState::Verified, 1_000, Some(i64::MAX))]);
        assert_eq!(huge.rescue(5_000), Rescue::Fails);
    }

    #[test]
    fn generalized_time_truncates_to_milliseconds() {
        let time = parse_generalized_time(b"20261101120000.1239Z").expect("valid");
        assert_eq!(time.to_ts_string(), "2026-11-01T12:00:00.123Z");
        assert!(parse_generalized_time(b"20261301120000Z").is_none());
        assert!(parse_generalized_time(b"20261101120000.120Z").is_none());
    }

    /// A minimal certificate: optional explicit `version` content, optional
    /// `issuerUniqueID [1]`, optional extensions (basicConstraints).
    fn test_certificate(version: Option<&[u8]>, unique: bool, with_extensions: bool) -> Vec<u8> {
        let algorithm = der::encode(
            0x30,
            &[
                der::encode(0x06, &der::oid(SHA256_WITH_RSA)),
                vec![0x05, 0x00],
            ]
            .concat(),
        );
        let name = der::encode(
            0x30,
            &der::encode(
                0x31,
                &der::encode(
                    0x30,
                    &[
                        der::encode(0x06, &der::oid("2.5.4.3")),
                        der::encode(0x0c, b"a"),
                    ]
                    .concat(),
                ),
            ),
        );
        let validity = der::encode(
            0x30,
            &[
                der::encode(0x17, b"260101000000Z"),
                der::encode(0x17, b"270101000000Z"),
            ]
            .concat(),
        );
        let spki = der::encode(
            0x30,
            &[
                der::encode(
                    0x30,
                    &[
                        der::encode(0x06, &der::oid(RSA_ENCRYPTION)),
                        vec![0x05, 0x00],
                    ]
                    .concat(),
                ),
                der::encode(0x03, &[0x00, 0x01]),
            ]
            .concat(),
        );
        let mut tbs = Vec::new();
        if let Some(version) = version {
            tbs.extend(der::encode(0xa0, &der::encode(0x02, version)));
        }
        tbs.extend(der::encode(0x02, &[0x01]));
        tbs.extend(&algorithm);
        tbs.extend(&name);
        tbs.extend(validity);
        tbs.extend(&name);
        tbs.extend(spki);
        if unique {
            tbs.extend(der::encode(0x81, &[0x00, 0x01]));
        }
        if with_extensions {
            let basic_constraints = [
                der::encode(0x06, &der::oid("2.5.29.19")),
                der::encode(0x01, &[0xff]),
                der::encode(0x04, &der::encode(0x30, &[])),
            ]
            .concat();
            tbs.extend(der::encode(
                0xa3,
                &der::encode(0x30, &der::encode(0x30, &basic_constraints)),
            ));
        }
        der::encode(
            0x30,
            &[
                der::encode(0x30, &tbs),
                algorithm,
                der::encode(0x03, &[0x00, 0x01]),
            ]
            .concat(),
        )
    }

    fn decodes(bytes: &[u8]) -> bool {
        certificate(&der::read_single(bytes).expect("one TLV")).is_ok()
    }

    /// RFC 5280 `Version` (H1-FIX2 Y5): v1 is the absent field, v2 and v3 are
    /// encoded; an explicit v1 is a DEFAULT value encoded (§12.2 1c);
    /// extensions need v3 and unique identifiers need v2 or v3 (module
    /// comments); values outside v1..v3 are rejected.
    #[test]
    fn certificate_versions() {
        // v1 (absent).
        assert!(decodes(&test_certificate(None, false, false)));
        assert!(!decodes(&test_certificate(None, true, false)));
        assert!(!decodes(&test_certificate(None, false, true)));
        // Explicit v1: DEFAULT encoded, with or without other members.
        assert!(!decodes(&test_certificate(Some(&[0x00]), false, false)));
        assert!(!decodes(&test_certificate(Some(&[0x00]), false, true)));
        // v2.
        assert!(decodes(&test_certificate(Some(&[0x01]), false, false)));
        assert!(decodes(&test_certificate(Some(&[0x01]), true, false)));
        assert!(!decodes(&test_certificate(Some(&[0x01]), false, true)));
        // v3.
        assert!(decodes(&test_certificate(Some(&[0x02]), false, false)));
        assert!(decodes(&test_certificate(Some(&[0x02]), true, true)));
        assert!(decodes(&test_certificate(Some(&[0x02]), false, true)));
        // Outside the module's version set, and a non-minimal INTEGER.
        assert!(!decodes(&test_certificate(Some(&[0x03]), false, false)));
        assert!(!decodes(&test_certificate(Some(&[0xff]), false, false)));
        assert!(!decodes(&test_certificate(
            Some(&[0x00, 0x02]),
            false,
            true
        )));
    }

    #[test]
    fn signer_parameter_forms() {
        let null = [0x05u8, 0x00];
        let null_tlv = der::read_single(&null).expect("NULL");
        let sha256 = der::oid(ID_SHA256);
        let rsa = der::oid(RSA_ENCRYPTION);
        let sha256_rsa = der::oid(SHA256_WITH_RSA);
        let ecdsa = der::oid(ECDSA_WITH_SHA256);
        let id = |oid: &[u8], parameters: Option<Tlv<'_>>| -> (Vec<u8>, Option<Vec<u8>>) {
            (oid.to_vec(), parameters.map(|tlv| tlv.raw.to_vec()))
        };
        let check = |digest: (Vec<u8>, Option<Vec<u8>>), signature: (Vec<u8>, Option<Vec<u8>>)| {
            let digest_parameters = digest
                .1
                .as_deref()
                .map(|raw| der::read_single(raw).expect("tlv"));
            let signature_parameters = signature
                .1
                .as_deref()
                .map(|raw| der::read_single(raw).expect("tlv"));
            check_signer_parameters(
                &AlgorithmId {
                    oid: &digest.0,
                    parameters: digest_parameters,
                },
                &AlgorithmId {
                    oid: &signature.0,
                    parameters: signature_parameters,
                },
            )
            .is_ok()
        };
        assert!(check(id(&sha256, None), id(&rsa, Some(null_tlv))));
        assert!(!check(id(&sha256, None), id(&rsa, None)));
        assert!(check(id(&sha256, Some(null_tlv)), id(&sha256_rsa, None)));
        assert!(check(id(&sha256, None), id(&sha256_rsa, Some(null_tlv))));
        assert!(!check(id(&sha256, None), id(&ecdsa, Some(null_tlv))));
        assert!(check(id(&sha256, None), id(&ecdsa, None)));
    }

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&text[index..index + 2], 16).expect("hex"))
            .collect()
    }

    /// Review A L-2: the ECDSA signer path. P-256 is also pinned by the X6
    /// vector `integrity-levels/l2-ts-signer-ecdsa-params-absent`; P-384 has
    /// no committed receipt, so both curves are checked here on fixed
    /// fixtures (key, DER signature over a fixed message), including the
    /// negative cases.
    #[test]
    fn ecdsa_signer_signatures_p256_and_p384() {
        let message = b"H1-FIX1 ECDSA timestamp signer fixture";
        let p384_key = hex("3076301006072a8648ce3d020106052b8104002203620004bf44fda84ac92e7c95742766910c01be6a0438acc929fd596fa44b7b6ff218d8aea9f85d06ef37703e0df594762df1117056bdbf72028d333ed43651a6bed705c972a75ad71362a9b7740e22c82990c50a4042859a2879db71ef97050c3668ad");
        let p384_signature = hex("306402303773aa3a9c4aed216ee725b144e5c081469597100c1e61b8685218aa6c1cf06812ed88a27e4b02e43781f17dadd4c2cb02300d1faf1b1c15bbb02e3206cd0ea24d6c0020928b669dfa8c0e694029d5b8bf83c666cdb215f3b8f51a9feb61cd82a4fa");
        let p256_key = hex("3059301306072a8648ce3d020106082a8648ce3d03010703420004e1b63df2af0d5616fa1079e11e0266d04bb252500d95d709be9f563b6aeaf2437042f5167d26e310b210461cf4c9fa1c210155fe66d0da128173665d37823ad3");
        let p256_signature = hex("304402203876f7fdf26a4ff05a738bcdbb5caaa7932a39423da840541d63a59c87cc598702207f859fc5b0ff3a4446716b49807c03df09766443ab350938b07feaf3037b502a");
        assert!(verify_ecdsa(
            &p384_key,
            HashAlgorithm::Sha384,
            message,
            &p384_signature
        ));
        assert!(verify_ecdsa(
            &p256_key,
            HashAlgorithm::Sha256,
            message,
            &p256_signature
        ));
        // Another message, another digest, the other curve's key.
        assert!(!verify_ecdsa(
            &p384_key,
            HashAlgorithm::Sha384,
            b"other",
            &p384_signature
        ));
        assert!(!verify_ecdsa(
            &p384_key,
            HashAlgorithm::Sha256,
            message,
            &p384_signature
        ));
        assert!(!verify_ecdsa(
            &p256_key,
            HashAlgorithm::Sha384,
            message,
            &p256_signature
        ));
        assert!(!verify_ecdsa(
            &p256_key,
            HashAlgorithm::Sha256,
            message,
            &p384_signature
        ));
        // A flipped signature byte.
        let mut flipped = p384_signature.clone();
        let last = flipped.len() - 1;
        flipped[last] ^= 1;
        assert!(!verify_ecdsa(
            &p384_key,
            HashAlgorithm::Sha384,
            message,
            &flipped
        ));
    }

    /// An RSA `SubjectPublicKeyInfo` with the given modulus and exponent
    /// magnitudes (big-endian, positive).
    fn rsa_spki(modulus: &[u8], exponent: &[u8]) -> Vec<u8> {
        let integer = |magnitude: &[u8]| {
            let mut content = Vec::new();
            if magnitude.first().is_some_and(|octet| octet & 0x80 != 0) {
                content.push(0x00);
            }
            content.extend_from_slice(magnitude);
            der::encode(0x02, &content)
        };
        let mut key = integer(modulus);
        key.extend(integer(exponent));
        let mut bits = vec![0x00];
        bits.extend(der::encode(0x30, &key));
        let mut algorithm = der::encode(0x06, &der::oid(RSA_ENCRYPTION));
        algorithm.extend(der::encode(0x05, &[]));
        let mut spki = der::encode(0x30, &algorithm);
        spki.extend(der::encode(0x03, &bits));
        der::encode(0x30, &spki)
    }

    /// §12.2 check 10 (S2-FIX1/Q4): the RSA key bounds, checked explicitly.
    #[test]
    fn rsa_key_bounds() {
        let modulus = |bits: usize| {
            let mut bytes = vec![0xFFu8; bits.div_ceil(8)];
            let top = bits % 8;
            if top != 0 {
                bytes[0] = (1u8 << top) - 1;
            }
            bytes
        };
        let f4 = [0x01, 0x00, 0x01];
        assert!(rsa_key_within_bounds(&rsa_spki(&modulus(2048), &f4)));
        assert!(rsa_key_within_bounds(&rsa_spki(&modulus(8192), &f4)));
        assert!(rsa_key_within_bounds(&rsa_spki(&modulus(3071), &f4)));
        assert!(!rsa_key_within_bounds(&rsa_spki(&modulus(2047), &f4)));
        assert!(!rsa_key_within_bounds(&rsa_spki(&modulus(1024), &f4)));
        assert!(!rsa_key_within_bounds(&rsa_spki(&modulus(8193), &f4)));
        let n = modulus(2048);
        assert!(!rsa_key_within_bounds(&rsa_spki(&n, &[0x03])));
        assert!(!rsa_key_within_bounds(&rsa_spki(&n, &[0x01, 0x00, 0x00])));
        assert!(!rsa_key_within_bounds(&rsa_spki(&n, &[0x01, 0x00, 0x02])));
        assert!(!rsa_key_within_bounds(&rsa_spki(&n, &[0xFF, 0xFF])));
        assert!(rsa_key_within_bounds(&rsa_spki(&n, &[0x01, 0x00, 0x03])));
        // e < 2^256: 2^256 - 1 is inside, 2^256 + 1 is not.
        assert!(rsa_key_within_bounds(&rsa_spki(&n, &[0xFF; 32])));
        let mut above = vec![0x01];
        above.extend([0x00; 31]);
        above.push(0x01);
        assert!(!rsa_key_within_bounds(&rsa_spki(&n, &above)));
        // A negative exponent or a malformed key is outside the bounds.
        let mut negative = rsa_spki(&n, &f4);
        let at = negative.len() - 4;
        assert_eq!(negative[at..], [0x03, 0x01, 0x00, 0x01]);
        negative[at + 1] = 0x81;
        assert!(!rsa_key_within_bounds(&negative));
        assert!(!rsa_key_within_bounds(&[0x30, 0x00]));
    }

    /// §12.2 check 10 (S2-FIX1/Q4): `Ecdsa-Sig-Value` strict DER with r, s in
    /// [1, n - 1], checked explicitly.
    #[test]
    fn ecdsa_signature_bounds() {
        let signature = |r: &[u8], s: &[u8]| {
            let mut content = der::encode(0x02, r);
            content.extend(der::encode(0x02, s));
            der::encode(0x30, &content)
        };
        let minus_one = |order: &[u8]| {
            let mut value = vec![0x00];
            value.extend_from_slice(order);
            let last = value.len() - 1;
            value[last] -= 1;
            value
        };
        let with_sign = |order: &[u8]| {
            let mut value = vec![0x00];
            value.extend_from_slice(order);
            value
        };
        for order in [&P256_ORDER[..], &P384_ORDER[..]] {
            assert!(ecdsa_signature_within_bounds(
                &signature(&[0x01], &[0x01]),
                order
            ));
            assert!(ecdsa_signature_within_bounds(
                &signature(&minus_one(order), &minus_one(order)),
                order
            ));
            // r or s = 0, = n, negative, non-minimal.
            assert!(!ecdsa_signature_within_bounds(
                &signature(&[0x00], &[0x01]),
                order
            ));
            assert!(!ecdsa_signature_within_bounds(
                &signature(&[0x01], &with_sign(order)),
                order
            ));
            assert!(!ecdsa_signature_within_bounds(
                &signature(&[0x81], &[0x01]),
                order
            ));
            assert!(!ecdsa_signature_within_bounds(
                &signature(&[0x00, 0x01], &[0x01]),
                order
            ));
            // Trailing octets, a third INTEGER, a missing one.
            let mut trailing = signature(&[0x01], &[0x01]);
            trailing.push(0x00);
            assert!(!ecdsa_signature_within_bounds(&trailing, order));
            let mut three = der::encode(0x02, &[0x01]);
            three.extend(der::encode(0x02, &[0x01]));
            three.extend(der::encode(0x02, &[0x01]));
            assert!(!ecdsa_signature_within_bounds(
                &der::encode(0x30, &three),
                order
            ));
            assert!(!ecdsa_signature_within_bounds(
                &der::encode(0x30, &der::encode(0x02, &[0x01])),
                order
            ));
        }
        // P-384's n - 1 is above P-256's n.
        assert!(!ecdsa_signature_within_bounds(
            &signature(&minus_one(&P384_ORDER), &[0x01]),
            &P256_ORDER
        ));
    }
}
