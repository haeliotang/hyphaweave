// SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
// SPDX-License-Identifier: Apache-2.0

//! Registered-kind body schemas and per-kind facts (§7.2, kind pages).
//!
//! This module performs check (6) of §14.5 — the kind body schema — and derives
//! from each body the structured facts that later checks (kind semantics,
//! authorisation, container state) need. It is deliberately *context-free*:
//! facts that require other records (owner trust, grant chains, consent
//! revocation, erasure cross-checks) are evaluated by [`crate::context`].
//!
//! Unknown kinds are opaque (§7.3): the body is never validated and the record
//! must not be rejected for unknown body members. Additional unknown members at
//! the `body` root of a registered kind are permitted (additive evolution,
//! §7.5); unknown members inside closed variant objects are errors.
//!
//! The order inside [`parse_body`] is the §14.5 order: the body *shape* (check
//! (6) of the per-record pipeline) is validated first, then the
//! context-free kind *semantic* rules (part of check (7)), and finally the
//! context-free kind↔envelope constraints of the kind pages. Rules that need
//! other records in the verification context are never evaluated here.

use crate::b64;
use crate::digest;
use crate::envelope::{self, Envelope, RecordFile, RefObject};
use crate::error_codes::{e, Code};
use crate::patterns;
use crate::time::Timestamp;
use crate::value::{Object, Value};

/// `weave.key.revoked.body.reason` closed vocabulary (§9.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RevokeReason {
    /// Retroactive; rescue only via verified pre-compromise timestamp.
    Compromise,
    /// Retired key.
    Retired,
    /// Treated as retired.
    Other,
}

/// `weave.grant.body.action` (§5.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantActionKind {
    /// `action: "grant"`.
    Grant,
    /// `action: "revoke"`.
    Revoke,
}

/// Body of `weave.key.declared` (§9.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyDeclaredBody {
    /// Declared key id.
    pub key: String,
    /// Declared key class.
    pub key_type: String,
    /// 32 raw public-key bytes.
    pub public_key: Vec<u8>,
    /// Owner key id for automated classes.
    pub owner: Option<String>,
    /// Claimed validity window start.
    pub valid_from: Option<Timestamp>,
    /// Claimed validity window end.
    pub valid_until: Option<Timestamp>,
}

/// Body of `weave.key.rotated` (§9.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyRotatedBody {
    /// Predecessor key id.
    pub old_key: String,
    /// Successor key id.
    pub new_key: String,
    /// Predecessor public key, when explicitly supplied.
    pub old_public_key: Option<Vec<u8>>,
    /// Successor public key.
    pub new_public_key: Vec<u8>,
}

/// Body of `weave.key.revoked` (§9.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyRevokedBody {
    /// Revoked key id.
    pub key: String,
    /// Reason (load-bearing).
    pub reason: RevokeReason,
    /// Claimed effective instant.
    pub effective_at: Timestamp,
}

/// The `grant` variant object (§5.5.1), closed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantSpec {
    /// Authorised grantee key id.
    pub grantee_key: String,
    /// Authorised kinds (1–64, unique).
    pub kinds: Vec<String>,
    /// Authorised actions (1–7, unique, closed vocabulary).
    pub actions: Vec<String>,
    /// Audit scope (1–32 strings, unique).
    pub scope: Vec<String>,
    /// Start of validity window.
    pub valid_from: Timestamp,
    /// End of validity window; `None` means unbounded.
    pub valid_until: Option<Timestamp>,
    /// Whether the grantee may delegate further.
    pub transferable: bool,
    /// Explicit revoker list, when present.
    pub revocation: Option<Vec<String>>,
}

/// The `revoke` variant object (§5.5.4), closed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevokeSpec {
    /// Reference to the grant being revoked.
    pub revokes: crate::envelope::RefObject,
    /// Claimed effective instant.
    pub effective_at: Timestamp,
}

/// Body of `weave.grant` (§5.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantBody {
    /// Variant discriminator.
    pub action: GrantActionKind,
    /// Present exactly when `action == "grant"`.
    pub grant: Option<GrantSpec>,
    /// Present exactly when `action == "revoke"`.
    pub revoke: Option<RevokeSpec>,
}

/// Body of `weave.consent.granted`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsentGrantedBody {
    /// Start of the claimed consent window.
    pub valid_from: Timestamp,
    /// End of the window; `None` means no stated end.
    pub valid_until: Option<Timestamp>,
}

/// Body of `weave.consent.revoked`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsentRevokedBody {
    /// Reference to the consent being withdrawn.
    pub revokes: crate::envelope::RefObject,
    /// Claimed effective instant.
    pub effective_at: Timestamp,
}

/// Body of `weave.erasure` (§10.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ErasureBody {
    /// Reference to the erased record.
    pub erased: crate::envelope::RefObject,
    /// Reason vocabulary value.
    pub reason: String,
    /// Authorisation basis, when supplied.
    pub basis: Option<crate::envelope::RefObject>,
    /// Claimed execution instant.
    pub executed_at: Option<Timestamp>,
}

/// Structured kind body; `Opaque` for unknown kinds (§7.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KindBody {
    /// `weave.key.declared` body.
    KeyDeclared(KeyDeclaredBody),
    /// `weave.key.rotated` body.
    KeyRotated(KeyRotatedBody),
    /// `weave.key.revoked` body.
    KeyRevoked(KeyRevokedBody),
    /// `weave.grant` body.
    Grant(GrantBody),
    /// `weave.consent.granted` body.
    ConsentGranted(ConsentGrantedBody),
    /// `weave.consent.revoked` body.
    ConsentRevoked(ConsentRevokedBody),
    /// `weave.erasure` body.
    Erasure(ErasureBody),
    /// Not interpreted: an unknown kind (§7.3), or the special
    /// `weave.erased` placeholder whose shape `envelope` validates (§4.5).
    Opaque,
}

/// The per-record signing obligation of §4.4, used to decide whether a valid
/// required signature exists. Evaluation against the verification context is
/// the record pipeline's job; this type only names the requirement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Obligation {
    /// No per-record signature is required.
    None,
    /// A signature by `actor.key` is required.
    ActorKey,
    /// `weave.key.declared`: self-signature by the declared key; automated
    /// classes additionally need the owner cosignature.
    DeclaredKey {
        /// Declared key id.
        declared_key: String,
        /// Owner key id for automated classes.
        owner_key: Option<String>,
    },
    /// `weave.key.rotated`: signatures by both keys.
    RotationBoth {
        /// Predecessor key id.
        old_key: String,
        /// Successor key id.
        new_key: String,
    },
    /// `weave.key.revoked`: signer rule depends on the reason.
    RevokedKey {
        /// Revoked key id.
        revoked_key: String,
        /// Revocation reason.
        reason: RevokeReason,
    },
    /// `weave.grant`: granter/revoker signature required.
    Grant {
        /// Variant discriminator.
        action: GrantActionKind,
    },
    /// `weave.consent.*`: a declared human/organization key must sign.
    Consent,
    /// `weave.erasure`: actor signature plus signer-table constraints.
    Erasure,
}

impl Obligation {
    /// Dedicated signer code of the seven signer-constrained kinds (§4.4), used
    /// when verifiable signatures exist but the required signer is missing.
    #[must_use]
    pub fn dedicated_code(&self) -> Option<Code> {
        match self {
            Self::None | Self::ActorKey => None,
            Self::DeclaredKey { .. } => Some(crate::error_codes::e::KEY_DECLARED_NOT_SELF_SIGNED),
            Self::RotationBoth { .. } => Some(crate::error_codes::e::KEY_ROTATION_SIGS),
            Self::RevokedKey { .. } => Some(crate::error_codes::e::KEY_REVOKE_SIGNER),
            Self::Grant { action } => Some(match action {
                GrantActionKind::Grant => crate::error_codes::e::GRANT_GRANTER,
                GrantActionKind::Revoke => crate::error_codes::e::GRANT_REVOKE_SIGNER,
            }),
            Self::Consent => Some(crate::error_codes::e::ACTOR_KEY_TYPE_MISMATCH),
            Self::Erasure => Some(crate::error_codes::e::ERASE_ACTOR),
        }
    }
}

/// Check (6) of §14.5: validates the kind body schema and derives facts.
///
/// A `weave.erased` placeholder is a special shape rather than a normal
/// envelope (§4.5); [`crate::envelope::parse_record_file`] validates it and this
/// function returns [`KindBody::Opaque`] for it, because there is no body to
/// interpret. Unknown kinds are opaque as well (§7.3).
///
/// # Errors
/// Returns the kind's schema/semantic error code (`E_KIND_BODY_SCHEMA`,
/// `E_GRANT_SCHEMA`, `E_KEY_VALIDITY`, `E_KEY_ROTATION_KEYS`,
/// `E_KEY_PUBLIC_KEY`, `E_KEY_ID_MISMATCH`, `E_KEY_OWNER_MISSING`,
/// `E_CONSENT_VALIDITY`, ...).
pub fn parse_body(record: &RecordFile) -> Result<KindBody, Code> {
    let Some(envelope) = record.envelope() else {
        // The `weave.erased` placeholder is a special shape, not a normal
        // envelope; `envelope::parse_record_file` already validated every
        // structural rule of §4.5, so there is no further body to interpret.
        return Ok(KindBody::Opaque);
    };
    match envelope.kind.as_str() {
        "weave.key.declared" => parse_key_declared(envelope).map(KindBody::KeyDeclared),
        "weave.key.rotated" => parse_key_rotated(envelope).map(KindBody::KeyRotated),
        "weave.key.revoked" => parse_key_revoked(envelope).map(KindBody::KeyRevoked),
        "weave.grant" => parse_grant(envelope).map(KindBody::Grant),
        "weave.consent.granted" => parse_consent_granted(envelope).map(KindBody::ConsentGranted),
        "weave.consent.revoked" => parse_consent_revoked(envelope).map(KindBody::ConsentRevoked),
        "weave.erasure" => parse_erasure(envelope).map(KindBody::Erasure),
        // §7.3: unknown kinds are opaque; the body is never inspected.
        _ => Ok(KindBody::Opaque),
    }
}

/// Derives the §4.4 signing obligation from the parsed record and body.
#[must_use]
pub fn obligation(record: &RecordFile, body: &KindBody) -> Obligation {
    let Some(envelope) = record.envelope() else {
        // A `weave.erased` placeholder has no `sigs` member at all (§4.5).
        return Obligation::None;
    };
    match body {
        KindBody::KeyDeclared(declared) => Obligation::DeclaredKey {
            declared_key: declared.key.clone(),
            owner_key: if is_automated_class(&declared.key_type) {
                declared.owner.clone()
            } else {
                None
            },
        },
        KindBody::KeyRotated(rotated) => Obligation::RotationBoth {
            old_key: rotated.old_key.clone(),
            new_key: rotated.new_key.clone(),
        },
        KindBody::KeyRevoked(revoked) => Obligation::RevokedKey {
            revoked_key: revoked.key.clone(),
            reason: revoked.reason,
        },
        KindBody::Grant(grant) => Obligation::Grant {
            action: grant.action,
        },
        KindBody::ConsentGranted(_) | KindBody::ConsentRevoked(_) => Obligation::Consent,
        KindBody::Erasure(_) => Obligation::Erasure,
        // Unknown kinds (and the placeholder, handled above) take the ordinary
        // §4.4 rule: every `accepted` record must carry a per-record signature.
        KindBody::Opaque => ordinary_obligation(envelope),
    }
}

/// §4.4 rules 1 and 3 for a normal envelope of a kind with no dedicated signer
/// rule: `stage == "accepted"` requires a signature by `actor.key`.
fn ordinary_obligation(envelope: &Envelope) -> Obligation {
    if envelope.stage == "accepted" {
        Obligation::ActorKey
    } else {
        Obligation::None
    }
}

/// True for the automated key classes that need an owner binding (§9.1).
fn is_automated_class(key_type: &str) -> bool {
    matches!(key_type, "agent" | "program" | "device")
}

// ---------------------------------------------------------------------------
// Body member tables (§9.1–§9.3, §5.5, §8.6, §10.2) and their closed
// vocabularies (Appendix C).
// ---------------------------------------------------------------------------

/// `weave.key.declared.key_type` closed vocabulary (§9.1, Appendix C).
const KEY_TYPES: [&str; 5] = ["human", "agent", "program", "device", "organization"];

/// `weave.grant.actions[]` closed vocabulary (§5.5.1, Appendix C).
const GRANT_ACTIONS: [&str; 7] = [
    "propose",
    "accept",
    "reject",
    "withdraw",
    "supersede",
    "erase",
    "grant",
];

/// `weave.erasure.reason` closed vocabulary (§10.2, Appendix C).
const ERASURE_REASONS: [&str; 6] = [
    "data-subject-request",
    "legal",
    "safety",
    "mistaken-inclusion",
    "retention-expired",
    "other",
];

/// Known members of the closed `grant` variant object (§5.5.1).
const GRANT_MEMBERS: [&str; 10] = [
    "grantee",
    "kinds",
    "actions",
    "scope",
    "valid_from",
    "valid_until",
    "transferable",
    "evidence",
    "remedy",
    "revocation",
];

/// Known members of the closed `grantee` object (§5.5.1).
const GRANTEE_MEMBERS: [&str; 1] = ["key"];

/// Known members of the closed `revoke` variant object (§5.5.4).
const REVOKE_MEMBERS: [&str; 3] = ["revokes", "effective_at", "reason"];

// ---------------------------------------------------------------------------
// Shared member helpers. Each takes the error code of the enclosing body so
// that the schema violations of a kind are reported with its own code
// (`E_KIND_BODY_SCHEMA` or `E_GRANT_SCHEMA`), and reference-object violations
// are mapped from `E_ENV_REFS` onto that body code.
// ---------------------------------------------------------------------------

fn required<'a>(object: &'a Object, name: &str, code: Code) -> Result<&'a Value, Code> {
    object.get(name).ok_or(code)
}

fn string_member<'a>(object: &'a Object, name: &str, code: Code) -> Result<&'a str, Code> {
    required(object, name, code)?.as_str().ok_or(code)
}

fn optional_string<'a>(
    object: &'a Object,
    name: &str,
    code: Code,
) -> Result<Option<&'a str>, Code> {
    match object.get(name) {
        Some(value) => value.as_str().map(Some).ok_or(code),
        None => Ok(None),
    }
}

fn key_id_member<'a>(object: &'a Object, name: &str, code: Code) -> Result<&'a str, Code> {
    let text = string_member(object, name, code)?;
    if digest::is_valid_key_id(text) {
        Ok(text)
    } else {
        Err(code)
    }
}

fn optional_key_id<'a>(
    object: &'a Object,
    name: &str,
    code: Code,
) -> Result<Option<&'a str>, Code> {
    match object.get(name) {
        Some(value) => {
            let text = value.as_str().ok_or(code)?;
            if digest::is_valid_key_id(text) {
                Ok(Some(text))
            } else {
                Err(code)
            }
        }
        None => Ok(None),
    }
}

fn timestamp_member(object: &Object, name: &str, code: Code) -> Result<Timestamp, Code> {
    let text = string_member(object, name, code)?;
    Timestamp::parse(text).ok_or(code)
}

fn optional_timestamp(object: &Object, name: &str, code: Code) -> Result<Option<Timestamp>, Code> {
    match object.get(name) {
        Some(value) => {
            let text = value.as_str().ok_or(code)?;
            Timestamp::parse(text).map(Some).ok_or(code)
        }
        None => Ok(None),
    }
}

/// A required member that is either `null` or a timestamp (§5.5.1, §8.6).
fn nullable_timestamp(object: &Object, name: &str, code: Code) -> Result<Option<Timestamp>, Code> {
    let value = required(object, name, code)?;
    if value.is_null() {
        return Ok(None);
    }
    let text = value.as_str().ok_or(code)?;
    Timestamp::parse(text).map(Some).ok_or(code)
}

fn bool_member(object: &Object, name: &str, code: Code) -> Result<bool, Code> {
    required(object, name, code)?.as_bool().ok_or(code)
}

/// Validates a required member that is either `null` or a string.
fn nullable_string(object: &Object, name: &str, code: Code) -> Result<(), Code> {
    let value = required(object, name, code)?;
    if value.is_null() || value.as_str().is_some() {
        Ok(())
    } else {
        Err(code)
    }
}

/// Decodes a 32-byte public key from strict unpadded base64url (§2.6). The
/// caller decides which code a malformed value gets.
fn decode_public_key(value: &Value) -> Result<Vec<u8>, ()> {
    let text = value.as_str().ok_or(())?;
    b64::decode_exact(text, 32).map_err(|_| ())
}

fn reference_member(object: &Object, name: &str, code: Code) -> Result<RefObject, Code> {
    let value = required(object, name, code)?;
    envelope::parse_ref_object(value).map_err(|_| code)
}

/// Validates a required member that is either `null` or a reference object.
fn validate_nullable_reference(object: &Object, name: &str, code: Code) -> Result<(), Code> {
    let value = required(object, name, code)?;
    if value.is_null() {
        return Ok(());
    }
    envelope::parse_ref_object(value).map_err(|_| code)?;
    Ok(())
}

/// A required member that is either `null` or a reference object; returns the
/// reference when one is present.
fn nullable_reference_object(
    object: &Object,
    name: &str,
    code: Code,
) -> Result<Option<RefObject>, Code> {
    let value = required(object, name, code)?;
    if value.is_null() {
        return Ok(None);
    }
    envelope::parse_ref_object(value)
        .map(Some)
        .map_err(|_| code)
}

/// Rejects every member not in `allowed` (a closed object).
fn reject_unknown_members(object: &Object, allowed: &[&str], code: Code) -> Result<(), Code> {
    for (name, _) in object.iter() {
        if !allowed.contains(&name) {
            return Err(code);
        }
    }
    Ok(())
}

/// A required array of strings with an item-count bound.
fn string_array<'a>(
    object: &'a Object,
    name: &str,
    code: Code,
    min: usize,
    max: usize,
) -> Result<Vec<&'a str>, Code> {
    let value = required(object, name, code)?;
    let array = value.as_array().ok_or(code)?;
    if array.len() < min || array.len() > max {
        return Err(code);
    }
    let mut items = Vec::with_capacity(array.len());
    for item in array {
        items.push(item.as_str().ok_or(code)?);
    }
    Ok(items)
}

/// A string array with an item-count bound, a per-element predicate and unique
/// elements (used for `kinds`/`actions`/`scope`/`revocation`).
fn checked_string_array<F>(
    object: &Object,
    name: &str,
    code: Code,
    min: usize,
    max: usize,
    valid: F,
) -> Result<Vec<String>, Code>
where
    F: Fn(&str) -> bool,
{
    let items = string_array(object, name, code, min, max)?;
    let mut seen: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    for item in &items {
        if !valid(item) || !seen.insert(*item) {
            return Err(code);
        }
    }
    Ok(items.into_iter().map(str::to_owned).collect())
}

/// A string array with an item-count bound and a per-element predicate but no
/// uniqueness rule (used for `weave.consent.granted.scope`).
fn validated_string_array<F>(
    object: &Object,
    name: &str,
    code: Code,
    min: usize,
    max: usize,
    valid: F,
) -> Result<(), Code>
where
    F: Fn(&str) -> bool,
{
    for item in string_array(object, name, code, min, max)? {
        if !valid(item) {
            return Err(code);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// `weave.key.declared` — §9.1, kind page.
// ---------------------------------------------------------------------------

fn parse_key_declared(envelope: &Envelope) -> Result<KeyDeclaredBody, Code> {
    const CODE: Code = e::KIND_BODY_SCHEMA;
    let body = &envelope.body;
    // Body member table (§9.1): known-member grammar is check (6).
    let algorithm = string_member(body, "algorithm", CODE)?;
    if algorithm != "ed25519" {
        return Err(CODE);
    }
    let key = key_id_member(body, "key", CODE)?.to_owned();
    let key_type = string_member(body, "key_type", CODE)?.to_owned();
    if !KEY_TYPES.contains(&key_type.as_str()) {
        return Err(CODE);
    }
    let public_key =
        decode_public_key(required(body, "public_key", CODE)?).map_err(|()| e::KEY_PUBLIC_KEY)?;
    let owner = optional_key_id(body, "owner", CODE)?.map(str::to_owned);
    let valid_from = optional_timestamp(body, "valid_from", CODE)?;
    let valid_until = optional_timestamp(body, "valid_until", CODE)?;
    optional_string(body, "note", CODE)?;
    // §9.1 rule 1: `body.key` must be the §2.5 derivation of `public_key`.
    if digest::derive_key_id(&public_key) != key {
        return Err(e::KEY_ID_MISMATCH);
    }
    // §9.1 rule 3, presence part: automated classes need an owner. Resolving
    // the owner's declaration and its class needs the context (§5.3).
    if is_automated_class(&key_type) && owner.is_none() {
        return Err(e::KEY_OWNER_MISSING);
    }
    // §9.1 rule 5: a claimed window must not be inverted.
    if valid_from
        .zip(valid_until)
        .is_some_and(|(from, until)| from > until)
    {
        return Err(e::KEY_VALIDITY);
    }
    // Kind page envelope requirements: a key self-description must describe
    // its own actor key and class.
    if envelope.actor.key != key {
        return Err(e::ENV_ACTOR);
    }
    if envelope.actor.actor_type != key_type {
        return Err(e::ACTOR_KEY_TYPE_MISMATCH);
    }
    Ok(KeyDeclaredBody {
        key,
        key_type,
        public_key,
        owner,
        valid_from,
        valid_until,
    })
}

// ---------------------------------------------------------------------------
// `weave.key.rotated` — §9.2, kind page.
// ---------------------------------------------------------------------------

fn parse_key_rotated(envelope: &Envelope) -> Result<KeyRotatedBody, Code> {
    const CODE: Code = e::KIND_BODY_SCHEMA;
    let body = &envelope.body;
    // Body member table (§9.2): known-member grammar is check (6).
    let new_key = key_id_member(body, "new_key", CODE)?.to_owned();
    let new_public_key = decode_public_key(required(body, "new_public_key", CODE)?)
        .map_err(|()| e::KEY_ROTATION_KEYS)?;
    let old_key = key_id_member(body, "old_key", CODE)?.to_owned();
    let old_public_key = match body.get("old_public_key") {
        Some(value) => Some(decode_public_key(value).map_err(|()| e::KEY_ROTATION_KEYS)?),
        None => None,
    };
    optional_string(body, "reason", CODE)?;
    // §9.2 rule 1: the rotation must actually change the key.
    if old_key == new_key {
        return Err(e::KEY_ROTATION_KEYS);
    }
    // §9.2 rule 2: a public key, when present, must match its key id.
    if digest::derive_key_id(&new_public_key) != new_key {
        return Err(e::KEY_ROTATION_KEYS);
    }
    if old_public_key
        .as_deref()
        .is_some_and(|bytes| digest::derive_key_id(bytes) != old_key)
    {
        return Err(e::KEY_ROTATION_KEYS);
    }
    // Kind page envelope requirement: `actor.key` is the predecessor key.
    if envelope.actor.key != old_key {
        return Err(e::ENV_ACTOR);
    }
    Ok(KeyRotatedBody {
        old_key,
        new_key,
        old_public_key,
        new_public_key,
    })
}

// ---------------------------------------------------------------------------
// `weave.key.revoked` — §9.3, kind page.
// ---------------------------------------------------------------------------

fn parse_key_revoked(envelope: &Envelope) -> Result<KeyRevokedBody, Code> {
    const CODE: Code = e::KIND_BODY_SCHEMA;
    let body = &envelope.body;
    // Body member table and closed reason vocabulary (§9.3).
    let effective_at = timestamp_member(body, "effective_at", CODE)?;
    let key = key_id_member(body, "key", CODE)?.to_owned();
    let reason = match string_member(body, "reason", CODE)? {
        "key-compromise" => RevokeReason::Compromise,
        "retired" => RevokeReason::Retired,
        "other" => RevokeReason::Other,
        _ => return Err(CODE),
    };
    optional_string(body, "note", CODE)?;
    // §9.3 rule 1: a revocation may not take effect after it was recorded.
    if effective_at > envelope.recorded_at {
        return Err(e::KEY_REVOKE_EFFECTIVE);
    }
    Ok(KeyRevokedBody {
        key,
        reason,
        effective_at,
    })
}

// ---------------------------------------------------------------------------
// `weave.grant` — §5.5, kind page.
// ---------------------------------------------------------------------------

fn parse_grant(envelope: &Envelope) -> Result<GrantBody, Code> {
    const CODE: Code = e::GRANT_SCHEMA;
    let body = &envelope.body;
    // §5.5.1: `action` is required and closed; exactly the matching variant
    // object is present. Unknown members at the `body` root are permitted
    // (§7.5); the `grant`/`revoke` variant objects themselves are closed.
    let action = match string_member(body, "action", CODE)? {
        "grant" => GrantActionKind::Grant,
        "revoke" => GrantActionKind::Revoke,
        _ => return Err(CODE),
    };
    let has_grant = body.contains("grant");
    let has_revoke = body.contains("revoke");
    match action {
        GrantActionKind::Grant => {
            if !has_grant || has_revoke {
                return Err(CODE);
            }
            let spec = parse_grant_spec(required(body, "grant", CODE)?)?;
            Ok(GrantBody {
                action,
                grant: Some(spec),
                revoke: None,
            })
        }
        GrantActionKind::Revoke => {
            if !has_revoke || has_grant {
                return Err(CODE);
            }
            let spec = parse_revoke_spec(required(body, "revoke", CODE)?)?;
            Ok(GrantBody {
                action,
                grant: None,
                revoke: Some(spec),
            })
        }
    }
}

fn parse_grant_spec(value: &Value) -> Result<GrantSpec, Code> {
    const CODE: Code = e::GRANT_SCHEMA;
    let object = value.as_object().ok_or(CODE)?;
    reject_unknown_members(object, &GRANT_MEMBERS, CODE)?;
    // `grantee` is a closed `{"key": <key id>}` object.
    let grantee = object.get_object("grantee").ok_or(CODE)?;
    reject_unknown_members(grantee, &GRANTEE_MEMBERS, CODE)?;
    let grantee_key = key_id_member(grantee, "key", CODE)?.to_owned();
    // 1–64 unique kind names (§7.1).
    let kinds = checked_string_array(object, "kinds", CODE, 1, 64, patterns::is_kind_name)?;
    // 1–7 unique closed-vocabulary actions.
    let actions = checked_string_array(object, "actions", CODE, 1, 7, |action| {
        GRANT_ACTIONS.contains(&action)
    })?;
    // 1–32 unique scope strings, each 1–256 Unicode scalar values.
    let scope = checked_string_array(object, "scope", CODE, 1, 32, |item| {
        patterns::scalars_between(item, 1, 256)
    })?;
    let valid_from = timestamp_member(object, "valid_from", CODE)?;
    let valid_until = nullable_timestamp(object, "valid_until", CODE)?;
    let transferable = bool_member(object, "transferable", CODE)?;
    // `evidence` and `remedy` are required nullable members; the values are
    // audit material and are not interpreted (§5.6).
    validate_nullable_reference(object, "evidence", CODE)?;
    nullable_string(object, "remedy", CODE)?;
    // Optional 1–8 unique revoker keys.
    let revocation = match object.get("revocation") {
        Some(_) => Some(checked_string_array(
            object,
            "revocation",
            CODE,
            1,
            8,
            digest::is_valid_key_id,
        )?),
        None => None,
    };
    // §5.5.1: an inverted window is `E_KEY_VALIDITY`, not `E_GRANT_SCHEMA`.
    if valid_until.is_some_and(|until| valid_from > until) {
        return Err(e::KEY_VALIDITY);
    }
    Ok(GrantSpec {
        grantee_key,
        kinds,
        actions,
        scope,
        valid_from,
        valid_until,
        transferable,
        revocation,
    })
}

fn parse_revoke_spec(value: &Value) -> Result<RevokeSpec, Code> {
    const CODE: Code = e::GRANT_SCHEMA;
    let object = value.as_object().ok_or(CODE)?;
    reject_unknown_members(object, &REVOKE_MEMBERS, CODE)?;
    let revokes = reference_member(object, "revokes", CODE)?;
    let effective_at = timestamp_member(object, "effective_at", CODE)?;
    nullable_string(object, "reason", CODE)?;
    Ok(RevokeSpec {
        revokes,
        effective_at,
    })
}

// ---------------------------------------------------------------------------
// `weave.consent.granted` — §8.6, kind page.
// ---------------------------------------------------------------------------

fn parse_consent_granted(envelope: &Envelope) -> Result<ConsentGrantedBody, Code> {
    const CODE: Code = e::KIND_BODY_SCHEMA;
    let body = &envelope.body;
    // Body member table and string bounds (§8.6 kind page).
    let purpose = string_member(body, "purpose", CODE)?;
    if !patterns::scalars_between(purpose, 1, 1024) {
        return Err(CODE);
    }
    validated_string_array(body, "scope", CODE, 1, 32, |item| {
        patterns::scalars_between(item, 1, 256)
    })?;
    let valid_from = timestamp_member(body, "valid_from", CODE)?;
    let valid_until = nullable_timestamp(body, "valid_until", CODE)?;
    validate_nullable_reference(body, "data_subject", CODE)?;
    nullable_string(body, "terms", CODE)?;
    // §8.6 / kind page rule 1: consent windows use `E_CONSENT_VALIDITY`.
    if valid_until.is_some_and(|until| valid_from > until) {
        return Err(e::CONSENT_VALIDITY);
    }
    Ok(ConsentGrantedBody {
        valid_from,
        valid_until,
    })
}

// ---------------------------------------------------------------------------
// `weave.consent.revoked` — §8.6, kind page.
// ---------------------------------------------------------------------------

fn parse_consent_revoked(envelope: &Envelope) -> Result<ConsentRevokedBody, Code> {
    const CODE: Code = e::KIND_BODY_SCHEMA;
    let body = &envelope.body;
    // Body member table (§8.6 kind page).
    let revokes = reference_member(body, "revokes", CODE)?;
    let effective_at = timestamp_member(body, "effective_at", CODE)?;
    nullable_string(body, "reason", CODE)?;
    Ok(ConsentRevokedBody {
        revokes,
        effective_at,
    })
}

// ---------------------------------------------------------------------------
// `weave.erasure` — §10.2, kind page.
// ---------------------------------------------------------------------------

fn parse_erasure(envelope: &Envelope) -> Result<ErasureBody, Code> {
    const CODE: Code = e::KIND_BODY_SCHEMA;
    let body = &envelope.body;
    // Body member table and closed reason vocabulary (§10.2).
    let erased = reference_member(body, "erased", CODE)?;
    let reason = string_member(body, "reason", CODE)?;
    if !ERASURE_REASONS.contains(&reason) {
        return Err(CODE);
    }
    let reason = reason.to_owned();
    // `reason_note` is a required nullable audit string (not interpreted).
    nullable_string(body, "reason_note", CODE)?;
    let basis = nullable_reference_object(body, "basis", CODE)?;
    let executed_at = optional_timestamp(body, "executed_at", CODE)?;
    Ok(ErasureBody {
        erased,
        reason,
        basis,
        executed_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json;
    use crate::value::Object;

    const HUMAN_1: &str = "ed25519:333f90d1d9dfb653b78df977b9b13ff2";
    const HUMAN_1_PUBLIC_KEY: &str = "QkfCVY3K9G2QZGZ8dIDS67d8VEi8uXpvx6sGEl_wjiw";
    const HUMAN_2: &str = "ed25519:928a1e1dbe45a5d298ce5f6b5ce2eabe";
    const HUMAN_2_PUBLIC_KEY: &str = "YT1Qy4_h1RAkRXOnFdTXbr63odSK4ASJYBA14TVGiLA";
    const AGENT_1: &str = "ed25519:b6190071e4bbc7c82afc702fa9ffa6f5";
    const AGENT_1_PUBLIC_KEY: &str = "YU2BJvrHfOrZQorPEopwttQOPlmXqv9KaU108gO1WZU";
    const KEY_OLD: &str = "ed25519:f6a2edbfb48098da6eb9018c5ee78673";
    const KEY_OLD_PUBLIC_KEY: &str = "gSBP0Jm78fwrwEQDLfar292wPqjUxqq1lAY4oCPfkOY";
    const KEY_NEW: &str = "ed25519:bbecfa632505e9d2df3c49b3e70e613f";
    const KEY_NEW_PUBLIC_KEY: &str = "beDOLrXdg6ohy3CIfhIG_B5LNa_Av2xD3cwQHC6Je7E";
    const RECORDED_AT: &str = "2026-11-01T00:00:00.000Z";
    const LATER: &str = "2027-11-01T00:00:00.000Z";

    fn object(members: Vec<(&str, Value)>) -> Object {
        let mut object = Object::new();
        for (name, value) in members {
            object.insert(name, value);
        }
        object
    }

    fn value_object(members: Vec<(&str, Value)>) -> Value {
        Value::Object(object(members))
    }

    fn strings(items: &[&str]) -> Value {
        Value::Array(items.iter().map(|item| Value::from(*item)).collect())
    }

    fn set(object: Object, name: &str, value: Value) -> Object {
        let mut object = object.without(name);
        object.insert(name, value);
        object
    }

    fn add(object: Object, name: &str, value: Value) -> Object {
        let mut object = object;
        object.insert(name, value);
        object
    }

    fn timestamp(text: &str) -> Timestamp {
        Timestamp::parse(text).expect("test timestamp literal is valid")
    }

    fn reference(kind: &str) -> Value {
        value_object(vec![
            (
                "origin",
                value_object(vec![
                    ("project", "example".into()),
                    ("instance", HUMAN_1.into()),
                ]),
            ),
            ("id", "unit-target".into()),
            ("digest", format!("sha256:{}", "0".repeat(64)).into()),
            ("kind", kind.into()),
        ])
    }

    fn root_object(
        kind: &str,
        stage: &str,
        actor_type: &str,
        actor_key: &str,
        recorded_at: &str,
        body: Object,
    ) -> Object {
        let mut actor = object(vec![("type", actor_type.into()), ("key", actor_key.into())]);
        if actor_type == "agent" {
            actor.insert("model", "example/model@1.0.0");
            actor.insert("on_behalf_of", HUMAN_1);
            actor.insert("grant", reference("weave.grant"));
            actor.insert("idempotency_key", "unit-idempotency-key");
        }
        object(vec![
            ("format", "weave-record/1".into()),
            (
                "origin",
                value_object(vec![
                    ("project", "example".into()),
                    ("instance", HUMAN_1.into()),
                ]),
            ),
            ("id", "unit-test-record".into()),
            ("kind", kind.into()),
            ("stage", stage.into()),
            ("actor", Value::Object(actor)),
            ("recorded_at", recorded_at.into()),
            ("body", Value::Object(body)),
        ])
    }

    fn parse(root: Object) -> Result<RecordFile, Code> {
        let bytes = json::canonical_object_bytes(&root);
        envelope::parse_record_file(&bytes)
    }

    fn record_full(
        kind: &str,
        stage: &str,
        actor_type: &str,
        actor_key: &str,
        recorded_at: &str,
        body: Object,
    ) -> RecordFile {
        parse(root_object(
            kind,
            stage,
            actor_type,
            actor_key,
            recorded_at,
            body,
        ))
        .expect("synthetic record must pass the envelope")
    }

    fn record_with(
        kind: &str,
        actor_type: &str,
        actor_key: &str,
        recorded_at: &str,
        body: Object,
    ) -> RecordFile {
        record_full(kind, "accepted", actor_type, actor_key, recorded_at, body)
    }

    fn record(kind: &str, body: Object) -> RecordFile {
        record_with(kind, "human", HUMAN_1, RECORDED_AT, body)
    }

    fn body_ok(file: &RecordFile) -> KindBody {
        parse_body(file).expect("the kind body must parse")
    }

    fn body_error(file: &RecordFile) -> Code {
        parse_body(file).expect_err("the kind body must be rejected")
    }

    // -- `weave.key.declared` -------------------------------------------------

    fn declared_body(key: &str, public_key: &str, key_type: &str) -> Object {
        object(vec![
            ("algorithm", "ed25519".into()),
            ("key", key.into()),
            ("key_type", key_type.into()),
            ("public_key", public_key.into()),
        ])
    }

    #[test]
    fn key_declared_bodies() {
        // A human declaration with the optional owner, note and window.
        let body = declared_body(HUMAN_1, HUMAN_1_PUBLIC_KEY, "human");
        let body = add(body, "owner", HUMAN_2.into());
        let body = add(body, "valid_from", RECORDED_AT.into());
        let body = add(body, "valid_until", LATER.into());
        let body = add(body, "note", "unit-test note".into());
        let file = record_with("weave.key.declared", "human", HUMAN_1, RECORDED_AT, body);
        let parsed = body_ok(&file);
        let KindBody::KeyDeclared(declared) = &parsed else {
            panic!("expected a KeyDeclared body");
        };
        assert_eq!(declared.key, HUMAN_1);
        assert_eq!(declared.key_type, "human");
        assert_eq!(declared.public_key.len(), 32);
        assert_eq!(declared.owner.as_deref(), Some(HUMAN_2));
        assert_eq!(declared.valid_from, Some(timestamp(RECORDED_AT)));
        assert_eq!(declared.valid_until, Some(timestamp(LATER)));
        assert_eq!(
            obligation(&file, &parsed),
            Obligation::DeclaredKey {
                declared_key: HUMAN_1.to_owned(),
                // A human declaration needs no owner cosignature even when the
                // optional `owner` member is present.
                owner_key: None,
            }
        );
        assert_eq!(
            obligation(&file, &parsed).dedicated_code(),
            Some(e::KEY_DECLARED_NOT_SELF_SIGNED)
        );

        // An automated declaration needs an owner; the obligation names it.
        let body = add(
            declared_body(AGENT_1, AGENT_1_PUBLIC_KEY, "agent"),
            "owner",
            HUMAN_1.into(),
        );
        let file = record_with("weave.key.declared", "agent", AGENT_1, RECORDED_AT, body);
        let parsed = body_ok(&file);
        let KindBody::KeyDeclared(declared) = &parsed else {
            panic!("expected a KeyDeclared body");
        };
        assert_eq!(declared.owner.as_deref(), Some(HUMAN_1));
        assert_eq!(
            obligation(&file, &parsed),
            Obligation::DeclaredKey {
                declared_key: AGENT_1.to_owned(),
                owner_key: Some(HUMAN_1.to_owned()),
            }
        );
    }

    #[test]
    fn key_declared_body_errors() {
        // `algorithm` is a closed vocabulary of one value.
        let file = record(
            "weave.key.declared",
            set(
                declared_body(HUMAN_1, HUMAN_1_PUBLIC_KEY, "human"),
                "algorithm",
                "rsa".into(),
            ),
        );
        assert_eq!(body_error(&file), e::KIND_BODY_SCHEMA);

        // `key_type` is a closed vocabulary (stage/kind-body-schema vector).
        let file = record_with(
            "weave.key.declared",
            "human",
            HUMAN_1,
            RECORDED_AT,
            declared_body(HUMAN_1, HUMAN_1_PUBLIC_KEY, "robot"),
        );
        assert_eq!(body_error(&file), e::KIND_BODY_SCHEMA);

        // A malformed public key, of any JSON type, is `E_KEY_PUBLIC_KEY`.
        for public_key in [
            Value::from("AAAA"),
            Value::from("A".repeat(42)),
            Value::from(1_i64),
        ] {
            let file = record(
                "weave.key.declared",
                set(
                    declared_body(HUMAN_1, HUMAN_1_PUBLIC_KEY, "human"),
                    "public_key",
                    public_key,
                ),
            );
            assert_eq!(body_error(&file), e::KEY_PUBLIC_KEY);
        }

        // The declared key id must be the §2.5 derivation of `public_key`.
        let file = record(
            "weave.key.declared",
            declared_body(HUMAN_1, HUMAN_2_PUBLIC_KEY, "human"),
        );
        assert_eq!(body_error(&file), e::KEY_ID_MISMATCH);

        // A missing required member is a body-shape violation.
        let file = record(
            "weave.key.declared",
            declared_body(HUMAN_1, HUMAN_1_PUBLIC_KEY, "human").without("key"),
        );
        assert_eq!(body_error(&file), e::KIND_BODY_SCHEMA);

        // Automated classes need an owner (presence part).
        let file = record_with(
            "weave.key.declared",
            "agent",
            AGENT_1,
            RECORDED_AT,
            declared_body(AGENT_1, AGENT_1_PUBLIC_KEY, "agent"),
        );
        assert_eq!(body_error(&file), e::KEY_OWNER_MISSING);

        // A malformed optional owner is a known-member grammar violation.
        let file = record(
            "weave.key.declared",
            add(
                declared_body(HUMAN_1, HUMAN_1_PUBLIC_KEY, "human"),
                "owner",
                "not-a-key-id".into(),
            ),
        );
        assert_eq!(body_error(&file), e::KIND_BODY_SCHEMA);

        // An inverted claimed window is `E_KEY_VALIDITY`.
        let body = add(
            declared_body(HUMAN_1, HUMAN_1_PUBLIC_KEY, "human"),
            "valid_from",
            LATER.into(),
        );
        let body = add(body, "valid_until", RECORDED_AT.into());
        let file = record("weave.key.declared", body);
        assert_eq!(body_error(&file), e::KEY_VALIDITY);

        // Wrong member type for a known optional member.
        let file = record(
            "weave.key.declared",
            add(
                declared_body(HUMAN_1, HUMAN_1_PUBLIC_KEY, "human"),
                "note",
                1_i64.into(),
            ),
        );
        assert_eq!(body_error(&file), e::KIND_BODY_SCHEMA);

        // Unknown members at the body root are permitted (§7.5).
        let file = record(
            "weave.key.declared",
            add(
                declared_body(HUMAN_1, HUMAN_1_PUBLIC_KEY, "human"),
                "future_member",
                1_i64.into(),
            ),
        );
        assert!(matches!(body_ok(&file), KindBody::KeyDeclared(_)));

        // Kind page envelope requirement: actor.key is the declared key.
        let file = record_with(
            "weave.key.declared",
            "human",
            HUMAN_2,
            RECORDED_AT,
            declared_body(HUMAN_1, HUMAN_1_PUBLIC_KEY, "human"),
        );
        assert_eq!(body_error(&file), e::ENV_ACTOR);

        // Kind page envelope requirement: actor.type equals body.key_type.
        let file = record_with(
            "weave.key.declared",
            "agent",
            HUMAN_1,
            RECORDED_AT,
            declared_body(HUMAN_1, HUMAN_1_PUBLIC_KEY, "human"),
        );
        assert_eq!(body_error(&file), e::ACTOR_KEY_TYPE_MISMATCH);
    }

    // -- `weave.key.rotated` --------------------------------------------------

    fn rotated_body() -> Object {
        object(vec![
            ("new_key", KEY_NEW.into()),
            ("new_public_key", KEY_NEW_PUBLIC_KEY.into()),
            ("old_key", KEY_OLD.into()),
            ("old_public_key", KEY_OLD_PUBLIC_KEY.into()),
            ("reason", "scheduled rotation".into()),
        ])
    }

    fn rotation_record(body: Object) -> RecordFile {
        record_with("weave.key.rotated", "human", KEY_OLD, RECORDED_AT, body)
    }

    #[test]
    fn key_rotated_bodies() {
        let file = rotation_record(rotated_body());
        let parsed = body_ok(&file);
        let KindBody::KeyRotated(rotated) = &parsed else {
            panic!("expected a KeyRotated body");
        };
        assert_eq!(rotated.old_key, KEY_OLD);
        assert_eq!(rotated.new_key, KEY_NEW);
        assert_eq!(
            digest::derive_key_id(
                rotated
                    .old_public_key
                    .as_deref()
                    .expect("old_public_key is present")
            ),
            KEY_OLD
        );
        assert_eq!(digest::derive_key_id(&rotated.new_public_key), KEY_NEW);
        assert_eq!(
            obligation(&file, &parsed),
            Obligation::RotationBoth {
                old_key: KEY_OLD.to_owned(),
                new_key: KEY_NEW.to_owned(),
            }
        );
        assert_eq!(
            obligation(&file, &parsed).dedicated_code(),
            Some(e::KEY_ROTATION_SIGS)
        );

        // `old_public_key` is optional.
        assert!(matches!(
            body_ok(&rotation_record(rotated_body().without("old_public_key"))),
            KindBody::KeyRotated(_)
        ));
    }

    #[test]
    fn key_rotated_body_errors() {
        // A rotation must change the key (§9.2 rule 1).
        let same = set(rotated_body(), "new_key", KEY_OLD.into());
        let same = set(same, "new_public_key", KEY_OLD_PUBLIC_KEY.into());
        assert_eq!(body_error(&rotation_record(same)), e::KEY_ROTATION_KEYS);

        // The successor public key must match its key id (§9.2 rule 2).
        let contradiction = set(rotated_body(), "new_public_key", KEY_OLD_PUBLIC_KEY.into());
        assert_eq!(
            body_error(&rotation_record(contradiction)),
            e::KEY_ROTATION_KEYS
        );

        // The predecessor public key, when present, must match its key id.
        let contradiction = set(rotated_body(), "old_public_key", KEY_NEW_PUBLIC_KEY.into());
        assert_eq!(
            body_error(&rotation_record(contradiction)),
            e::KEY_ROTATION_KEYS
        );

        // A malformed public key is `E_KEY_ROTATION_KEYS` (not E_KEY_PUBLIC_KEY).
        let malformed = set(rotated_body(), "new_public_key", "AAAA".into());
        assert_eq!(
            body_error(&rotation_record(malformed)),
            e::KEY_ROTATION_KEYS
        );

        // Required member shapes.
        assert_eq!(
            body_error(&rotation_record(rotated_body().without("new_key"))),
            e::KIND_BODY_SCHEMA
        );
        let bad_key = set(rotated_body(), "old_key", "not-a-key-id".into());
        assert_eq!(body_error(&rotation_record(bad_key)), e::KIND_BODY_SCHEMA);

        // Kind page envelope requirement: actor.key is the old key.
        let file = record_with(
            "weave.key.rotated",
            "human",
            HUMAN_1,
            RECORDED_AT,
            rotated_body(),
        );
        assert_eq!(body_error(&file), e::ENV_ACTOR);

        // Unknown members at the body root are permitted (§7.5).
        let file = rotation_record(add(rotated_body(), "future_member", 1_i64.into()));
        assert!(matches!(body_ok(&file), KindBody::KeyRotated(_)));
    }

    // -- `weave.key.revoked` --------------------------------------------------

    fn revoked_body() -> Object {
        object(vec![
            ("effective_at", RECORDED_AT.into()),
            ("key", KEY_OLD.into()),
            ("reason", "retired".into()),
            ("note", "unit-test note".into()),
        ])
    }

    #[test]
    fn key_revoked_bodies() {
        let file = record("weave.key.revoked", revoked_body());
        let parsed = body_ok(&file);
        let KindBody::KeyRevoked(revoked) = &parsed else {
            panic!("expected a KeyRevoked body");
        };
        assert_eq!(revoked.key, KEY_OLD);
        assert_eq!(revoked.reason, RevokeReason::Retired);
        assert_eq!(revoked.effective_at, timestamp(RECORDED_AT));
        assert_eq!(
            obligation(&file, &parsed),
            Obligation::RevokedKey {
                revoked_key: KEY_OLD.to_owned(),
                reason: RevokeReason::Retired,
            }
        );
        assert_eq!(
            obligation(&file, &parsed).dedicated_code(),
            Some(e::KEY_REVOKE_SIGNER)
        );

        for (text, expected) in [
            ("key-compromise", RevokeReason::Compromise),
            ("retired", RevokeReason::Retired),
            ("other", RevokeReason::Other),
        ] {
            let body = set(revoked_body(), "reason", text.into());
            let file = record("weave.key.revoked", body);
            let KindBody::KeyRevoked(revoked) = body_ok(&file) else {
                panic!("expected a KeyRevoked body");
            };
            assert_eq!(revoked.reason, expected);
        }
    }

    #[test]
    fn key_revoked_body_errors() {
        // §9.3 rule 1: `effective_at` may not be later than `recorded_at`.
        let late = set(revoked_body(), "effective_at", LATER.into());
        assert_eq!(
            body_error(&record("weave.key.revoked", late)),
            e::KEY_REVOKE_EFFECTIVE
        );

        // The reason is a closed vocabulary.
        let bad = set(revoked_body(), "reason", "because".into());
        assert_eq!(
            body_error(&record("weave.key.revoked", bad)),
            e::KIND_BODY_SCHEMA
        );

        // Known-member grammar.
        let bad = set(revoked_body(), "key", "not-a-key-id".into());
        assert_eq!(
            body_error(&record("weave.key.revoked", bad)),
            e::KIND_BODY_SCHEMA
        );
        let bad = set(revoked_body(), "effective_at", "not-a-timestamp".into());
        assert_eq!(
            body_error(&record("weave.key.revoked", bad)),
            e::KIND_BODY_SCHEMA
        );
        let bad = set(revoked_body(), "note", 1_i64.into());
        assert_eq!(
            body_error(&record("weave.key.revoked", bad)),
            e::KIND_BODY_SCHEMA
        );

        // Unknown members at the body root are permitted (§7.5).
        let file = record(
            "weave.key.revoked",
            add(revoked_body(), "future_member", 1_i64.into()),
        );
        assert!(matches!(body_ok(&file), KindBody::KeyRevoked(_)));
    }

    // -- `weave.grant` --------------------------------------------------------

    fn grantee() -> Value {
        value_object(vec![("key", HUMAN_1.into())])
    }

    fn grant_spec() -> Object {
        object(vec![
            ("grantee", grantee()),
            ("kinds", strings(&["example.note", "example.receipt"])),
            ("actions", strings(&["propose", "accept"])),
            ("scope", strings(&["site A receipts"])),
            ("valid_from", RECORDED_AT.into()),
            ("valid_until", LATER.into()),
            ("transferable", true.into()),
            ("evidence", Value::Null),
            ("remedy", Value::Null),
        ])
    }

    fn grant_record(spec: Object) -> RecordFile {
        record(
            "weave.grant",
            object(vec![
                ("action", "grant".into()),
                ("grant", Value::Object(spec)),
            ]),
        )
    }

    fn revoke_spec() -> Object {
        object(vec![
            ("revokes", reference("weave.grant")),
            ("effective_at", RECORDED_AT.into()),
            ("reason", Value::Null),
        ])
    }

    fn revoke_record(spec: Object) -> RecordFile {
        record(
            "weave.grant",
            object(vec![
                ("action", "revoke".into()),
                ("revoke", Value::Object(spec)),
            ]),
        )
    }

    #[test]
    fn grant_bodies() {
        let body = set(grant_spec(), "revocation", strings(&[HUMAN_1, HUMAN_2]));
        let file = grant_record(body);
        let parsed = body_ok(&file);
        let KindBody::Grant(grant) = &parsed else {
            panic!("expected a Grant body");
        };
        assert_eq!(grant.action, GrantActionKind::Grant);
        let spec = grant.grant.as_ref().expect("grant variant is present");
        assert!(grant.revoke.is_none());
        assert_eq!(spec.grantee_key, HUMAN_1);
        assert_eq!(spec.kinds, vec!["example.note", "example.receipt"]);
        assert_eq!(spec.actions, vec!["propose", "accept"]);
        assert_eq!(spec.scope, vec!["site A receipts"]);
        assert_eq!(spec.valid_from, timestamp(RECORDED_AT));
        assert_eq!(spec.valid_until, Some(timestamp(LATER)));
        assert!(spec.transferable);
        assert_eq!(
            spec.revocation,
            Some(vec![HUMAN_1.to_owned(), HUMAN_2.to_owned()])
        );
        assert_eq!(
            obligation(&file, &parsed),
            Obligation::Grant {
                action: GrantActionKind::Grant,
            }
        );
        assert_eq!(
            obligation(&file, &parsed).dedicated_code(),
            Some(e::GRANT_GRANTER)
        );

        // `valid_until: null` is unbounded and valid.
        let unbounded = set(grant_spec(), "valid_until", Value::Null);
        assert!(matches!(
            body_ok(&grant_record(unbounded)),
            KindBody::Grant(_)
        ));

        // A reference object in `evidence` is accepted, as is a string remedy.
        let evidence = set(grant_spec(), "evidence", reference("example.note"));
        let evidence = set(evidence, "remedy", "audit remedy".into());
        assert!(matches!(
            body_ok(&grant_record(evidence)),
            KindBody::Grant(_)
        ));

        // Unknown members at the `body` root are permitted (§7.5).
        let file = record(
            "weave.grant",
            add(
                object(vec![
                    ("action", "grant".into()),
                    ("grant", Value::Object(grant_spec())),
                ]),
                "future_member",
                1_i64.into(),
            ),
        );
        assert!(matches!(body_ok(&file), KindBody::Grant(_)));

        // The `revoke` variant.
        let file = revoke_record(revoke_spec());
        let parsed = body_ok(&file);
        let KindBody::Grant(grant) = &parsed else {
            panic!("expected a Grant body");
        };
        assert_eq!(grant.action, GrantActionKind::Revoke);
        assert!(grant.grant.is_none());
        let spec = grant.revoke.as_ref().expect("revoke variant is present");
        assert_eq!(spec.revokes.kind.as_deref(), Some("weave.grant"));
        assert_eq!(spec.effective_at, timestamp(RECORDED_AT));
        assert_eq!(
            obligation(&file, &parsed),
            Obligation::Grant {
                action: GrantActionKind::Revoke,
            }
        );
        assert_eq!(
            obligation(&file, &parsed).dedicated_code(),
            Some(e::GRANT_REVOKE_SIGNER)
        );

        // `reason` is required but nullable.
        let string_reason = set(revoke_spec(), "reason", "engagement ended".into());
        assert!(matches!(
            body_ok(&revoke_record(string_reason)),
            KindBody::Grant(_)
        ));
    }

    #[test]
    fn grant_schema_errors() {
        let schema = e::GRANT_SCHEMA;

        // `action` handling and variant pairing.
        let file = record(
            "weave.grant",
            object(vec![("grant", Value::Object(grant_spec()))]),
        );
        assert_eq!(body_error(&file), schema);
        let file = record("weave.grant", object(vec![("action", "delegate".into())]));
        assert_eq!(body_error(&file), schema);
        let file = record("weave.grant", object(vec![("action", "grant".into())]));
        assert_eq!(body_error(&file), schema);
        let file = record(
            "weave.grant",
            object(vec![
                ("action", "grant".into()),
                ("grant", Value::Object(grant_spec())),
                ("revoke", Value::Object(revoke_spec())),
            ]),
        );
        assert_eq!(body_error(&file), schema);
        let file = record(
            "weave.grant",
            object(vec![
                ("action", "revoke".into()),
                ("grant", Value::Object(grant_spec())),
            ]),
        );
        assert_eq!(body_error(&file), schema);

        // The `grant` variant object is closed.
        let file = grant_record(add(grant_spec(), "future_member", 1_i64.into()));
        assert_eq!(body_error(&file), schema);
        let file = grant_record(set(
            grant_spec(),
            "grantee",
            value_object(vec![
                ("key", HUMAN_1.into()),
                ("future_member", 1_i64.into()),
            ]),
        ));
        assert_eq!(body_error(&file), schema);
        let file = grant_record(set(grant_spec(), "grantee", object(vec![]).into()));
        assert_eq!(body_error(&file), schema);
        let file = grant_record(set(
            grant_spec(),
            "grantee",
            value_object(vec![("key", "not-a-key-id".into())]),
        ));
        assert_eq!(body_error(&file), schema);

        // List bounds, vocabularies and uniqueness.
        let file = grant_record(set(grant_spec(), "kinds", strings(&[])));
        assert_eq!(body_error(&file), schema);
        let file = grant_record(set(
            grant_spec(),
            "kinds",
            strings(&["example.note", "example.note"]),
        ));
        assert_eq!(body_error(&file), schema);
        let file = grant_record(set(grant_spec(), "kinds", strings(&["Bare-name"])));
        assert_eq!(body_error(&file), schema);
        let file = grant_record(set(grant_spec(), "actions", strings(&["approve"])));
        assert_eq!(body_error(&file), schema);
        let file = grant_record(set(grant_spec(), "actions", strings(&["accept", "accept"])));
        assert_eq!(body_error(&file), schema);
        let file = grant_record(set(grant_spec(), "scope", strings(&[])));
        assert_eq!(body_error(&file), schema);
        let file = grant_record(set(grant_spec(), "scope", strings(&[""])));
        assert_eq!(body_error(&file), schema);
        let file = grant_record(set(grant_spec(), "scope", strings(&["a", "a"])));
        assert_eq!(body_error(&file), schema);
        let long_scope = Value::from("a".repeat(257));
        let file = grant_record(set(grant_spec(), "scope", Value::Array(vec![long_scope])));
        assert_eq!(body_error(&file), schema);
        let too_many_scope = Value::Array(
            (0..33)
                .map(|index| Value::from(format!("scope-{index}")))
                .collect(),
        );
        let file = grant_record(set(grant_spec(), "scope", too_many_scope));
        assert_eq!(body_error(&file), schema);

        // Known-member types.
        let file = grant_record(set(grant_spec(), "transferable", 1_i64.into()));
        assert_eq!(body_error(&file), schema);
        let file = grant_record(set(grant_spec(), "valid_from", "not-a-timestamp".into()));
        assert_eq!(body_error(&file), schema);
        let file = grant_record(set(grant_spec(), "valid_until", 1_i64.into()));
        assert_eq!(body_error(&file), schema);
        let file = grant_record(set(grant_spec(), "remedy", 1_i64.into()));
        assert_eq!(body_error(&file), schema);
        let file = grant_record(set(
            grant_spec(),
            "evidence",
            value_object(vec![("id", "no-origin-or-digest".into())]),
        ));
        assert_eq!(body_error(&file), schema);
        let missing_required = grant_spec().without("valid_from");
        assert_eq!(body_error(&grant_record(missing_required)), schema);

        // Optional `revocation` list bounds and grammar.
        let file = grant_record(set(grant_spec(), "revocation", strings(&[])));
        assert_eq!(body_error(&file), schema);
        let file = grant_record(set(
            grant_spec(),
            "revocation",
            strings(&[HUMAN_1, HUMAN_1]),
        ));
        assert_eq!(body_error(&file), schema);
        let file = grant_record(set(grant_spec(), "revocation", strings(&["nope"])));
        assert_eq!(body_error(&file), schema);
        let too_many_revokers = Value::Array(
            (0..9)
                .map(|index| Value::from(format!("ed25519:{index:032x}")))
                .collect(),
        );
        let file = grant_record(set(grant_spec(), "revocation", too_many_revokers));
        assert_eq!(body_error(&file), schema);

        // An inverted window uses `E_KEY_VALIDITY`, not `E_GRANT_SCHEMA`.
        let inverted = set(grant_spec(), "valid_from", LATER.into());
        let inverted = set(inverted, "valid_until", RECORDED_AT.into());
        assert_eq!(body_error(&grant_record(inverted)), e::KEY_VALIDITY);

        // The `revoke` variant object is closed and has its own grammar.
        let file = revoke_record(add(revoke_spec(), "future_member", 1_i64.into()));
        assert_eq!(body_error(&file), schema);
        let file = revoke_record(revoke_spec().without("revokes"));
        assert_eq!(body_error(&file), schema);
        let file = revoke_record(set(
            revoke_spec(),
            "revokes",
            value_object(vec![("id", "no-origin-or-digest".into())]),
        ));
        assert_eq!(body_error(&file), schema);
        let file = revoke_record(set(revoke_spec(), "effective_at", 1_i64.into()));
        assert_eq!(body_error(&file), schema);
        let file = revoke_record(set(revoke_spec(), "reason", 1_i64.into()));
        assert_eq!(body_error(&file), schema);
    }

    // -- `weave.consent.*` ----------------------------------------------------

    fn consent_granted_body() -> Object {
        object(vec![
            ("purpose", "operational energy reporting".into()),
            ("scope", strings(&["electricity meter readings at site A"])),
            ("valid_from", RECORDED_AT.into()),
            ("valid_until", LATER.into()),
            ("data_subject", Value::Null),
            ("terms", Value::Null),
        ])
    }

    #[test]
    fn consent_granted_bodies() {
        let file = record("weave.consent.granted", consent_granted_body());
        let parsed = body_ok(&file);
        let KindBody::ConsentGranted(consent) = &parsed else {
            panic!("expected a ConsentGranted body");
        };
        assert_eq!(consent.valid_from, timestamp(RECORDED_AT));
        assert_eq!(consent.valid_until, Some(timestamp(LATER)));
        assert_eq!(obligation(&file, &parsed), Obligation::Consent);
        assert_eq!(
            obligation(&file, &parsed).dedicated_code(),
            Some(e::ACTOR_KEY_TYPE_MISMATCH)
        );

        // `null` means no stated end; a reference subject is accepted.
        let unbounded = set(consent_granted_body(), "valid_until", Value::Null);
        let with_subject = set(
            unbounded,
            "data_subject",
            reference("weave.consent.granted"),
        );
        let with_terms = set(with_subject, "terms", "stated terms".into());
        assert!(matches!(
            body_ok(&record("weave.consent.granted", with_terms)),
            KindBody::ConsentGranted(_)
        ));

        // `scope` has no uniqueness rule for consent (unlike grant scope).
        let duplicated = set(
            consent_granted_body(),
            "scope",
            strings(&["scope-a", "scope-a"]),
        );
        assert!(matches!(
            body_ok(&record("weave.consent.granted", duplicated)),
            KindBody::ConsentGranted(_)
        ));

        // Unknown members at the body root are permitted (§7.5).
        let file = record(
            "weave.consent.granted",
            add(consent_granted_body(), "future_member", 1_i64.into()),
        );
        assert!(matches!(body_ok(&file), KindBody::ConsentGranted(_)));
    }

    #[test]
    fn consent_granted_body_errors() {
        let schema = e::KIND_BODY_SCHEMA;
        let file = record(
            "weave.consent.granted",
            set(consent_granted_body(), "purpose", "".into()),
        );
        assert_eq!(body_error(&file), schema);
        let file = record(
            "weave.consent.granted",
            set(
                consent_granted_body(),
                "purpose",
                Value::from("a".repeat(1025)),
            ),
        );
        assert_eq!(body_error(&file), schema);
        let file = record(
            "weave.consent.granted",
            set(consent_granted_body(), "scope", strings(&[])),
        );
        assert_eq!(body_error(&file), schema);
        let too_many_scope = Value::Array(
            (0..33)
                .map(|index| Value::from(format!("scope-{index}")))
                .collect(),
        );
        let file = record(
            "weave.consent.granted",
            set(consent_granted_body(), "scope", too_many_scope),
        );
        assert_eq!(body_error(&file), schema);
        let long_scope = Value::from("a".repeat(257));
        let file = record(
            "weave.consent.granted",
            set(
                consent_granted_body(),
                "scope",
                Value::Array(vec![long_scope]),
            ),
        );
        assert_eq!(body_error(&file), schema);
        let file = record(
            "weave.consent.granted",
            set(
                consent_granted_body(),
                "data_subject",
                value_object(vec![("id", "no-origin-or-digest".into())]),
            ),
        );
        assert_eq!(body_error(&file), schema);
        let file = record(
            "weave.consent.granted",
            set(consent_granted_body(), "terms", 1_i64.into()),
        );
        assert_eq!(body_error(&file), schema);
        let file = record(
            "weave.consent.granted",
            consent_granted_body().without("terms"),
        );
        assert_eq!(body_error(&file), schema);
        // §8.6: consent windows use `E_CONSENT_VALIDITY`.
        let inverted = set(consent_granted_body(), "valid_from", LATER.into());
        let inverted = set(inverted, "valid_until", RECORDED_AT.into());
        assert_eq!(
            body_error(&record("weave.consent.granted", inverted)),
            e::CONSENT_VALIDITY
        );
    }

    fn consent_revoked_body() -> Object {
        object(vec![
            ("revokes", reference("weave.consent.granted")),
            ("effective_at", RECORDED_AT.into()),
            ("reason", Value::Null),
        ])
    }

    #[test]
    fn consent_revoked_bodies() {
        let file = record("weave.consent.revoked", consent_revoked_body());
        let parsed = body_ok(&file);
        let KindBody::ConsentRevoked(consent) = &parsed else {
            panic!("expected a ConsentRevoked body");
        };
        assert_eq!(
            consent.revokes.kind.as_deref(),
            Some("weave.consent.granted")
        );
        assert_eq!(consent.effective_at, timestamp(RECORDED_AT));
        assert_eq!(obligation(&file, &parsed), Obligation::Consent);

        // `reason` is required but nullable; a future `effective_at` is allowed.
        let scheduled = set(consent_revoked_body(), "effective_at", LATER.into());
        let scheduled = set(scheduled, "reason", "project ended".into());
        assert!(matches!(
            body_ok(&record("weave.consent.revoked", scheduled)),
            KindBody::ConsentRevoked(_)
        ));

        // Unknown members at the body root are permitted (§7.5).
        let file = record(
            "weave.consent.revoked",
            add(consent_revoked_body(), "future_member", 1_i64.into()),
        );
        assert!(matches!(body_ok(&file), KindBody::ConsentRevoked(_)));
    }

    #[test]
    fn consent_revoked_body_errors() {
        let schema = e::KIND_BODY_SCHEMA;
        let file = record(
            "weave.consent.revoked",
            set(
                consent_revoked_body(),
                "revokes",
                value_object(vec![("id", "no-origin-or-digest".into())]),
            ),
        );
        assert_eq!(body_error(&file), schema);
        let file = record(
            "weave.consent.revoked",
            set(
                consent_revoked_body(),
                "effective_at",
                "not-a-timestamp".into(),
            ),
        );
        assert_eq!(body_error(&file), schema);
        let file = record(
            "weave.consent.revoked",
            set(consent_revoked_body(), "reason", 1_i64.into()),
        );
        assert_eq!(body_error(&file), schema);
        let file = record(
            "weave.consent.revoked",
            consent_revoked_body().without("revokes"),
        );
        assert_eq!(body_error(&file), schema);
    }

    // -- `weave.erasure` ------------------------------------------------------

    fn erasure_body() -> Object {
        object(vec![
            ("erased", reference("example.note")),
            ("reason", "data-subject-request".into()),
            ("reason_note", Value::Null),
            ("basis", Value::Null),
        ])
    }

    #[test]
    fn erasure_bodies() {
        let file = record("weave.erasure", erasure_body());
        let parsed = body_ok(&file);
        let KindBody::Erasure(erasure) = &parsed else {
            panic!("expected an Erasure body");
        };
        assert_eq!(erasure.reason, "data-subject-request");
        assert_eq!(erasure.erased.kind.as_deref(), Some("example.note"));
        assert!(erasure.basis.is_none());
        assert!(erasure.executed_at.is_none());
        assert_eq!(obligation(&file, &parsed), Obligation::Erasure);
        assert_eq!(
            obligation(&file, &parsed).dedicated_code(),
            Some(e::ERASE_ACTOR)
        );

        // Optional nullable members and `executed_at`.
        let body = set(erasure_body(), "reason_note", "DS-2026-0042".into());
        let body = set(body, "basis", reference("weave.grant"));
        let body = add(body, "executed_at", RECORDED_AT.into());
        let parsed = body_ok(&record("weave.erasure", body));
        let KindBody::Erasure(erasure) = &parsed else {
            panic!("expected an Erasure body");
        };
        assert_eq!(
            erasure.basis.as_ref().expect("basis").kind.as_deref(),
            Some("weave.grant")
        );
        assert_eq!(erasure.executed_at, Some(timestamp(RECORDED_AT)));

        // Unknown members at the body root are permitted (§7.5).
        let file = record(
            "weave.erasure",
            add(erasure_body(), "future_member", 1_i64.into()),
        );
        assert!(matches!(body_ok(&file), KindBody::Erasure(_)));
    }

    #[test]
    fn erasure_body_errors() {
        let schema = e::KIND_BODY_SCHEMA;
        // Closed reason vocabulary (§10.2, erasure/reason-invalid vector).
        let file = record(
            "weave.erasure",
            set(erasure_body(), "reason", "because-i-said-so".into()),
        );
        assert_eq!(body_error(&file), schema);
        let file = record(
            "weave.erasure",
            set(
                erasure_body(),
                "erased",
                value_object(vec![("id", "no-origin-or-digest".into())]),
            ),
        );
        assert_eq!(body_error(&file), schema);
        let file = record(
            "weave.erasure",
            set(
                erasure_body(),
                "basis",
                value_object(vec![("id", "no-origin-or-digest".into())]),
            ),
        );
        assert_eq!(body_error(&file), schema);
        let file = record(
            "weave.erasure",
            set(erasure_body(), "reason_note", 1_i64.into()),
        );
        assert_eq!(body_error(&file), schema);
        let file = record(
            "weave.erasure",
            add(erasure_body(), "executed_at", "not-a-timestamp".into()),
        );
        assert_eq!(body_error(&file), schema);
        let file = record("weave.erasure", erasure_body().without("erased"));
        assert_eq!(body_error(&file), schema);
        let file = record("weave.erasure", erasure_body().without("reason_note"));
        assert_eq!(body_error(&file), schema);
        let file = record("weave.erasure", erasure_body().without("basis"));
        assert_eq!(body_error(&file), schema);
    }

    // -- unknown kinds and §4.4 obligations -----------------------------------

    #[test]
    fn unknown_kinds_are_opaque() {
        let file = record_full(
            "koinoweave.receipt",
            "accepted",
            "human",
            HUMAN_1,
            RECORDED_AT,
            object(vec![("payload", 1_i64.into())]),
        );
        let parsed = body_ok(&file);
        assert_eq!(parsed, KindBody::Opaque);
        // §4.4 rule 1: `accepted` ordinary records require a signature by the
        // actor key, even when the kind is not understood.
        assert_eq!(obligation(&file, &parsed), Obligation::ActorKey);
        assert_eq!(obligation(&file, &parsed).dedicated_code(), None);

        let file = record_full(
            "koinoweave.receipt",
            "proposed",
            "human",
            HUMAN_1,
            RECORDED_AT,
            object(vec![]),
        );
        let parsed = body_ok(&file);
        assert_eq!(parsed, KindBody::Opaque);
        // §4.4: a non-accepted ordinary record may rely on the container
        // signature only.
        assert_eq!(obligation(&file, &parsed), Obligation::None);
    }

    #[test]
    fn ordinary_obligation_splits_on_stage() {
        let accepted = record_full(
            "example.note",
            "accepted",
            "human",
            HUMAN_1,
            RECORDED_AT,
            object(vec![("text", "unit test".into())]),
        );
        assert_eq!(
            obligation(&accepted, &body_ok(&accepted)),
            Obligation::ActorKey
        );
        for stage in ["proposed", "rejected", "withdrawn", "superseded"] {
            let file = record_full(
                "example.note",
                stage,
                "human",
                HUMAN_1,
                RECORDED_AT,
                object(vec![("text", "unit test".into())]),
            );
            assert_eq!(obligation(&file, &body_ok(&file)), Obligation::None);
        }
    }

    #[test]
    fn placeholder_is_opaque_and_needs_no_signature() {
        let root = object(vec![
            ("format", "weave-record/1".into()),
            ("kind", "weave.erased".into()),
            (
                "origin",
                value_object(vec![
                    ("project", "example".into()),
                    ("instance", HUMAN_1.into()),
                ]),
            ),
            ("id", "unit-erased-record".into()),
            ("digest", format!("sha256:{}", "1".repeat(64)).into()),
            ("attestation", reference("weave.erasure")),
        ]);
        let file = parse(root).expect("the placeholder must parse as a special shape");
        let parsed = body_ok(&file);
        assert_eq!(parsed, KindBody::Opaque);
        assert_eq!(obligation(&file, &parsed), Obligation::None);
    }

    #[test]
    fn dedicated_signer_codes_cover_the_seven_kinds() {
        assert_eq!(Obligation::None.dedicated_code(), None);
        assert_eq!(Obligation::ActorKey.dedicated_code(), None);
        assert_eq!(
            Obligation::DeclaredKey {
                declared_key: HUMAN_1.to_owned(),
                owner_key: None,
            }
            .dedicated_code(),
            Some(e::KEY_DECLARED_NOT_SELF_SIGNED)
        );
        assert_eq!(
            Obligation::RotationBoth {
                old_key: KEY_OLD.to_owned(),
                new_key: KEY_NEW.to_owned(),
            }
            .dedicated_code(),
            Some(e::KEY_ROTATION_SIGS)
        );
        assert_eq!(
            Obligation::RevokedKey {
                revoked_key: KEY_OLD.to_owned(),
                reason: RevokeReason::Compromise,
            }
            .dedicated_code(),
            Some(e::KEY_REVOKE_SIGNER)
        );
        assert_eq!(
            Obligation::Grant {
                action: GrantActionKind::Grant,
            }
            .dedicated_code(),
            Some(e::GRANT_GRANTER)
        );
        assert_eq!(
            Obligation::Grant {
                action: GrantActionKind::Revoke,
            }
            .dedicated_code(),
            Some(e::GRANT_REVOKE_SIGNER)
        );
        assert_eq!(
            Obligation::Consent.dedicated_code(),
            Some(e::ACTOR_KEY_TYPE_MISMATCH)
        );
        assert_eq!(Obligation::Erasure.dedicated_code(), Some(e::ERASE_ACTOR));
    }
}
