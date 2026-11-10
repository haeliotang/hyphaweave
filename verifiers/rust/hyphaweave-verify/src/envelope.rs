// SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
// SPDX-License-Identifier: Apache-2.0

//! Record envelope parsing and structural validation (§4, §6.1, §8.1).
//!
//! [`parse_record_file`] performs the first two record checks of §14.5 — canonical
//! bytes and envelope structure — and returns a structured record whose `sigs`
//! array has *not* yet been interpreted: signature presence/format is the third
//! check and is performed by [`parse_sigs`].
//!
//! A `weave.erased` placeholder is a special shape rather than a normal
//! envelope (§4.5, kind page): every structural violation of the placeholder is
//! `E_KIND_BODY_SCHEMA`, except that a wrong `format` keeps `E_ENV_FORMAT` and
//! the shared `origin`/`id` members keep their envelope codes.

use crate::b64;
use crate::digest;
use crate::error_codes::{e, Code};
use crate::json;
use crate::limits;
use crate::patterns;
use crate::time::Timestamp;
use crate::value::{Object, Value};

/// Maximum number of scalar values in an `id`; kept next to the parser for
/// readability (the specification states it inline).
const ID_SCALAR_LIMIT: usize = 256;

/// Or an origin object (§4.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Origin {
    /// Project slug.
    pub project: String,
    /// Key id of the instance that created the record.
    pub instance: String,
}

/// A reference object (§6.1). Unknown members are rejected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefObject {
    /// Referenced record origin.
    pub origin: Origin,
    /// Referenced record id.
    pub id: String,
    /// Digest string of the referenced record.
    pub digest: String,
    /// Optional kind claim about the referenced record.
    pub kind: Option<String>,
    /// Optional location hints; never fetched.
    pub hints: Vec<String>,
}

/// A `refs[]` entry: exactly `{"rel":<rel>,"ref":<reference object>}`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefEntry {
    /// One of the ten closed relation words.
    pub rel: String,
    /// The reference object.
    pub reference: RefObject,
}

/// Actor object (§4.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Actor {
    /// `human`, `agent`, `program`, `device` or `organization`.
    pub actor_type: String,
    /// Actor key id.
    pub key: String,
    /// `provider/model@version`, required for `agent`.
    pub model: Option<String>,
    /// Principal the agent acts for, required for `agent`.
    pub on_behalf_of: Option<String>,
    /// Delegated authorisation reference, required for `agent`.
    pub grant: Option<RefObject>,
    /// Idempotency key, required for `agent`.
    pub idempotency_key: Option<String>,
}

/// Labels object (§8.1).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Labels {
    /// `public`, `internal`, `personal` or `local-only`.
    pub sensitivity: Option<String>,
    /// SPDX licence expression (syntax checked).
    pub licence: Option<String>,
    /// Consent reference.
    pub consent: Option<RefObject>,
}

impl Labels {
    /// Sensitivity rank (§8.2); `public` ranks 0.
    #[must_use]
    pub fn sensitivity_rank(&self) -> Option<u8> {
        match self.sensitivity.as_deref() {
            Some("public") => Some(0),
            Some("internal") => Some(1),
            Some("personal") => Some(2),
            Some("local-only") => Some(3),
            _ => None,
        }
    }
}

/// A parsed and structurally validated normal record envelope. The `sigs`
/// member is deliberately absent; see [`parse_sigs`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    /// `format` member (`weave-record/1`).
    pub format: String,
    /// Kind name.
    pub kind: String,
    /// Origin object.
    pub origin: Origin,
    /// Record id.
    pub id: String,
    /// Stage value.
    pub stage: String,
    /// Actor object.
    pub actor: Actor,
    /// Claimed recording time.
    pub recorded_at: Timestamp,
    /// Optional claimed occurrence time.
    pub occurred_at: Option<Timestamp>,
    /// Reference entries in input order.
    pub refs: Vec<RefEntry>,
    /// Labels, when present.
    pub labels: Option<Labels>,
    /// Salt, when present (16 bytes in unpadded base64url).
    pub salt: Option<String>,
    /// Record body; semantics are the kind's.
    pub body: Object,
}

/// A `weave.erased` placeholder (§4.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ErasedPlaceholder {
    /// Shared origin member.
    pub origin: Origin,
    /// Shared id member.
    pub id: String,
    /// Original record digest of the erased record.
    pub digest: String,
    /// Reference to the attesting `weave.erasure` record.
    pub attestation: RefObject,
}

/// A record file: the parsed JSON object plus its structured interpretation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParsedRecord {
    /// A normal envelope.
    Normal(Box<Envelope>),
    /// A `weave.erased` placeholder.
    Erased(ErasedPlaceholder),
}

/// A parsed record file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordFile {
    /// The canonical-JSON object exactly as received (used for the record
    /// digest; a signature must never be verified over re-serialised bytes that
    /// differ from the bytes received).
    pub object: Object,
    /// Structured record.
    pub parsed: ParsedRecord,
}

impl RecordFile {
    /// Kind name.
    #[must_use]
    pub fn kind(&self) -> &str {
        match &self.parsed {
            ParsedRecord::Normal(envelope) => &envelope.kind,
            ParsedRecord::Erased(_) => "weave.erased",
        }
    }

    /// Envelope id.
    #[must_use]
    pub fn id(&self) -> &str {
        match &self.parsed {
            ParsedRecord::Normal(envelope) => &envelope.id,
            ParsedRecord::Erased(placeholder) => &placeholder.id,
        }
    }

    /// Origin.
    #[must_use]
    pub fn origin(&self) -> &Origin {
        match &self.parsed {
            ParsedRecord::Normal(envelope) => &envelope.origin,
            ParsedRecord::Erased(placeholder) => &placeholder.origin,
        }
    }

    /// Normal envelope, if this is not a placeholder.
    #[must_use]
    pub fn envelope(&self) -> Option<&Envelope> {
        match &self.parsed {
            ParsedRecord::Normal(envelope) => Some(envelope),
            ParsedRecord::Erased(_) => None,
        }
    }

    /// Placeholder, if this is one.
    #[must_use]
    pub fn erased(&self) -> Option<&ErasedPlaceholder> {
        match &self.parsed {
            ParsedRecord::Normal(_) => None,
            ParsedRecord::Erased(placeholder) => Some(placeholder),
        }
    }

    /// Computes the own record digest (§2.2) from the received object.
    #[must_use]
    pub fn digest(&self) -> String {
        digest::record_digest(&self.object)
    }
}

/// Parses one record file: canonical file form (§1.8), size limit (§13), then
/// envelope structure (§4).
///
/// This function does not look at `sigs` at all: signature presence and format
/// are the separate third check ([`parse_sigs`]).
pub fn parse_record_file(bytes: &[u8]) -> Result<RecordFile, Code> {
    let object = json::parse_canonical_object(bytes, limits::MAX_RECORD_BYTES)?;
    let parsed = if object.get_str("kind") == Some("weave.erased") {
        ParsedRecord::Erased(parse_placeholder(&object)?)
    } else {
        ParsedRecord::Normal(Box::new(parse_envelope(&object)?))
    };
    Ok(RecordFile { object, parsed })
}

/// The seven registered normal kinds whose stage **MUST** be `accepted` (§4.4).
pub const SIGNER_CONSTRAINED_KINDS: [&str; 7] = [
    "weave.key.declared",
    "weave.key.rotated",
    "weave.key.revoked",
    "weave.grant",
    "weave.consent.granted",
    "weave.consent.revoked",
    "weave.erasure",
];

/// True when the kind is registered by version 0.1 of the format (§7.2).
#[must_use]
pub fn is_registered_kind(kind: &str) -> bool {
    match kind {
        "weave.consent.granted"
        | "weave.consent.revoked"
        | "weave.erased"
        | "weave.erasure"
        | "weave.grant"
        | "weave.key.declared"
        | "weave.key.revoked"
        | "weave.key.rotated" => true,
        _ => false,
    }
}

const TOP_LEVEL_MEMBERS: [&str; 13] = [
    "format",
    "kind",
    "origin",
    "id",
    "stage",
    "actor",
    "recorded_at",
    "occurred_at",
    "refs",
    "labels",
    "salt",
    "body",
    "sigs",
];

const REQUIRED_TOP_LEVEL: [&str; 8] = [
    "format",
    "kind",
    "origin",
    "id",
    "stage",
    "actor",
    "recorded_at",
    "body",
];

fn parse_envelope(object: &Object) -> Result<Envelope, Code> {
    // Required members first, then closedness (§4 table). Both are envelope
    // structure checks; a record carrying both defects is not defined by the
    // vectors and is recorded in docs/h1-findings.md.
    for required in REQUIRED_TOP_LEVEL {
        if !object.contains(required) {
            return Err(e::ENV_MISSING_FIELD);
        }
    }
    if object.first_unknown(TOP_LEVEL_MEMBERS).is_some() {
        return Err(e::ENV_UNKNOWN_FIELD);
    }

    let format = object.get_str("format").ok_or(e::ENV_FORMAT)?;
    if format != "weave-record/1" {
        return Err(e::ENV_FORMAT);
    }

    let kind = object.get_str("kind").ok_or(e::ENV_KIND_SYNTAX)?;
    if !patterns::is_kind_name(kind) {
        return Err(e::ENV_KIND_SYNTAX);
    }

    let origin = parse_origin(object.get("origin").ok_or(e::ENV_ORIGIN)?)?;
    let id = object.get("id").ok_or(e::ENV_ID)?;
    let id_text = id.as_str().ok_or(e::ENV_ID)?;
    if !patterns::is_envelope_id(id_text) {
        return Err(e::ENV_ID);
    }

    let stage = object.get_str("stage").ok_or(e::ENV_STAGE)?;
    if !matches!(
        stage,
        "proposed" | "accepted" | "rejected" | "withdrawn" | "superseded"
    ) {
        return Err(e::ENV_STAGE);
    }
    // §4.4/§7.2: the seven registered signer-constrained kinds are `accepted`
    // only; a different stage is an envelope error for those kinds.
    if stage != "accepted" && SIGNER_CONSTRAINED_KINDS.contains(&kind) {
        return Err(e::ENV_STAGE);
    }

    let actor = parse_actor(object.get("actor").ok_or(e::ENV_ACTOR)?)?;

    let recorded_at = parse_timestamp(object.get("recorded_at").ok_or(e::ENV_TIME)?)?;
    let occurred_at = match object.get("occurred_at") {
        Some(value) => Some(parse_timestamp(value)?),
        None => None,
    };

    let refs = match object.get("refs") {
        Some(value) => parse_refs(value)?,
        None => Vec::new(),
    };

    let labels = match object.get("labels") {
        Some(value) => Some(parse_labels(value)?),
        None => None,
    };

    let salt = match object.get("salt") {
        Some(value) => {
            let text = value.as_str().ok_or(e::ENV_SALT)?;
            b64::decode_exact(text, 16).map_err(|_| e::ENV_SALT)?;
            Some(text.to_owned())
        }
        None => None,
    };
    // §8.3: personal and local-only records must carry a salt.
    if salt.is_none() {
        if let Some(labels) = &labels {
            if matches!(labels.sensitivity.as_deref(), Some("personal" | "local-only")) {
                return Err(e::ENV_SALT_MISSING);
            }
        }
    }

    let body = object.get_object("body").ok_or(e::ENV_BODY)?.clone();

    Ok(Envelope {
        format: format.to_owned(),
        kind: kind.to_owned(),
        origin,
        id: id_text.to_owned(),
        stage: stage.to_owned(),
        actor,
        recorded_at,
        occurred_at,
        refs,
        labels,
        salt,
        body,
    })
}

fn parse_placeholder(object: &Object) -> Result<ErasedPlaceholder, Code> {
    // `format` keeps its envelope code; the rest of the shape is
    // `E_KIND_BODY_SCHEMA` (§4.5, kind page).
    if let Some(value) = object.get("format") {
        match value.as_str() {
            Some("weave-record/1") => {}
            _ => return Err(e::ENV_FORMAT),
        }
    }
    const PLACEHOLDER_MEMBERS: [&str; 6] = [
        "format",
        "kind",
        "origin",
        "id",
        "digest",
        "attestation",
    ];
    for required in PLACEHOLDER_MEMBERS {
        if !object.contains(required) {
            return Err(e::KIND_BODY_SCHEMA);
        }
    }
    if object.first_unknown(PLACEHOLDER_MEMBERS).is_some() {
        return Err(e::KIND_BODY_SCHEMA);
    }
    let origin = parse_origin(object.get("origin").ok_or(e::ENV_ORIGIN)?)?;
    let id_value = object.get("id").ok_or(e::ENV_ID)?;
    let id_text = id_value.as_str().ok_or(e::ENV_ID)?;
    if !patterns::is_envelope_id(id_text) {
        return Err(e::ENV_ID);
    }
    if object.get_str("kind") != Some("weave.erased") {
        return Err(e::KIND_BODY_SCHEMA);
    }
    let digest_text = object
        .get_str("digest")
        .ok_or(e::KIND_BODY_SCHEMA)?;
    if digest::parse_digest_string(digest_text).is_none() {
        return Err(e::KIND_BODY_SCHEMA);
    }
    let attestation = parse_ref_object(
        object.get("attestation").ok_or(e::KIND_BODY_SCHEMA)?,
    )
    .map_err(|_| e::KIND_BODY_SCHEMA)?;
    Ok(ErasedPlaceholder {
        origin,
        id: id_text.to_owned(),
        digest: digest_text.to_owned(),
        attestation,
    })
}

fn parse_origin(value: &Value) -> Result<Origin, Code> {
    let object = value.as_object().ok_or(e::ENV_ORIGIN)?;
    const MEMBERS: [&str; 2] = ["project", "instance"];
    for required in MEMBERS {
        if !object.contains(required) {
            return Err(e::ENV_ORIGIN);
        }
    }
    if object.first_unknown(MEMBERS).is_some() {
        return Err(e::ENV_ORIGIN);
    }
    let project = object.get_str("project").ok_or(e::ENV_ORIGIN)?;
    if !patterns::is_project_slug(project) {
        return Err(e::ENV_ORIGIN);
    }
    let instance = object.get_str("instance").ok_or(e::ENV_ORIGIN)?;
    if !digest::is_valid_key_id(instance) {
        return Err(e::ENV_ORIGIN);
    }
    Ok(Origin {
        project: project.to_owned(),
        instance: instance.to_owned(),
    })
}

fn parse_actor(value: &Value) -> Result<Actor, Code> {
    let object = value.as_object().ok_or(e::ENV_ACTOR)?;
    // The actor object is closed. An undefined member is E_ENV_ACTOR (the
    // actor-specific "structurally invalid" code), while a defined member that
    // is forbidden for this actor type is also E_ENV_ACTOR (§4.2).
    const MEMBERS: [&str; 6] = [
        "type",
        "key",
        "model",
        "on_behalf_of",
        "grant",
        "idempotency_key",
    ];
    if object.first_unknown(MEMBERS).is_some() {
        return Err(e::ENV_ACTOR);
    }
    let actor_type = object.get_str("type").ok_or(e::ENV_ACTOR_TYPE)?;
    if !matches!(
        actor_type,
        "human" | "agent" | "program" | "device" | "organization"
    ) {
        return Err(e::ENV_ACTOR_TYPE);
    }
    let key = object.get_str("key").ok_or(e::ENV_ACTOR_KEY)?;
    if !digest::is_valid_key_id(key) {
        return Err(e::ENV_ACTOR_KEY);
    }
    let is_agent = actor_type == "agent";
    if !is_agent {
        // §4.2: the four agent-only members MUST be absent for non-agent actors.
        for forbidden in ["model", "on_behalf_of", "grant", "idempotency_key"] {
            if object.contains(forbidden) {
                return Err(e::ENV_ACTOR);
            }
        }
    }
    let model = match object.get("model") {
        Some(value) => {
            if !is_agent {
                return Err(e::ENV_ACTOR);
            }
            let text = value.as_str().ok_or(e::ENV_ACTOR_MODEL)?;
            if !patterns::is_model_string(text) {
                return Err(e::ENV_ACTOR_MODEL);
            }
            Some(text.to_owned())
        }
        None => None,
    };
    let on_behalf_of = match object.get("on_behalf_of") {
        Some(value) => {
            if !is_agent {
                return Err(e::ENV_ACTOR);
            }
            let text = value.as_str().ok_or(e::ENV_ACTOR_ON_BEHALF)?;
            if !digest::is_valid_key_id(text) {
                return Err(e::ENV_ACTOR_ON_BEHALF);
            }
            Some(text.to_owned())
        }
        None => None,
    };
    let grant = match object.get("grant") {
        Some(value) => {
            if !is_agent {
                return Err(e::ENV_ACTOR);
            }
            Some(parse_ref_object(value).map_err(|_| e::ENV_REFS)?)
        }
        None => None,
    };
    let idempotency_key = match object.get("idempotency_key") {
        Some(value) => {
            if !is_agent {
                return Err(e::ENV_ACTOR);
            }
            let text = value.as_str().ok_or(e::ENV_ACTOR_IDEMPOTENCY)?;
            if !patterns::is_idempotency_key(text) {
                return Err(e::ENV_ACTOR_IDEMPOTENCY);
            }
            Some(text.to_owned())
        }
        None => None,
    };
    if is_agent {
        if model.is_none() {
            return Err(e::ENV_ACTOR_MODEL_MISSING);
        }
        if on_behalf_of.is_none() {
            return Err(e::ENV_ACTOR_ON_BEHALF_MISSING);
        }
        if grant.is_none() {
            return Err(e::ENV_ACTOR_GRANT_MISSING);
        }
        if idempotency_key.is_none() {
            return Err(e::ENV_ACTOR_IDEMPOTENCY_MISSING);
        }
    }
    Ok(Actor {
        actor_type: actor_type.to_owned(),
        key: key.to_owned(),
        model,
        on_behalf_of,
        grant,
        idempotency_key,
    })
}

fn parse_timestamp(value: &Value) -> Result<Timestamp, Code> {
    let text = value.as_str().ok_or(e::ENV_TIME)?;
    Timestamp::parse(text).ok_or(e::ENV_TIME)
}

/// The ten relation words of §6.2.
pub const REL_WORDS: [&str; 10] = [
    "derived_from",
    "handed_off_to",
    "receipt_of",
    "executed_as",
    "assessed_by",
    "compensated_by",
    "migrated_from",
    "reshaped_from",
    "supersedes",
    "correction_of",
];

fn parse_refs(value: &Value) -> Result<Vec<RefEntry>, Code> {
    let array = value.as_array().ok_or(e::ENV_REFS)?;
    if array.len() > limits::MAX_REFS {
        return Err(e::ENV_REFS);
    }
    let mut entries: Vec<RefEntry> = Vec::with_capacity(array.len());
    for item in array {
        let object = item.as_object().ok_or(e::ENV_REFS)?;
        const MEMBERS: [&str; 2] = ["rel", "ref"];
        for required in MEMBERS {
            if !object.contains(required) {
                return Err(e::ENV_REFS);
            }
        }
        if object.first_unknown(MEMBERS).is_some() {
            return Err(e::ENV_REFS);
        }
        let rel = object.get_str("rel").ok_or(e::ENV_REFS)?;
        if !REL_WORDS.contains(&rel) {
            return Err(e::ENV_REFS);
        }
        let reference = parse_ref_object(object.get("ref").ok_or(e::ENV_REFS)?)?;
        let entry = RefEntry {
            rel: rel.to_owned(),
            reference,
        };
        if entries.contains(&entry) {
            return Err(e::ENV_REFS);
        }
        entries.push(entry);
    }
    Ok(entries)
}

/// Parses a closed reference object (§6.1). A malformed reference object is the
/// caller's responsibility to map onto its context code: `E_ENV_REFS` in the
/// envelope, `E_KIND_BODY_SCHEMA`/`E_GRANT_SCHEMA` in kind bodies.
pub fn parse_ref_object(value: &Value) -> Result<RefObject, Code> {
    let object = value.as_object().ok_or(e::ENV_REFS)?;
    const MEMBERS: [&str; 5] = ["origin", "id", "digest", "kind", "hints"];
    for required in ["origin", "id", "digest"] {
        if !object.contains(required) {
            return Err(e::ENV_REFS);
        }
    }
    if object.first_unknown(MEMBERS).is_some() {
        return Err(e::ENV_REFS);
    }
    let origin = parse_origin(object.get("origin").ok_or(e::ENV_REFS)?)?;
    let id = object.get_str("id").ok_or(e::ENV_REFS)?;
    if id.chars().count() > ID_SCALAR_LIMIT || !patterns::is_envelope_id(id) {
        return Err(e::ENV_REFS);
    }
    let digest_text = object.get_str("digest").ok_or(e::ENV_REFS)?;
    if digest::parse_digest_string(digest_text).is_none() {
        return Err(e::ENV_REFS);
    }
    let kind = match object.get("kind") {
        Some(value) => {
            let text = value.as_str().ok_or(e::ENV_REFS)?;
            if !patterns::is_kind_name(text) {
                return Err(e::ENV_REFS);
            }
            Some(text.to_owned())
        }
        None => None,
    };
    let hints = match object.get("hints") {
        Some(value) => {
            let array = value.as_array().ok_or(e::ENV_REFS)?;
            if array.len() > limits::MAX_HINTS {
                return Err(e::ENV_REFS);
            }
            let mut hints = Vec::with_capacity(array.len());
            for hint in array {
                let text = hint.as_str().ok_or(e::ENV_REFS)?;
                if !patterns::is_uri_hint(text) {
                    return Err(e::ENV_REFS);
                }
                hints.push(text.to_owned());
            }
            hints
        }
        None => Vec::new(),
    };
    Ok(RefObject {
        origin,
        id: id.to_owned(),
        digest: digest_text.to_owned(),
        kind,
        hints,
    })
}

fn parse_labels(value: &Value) -> Result<Labels, Code> {
    let object = value.as_object().ok_or(e::ENV_LABELS)?;
    const MEMBERS: [&str; 3] = ["sensitivity", "licence", "consent"];
    if object.first_unknown(MEMBERS).is_some() {
        return Err(e::ENV_LABELS);
    }
    let sensitivity = match object.get("sensitivity") {
        Some(value) => {
            let text = value.as_str().ok_or(e::ENV_LABELS)?;
            if !matches!(text, "public" | "internal" | "personal" | "local-only") {
                return Err(e::ENV_SENSITIVITY);
            }
            Some(text.to_owned())
        }
        None => None,
    };
    let licence = match object.get("licence") {
        Some(value) => {
            let text = value.as_str().ok_or(e::ENV_LICENCE)?;
            if !crate::labels::is_valid_licence_expression(text) {
                return Err(e::ENV_LICENCE);
            }
            Some(text.to_owned())
        }
        None => None,
    };
    let consent = match object.get("consent") {
        Some(value) => Some(parse_ref_object(value).map_err(|_| e::ENV_LABELS)?),
        None => None,
    };
    Ok(Labels {
        sensitivity,
        licence,
        consent,
    })
}

/// One `sigs[]` entry (§4.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigEntry {
    /// Algorithm name token.
    pub alg: String,
    /// Key id (algorithm-specific grammar).
    pub key: String,
    /// Raw base64url text as received.
    pub value: String,
    /// Decoded value bytes (always present for a structurally valid entry).
    pub decoded_value: Vec<u8>,
    /// True for `alg == "ed25519"`; entries with unknown algorithms are
    /// structurally validated and then ignored (§3.6).
    pub known_algorithm: bool,
}

/// The third record check of §14.5: `sigs` presence and format (§4.3).
///
/// Returns the parsed entries, or `Ok(None)` when the member is absent. The
/// per-record signing obligation itself is a later check (§4.4) and is
/// evaluated by the record pipeline. The array, when present, must contain 1–16
/// entries sorted strictly ascending by key.
pub fn parse_sigs(object: &Object) -> Result<Option<Vec<SigEntry>>, Code> {
    let Some(value) = object.get("sigs") else {
        return Ok(None);
    };
    let array = value.as_array().ok_or(e::ENV_SIGS)?;
    if array.is_empty() || array.len() > limits::MAX_SIGS {
        return Err(e::ENV_SIGS);
    }
    let mut entries: Vec<SigEntry> = Vec::with_capacity(array.len());
    let mut previous_key: Option<String> = None;
    for item in array {
        let object = item.as_object().ok_or(e::ENV_SIGS)?;
        const MEMBERS: [&str; 3] = ["alg", "key", "value"];
        for required in MEMBERS {
            if !object.contains(required) {
                return Err(e::ENV_SIGS);
            }
        }
        if object.first_unknown(MEMBERS).is_some() {
            return Err(e::ENV_SIGS);
        }
        let alg = object.get_str("alg").ok_or(e::ENV_SIGS)?;
        if !digest::is_algorithm_name(alg) {
            return Err(e::ENV_SIGS);
        }
        let key = object.get_str("key").ok_or(e::ENV_SIGS)?;
        let value = object.get_str("value").ok_or(e::ENV_SIGS)?;
        let known_algorithm = alg == "ed25519";
        let decoded_value = if known_algorithm {
            if !digest::is_valid_key_id(key) {
                return Err(e::ENV_SIG_KEY);
            }
            b64::decode_exact(value, 64).map_err(|_| e::ENV_SIG_VALUE)?
        } else {
            // Unknown algorithms: key and value are checked structurally only.
            let valid_key = match key.split_once(':') {
                Some((algorithm, hex)) => {
                    digest::is_algorithm_name(algorithm)
                        && !hex.is_empty()
                        && hex.len() <= 128
                        && hex.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                }
                None => false,
            };
            if !valid_key {
                return Err(e::ENV_SIGS);
            }
            b64::decode_range(value, 1, limits::MAX_SIG_VALUE_BYTES)
                .map_err(|_| e::ENV_SIGS)?
        };
        if let Some(previous) = &previous_key {
            // Ascending by key, unique keys.
            if json::utf16_cmp(previous, key) != std::cmp::Ordering::Less {
                return Err(e::ENV_SIGS);
            }
        }
        previous_key = Some(key.to_owned());
        entries.push(SigEntry {
            alg: alg.to_owned(),
            key: key.to_owned(),
            value: value.to_owned(),
            decoded_value,
            known_algorithm,
        });
    }
    Ok(Some(entries))
}

/// Parses a signature array from the manifest attestation file (§11.3).
///
/// The attestation file's `signatures` member uses the `sigs` entry grammar of
/// §4.3, but its structural violations are `E_MANIFEST_SCHEMA` (the attestation
/// file is a closed object; known-algorithm cryptographic failure is
/// `E_MANIFEST_SIG_INVALID` and belongs to the caller). The array must contain
/// 1–16 entries sorted strictly ascending by key; an empty array is
/// `E_MANIFEST_UNSIGNED`.
pub fn parse_signature_array(value: &Value) -> Result<Vec<SigEntry>, Code> {
    let array = value.as_array().ok_or(e::MANIFEST_SCHEMA)?;
    if array.is_empty() {
        return Err(e::MANIFEST_UNSIGNED);
    }
    if array.len() > limits::MAX_SIGS {
        return Err(e::MANIFEST_SCHEMA);
    }
    let mut entries: Vec<SigEntry> = Vec::with_capacity(array.len());
    let mut previous_key: Option<String> = None;
    for item in array {
        let object = item.as_object().ok_or(e::MANIFEST_SCHEMA)?;
        const MEMBERS: [&str; 3] = ["alg", "key", "value"];
        for required in MEMBERS {
            if !object.contains(required) {
                return Err(e::MANIFEST_SCHEMA);
            }
        }
        if object.first_unknown(MEMBERS).is_some() {
            return Err(e::MANIFEST_SCHEMA);
        }
        let alg = object.get_str("alg").ok_or(e::MANIFEST_SCHEMA)?;
        if !digest::is_algorithm_name(alg) {
            return Err(e::MANIFEST_SCHEMA);
        }
        let key = object.get_str("key").ok_or(e::MANIFEST_SCHEMA)?;
        let value = object.get_str("value").ok_or(e::MANIFEST_SCHEMA)?;
        let known_algorithm = alg == "ed25519";
        let decoded_value = if known_algorithm {
            if !digest::is_valid_key_id(key) {
                return Err(e::MANIFEST_SCHEMA);
            }
            b64::decode_exact(value, 64).map_err(|_| e::MANIFEST_SCHEMA)?
        } else {
            let valid_key = match key.split_once(':') {
                Some((algorithm, hex)) => {
                    digest::is_algorithm_name(algorithm)
                        && !hex.is_empty()
                        && hex.len() <= 128
                        && hex.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                }
                None => false,
            };
            if !valid_key {
                return Err(e::MANIFEST_SCHEMA);
            }
            b64::decode_range(value, 1, limits::MAX_SIG_VALUE_BYTES)
                .map_err(|_| e::MANIFEST_SCHEMA)?
        };
        if let Some(previous) = &previous_key {
            if json::utf16_cmp(previous, key) != std::cmp::Ordering::Less {
                return Err(e::MANIFEST_SCHEMA);
            }
        }
        previous_key = Some(key.to_owned());
        entries.push(SigEntry {
            alg: alg.to_owned(),
            key: key.to_owned(),
            value: value.to_owned(),
            decoded_value,
            known_algorithm,
        });
    }
    Ok(entries)
}
