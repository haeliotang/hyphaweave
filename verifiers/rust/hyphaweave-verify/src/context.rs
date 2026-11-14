// SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
// SPDX-License-Identifier: Apache-2.0

//! Verification context: trust roots, key state, signatures, references and
//! grants.
//!
//! The verification context is the set of records against which a target is
//! verified: the target's records plus records supplied externally by the local
//! keyset (§0.2). This module owns context-level state:
//!
//! - the local keyset is the only source of trust roots (§5.3, R2); container
//!   and target declarations can extend that trust through a fixed point of
//!   cosignatures, but can never create a root;
//! - declarations resolve to a governing declaration (earliest claimed
//!   `recorded_at`, tie: smallest record digest) per §5.3;
//! - signature checking under §3.4 plus the key-lifecycle effects of §9.4,
//!   including the compromise rule that needs verified timestamp evidence;
//! - reference resolution with the five states of §6.3;
//! - grant coverage and the delegated-grant chain of §5.5.2, judged at the
//!   verification time of the record being checked (R1);
//! - the container cross-record checks of §10.3, §8.5 and §5.4.
//!
//! All state is computed deterministically: records are in report order, maps
//! are ordered, and memoised record evaluation is recursive over digest
//! references, which cannot form cycles (§6.4).

use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::digest;
use crate::ed25519;
use crate::envelope::{self, ParsedRecord, RecordFile, RefObject, SigEntry};
use crate::error_codes::{e, n, Code};
use crate::json::utf16_cmp;
use crate::kinds::{self, GrantActionKind, KindBody, RevokeReason};
use crate::options::{UsageError, VerifyOptions};
use crate::report::{RecordReport, Verdict};
use crate::time::Timestamp;
use crate::timestamp::{ChainEvidence, Rescue};

/// Outcome of checking one signature through the context.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigState {
    /// The signature verifies and its key state passes at the claimed time.
    Valid,
    /// The signature or its key state fails: an invalid unit.
    Invalid(Code),
    /// The signature cannot be checked from the input: an unverifiable unit.
    Unverified(Code),
}

impl SigState {
    /// Report spelling of `sigs[].state` (§14.6).
    #[must_use]
    pub fn report_state(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::Invalid(_) => "invalid",
            Self::Unverified(_) => "unverified",
        }
    }
}

/// Where a verified signature's public-key material came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MaterialSource {
    /// Material supplied by the record under verification itself (§9.5).
    SelfRecord,
    /// Material from a trusted declaration in the verification context.
    TrustedDeclaration,
    /// Material from a declared but untrusted declaration (manifest signatures
    /// and declaration owner cosignatures only).
    UntrustedDeclaration,
    /// Explicit `weave.key.rotated` material (§9.2 rule 5).
    Rotation,
}

/// Full result of checking one signature entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SignatureResolution {
    /// Signature/key-state outcome.
    pub state: SigState,
    /// Key class from the governing declaration or explicit rotation material.
    pub key_class: Option<String>,
    /// Where the public-key material came from.
    pub material_source: Option<MaterialSource>,
    /// True when the material came from the verification context (a declaration
    /// or explicit rotation material) rather than from the record itself; the
    /// reference report calls this trust-on-first-use.
    pub material_from_context: bool,
}

impl SignatureResolution {
    fn invalid(code: Code) -> Self {
        Self {
            state: SigState::Invalid(code),
            key_class: None,
            material_source: None,
            material_from_context: false,
        }
    }
}

/// Outcome of the manifest signature obligation (§11.3).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ManifestSigOutcome {
    /// The code of the first failing `ed25519` entry in array order, or
    /// `E_SIG_UNVERIFIABLE` when no `ed25519` entry exists; `None` when every
    /// entry passes.
    pub code: Option<Code>,
    /// At least one check used context key material (§14.9 TOFU predicate).
    pub context_trusted: bool,
}

/// Where a record slot came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SlotSource {
    /// A target record (record target or container record).
    Target,
    /// A local keyset record (`--keys`).
    Keyset,
}

/// Why a key declaration does not simply establish its key (or, when
/// `None`, why it does).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DeclIssue {
    /// The declaration is valid (trusted or a duplicate of a trusted key).
    None,
    /// No valid self-signature by the declared key (dedicated kind code).
    SelfSignature,
    /// Automated declaration without a usable owner member.
    OwnerMissing,
    /// Owner key cannot be resolved in the context.
    OwnerUnknown,
    /// Owner resolves but is not trusted.
    OwnerUntrusted,
    /// Automated declaration without a valid owner cosignature.
    NotCosigned,
    /// Human/organization declaration with no chain to a trusted root.
    UntrustedSelfAttested,
    /// The declaration's class differs from its key id's governing class
    /// (`E_KEY_CLASS_CONFLICT`, §5.3, S1).
    ClassConflict,
    /// Declaration body did not parse; the body error is reported instead.
    BodyInvalid,
}

/// Resolved declaration candidates for one key id.
#[derive(Clone, Debug)]
pub(crate) struct DeclInfo {
    /// Key class.
    pub class: String,
    /// Raw 32-byte public key.
    pub public_key: [u8; 32],
    /// Owner key id for automated classes.
    pub owner: Option<String>,
    /// Validity window start.
    pub valid_from: Option<Timestamp>,
    /// Validity window end.
    pub valid_until: Option<Timestamp>,
}

/// Trusted key state derived from a governing declaration.
#[derive(Clone, Debug)]
pub(crate) struct TrustedKey {
    /// Key class.
    pub class: String,
    /// Raw public key.
    pub public_key: [u8; 32],
    /// Validity window start.
    pub valid_from: Option<Timestamp>,
    /// Validity window end.
    pub valid_until: Option<Timestamp>,
    /// True when the keyset declares this key id: its class, window and
    /// material come from the local keyset (not TOFU, §14.9).
    pub from_keyset: bool,
}

/// A keyset declaration's pin of a key id's class and window (§5.3, T4).
#[derive(Clone, Debug)]
pub(crate) struct KeysetPin {
    /// Pinned class.
    pub class: String,
    /// Pinned window start.
    pub valid_from: Option<Timestamp>,
    /// Pinned window end.
    pub valid_until: Option<Timestamp>,
}

/// Explicit key material supplied by a `weave.key.rotated` record (§9.2 rule 5).
#[derive(Clone, Debug)]
pub(crate) struct RotationMaterial {
    /// Raw public key.
    pub public_key: [u8; 32],
    /// Class named by the rotation's `actor.type`.
    pub class: String,
    /// True when the rotation record is a keyset record.
    pub from_keyset: bool,
}

/// One record slot of the context.
pub(crate) struct Slot {
    /// Parsed record, or `None` when the file failed parse/canonical checks.
    pub record: Option<RecordFile>,
    /// Parse error code for a record that could not be parsed.
    pub parse_error: Option<Code>,
    /// Own record digest, when the record parsed.
    pub digest: Option<String>,
    /// Parsed kind body (§14.5 check 6), when applicable.
    pub body: Option<KindBody>,
    /// Body error, reported at check (6).
    pub body_error: Option<Code>,
    /// Envelope-structure failure code, reported at check (2).
    pub envelope_error: Option<Code>,
    /// Schema facts of a structurally valid key declaration (§5.3, V5).
    pub decl_schema: Option<kinds::KeyDeclaredBody>,
    /// Declaration candidate, when the record is a parseable key declaration.
    pub decl: Option<DeclInfo>,
    /// Declaration trust outcome.
    pub decl_issue: DeclIssue,
    /// Record source.
    pub source: SlotSource,
    /// Memoised evaluation.
    pub eval: EvalState,
}

/// Memoisation state of one record verdict.
pub(crate) enum EvalState {
    /// Not evaluated yet.
    Pending,
    /// Evaluation in progress (cycle guard; digest references are acyclic, so a
    /// re-entry indicates a malformed context).
    Running,
    /// Evaluated.
    Done(Box<RecordReport>),
}

impl Slot {
    fn new(record: Option<RecordFile>, parse_error: Option<Code>, source: SlotSource) -> Self {
        Self {
            record,
            parse_error,
            digest: None,
            body: None,
            body_error: None,
            envelope_error: None,
            decl_schema: None,
            decl: None,
            decl_issue: DeclIssue::None,
            source,
            eval: EvalState::Pending,
        }
    }

    /// Kind name, when known.
    pub(crate) fn kind(&self) -> Option<&str> {
        self.record.as_ref().map(RecordFile::kind)
    }
}

/// One reference-resolution result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Resolution {
    /// One of the five §6.3 states.
    pub state: &'static str,
    /// Resolved target slot for `found` and `erased`.
    pub target_slot: Option<usize>,
    /// Resolved target kind (for kind-claim contradiction checks).
    pub target_kind: Option<String>,
    /// Target sensitivity rank for label propagation.
    pub target_sensitivity: Option<u8>,
}

impl Resolution {
    fn simple(state: &'static str) -> Self {
        Self {
            state,
            target_slot: None,
            target_kind: None,
            target_sensitivity: None,
        }
    }
}

/// Cross-record container outcomes of §14.5 (8).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CrossCheckOutcome {
    /// Container-level invalid error codes.
    pub container_errors: Vec<Code>,
    /// Container-level notices.
    pub container_notices: Vec<Code>,
    /// Additional per-record errors by slot index.
    pub record_errors: Vec<(usize, Code)>,
    /// Additional per-record notices by slot index.
    pub record_notices: Vec<(usize, Code)>,
}

/// A usable grant for authorisation (or grant-chain) checks.
#[derive(Clone, Debug)]
pub(crate) struct UsableGrant {
    /// Grant specification from the body.
    pub spec: kinds::GrantSpec,
}

/// Full record identity: `(origin.project, origin.instance, id)`.
///
/// §6.3 and §10.3 match records and placeholders by "the same `origin` and
/// `id`"; `origin` is the `{project, instance}` pair (§4.1). Dropping the
/// instance would let a record or placeholder of another instance stand in for
/// the referenced one, and a placeholder's own `origin` is not covered by the
/// digest it carries.
pub(crate) type IdentityKey = (String, String, String);

fn identity_key(origin: &envelope::Origin, id: &str) -> IdentityKey {
    (
        origin.project.clone(),
        origin.instance.clone(),
        id.to_owned(),
    )
}

/// One target's verification context.
pub struct World {
    pub(crate) slots: Vec<Slot>,
    pub(crate) target_count: usize,
    pub(crate) options: VerifyOptions,
    pub(crate) evidence: ChainEvidence,
    /// Context slots by full record identity `(origin.project, origin.instance,
    /// id)` (§4.1, §6.3, §10.3: "the same `origin` and `id`").
    pub(crate) by_origin_id: HashMap<IdentityKey, Vec<usize>>,
    pub(crate) trusted: BTreeMap<String, TrustedKey>,
    /// Keyset declarations' class/window pins by key id (§5.3, T4).
    pub(crate) keyset_pins: BTreeMap<String, KeysetPin>,
    /// Governing class by key id (§5.3, U4).
    pub(crate) governing_class: BTreeMap<String, String>,
    /// Explicit rotation material candidates: (key id, rotation slot, material).
    pub(crate) rotation_candidates: Vec<(String, usize, RotationMaterial)>,
    /// True when this context verifies a container target (as opposed to one
    /// standalone record).
    pub(crate) container_context: bool,
}

impl World {
    /// Builds the verification context from the target's record slots (in
    /// report order) plus the local keyset.
    ///
    /// # Errors
    /// A keyset file that is not a structurally valid record — canonical bytes,
    /// envelope, signature presence/format, kind body — is a usage error
    /// (§14.1). Any semantic or cryptographic failure of a keyset record is not
    /// a usage error; it simply establishes no trust.
    pub fn new(
        slots: Vec<Option<RecordFile>>,
        options: &VerifyOptions,
    ) -> Result<Self, UsageError> {
        let results: Vec<Result<RecordFile, Code>> = slots
            .into_iter()
            .map(|slot| slot.ok_or(e::JSON_INVALID))
            .collect();
        Self::from_results(results, options)
    }

    /// Builds the verification context when the caller already parsed the target
    /// records and knows their parse/canonical error code (container records and
    /// the record target use this form).
    ///
    /// # Errors
    /// Same as [`World::new`].
    pub fn from_results(
        results: Vec<Result<RecordFile, Code>>,
        options: &VerifyOptions,
    ) -> Result<Self, UsageError> {
        Self::from_results_with_context(results, Vec::new(), options)
    }

    /// Like [`World::from_results`], with further container records that are
    /// part of the verification context but not reported (record files in
    /// `records/` that the manifest does not list). Such a container is
    /// invalid at the records listing; the extra records can still supply key
    /// material to the manifest signature check of step (5).
    ///
    /// # Errors
    /// Same as [`World::new`].
    pub fn from_results_with_context(
        results: Vec<Result<RecordFile, Code>>,
        extra: Vec<RecordFile>,
        options: &VerifyOptions,
    ) -> Result<Self, UsageError> {
        let target_count = results.len();
        let mut world = Self {
            slots: Vec::with_capacity(target_count + options.keyset.len()),
            target_count,
            options: options.clone(),
            evidence: ChainEvidence::none(),
            by_origin_id: HashMap::new(),
            trusted: BTreeMap::new(),
            keyset_pins: BTreeMap::new(),
            governing_class: BTreeMap::new(),
            rotation_candidates: Vec::new(),
            container_context: false,
        };
        for result in results {
            let slot = match result {
                Ok(record) => Slot::new(Some(record), None, SlotSource::Target),
                Err(code) => Slot::new(None, Some(code), SlotSource::Target),
            };
            world.push_slot(slot);
        }
        for record in extra {
            world.push_slot(Slot::new(Some(record), None, SlotSource::Target));
        }
        for bytes in &options.keyset {
            // §14.1: a keyset file whose first failing check belongs to the
            // structural group is a usage error (exit 2); a structurally valid
            // file that fails a semantic or cryptographic rule establishes no
            // trust and is otherwise an ordinary context record.
            let record = envelope::parse_record_file(bytes).map_err(|code| {
                UsageError(format!(
                    "--keys: a keyset file is not a structurally valid record ({code})"
                ))
            })?;
            if let Some(code) = structural_error(&record) {
                return Err(UsageError(format!(
                    "--keys: a keyset file is not a structurally valid record ({code})"
                )));
            }
            let slot = Slot::new(Some(record), None, SlotSource::Keyset);
            world.push_slot(slot);
        }
        world.compute_digests_and_bodies()?;
        world.build_trust()?;
        Ok(world)
    }

    fn push_slot(&mut self, slot: Slot) {
        self.slots.push(slot);
    }

    fn compute_digests_and_bodies(&mut self) -> Result<(), UsageError> {
        for index in 0..self.slots.len() {
            let (digest_string, kind) = {
                let Some(record) = &self.slots[index].record else {
                    continue;
                };
                (record.digest(), record.kind().to_owned())
            };
            let invalid_code = self.slots[index]
                .record
                .as_ref()
                .and_then(|record| record.invalid().map(|partial| partial.code));
            if let Some(record) = &self.slots[index].record {
                if let Some(origin) = record.origin() {
                    let key = identity_key(origin, record.id());
                    self.by_origin_id.entry(key).or_default().push(index);
                }
            }
            self.slots[index].digest = Some(digest_string);
            if let Some(code) = invalid_code {
                self.slots[index].envelope_error = Some(code);
                continue;
            }
            if kind == "weave.erased" {
                continue;
            }
            let Some(body_result) = self.slots[index].record.as_ref().map(kinds::parse_body) else {
                continue;
            };
            match body_result {
                Ok(body) => {
                    self.slots[index].body = Some(body);
                }
                Err(code) => {
                    self.slots[index].body_error = Some(code);
                }
            }
        }
        Ok(())
    }

    /// Slot accessor for the record pipeline.
    pub(crate) fn slot(&self, index: usize) -> &Slot {
        &self.slots[index]
    }

    /// Number of target records (keyset records are not counted).
    #[must_use]
    pub fn slot_count(&self) -> usize {
        self.target_count
    }

    /// Marks this context as verifying a container target (§14.9 report detail).
    pub fn set_container_context(&mut self) {
        self.container_context = true;
    }

    /// Attaches pre-verified timestamp evidence (used by the §9.4 compromise
    /// rule and by manifest signature checking).
    pub fn set_timestamp_evidence(&mut self, evidence: ChainEvidence) {
        self.evidence = evidence;
    }

    /// Evaluates one target record by slot index.
    pub fn evaluate(&mut self, index: usize) -> RecordReport {
        match &self.slots[index].eval {
            EvalState::Done(report) => return (**report).clone(),
            EvalState::Running => {
                // Not constructible from a conforming digest-reference graph;
                // never panic on hostile input.
                let mut report = self.empty_report(index);
                report.verdict = Verdict::Unverifiable;
                report.errors.push(e::SIG_UNVERIFIABLE);
                return report;
            }
            EvalState::Pending => {}
        }
        self.slots[index].eval = EvalState::Running;
        let report = crate::record::evaluate_normalized(self, index);
        self.slots[index].eval = EvalState::Done(Box::new(report.clone()));
        report
    }

    /// A report skeleton for one slot with whatever metadata is known.
    pub(crate) fn empty_report(&self, index: usize) -> RecordReport {
        let slot = &self.slots[index];
        let mut report = RecordReport {
            digest: slot.digest.clone(),
            id: None,
            kind: None,
            stage: None,
            origin: None,
            // §14.6 (F9): undetermined until the record parsed.
            kind_known: None,
            verdict: Verdict::Invalid,
            errors: Vec::new(),
            notices: Vec::new(),
            refs: Vec::new(),
            sigs: Vec::new(),
            attestation: None,
        };
        if let Some(record) = &slot.record {
            match &record.parsed {
                ParsedRecord::Normal(envelope) => {
                    report.id = Some(envelope.id.clone());
                    report.kind = Some(envelope.kind.clone());
                    report.kind_known = Some(envelope::is_registered_kind(&envelope.kind));
                    report.stage = Some(envelope.stage.clone());
                    report.origin = Some(crate::report::OriginReport {
                        project: envelope.origin.project.clone(),
                        instance: envelope.origin.instance.clone(),
                    });
                }
                ParsedRecord::Erased(placeholder) => {
                    report.id = Some(placeholder.id.clone());
                    report.kind = Some("weave.erased".to_owned());
                    report.kind_known = Some(true);
                    report.origin = Some(crate::report::OriginReport {
                        project: placeholder.origin.project.clone(),
                        instance: placeholder.origin.instance.clone(),
                    });
                }
                ParsedRecord::Invalid(partial) => {
                    report.id = partial.id.clone();
                    report.kind = partial.kind.clone();
                    report.kind_known = partial.kind.as_ref().map(|_| partial.kind_known);
                    report.stage = partial.stage.clone();
                    report.origin =
                        partial
                            .origin
                            .as_ref()
                            .map(|origin| crate::report::OriginReport {
                                project: origin.project.clone(),
                                instance: origin.instance.clone(),
                            });
                }
            }
        }
        if let Some(code) = slot.parse_error {
            report.errors.push(code);
        }
        report
    }

    /// The §14.9 facts about the target records that are not visible in the
    /// report fields. `records_reported` is false when the container pipeline
    /// stopped before per-record evaluation (`records: []`): no record is then
    /// part of the report.
    #[must_use]
    pub fn limitation_facts(&self, records_reported: bool) -> crate::limitations::LimitationFacts {
        let mut facts = crate::limitations::LimitationFacts::default();
        if !records_reported {
            return facts;
        }
        for slot in self.slots.iter().take(self.target_count) {
            let Some(record) = slot.record.as_ref() else {
                continue;
            };
            // A record "carries a labels member" when its envelope passed the
            // structure checks with that member (F37).
            if record
                .envelope()
                .is_some_and(|envelope| envelope.labels.is_some())
            {
                facts.labels_present = true;
            }
            // A `weave.erased` record, well formed or not (F37).
            if record.kind() == "weave.erased" {
                facts.placeholder_present = true;
                if !self.container_context {
                    facts.standalone_placeholder = true;
                }
            }
        }
        facts
    }

    /// Evaluates every target record, in slot order.
    pub fn evaluate_all(&mut self) -> Vec<RecordReport> {
        let count = self.target_count;
        (0..count).map(|index| self.evaluate(index)).collect()
    }

    /// The timestamp evidence attached to the context.
    #[must_use]
    pub fn timestamp_evidence(&self) -> &ChainEvidence {
        &self.evidence
    }
}

// ---------------------------------------------------------------------------
// Trust roots, governing class and declarations (§5.3, §9.1, R2, S1, T4, U4, V5)
// ---------------------------------------------------------------------------

/// Order key of the §5.3 declaration-resolution order and of the §9.5
/// revocation order: claimed `recorded_at`, then the §2.2 record digest.
pub(crate) type OrderKey = (Timestamp, String);

/// The structural group of §14.1 / §5.3 for one parsed record: canonical form
/// (already passed when a `RecordFile` exists), envelope structure, `sigs`
/// presence and format (including a required per-record signature that is
/// absent or empty) and the registered-kind body **schema** — for
/// `weave.key.declared` the presence and encoding of `public_key`, for
/// `weave.key.rotated` the encoding/length of the key material (V5).
///
/// Returns the first structural failure, or `None` when the record is
/// structurally valid. Semantic, key-lifecycle, actor/authorisation and
/// cryptographic failures are not structural.
pub(crate) fn structural_error(record: &RecordFile) -> Option<Code> {
    if let Some(partial) = record.invalid() {
        return Some(partial.code);
    }
    let Some(envelope) = record.envelope() else {
        // A structurally sound `weave.erased` placeholder.
        return None;
    };
    let signature_required = envelope.stage == "accepted"
        || envelope::SIGNER_CONSTRAINED_KINDS.contains(&envelope.kind.as_str());
    let absent_or_empty = match record.object.get("sigs") {
        None => true,
        Some(value) => value.as_array().is_some_and(<[_]>::is_empty),
    };
    if signature_required && absent_or_empty {
        return Some(e::SIG_REQUIRED);
    }
    if let Err(code) = envelope::parse_sigs(&record.object) {
        return Some(code);
    }
    if let Some(code) = kinds::key_material_structural_error(envelope) {
        return Some(code);
    }
    if envelope.kind == "weave.key.declared" {
        return kinds::parse_key_declared_schema(envelope).err();
    }
    match kinds::parse_body(record) {
        Err(code)
            if matches!(
                code,
                e::KIND_BODY_SCHEMA | e::GRANT_SCHEMA | e::KEY_PUBLIC_KEY
            ) =>
        {
            Some(code)
        }
        _ => None,
    }
}

impl World {
    /// Builds the governing classes and the trusted-key fixed point.
    ///
    /// 1. Every structurally valid `weave.key.declared` (keyset and target) is
    ///    a class candidate (§5.3, V5).
    /// 2. The **governing class** of a key id is decided before, and
    ///    independently of, the trust closure: the keyset declaration's class
    ///    when the keyset declares the key id, otherwise the class of the
    ///    structurally valid declaration with the smallest
    ///    `(recorded_at, record digest)` pair (U4). Every structurally valid
    ///    target declaration of a different class is invalid with
    ///    `E_KEY_CLASS_CONFLICT` (S1).
    /// 3. The trust closure: keyset human/organization declarations that pass
    ///    their own checks are roots; automated declarations are trusted
    ///    through a trusted owner's cosignature; target human/organization
    ///    declarations are valid when their key is already trusted or when a
    ///    trusted human/organization key cosigns them (R2).
    /// 4. The governing validity window is the keyset declaration's when the
    ///    keyset declares the key id, otherwise that of the semantically valid
    ///    context declaration with the smallest `(recorded_at, digest)` (S1).
    ///
    /// # Errors
    /// Two structurally valid keyset declarations for one key id with a
    /// different class or window are a usage error (§14.1, T4).
    fn build_trust(&mut self) -> Result<(), UsageError> {
        // (1) Structurally valid declarations.
        let mut schema: Vec<(usize, kinds::KeyDeclaredBody)> = Vec::new();
        for index in 0..self.slots.len() {
            let Some(record) = self.slots[index].record.as_ref() else {
                continue;
            };
            if record.kind() != "weave.key.declared" || structural_error(record).is_some() {
                continue;
            }
            let Some(envelope) = record.envelope() else {
                continue;
            };
            if let Ok(body) = kinds::parse_key_declared_schema(envelope) {
                schema.push((index, body));
            }
        }
        // Keyset pins and the keyset conflict usage error (T4).
        self.keyset_pins.clear();
        for (index, body) in &schema {
            if self.slots[*index].source != SlotSource::Keyset {
                continue;
            }
            let pin = KeysetPin {
                class: body.key_type.clone(),
                valid_from: body.valid_from,
                valid_until: body.valid_until,
            };
            match self.keyset_pins.get(&body.key) {
                None => {
                    self.keyset_pins.insert(body.key.clone(), pin);
                }
                Some(existing) => {
                    if existing.class != pin.class
                        || existing.valid_from != pin.valid_from
                        || existing.valid_until != pin.valid_until
                    {
                        return Err(UsageError(format!(
                            "--keys: two keyset declarations for {} disagree on key_type or validity window",
                            body.key
                        )));
                    }
                }
            }
        }
        // (2) Governing class.
        self.governing_class.clear();
        let mut best: BTreeMap<String, (OrderKey, String)> = BTreeMap::new();
        for (index, body) in &schema {
            if self.slots[*index].source == SlotSource::Keyset {
                continue;
            }
            let Some(order) = self.order_key(*index) else {
                continue;
            };
            let replace = match best.get(&body.key) {
                None => true,
                Some((current, _)) => order_less(&order, current),
            };
            if replace {
                best.insert(body.key.clone(), (order, body.key_type.clone()));
            }
        }
        for (key, (_, class)) in best {
            self.governing_class.insert(key, class);
        }
        for (key, pin) in &self.keyset_pins {
            self.governing_class.insert(key.clone(), pin.class.clone());
        }
        for (index, body) in &schema {
            self.slots[*index].decl_schema = Some(body.clone());
        }

        // Declaration candidates for the trust closure: declarations whose body
        // also passed the semantic body rules (rule 1, owner presence, window).
        let mut candidates: Vec<usize> = Vec::new();
        for index in 0..self.slots.len() {
            let Some(KindBody::KeyDeclared(body)) = self.slots[index].body.as_ref() else {
                continue;
            };
            if self.slots[index].decl_schema.is_none() {
                continue;
            }
            let Ok(public_key) = <[u8; 32]>::try_from(body.public_key.as_slice()) else {
                continue;
            };
            let info = DeclInfo {
                class: body.key_type.clone(),
                public_key,
                owner: body.owner.clone(),
                valid_from: body.valid_from,
                valid_until: body.valid_until,
            };
            self.slots[index].decl = Some(info);
            candidates.push(index);
        }

        // (3) Trust closure: keyset first, then the target declarations.
        self.trusted.clear();
        for pass_keyset_only in [true, false] {
            let mut changed = true;
            while changed {
                changed = false;
                for &index in &candidates {
                    if pass_keyset_only && self.slots[index].source != SlotSource::Keyset {
                        continue;
                    }
                    let Some(key) = self.decl_key(index) else {
                        continue;
                    };
                    let already = self.trusted.contains_key(&key);
                    if self.try_trust_candidate(index) && !already {
                        changed = true;
                    }
                }
            }
        }
        // Final pass so that every candidate's issue reflects the fixed point.
        for &index in &candidates {
            self.try_trust_candidate(index);
        }

        // (4) Governing validity window and material for every trusted key.
        let trusted_keys: Vec<String> = self.trusted.keys().cloned().collect();
        for key in trusted_keys {
            let mut window: Option<(OrderKey, Option<Timestamp>, Option<Timestamp>)> = None;
            if let Some(pin) = self.keyset_pins.get(&key) {
                let pin_window = (pin.valid_from, pin.valid_until);
                if let Some(entry) = self.trusted.get_mut(&key) {
                    entry.valid_from = pin_window.0;
                    entry.valid_until = pin_window.1;
                    entry.from_keyset = true;
                }
                continue;
            }
            for &index in &candidates {
                if self.slots[index].decl_issue != DeclIssue::None
                    || self.decl_key(index).as_deref() != Some(key.as_str())
                {
                    continue;
                }
                let Some(order) = self.order_key(index) else {
                    continue;
                };
                let Some(info) = self.slots[index].decl.as_ref() else {
                    continue;
                };
                let replace = match &window {
                    None => true,
                    Some((current, _, _)) => order_less(&order, current),
                };
                if replace {
                    window = Some((order, info.valid_from, info.valid_until));
                }
            }
            if let (Some((_, from, until)), Some(entry)) = (window, self.trusted.get_mut(&key)) {
                entry.valid_from = from;
                entry.valid_until = until;
                entry.from_keyset = false;
            }
        }
        self.collect_rotation_candidates();
        Ok(())
    }

    /// The declaration-resolution order key of a slot.
    pub(crate) fn order_key(&self, index: usize) -> Option<OrderKey> {
        let record = self.slots[index].record.as_ref()?;
        let envelope = record.envelope()?;
        Some((envelope.recorded_at, self.slots[index].digest.clone()?))
    }

    /// The declared key id of a declaration candidate.
    pub(crate) fn decl_key(&self, index: usize) -> Option<String> {
        self.slots[index]
            .decl_schema
            .as_ref()
            .map(|body| body.key.clone())
    }

    /// Governing class of a key id (§5.3), independent of trust.
    pub(crate) fn governing_class_of(&self, key: &str) -> Option<&str> {
        self.governing_class.get(key).map(String::as_str)
    }

    /// Evaluates one declaration candidate against the current trusted set and
    /// records its issue; registers its key when it is valid. Returns true when
    /// the declaration is valid.
    fn try_trust_candidate(&mut self, index: usize) -> bool {
        let issue = self.candidate_issue(index);
        self.slots[index].decl_issue = issue;
        if issue != DeclIssue::None {
            return false;
        }
        let (Some(key), Some(decl)) = (self.decl_key(index), self.slots[index].decl.clone()) else {
            return false;
        };
        if !self.trusted.contains_key(&key) {
            let class = self
                .governing_class_of(&key)
                .unwrap_or(decl.class.as_str())
                .to_owned();
            self.trusted.insert(
                key,
                TrustedKey {
                    class,
                    public_key: decl.public_key,
                    valid_from: decl.valid_from,
                    valid_until: decl.valid_until,
                    from_keyset: self.slots[index].source == SlotSource::Keyset,
                },
            );
        }
        true
    }

    /// The §9.1 rule order for one declaration: self-signature (rule 2), owner
    /// binding (rule 3), governing class and trust (rule 4).
    fn candidate_issue(&self, index: usize) -> DeclIssue {
        let Some(decl) = self.slots[index].decl.clone() else {
            return DeclIssue::BodyInvalid;
        };
        let Some(key) = self.decl_key(index) else {
            return DeclIssue::BodyInvalid;
        };
        let Some(record) = self.slots[index].record.as_ref() else {
            return DeclIssue::BodyInvalid;
        };
        let Some(digest_string) = self.slots[index].digest.as_deref() else {
            return DeclIssue::BodyInvalid;
        };
        let message = digest::record_signature_message(digest_string);
        // Rule 2: a valid self-signature (unknown-algorithm entries ignored).
        if !signed_by(record, &key, &decl.public_key, &message) {
            return DeclIssue::SelfSignature;
        }
        let is_keyset = self.slots[index].source == SlotSource::Keyset;
        let automated = !matches!(decl.class.as_str(), "human" | "organization");
        // Rule 3: owner binding for automated classes.
        if automated {
            let Some(owner) = decl.owner.as_deref() else {
                return DeclIssue::OwnerMissing;
            };
            match self.governing_class_of(owner) {
                None => return DeclIssue::OwnerUnknown,
                Some(class) if !matches!(class, "human" | "organization") => {
                    return DeclIssue::OwnerMissing;
                }
                Some(_) => {}
            }
        }
        // Rule 4: the governing class (S1, U4) ...
        if self.governing_class_of(&key) != Some(decl.class.as_str()) {
            return DeclIssue::ClassConflict;
        }
        // ... then trust.
        if automated {
            let owner = decl.owner.as_deref().unwrap_or_default();
            let owner_material = self
                .trusted
                .get(owner)
                .map(|trusted| trusted.public_key)
                .or_else(|| self.declared_material(owner));
            let cosigned = owner_material
                .is_some_and(|material| signed_by(record, owner, &material, &message));
            if !cosigned {
                return DeclIssue::NotCosigned;
            }
            if !self.trusted.contains_key(owner) {
                return DeclIssue::OwnerUntrusted;
            }
            return DeclIssue::None;
        }
        if is_keyset || self.trusted.contains_key(&key) {
            return DeclIssue::None;
        }
        if self.cosigned_by_trusted_human(record, &message, &key) {
            DeclIssue::None
        } else {
            DeclIssue::UntrustedSelfAttested
        }
    }

    fn cosigned_by_trusted_human(
        &self,
        record: &RecordFile,
        message: &[u8],
        own_key: &str,
    ) -> bool {
        let Ok(Some(entries)) = envelope::parse_sigs(&record.object) else {
            return false;
        };
        entries.iter().any(|entry| {
            entry.known_algorithm
                && entry.key != own_key
                && self.trusted.get(&entry.key).is_some_and(|trusted| {
                    matches!(trusted.class.as_str(), "human" | "organization")
                        && ed25519::verify(&trusted.public_key, &entry.decoded_value, message)
                            .is_ok()
                })
        })
    }

    /// Public-key material of a key from any `weave.key.declared` record of the
    /// context whose envelope and `sigs` format passed and whose `body.key`/`body.public_key`
    /// are well formed and consistent (the key id is the derivation of the
    /// public key). Trust and the other body rules are not required: §11.3 and
    /// §4.4 ask whether a key "resolves through a declaration", which is a
    /// question of available material (F41).
    pub(crate) fn declared_material(&self, key: &str) -> Option<[u8; 32]> {
        self.slots.iter().find_map(|slot| {
            let record = slot.record.as_ref()?;
            let envelope = record.envelope()?;
            if envelope.kind != "weave.key.declared" || envelope.body.get_str("key") != Some(key) {
                return None;
            }
            // The record's own structure (envelope and `sigs` format) passed.
            envelope::parse_sigs(&record.object).ok()?;
            let text = envelope.body.get_str("public_key")?;
            let bytes = crate::b64::decode_exact(text, 32).ok()?;
            if digest::derive_key_id(&bytes) != key {
                return None;
            }
            <[u8; 32]>::try_from(bytes.as_slice()).ok()
        })
    }

    /// True when the declared material of `key` comes from the local keyset.
    fn declared_material_from_keyset(&self, key: &str) -> bool {
        self.keyset_pins.contains_key(key)
    }

    /// Collects the explicit-material candidates of every structurally sound
    /// `weave.key.rotated` record; they supply material only once the rotation
    /// record itself is valid (§5.3, §9.2 rule 5).
    fn collect_rotation_candidates(&mut self) {
        self.rotation_candidates.clear();
        for index in 0..self.slots.len() {
            let Some(KindBody::KeyRotated(body)) = self.slots[index].body.clone() else {
                continue;
            };
            let class = self.slots[index]
                .record
                .as_ref()
                .and_then(RecordFile::envelope)
                .map(|envelope| envelope.actor.actor_type.clone())
                .unwrap_or_default();
            let from_keyset = self.slots[index].source == SlotSource::Keyset;
            if let Ok(public_key) = <[u8; 32]>::try_from(body.new_public_key.as_slice()) {
                self.rotation_candidates.push((
                    body.new_key.clone(),
                    index,
                    RotationMaterial {
                        public_key,
                        class: class.clone(),
                        from_keyset,
                    },
                ));
            }
            if let Some(old_public_key) = &body.old_public_key {
                if let Ok(public_key) = <[u8; 32]>::try_from(old_public_key.as_slice()) {
                    self.rotation_candidates.push((
                        body.old_key.clone(),
                        index,
                        RotationMaterial {
                            public_key,
                            class,
                            from_keyset,
                        },
                    ));
                }
            }
        }
    }

    /// Explicit key material for `key` from a **valid** rotation record of the
    /// context (first in context order), if any.
    pub(crate) fn rotation_material(&mut self, key: &str) -> Option<RotationMaterial> {
        let candidates: Vec<(usize, RotationMaterial)> = self
            .rotation_candidates
            .iter()
            .filter(|(candidate_key, _, _)| candidate_key == key)
            .map(|(_, index, material)| (*index, material.clone()))
            .collect();
        for (index, material) in candidates {
            if self.slot_is_valid(index) {
                return Some(material);
            }
        }
        None
    }

    /// True when the record in `index` evaluates to `valid`.
    pub(crate) fn slot_is_valid(&mut self, index: usize) -> bool {
        if matches!(self.slots[index].eval, EvalState::Running) {
            return false;
        }
        self.evaluate(index).verdict == Verdict::Valid
    }

    /// Class of a key if its material is available (trusted declaration or
    /// valid explicit rotation material).
    pub(crate) fn key_class(&mut self, key: &str) -> Option<String> {
        if let Some(trusted) = self.trusted.get(key) {
            return Some(trusted.class.clone());
        }
        self.rotation_material(key).map(|material| material.class)
    }
}

/// True when `left` precedes `right` in the declaration-resolution order.
pub(crate) fn order_less(left: &OrderKey, right: &OrderKey) -> bool {
    match left.0.cmp(&right.0) {
        std::cmp::Ordering::Less => true,
        std::cmp::Ordering::Greater => false,
        std::cmp::Ordering::Equal => utf16_cmp(&left.1, &right.1) == std::cmp::Ordering::Less,
    }
}

/// True when the record carries a valid `ed25519` signature by `key` made with
/// `public_key` over `message` (unknown-algorithm entries are ignored, §3.6).
fn signed_by(record: &RecordFile, key: &str, public_key: &[u8; 32], message: &[u8]) -> bool {
    let Ok(Some(entries)) = envelope::parse_sigs(&record.object) else {
        return false;
    };
    entries.iter().any(|entry| {
        entry.known_algorithm
            && entry.key == key
            && ed25519::verify(public_key, &entry.decoded_value, message).is_ok()
    })
}

// ---------------------------------------------------------------------------
// Signature checking and key lifecycle (§3.4, §9.4, §9.5)
// ---------------------------------------------------------------------------

/// Key material resolved for one signature.
struct SignatureMaterial {
    public_key: [u8; 32],
    class: Option<String>,
    /// Validity window from the governing declaration, when the material came
    /// from a trusted declaration.
    window: Option<(Option<Timestamp>, Option<Timestamp>)>,
    /// Provenance of the material.
    source: MaterialSource,
    /// The TOFU predicate of §14.9: the material came from the verification
    /// context rather than from the local keyset.
    context_trusted: bool,
}

/// One signature check request (§3.4 + §9.4).
pub(crate) struct SigCheck<'a> {
    /// Key id named by the signature entry.
    pub key_id: &'a str,
    /// Decoded signature bytes.
    pub signature: &'a [u8],
    /// Signature message.
    pub message: &'a [u8],
    /// The signature's claimed time (`recorded_at`, or a manifest's `created_at`).
    pub claimed_at: Timestamp,
    /// Material supplied by the record under verification itself.
    pub self_material: Option<&'a [u8]>,
    /// Manifest attestation mapping (§11.3).
    pub manifest: bool,
    /// For a `weave.key.revoked` record: only revocations ordered strictly
    /// before this key count (§9.5, T9/U3).
    pub revocation_cutoff: Option<&'a OrderKey>,
    /// Accept material from a declared but untrusted declaration (manifest
    /// signatures, §11.3).
    pub allow_untrusted_declaration: bool,
}

/// Valid revocation state of one key (§9.4, S2/T2).
#[derive(Clone, Debug, Default)]
pub(crate) struct RevocationState {
    /// Earliest `effective_at` among valid `retired`/`other` revocations.
    pub retired_from: Option<Timestamp>,
    /// Earliest `effective_at` among valid `key-compromise` revocations.
    pub compromised_from: Option<Timestamp>,
}

impl World {
    fn resolve_signature_material(&mut self, check: &SigCheck<'_>) -> Option<SignatureMaterial> {
        let key_id = check.key_id;
        if let Some(bytes) = check.self_material {
            if let Ok(public_key) = <[u8; 32]>::try_from(bytes) {
                let class = self.key_class(key_id);
                // §9.1 rule 5 / §9.4 apply to every signature made by the key,
                // a declaration's own self-signature included (F38).
                let window = self.governing_window(key_id);
                return Some(SignatureMaterial {
                    public_key,
                    class,
                    window,
                    source: MaterialSource::SelfRecord,
                    // Material supplied by the record under verification is not
                    // "context" material for the §14.9 TOFU predicate (pinned by
                    // container/manifest-context-trusted-tofu; F33).
                    context_trusted: false,
                });
            }
        }
        if let Some(trusted) = self.trusted.get(key_id) {
            return Some(SignatureMaterial {
                public_key: trusted.public_key,
                class: Some(trusted.class.clone()),
                window: Some((trusted.valid_from, trusted.valid_until)),
                source: MaterialSource::TrustedDeclaration,
                context_trusted: !trusted.from_keyset,
            });
        }
        if let Some(material) = self.rotation_material(key_id) {
            return Some(SignatureMaterial {
                public_key: material.public_key,
                class: Some(material.class.clone()),
                window: None,
                source: MaterialSource::Rotation,
                context_trusted: !material.from_keyset,
            });
        }
        if check.allow_untrusted_declaration {
            // §11.3: a required key resolves through a declaration; it need not
            // be trusted for the cryptographic equation.
            if let Some(public_key) = self.declared_material(key_id) {
                return Some(SignatureMaterial {
                    public_key,
                    class: self.governing_class_of(key_id).map(str::to_owned),
                    window: self.governing_window(key_id),
                    source: MaterialSource::UntrustedDeclaration,
                    context_trusted: !self.declared_material_from_keyset(key_id),
                });
            }
        }
        None
    }

    /// The governing validity window of a key id without trust (§5.3): the
    /// keyset pin, else the earliest semantically valid context declaration.
    pub(crate) fn governing_window(
        &self,
        key: &str,
    ) -> Option<(Option<Timestamp>, Option<Timestamp>)> {
        if let Some(pin) = self.keyset_pins.get(key) {
            return Some((pin.valid_from, pin.valid_until));
        }
        if let Some(trusted) = self.trusted.get(key) {
            return Some((trusted.valid_from, trusted.valid_until));
        }
        let mut best: Option<(OrderKey, Option<Timestamp>, Option<Timestamp>)> = None;
        for index in 0..self.slots.len() {
            if self.slots[index].decl_issue != DeclIssue::None
                && self.slots[index].decl_issue != DeclIssue::UntrustedSelfAttested
                && self.slots[index].decl_issue != DeclIssue::OwnerUntrusted
            {
                continue;
            }
            let Some(info) = self.slots[index].decl.as_ref() else {
                continue;
            };
            if self.decl_key(index).as_deref() != Some(key) {
                continue;
            }
            let Some(order) = self.order_key(index) else {
                continue;
            };
            let replace = match &best {
                None => true,
                Some((current, _, _)) => order_less(&order, current),
            };
            if replace {
                best = Some((order, info.valid_from, info.valid_until));
            }
        }
        best.map(|(_, from, until)| (from, until))
    }

    /// Checks one signature through the context: key resolution, the §3.4
    /// cryptography, then the §9.4 key-lifecycle effects at the claimed time.
    /// The cryptography runs first, so a failing equation reports its §3.4
    /// code even for an expired, revoked or compromised key (S8⑪).
    pub(crate) fn check_signature(&mut self, check: &SigCheck<'_>) -> SignatureResolution {
        if check.signature.len() != 64 {
            let code = if check.manifest {
                e::MANIFEST_SCHEMA
            } else {
                e::ENV_SIG_VALUE
            };
            return SignatureResolution::invalid(code);
        }
        let Some(material) = self.resolve_signature_material(check) else {
            return SignatureResolution {
                state: SigState::Unverified(e::KEY_UNKNOWN),
                key_class: self.governing_class_of(check.key_id).map(str::to_owned),
                material_source: None,
                material_from_context: false,
            };
        };
        let result = |state: SigState, material: &SignatureMaterial| SignatureResolution {
            state,
            key_class: material.class.clone(),
            material_source: Some(material.source),
            material_from_context: material.context_trusted,
        };
        if let Err(code) = ed25519::verify(&material.public_key, check.signature, check.message) {
            let mapped = if check.manifest {
                e::MANIFEST_SIG_INVALID
            } else {
                code
            };
            return result(SigState::Invalid(mapped), &material);
        }
        if let Some((valid_from, valid_until)) = material.window {
            if valid_from.is_some_and(|from| check.claimed_at < from)
                || valid_until.is_some_and(|until| check.claimed_at > until)
            {
                return result(SigState::Invalid(e::KEY_EXPIRED), &material);
            }
        }
        let state = self.key_revocation_state(check.key_id, check.revocation_cutoff);
        // §9.4 rule 1: retired/other family, never rescuable.
        if state
            .retired_from
            .is_some_and(|effective| check.claimed_at >= effective)
        {
            return result(SigState::Invalid(e::KEY_REVOKED), &material);
        }
        // §9.4 rule 2: compromise family with the earliest T.
        if let Some(compromised_from) = state.compromised_from {
            return match self.evidence.rescue(compromised_from.to_unix_millis()) {
                Rescue::Rescued => result(SigState::Valid, &material),
                Rescue::Untrusted => result(SigState::Unverified(e::TS_UNTRUSTED), &material),
                Rescue::Fails => result(SigState::Invalid(e::KEY_COMPROMISED), &material),
            };
        }
        result(SigState::Valid, &material)
    }

    /// Collects every **valid** key revocation of `key_id` in the verification
    /// context, keyset records included, independent of record order (S2). With
    /// a cutoff (the revocation record being judged), only revocations ordered
    /// strictly before it count (§9.5, T9/U3).
    pub(crate) fn key_revocation_state(
        &mut self,
        key_id: &str,
        cutoff: Option<&OrderKey>,
    ) -> RevocationState {
        let mut candidates: Vec<usize> = Vec::new();
        for (index, slot) in self.slots.iter().enumerate() {
            let Some(KindBody::KeyRevoked(body)) = slot.body.as_ref() else {
                continue;
            };
            if body.key == key_id {
                candidates.push(index);
            }
        }
        let mut state = RevocationState::default();
        for index in candidates {
            if let Some(cutoff) = cutoff {
                match self.order_key(index) {
                    Some(order) if order_less(&order, cutoff) => {}
                    _ => continue,
                }
            }
            if !self.slot_is_valid(index) {
                continue;
            }
            let Some(KindBody::KeyRevoked(body)) = self.slots[index].body.clone() else {
                continue;
            };
            let slot = match body.reason {
                RevokeReason::Compromise => &mut state.compromised_from,
                RevokeReason::Retired | RevokeReason::Other => &mut state.retired_from,
            };
            if slot.is_none_or(|current| body.effective_at < current) {
                *slot = Some(body.effective_at);
            }
        }
        state
    }
}

// ---------------------------------------------------------------------------
// Reference resolution (§6.3)
// ---------------------------------------------------------------------------

const FOUND: &str = "found";
const MISSING: &str = "missing";
const ERASED: &str = "erased";
const UNVERIFIABLE: &str = "unverifiable";

impl World {
    /// Resolves one reference against the context.
    pub(crate) fn resolve(&mut self, reference: &RefObject) -> Resolution {
        let Some(parsed) = digest::parse_digest_string(&reference.digest) else {
            return Resolution::simple(UNVERIFIABLE);
        };
        if parsed.algorithm != "sha256" {
            return Resolution::simple(UNVERIFIABLE);
        }
        let lookup = identity_key(&reference.origin, &reference.id);
        let Some(indices) = self.by_origin_id.get(&lookup).cloned() else {
            return Resolution::simple(MISSING);
        };
        if indices.is_empty() {
            return Resolution::simple(MISSING);
        }
        let mut had_parseable = false;
        for index in indices {
            let Some(record) = self.slots[index].record.clone() else {
                continue;
            };
            had_parseable = true;
            match &record.parsed {
                ParsedRecord::Erased(placeholder) => {
                    if placeholder.digest == reference.digest {
                        return Resolution {
                            state: ERASED,
                            target_slot: Some(index),
                            target_kind: Some("weave.erased".to_owned()),
                            target_sensitivity: None,
                        };
                    }
                }
                ParsedRecord::Invalid(_) => {
                    if record.digest() == reference.digest {
                        return Resolution::simple(UNVERIFIABLE);
                    }
                }
                ParsedRecord::Normal(_) => {
                    if record.digest() == reference.digest {
                        let verdict = self.evaluate(index).verdict;
                        if verdict == Verdict::Valid {
                            let kind = record.kind().to_owned();
                            let sensitivity = record
                                .envelope()
                                .and_then(|envelope| envelope.labels.as_ref())
                                .and_then(|labels| labels.sensitivity_rank());
                            return Resolution {
                                state: FOUND,
                                target_slot: Some(index),
                                target_kind: Some(kind),
                                target_sensitivity: sensitivity,
                            };
                        }
                        return Resolution::simple(UNVERIFIABLE);
                    }
                }
            }
        }
        let _ = had_parseable;
        // The origin+id exists but no record carries the referenced digest.
        Resolution::simple(UNVERIFIABLE)
    }

    /// Finds a context record by `(origin, id, digest)` identity, ignoring the
    /// target's own verdict. Used by the erasure cross-checks, which concern the
    /// recorded identity rather than the record's individual verdict.
    pub(crate) fn identity_match(&self, reference: &RefObject) -> Option<usize> {
        let lookup = identity_key(&reference.origin, &reference.id);
        let indices = self.by_origin_id.get(&lookup)?;
        for &index in indices {
            let Some(record) = self.slots[index].record.as_ref() else {
                continue;
            };
            let matches = match &record.parsed {
                crate::envelope::ParsedRecord::Erased(placeholder) => {
                    placeholder.digest == reference.digest
                }
                crate::envelope::ParsedRecord::Normal(_) => record.digest() == reference.digest,
                crate::envelope::ParsedRecord::Invalid(_) => false,
            };
            if matches {
                return Some(index);
            }
        }
        None
    }

    /// The record of a slot, when parseable.
    pub(crate) fn record_of(&self, index: usize) -> Option<&RecordFile> {
        self.slots[index].record.as_ref()
    }

    /// The parsed body of a slot, when it parsed.
    pub(crate) fn body_of(&self, index: usize) -> Option<&KindBody> {
        self.slots[index].body.as_ref()
    }

    /// The body error of a slot, when body parsing failed.
    pub(crate) fn body_error(&self, index: usize) -> Option<Code> {
        self.slots[index].body_error
    }

    /// The declaration trust outcome of a slot.
    pub(crate) fn decl_issue(&self, index: usize) -> DeclIssue {
        self.slots[index].decl_issue
    }
}

// ---------------------------------------------------------------------------
// Grants and delegated grant chains (§5.4, §5.5, R1)
// ---------------------------------------------------------------------------

impl World {
    /// Resolves a grant reference and validates its whole delegation chain at
    /// the given verification time. The returned grant covers `grant` action
    /// records only; a reference to a revocation record is `E_GRANT_GRANTER`.
    pub(crate) fn grant_lookup(
        &mut self,
        reference: &RefObject,
        at: Timestamp,
    ) -> Result<UsableGrant, Code> {
        let resolution = self.resolve(reference);
        if resolution.state != FOUND {
            return Err(e::GRANT_UNRESOLVED);
        }
        let Some(index) = resolution.target_slot else {
            return Err(e::GRANT_UNRESOLVED);
        };
        let Some(KindBody::Grant(body)) = self.slots[index].body.clone() else {
            return Err(e::GRANT_UNRESOLVED);
        };
        if body.action != GrantActionKind::Grant {
            return Err(e::GRANT_GRANTER);
        }
        let Some(spec) = body.grant.clone() else {
            return Err(e::GRANT_GRANTER);
        };
        let Some(record) = self.slots[index].record.clone() else {
            return Err(e::GRANT_UNRESOLVED);
        };
        let actor = record
            .envelope()
            .map(|envelope| envelope.actor.clone())
            .ok_or(e::GRANT_UNRESOLVED)?;
        match actor.actor_type.as_str() {
            "human" | "organization" => {}
            "agent" => {
                // §5.5.2: steps 1–5, then step 6 (validity at `at`), then
                // step 7 (depth); the first failing step decides (P5 shape).
                let too_deep = self.grant_chain_check(index, 0, crate::limits::MAX_GRANT_CHAIN)?;
                self.grant_chain_validity(index, at)?;
                if too_deep {
                    return Err(e::GRANT_UNRESOLVED);
                }
                return Ok(UsableGrant { spec });
            }
            _ => return Err(e::GRANT_UNRESOLVED),
        }
        self.grant_chain_validity(index, at)?;
        let _ = actor;
        Ok(UsableGrant { spec })
    }

    /// Checks the delegation-chain structure of `slot` against its parents
    /// (§5.5.2 steps 1–5). Returns `Ok(true)` when the walk reached the
    /// step-7 depth bound: §5.5.2 evaluates its steps in order, so the caller
    /// reports that `E_GRANT_UNRESOLVED` only after step 6 (validity) passed
    /// (H1-FIX2 gate 5, docs/h1-findings.md F68).
    fn grant_chain_check(
        &mut self,
        slot: usize,
        depth: usize,
        max_depth: usize,
    ) -> Result<bool, Code> {
        // §5.5.2 step 7 (S10, T8): at most MAX_GRANT_CHAIN links from the cited
        // grant to its root; `max_depth` is one more when the record being
        // verified is itself a grant, whose own link is not counted.
        if depth > max_depth {
            return Ok(true);
        }
        let Some(KindBody::Grant(body)) = self.slots[slot].body.clone() else {
            return Err(e::GRANT_UNRESOLVED);
        };
        if body.action != GrantActionKind::Grant {
            return Err(e::GRANT_GRANTER);
        }
        let Some(child_spec) = body.grant.clone() else {
            return Err(e::GRANT_GRANTER);
        };
        let Some(record) = self.slots[slot].record.clone() else {
            return Err(e::GRANT_UNRESOLVED);
        };
        let Some(actor) = record.envelope().map(|envelope| envelope.actor.clone()) else {
            return Err(e::GRANT_UNRESOLVED);
        };
        match actor.actor_type.as_str() {
            "human" | "organization" => Ok(false),
            "agent" => {
                let Some(parent_ref) = actor.grant.clone() else {
                    return Err(e::GRANT_UNRESOLVED);
                };
                let parent_resolution = self.resolve(&parent_ref);
                if parent_resolution.state != FOUND {
                    return Err(e::GRANT_UNRESOLVED);
                }
                let Some(parent_slot) = parent_resolution.target_slot else {
                    return Err(e::GRANT_UNRESOLVED);
                };
                let Some(KindBody::Grant(parent_body)) = self.slots[parent_slot].body.clone()
                else {
                    return Err(e::GRANT_UNRESOLVED);
                };
                if parent_body.action != GrantActionKind::Grant {
                    return Err(e::GRANT_GRANTER);
                }
                let Some(parent_spec) = parent_body.grant.clone() else {
                    return Err(e::GRANT_GRANTER);
                };
                if !parent_spec.kinds.iter().any(|kind| kind == "weave.grant")
                    || !parent_spec.actions.iter().any(|action| action == "grant")
                {
                    return Err(e::GRANT_GRANTER);
                }
                if !parent_spec.transferable {
                    return Err(e::GRANT_NOT_TRANSFERABLE);
                }
                if parent_spec.grantee_key != actor.key {
                    return Err(e::GRANT_GRANTER);
                }
                self.check_grant_is_subset(&actor.key, &child_spec, &parent_spec)?;
                self.grant_chain_check(parent_slot, depth + 1, max_depth)
            }
            _ => Err(e::GRANT_UNRESOLVED),
        }
    }

    fn check_grant_is_subset(
        &self,
        granter_key: &str,
        child: &kinds::GrantSpec,
        parent: &kinds::GrantSpec,
    ) -> Result<(), Code> {
        let _ = granter_key;
        for kind in &child.kinds {
            if !parent.kinds.contains(kind) {
                return Err(e::GRANT_DELEGATION_EXCEEDS);
            }
        }
        for action in &child.actions {
            if !parent.actions.contains(action) {
                return Err(e::GRANT_DELEGATION_EXCEEDS);
            }
        }
        for scope in &child.scope {
            if !parent.scope.contains(scope) {
                return Err(e::GRANT_DELEGATION_EXCEEDS);
            }
        }
        if child.valid_from < parent.valid_from {
            return Err(e::GRANT_DELEGATION_EXCEEDS);
        }
        match (child.valid_until, parent.valid_until) {
            (Some(child_until), Some(parent_until)) => {
                if child_until > parent_until {
                    return Err(e::GRANT_DELEGATION_EXCEEDS);
                }
            }
            (None, Some(_)) => return Err(e::GRANT_DELEGATION_EXCEEDS),
            _ => {}
        }
        Ok(())
    }

    /// Checks window and revocation state of the whole chain at one time
    /// (§5.5.2 step 6, R1). The chain starts at `slot` and follows parents.
    fn grant_chain_validity(&mut self, slot: usize, at: Timestamp) -> Result<(), Code> {
        let mut current = Some(slot);
        let mut depth = 0usize;
        let mut visited: Vec<usize> = Vec::new();
        while let Some(index) = current {
            if depth > crate::limits::MAX_GRANT_CHAIN || visited.contains(&index) {
                return Err(e::GRANT_UNRESOLVED);
            }
            visited.push(index);
            depth += 1;
            let Some(KindBody::Grant(body)) = self.slots[index].body.clone() else {
                return Err(e::GRANT_UNRESOLVED);
            };
            let Some(spec) = body.grant.clone() else {
                return Err(e::GRANT_GRANTER);
            };
            if self.grant_revoked_at(index, at) {
                return Err(e::GRANT_REVOKED);
            }
            if at < spec.valid_from {
                return Err(e::GRANT_EXPIRED);
            }
            if let Some(valid_until) = spec.valid_until {
                if at > valid_until {
                    return Err(e::GRANT_EXPIRED);
                }
            }
            let Some(record) = self.slots[index].record.clone() else {
                return Err(e::GRANT_UNRESOLVED);
            };
            current = record
                .envelope()
                .and_then(|envelope| envelope.actor.grant.clone())
                .and_then(|parent| {
                    let resolution = self.resolve(&parent);
                    resolution.target_slot
                });
        }
        Ok(())
    }

    /// True when a grant record is revoked at `at` by a revocation record in the
    /// context (§5.5.4, §9.6). The revocation's reference must name the grant
    /// with a matching digest and `effective_at <= at`.
    fn grant_revoked_at(&mut self, grant_slot: usize, at: Timestamp) -> bool {
        let Some(grant_digest) = self.slots[grant_slot].digest.clone() else {
            return false;
        };
        let mut revocation_slots: Vec<usize> = Vec::new();
        for (index, slot) in self.slots.iter().enumerate() {
            let Some(KindBody::Grant(body)) = slot.body.as_ref() else {
                continue;
            };
            if body.action != GrantActionKind::Revoke {
                continue;
            }
            let Some(revoke) = body.revoke.as_ref() else {
                continue;
            };
            if revoke.revokes.digest == grant_digest && revoke.effective_at <= at {
                revocation_slots.push(index);
            }
        }
        // §5.5.4/§9.6 (S10): only a revocation record that is itself valid
        // revokes anything.
        revocation_slots
            .into_iter()
            .any(|index| self.slot_is_valid(index))
    }
}

// ---------------------------------------------------------------------------
// Consent revocation (§8.6)
// ---------------------------------------------------------------------------

impl World {
    /// True when the consent record at `consent_slot` is revoked at `at`, either
    /// because a `weave.consent.revoked` record in the context revokes it with
    /// `effective_at <= at` (§8.6).
    pub(crate) fn consent_revoked_at(&mut self, consent_slot: usize, at: Timestamp) -> bool {
        let Some(consent_digest) = self.slots[consent_slot].digest.clone() else {
            return false;
        };
        let mut candidates: Vec<usize> = Vec::new();
        for (index, slot) in self.slots.iter().enumerate() {
            if slot.kind() != Some("weave.consent.revoked") {
                continue;
            }
            let Some(KindBody::ConsentRevoked(body)) = slot.body.as_ref() else {
                continue;
            };
            if body.revokes.digest == consent_digest && body.effective_at <= at {
                candidates.push(index);
            }
        }
        for index in candidates {
            let verdict = self.evaluate(index).verdict;
            if verdict == Verdict::Valid {
                return true;
            }
        }
        false
    }
}

// ---------------------------------------------------------------------------
// Manifest signature obligation (§11.3)
// ---------------------------------------------------------------------------

impl World {
    /// Checks the manifest attestation signatures (§11.3).
    ///
    /// Unknown-algorithm entries are ignored; at least one `ed25519` entry must
    /// exist (`E_SIG_UNVERIFIABLE` otherwise). **Every** `ed25519` entry is
    /// judged in array order and the first failing entry decides the code
    /// (W10): a key that does not resolve as a required key is `E_KEY_UNKNOWN`
    /// (unverifiable), a failing equation is `E_MANIFEST_SIG_INVALID`, and a
    /// key-state failure at the manifest's `created_at` is the §9.4 code. A
    /// required key resolves through a `weave.key.declared` or a valid
    /// `weave.key.rotated` record of the keyset or the container; it need not
    /// be trusted for the equation (T17/A-L8).
    pub fn check_manifest_signatures(
        &mut self,
        signatures: &[SigEntry],
        manifest_digest: &str,
        created_at: &Timestamp,
    ) -> ManifestSigOutcome {
        let message = digest::manifest_signature_message(manifest_digest);
        let mut outcome = ManifestSigOutcome::default();
        let mut any_known = false;
        for entry in signatures {
            if !entry.known_algorithm {
                continue;
            }
            any_known = true;
            let resolution = self.check_signature(&SigCheck {
                key_id: &entry.key,
                signature: &entry.decoded_value,
                message: &message,
                claimed_at: *created_at,
                self_material: None,
                manifest: true,
                revocation_cutoff: None,
                allow_untrusted_declaration: true,
            });
            // §11.5/§14.9: the check counts for the TOFU predicate when the
            // context material verified the equation.
            if !matches!(resolution.state, SigState::Invalid(e::MANIFEST_SIG_INVALID)) {
                outcome.context_trusted |= resolution.material_from_context;
            }
            let code = match resolution.state {
                SigState::Valid => None,
                SigState::Invalid(code) | SigState::Unverified(code) => Some(code),
            };
            if outcome.code.is_none() {
                outcome.code = code;
            }
        }
        if !any_known {
            outcome.code = Some(e::SIG_UNVERIFIABLE);
        }
        outcome
    }

    /// Verifies a supplied `--previous` container's attestation signatures in
    /// **this** (the target's) verification context (§11.5 W1, X2, X5):
    /// unknown algorithms ignored, at least one `ed25519` entry, and every
    /// `ed25519` entry (1) resolves as a required key of the target context
    /// and verifies, (2) is trusted in the target's final trust closure, and
    /// (3) passes the validity window and every revocation family at the
    /// previous manifest's `created_at` (`created_at >= T` breaks the link).
    ///
    /// Returns `(verified, context_trusted)`.
    pub fn check_previous_signatures(
        &mut self,
        signatures: &[SigEntry],
        manifest_digest: &str,
        created_at: Timestamp,
    ) -> (bool, bool) {
        let message = digest::manifest_signature_message(manifest_digest);
        let mut context_trusted = false;
        let mut any_known = false;
        let mut all_ok = true;
        for entry in signatures {
            if !entry.known_algorithm {
                continue;
            }
            any_known = true;
            // (1) Required key material: a declaration (keyset or target) or a
            // valid rotation record's explicit material.
            let material = match self.declared_material(&entry.key) {
                Some(public_key) => Some((public_key, !self.keyset_pins.contains_key(&entry.key))),
                None => self
                    .rotation_material(&entry.key)
                    .map(|material| (material.public_key, !material.from_keyset)),
            };
            let Some((public_key, from_context)) = material else {
                all_ok = false;
                continue;
            };
            if ed25519::verify(&public_key, &entry.decoded_value, &message).is_err() {
                all_ok = false;
                continue;
            }
            context_trusted |= from_context;
            // (2) Trusted in the final closure, or the old key of a valid
            // rotation (with explicit old material) whose new key is trusted.
            let trusted =
                self.trusted.contains_key(&entry.key) || self.rotated_to_trusted(&entry.key);
            if !trusted {
                all_ok = false;
                continue;
            }
            // (3) Window and revocations at the previous `created_at`.
            if let Some((from, until)) = self.governing_window(&entry.key) {
                if from.is_some_and(|from| created_at < from)
                    || until.is_some_and(|until| created_at > until)
                {
                    all_ok = false;
                    continue;
                }
            }
            let state = self.key_revocation_state(&entry.key, None);
            if state.retired_from.is_some_and(|t| created_at >= t)
                || state.compromised_from.is_some_and(|t| created_at >= t)
            {
                all_ok = false;
            }
        }
        (any_known && all_ok, context_trusted)
    }

    /// True when `key` is the `old_key` of a valid rotation record that lists
    /// `old_public_key` and whose `new_key` is trusted (§11.5 W1 rule 2).
    fn rotated_to_trusted(&mut self, key: &str) -> bool {
        let candidates: Vec<(usize, String)> = self
            .slots
            .iter()
            .enumerate()
            .filter_map(|(index, slot)| match slot.body.as_ref() {
                Some(KindBody::KeyRotated(body))
                    if body.old_key == key && body.old_public_key.is_some() =>
                {
                    Some((index, body.new_key.clone()))
                }
                _ => None,
            })
            .collect();
        for (index, new_key) in candidates {
            if self.trusted.contains_key(&new_key) && self.slot_is_valid(index) {
                return true;
            }
        }
        false
    }
}

// ---------------------------------------------------------------------------
// Container cross-record checks (§10.3, §8.5, §5.4 idempotency)
// ---------------------------------------------------------------------------

impl World {
    /// Runs the cross-record checks of the container order (§14.5 step 8).
    pub fn container_cross_checks(&mut self) -> CrossCheckOutcome {
        let mut outcome = CrossCheckOutcome::default();
        let count = self.target_count;
        let mut local_only = false;
        let mut erasure_slots: Vec<usize> = Vec::new();
        let mut placeholder_slots: Vec<usize> = Vec::new();
        let mut idempotency: BTreeMap<(String, String, String), Vec<usize>> = BTreeMap::new();
        for index in 0..count {
            let Some(record) = self.slots[index].record.clone() else {
                continue;
            };
            match &record.parsed {
                ParsedRecord::Erased(placeholder) => {
                    placeholder_slots.push(index);
                    let _ = placeholder;
                }
                ParsedRecord::Invalid(_) => {}
                ParsedRecord::Normal(envelope) => {
                    if let Some(labels) = &envelope.labels {
                        if labels.sensitivity.as_deref() == Some("local-only") {
                            local_only = true;
                        }
                    }
                    if let Some(idempotency_key) = &envelope.actor.idempotency_key {
                        idempotency
                            .entry((
                                envelope.origin.project.clone(),
                                envelope.origin.instance.clone(),
                                idempotency_key.clone(),
                            ))
                            .or_default()
                            .push(index);
                    }
                    if record.kind() == "weave.erasure" {
                        erasure_slots.push(index);
                    }
                }
            }
        }
        if local_only {
            outcome.container_errors.push(e::LABEL_LOCAL_ONLY_EXPORTED);
        }
        for indices in idempotency.values() {
            if indices.len() > 1 {
                outcome.container_notices.push(n::IDEMPOTENCY_DUPLICATE);
                break;
            }
        }
        // Erasure cross-checks, evaluated from both directions.
        for &erasure_slot in &erasure_slots {
            let Some(KindBody::Erasure(body)) = self.slots[erasure_slot].body.clone() else {
                continue;
            };
            let erased_ref = body.erased.clone();
            let lookup = identity_key(&erased_ref.origin, &erased_ref.id);
            let candidates = self.by_origin_id.get(&lookup).cloned().unwrap_or_default();
            let mut matching_placeholder: Option<usize> = None;
            for candidate in candidates {
                if candidate >= count {
                    continue;
                }
                let Some(record) = self.slots[candidate].record.clone() else {
                    continue;
                };
                if let ParsedRecord::Erased(placeholder) = &record.parsed {
                    if matching_placeholder.is_none() {
                        matching_placeholder = Some(candidate);
                    }
                    let _ = placeholder;
                }
            }
            let Some(placeholder_slot) = matching_placeholder else {
                outcome.container_errors.push(e::ERASE_DIGEST_MISMATCH);
                continue;
            };
            let placeholder = self.slots[placeholder_slot]
                .record
                .as_ref()
                .and_then(RecordFile::erased)
                .cloned();
            let Some(placeholder) = placeholder else {
                continue;
            };
            if placeholder.digest != erased_ref.digest {
                outcome.container_errors.push(e::ERASE_DIGEST_MISMATCH);
            }
            // Rule 2: the placeholder's attestation must resolve to this record.
            // Cross-checks use identity+digest matching, not the target's own
            // verdict: an erasure record can be invalid for its own reasons
            // (E_ERASE_ACTOR) while still being the attested record.
            let Some(erasure_record) = self.slots[erasure_slot].record.clone() else {
                continue;
            };
            let erasure_digest = erasure_record.digest();
            if placeholder.attestation.digest != erasure_digest {
                outcome.container_errors.push(e::ERASE_ATTESTATION);
            }
        }
        for &placeholder_slot in &placeholder_slots {
            let Some(placeholder) = self.slots[placeholder_slot]
                .record
                .as_ref()
                .and_then(RecordFile::erased)
                .cloned()
            else {
                continue;
            };
            // Rule 1 + 3: a live record with the same identity and the original
            // digest contradicts the placeholder; two placeholders for the same
            // target are also a contradiction.
            let lookup = identity_key(&placeholder.origin, &placeholder.id);
            let candidates = self.by_origin_id.get(&lookup).cloned().unwrap_or_default();
            let mut placeholder_count = 0usize;
            for candidate in candidates {
                if candidate >= count {
                    continue;
                }
                let Some(record) = self.slots[candidate].record.clone() else {
                    continue;
                };
                match &record.parsed {
                    ParsedRecord::Erased(_) => placeholder_count += 1,
                    ParsedRecord::Normal(_) => {
                        if record.digest() == placeholder.digest {
                            outcome.container_errors.push(e::ERASE_CONTRADICTION);
                        }
                    }
                    ParsedRecord::Invalid(_) => {}
                }
            }
            if placeholder_count > 1 {
                outcome.container_errors.push(e::ERASE_CONTRADICTION);
            }
            // Rule 2 from the placeholder side: the attestation reference must
            // resolve to an erasure record (§10.3). The digest agreement between
            // the erasure record's `erased` reference and the placeholder's
            // original digest is rule 1, reported from the erasure-record side as
            // E_ERASE_DIGEST_MISMATCH.
            let mut resolved_ok = false;
            if let Some(target) = self.identity_match(&placeholder.attestation) {
                if self.slots[target].kind() == Some("weave.erasure") {
                    resolved_ok = true;
                }
            }
            if !resolved_ok {
                outcome.container_errors.push(e::ERASE_ATTESTATION);
            }
        }
        outcome.container_errors.sort_unstable();
        outcome.container_errors.dedup();
        outcome.container_notices.sort_unstable();
        outcome.container_notices.dedup();
        // §14.7 test-only hook: skipped checks are treated as passed.
        outcome
            .container_errors
            .retain(|code| !self.options.skipped(code));
        outcome
    }
}

impl World {
    /// Validates a grant record's own delegation chain at `at`: used by the
    /// record pipeline's kind-semantics step for `weave.grant` records.
    pub(crate) fn check_grant_record_chain(
        &mut self,
        index: usize,
        at: Timestamp,
    ) -> Result<(), Code> {
        let Some(KindBody::Grant(body)) = self.slots[index].body.clone() else {
            return Err(e::GRANT_SCHEMA);
        };
        if body.action != GrantActionKind::Grant {
            return Ok(());
        }
        let Some(record) = self.slots[index].record.clone() else {
            return Err(e::GRANT_UNRESOLVED);
        };
        let Some(actor) = record.envelope().map(|envelope| envelope.actor.clone()) else {
            return Err(e::GRANT_UNRESOLVED);
        };
        match actor.actor_type.as_str() {
            // §5.5.2 step 6 (S9): a root grant record is not judged against
            // its own window or revocation at its own `recorded_at`.
            "human" | "organization" => Ok(()),
            "agent" => {
                let too_deep =
                    self.grant_chain_check(index, 0, crate::limits::MAX_GRANT_CHAIN + 1)?;
                // Only the ancestors are judged at the grant's own
                // `recorded_at` (S9); the chain starts at the parent.
                let parent = actor
                    .grant
                    .as_ref()
                    .and_then(|reference| self.resolve(reference).target_slot)
                    .ok_or(e::GRANT_UNRESOLVED)?;
                self.grant_chain_validity(parent, at)?;
                // §5.5.2 step 7 after step 6 (F68).
                if too_deep {
                    return Err(e::GRANT_UNRESOLVED);
                }
                Ok(())
            }
            _ => Err(e::GRANT_UNRESOLVED),
        }
    }

    /// The revoker keys authorised for a grant by §5.5.4: the explicit
    /// `grant.revocation` list when present, otherwise the granter's key and its
    /// explicit rotation successors (depth at most 8).
    pub(crate) fn authorised_revoker_keys(&mut self, grant_slot: usize) -> Vec<String> {
        let Some(KindBody::Grant(body)) = self.slots[grant_slot].body.clone() else {
            return Vec::new();
        };
        let Some(spec) = body.grant.clone() else {
            return Vec::new();
        };
        if let Some(revokers) = spec.revocation {
            return revokers;
        }
        let Some(record) = self.slots[grant_slot].record.clone() else {
            return Vec::new();
        };
        let Some(granter) = record.envelope().map(|envelope| envelope.actor.key.clone()) else {
            return Vec::new();
        };
        let mut authorised = vec![granter.clone()];
        // Explicit rotation successors through valid rotation records only, at
        // most MAX_GRANT_CHAIN rotation steps (§5.5.4, S10).
        let rotations: Vec<(usize, String, String)> = self
            .slots
            .iter()
            .enumerate()
            .filter_map(|(index, slot)| match slot.body.as_ref() {
                Some(KindBody::KeyRotated(rotated)) => {
                    Some((index, rotated.old_key.clone(), rotated.new_key.clone()))
                }
                _ => None,
            })
            .collect();
        let mut edges: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (index, old_key, new_key) in rotations {
            if self.slot_is_valid(index) {
                edges.entry(old_key).or_default().push(new_key);
            }
        }
        let mut frontier = vec![granter];
        let mut seen: BTreeSet<String> = authorised.iter().cloned().collect();
        for _ in 0..crate::limits::MAX_GRANT_CHAIN {
            let mut next = Vec::new();
            for key in frontier {
                if let Some(successors) = edges.get(&key) {
                    for successor in successors {
                        if seen.insert(successor.clone()) {
                            authorised.push(successor.clone());
                            next.push(successor.clone());
                        }
                    }
                }
            }
            frontier = next;
            if frontier.is_empty() {
                break;
            }
        }
        authorised
    }
}
