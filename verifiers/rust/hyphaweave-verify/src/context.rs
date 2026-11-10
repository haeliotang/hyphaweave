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
use crate::timestamp::ChainEvidence;

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
    /// Invalid errors contributed by known-algorithm signatures that fail.
    pub invalid_errors: Vec<Code>,
    /// Unverifiable errors contributed when no required signature can be
    /// established.
    pub unverifiable_errors: Vec<Code>,
    /// Notices.
    pub notices: Vec<Code>,
    /// True when at least one valid known-algorithm signature exists.
    pub verified: bool,
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
    /// Inverted validity window (reported by the body schema check).
    Validity,
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
}

/// Explicit key material supplied by a `weave.key.rotated` record (§9.2 rule 5).
#[derive(Clone, Debug)]
pub(crate) struct RotationMaterial {
    /// Raw public key.
    pub public_key: [u8; 32],
    /// Class named by the rotation's `actor.type`.
    pub class: String,
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

/// One target's verification context.
pub struct World {
    pub(crate) slots: Vec<Slot>,
    pub(crate) target_count: usize,
    pub(crate) options: VerifyOptions,
    pub(crate) evidence: ChainEvidence,
    pub(crate) by_origin_id: HashMap<(String, String), Vec<usize>>,
    pub(crate) trusted: BTreeMap<String, TrustedKey>,
    /// Trusted keys that came from the local keyset (no `N_KEY_TOFU`).
    pub(crate) keyset_roots: BTreeSet<String>,
    pub(crate) rotation_material: BTreeMap<String, RotationMaterial>,
    /// Report-limitation flags collected while verifying (§14.9; the reference
    /// report emits prose only for the features that were actually present).
    pub(crate) limitation_flags: BTreeSet<&'static str>,
    /// True when this context verifies a container target (as opposed to one
    /// standalone record); some limitations are container-only in the reference
    /// report.
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
        let target_count = results.len();
        let mut world = Self {
            slots: Vec::with_capacity(target_count + options.keyset.len()),
            target_count,
            options: options.clone(),
            evidence: ChainEvidence::none(),
            by_origin_id: HashMap::new(),
            trusted: BTreeMap::new(),
            keyset_roots: BTreeSet::new(),
            rotation_material: BTreeMap::new(),
            limitation_flags: BTreeSet::new(),
            container_context: false,
        };
        for result in results {
            let slot = match result {
                Ok(record) => Slot::new(Some(record), None, SlotSource::Target),
                Err(code) => Slot::new(None, Some(code), SlotSource::Target),
            };
            world.push_slot(slot);
        }
        for bytes in &options.keyset {
            let record = envelope::parse_record_file(bytes).map_err(|code| {
                UsageError(format!(
                    "keyset file is not a structurally valid record: {code}"
                ))
            })?;
            if let Some(partial) = record.invalid() {
                return Err(UsageError(format!(
                    "keyset file is not a structurally valid record: {}",
                    partial.code
                )));
            }
            // Signature presence/format is part of the structural check (§14.1).
            envelope::parse_sigs(&record.object).map_err(|code| {
                UsageError(format!(
                    "keyset file is not a structurally valid record: {code}"
                ))
            })?;
            let slot = Slot::new(Some(record), None, SlotSource::Keyset);
            world.push_slot(slot);
        }
        world.compute_digests_and_bodies()?;
        world.build_trust();
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
                    let (project, instance) = (origin.project.clone(), origin.instance.clone());
                    let id = record.id().to_owned();
                    self.by_origin_id
                        .entry((project.clone(), id))
                        .or_default()
                        .push(index);
                    let _ = instance;
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
            let body_result = {
                let record = self.slots[index].record.as_ref().expect("record present");
                kinds::parse_body(record)
            };
            match body_result {
                Ok(body) => {
                    if self.slots[index].source == SlotSource::Keyset
                        && !matches!(body, KindBody::Opaque)
                    {
                        // The kind body is part of the keyset structural check.
                        // (A parse failure was turned into a usage error below.)
                    }
                    self.slots[index].body = Some(body);
                }
                Err(code) => {
                    if self.slots[index].source == SlotSource::Keyset {
                        return Err(UsageError(format!(
                            "keyset file is not a structurally valid record: {code}"
                        )));
                    }
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
            kind_known: Some(false),
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
                    report.kind_known = Some(partial.kind_known);
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

    /// Records that a §14.9 limitation applies to this run.
    pub(crate) fn note_limitation(&mut self, flag: &'static str) {
        self.limitation_flags.insert(flag);
    }

    /// Builds the report's `limitations` prose (§14.9). The specification fixes
    /// the duty to list what was not verified, not the wording; the H1 verifier
    /// mirrors the reference report wording so gate 3 can compare bytes.
    #[must_use]
    pub(crate) fn limitations(
        &self,
        container: Option<&crate::report::ContainerReport>,
    ) -> Vec<String> {
        const OFFLINE: &str = "Offline verification: only this container's records and the supplied keyset are in the verification context; references to records outside the context resolve as missing.";
        const CHAIN: &str = "The internal hash chain of a claimed L1/L2 container cannot be recomputed offline: chain.status is unverified and level_verified is reported as L0.";
        const NO_ANCHOR: &str = "No matching TSA trust anchor was available: timestamps are present-unverified and the container cannot be reported valid.";
        const PREVIOUS: &str = "The embedded previous manifest's own signature was not re-verified; only its digest was checked against previous_manifest.digest.";
        const KEY_TRUST: &str = "Key trust is trust-on-first-use from key-lifecycle records in the context; no certificate authority, network lookup or pinned local trust store was consulted.";
        const UNREGISTERED: &str = "An unregistered kind is transported and integrity-checked but its body is never interpreted (K3 forward compatibility).";
        const ERASED: &str = "A weave.erased placeholder has no content: its integrity rests on the signed attestation, the retained original digest and the manifest entry, not on a hash of the deleted record.";
        const LABELS: &str = "Labels, consent coverage and licences are claims checked for consistency only; their truth is not established offline.";
        let mut out = vec![OFFLINE.to_owned()];
        let chain_unverified = container
            .and_then(|container| container.chain.as_ref())
            .is_some_and(|chain| chain.status == "unverified");
        if chain_unverified {
            out.push(CHAIN.to_owned());
        }
        if container.is_some_and(|container| {
            container.level_claimed.as_deref() == Some("L2")
                && container.anchor_verified == Some(false)
                && !container.timestamps.is_empty()
        }) {
            out.push(NO_ANCHOR.to_owned());
        }
        if container.is_some_and(|container| container.previous_manifest_digest.is_some()) {
            out.push(PREVIOUS.to_owned());
        }
        if self.limitation_flags.contains("keytrust") {
            out.push(KEY_TRUST.to_owned());
        }
        if self.limitation_flags.contains("unreg") {
            out.push(UNREGISTERED.to_owned());
        }
        if self.limitation_flags.contains("erased") {
            out.push(ERASED.to_owned());
        }
        if self.limitation_flags.contains("labels") {
            out.push(LABELS.to_owned());
        }
        out
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
// Trust roots and declarations (§5.3, §9.1, R2)
// ---------------------------------------------------------------------------

impl World {
    /// Builds the trusted-key fixed point from the keyset and the target
    /// declarations.
    fn build_trust(&mut self) {
        // Candidate declarations: every parseable `weave.key.declared` record.
        let mut candidates: Vec<usize> = Vec::new();
        let mut infos: Vec<(usize, DeclInfo)> = Vec::new();
        for (index, slot) in self.slots.iter().enumerate() {
            if slot.kind() != Some("weave.key.declared") {
                continue;
            }
            if slot.record.is_none() || slot.envelope_error.is_some() {
                continue;
            }
            let Some(KindBody::KeyDeclared(body)) = slot.body.as_ref() else {
                continue;
            };
            let Some(public_key) =
                <Vec<u8> as TryInto<[u8; 32]>>::try_into(body.public_key.clone()).ok()
            else {
                continue;
            };
            infos.push((
                index,
                DeclInfo {
                    class: body.key_type.clone(),
                    public_key,
                    owner: body.owner.clone(),
                    valid_from: body.valid_from,
                    valid_until: body.valid_until,
                },
            ));
            candidates.push(index);
        }
        for (index, info) in infos {
            self.slots[index].decl = Some(info);
        }

        // Keyset first: a valid human/organization keyset declaration is a
        // trust root, and a keyset automated declaration may extend that trust
        // through its owner cosignature (the keyset is the local trust input).
        self.keyset_roots.clear();
        let mut changed = true;
        while changed {
            changed = false;
            for &index in &candidates {
                if self.slots[index].source != SlotSource::Keyset {
                    continue;
                }
                let key = self.decl_key(index);
                if key.is_some() && !self.trusted.contains_key(&key.clone().unwrap_or_default()) {
                    if let Some(key) = self.try_trust_candidate(index) {
                        self.keyset_roots.insert(key);
                        changed = true;
                    }
                }
            }
        }

        // Then the container/target declarations close over the keyset roots.
        let mut changed = true;
        while changed {
            changed = false;
            for &index in &candidates {
                let Some(key) = self.decl_key(index) else {
                    continue;
                };
                if self.trusted.contains_key(&key) {
                    continue;
                }
                if self.try_trust_candidate(index).is_some() {
                    changed = true;
                }
            }
        }

        // Compute declaration resolution: the earliest valid declaration
        // governs; a tie is broken by the lexicographically smallest digest.
        let mut governing: HashMap<String, usize> = HashMap::new();
        for &index in &candidates {
            if self.slots[index].decl_issue != DeclIssue::None {
                continue;
            }
            let Some(key) = self.decl_key(index) else {
                continue;
            };
            match governing.get(&key).copied() {
                None => {
                    governing.insert(key, index);
                }
                Some(current) => {
                    let candidate_is_earlier = self.declared_earlier(index, current);
                    if candidate_is_earlier {
                        governing.insert(key, index);
                    }
                }
            }
        }
        for (key, index) in governing {
            if let Some(info) = self.slots[index].decl.clone() {
                let Some(digest_string) = self.slots[index].digest.clone() else {
                    continue;
                };
                let _ = digest_string;
                self.trusted.insert(
                    key,
                    TrustedKey {
                        class: info.class,
                        public_key: info.public_key,
                        valid_from: info.valid_from,
                        valid_until: info.valid_until,
                    },
                );
            }
        }
        self.collect_rotation_material();
    }

    fn declared_earlier(&self, candidate: usize, current: usize) -> bool {
        let candidate_time = self.decl_recorded_at(candidate);
        let current_time = self.decl_recorded_at(current);
        match (candidate_time, current_time) {
            (Some(left), Some(right)) => match left.cmp(&right) {
                std::cmp::Ordering::Less => true,
                std::cmp::Ordering::Greater => false,
                std::cmp::Ordering::Equal => {
                    let left = self.slots[candidate].digest.clone().unwrap_or_default();
                    let right = self.slots[current].digest.clone().unwrap_or_default();
                    utf16_cmp(&left, &right) == std::cmp::Ordering::Less
                }
            },
            _ => false,
        }
    }

    fn decl_recorded_at(&self, index: usize) -> Option<Timestamp> {
        let record = self.slots[index].record.as_ref()?;
        record.envelope().map(|envelope| envelope.recorded_at)
    }

    /// The declared key id of a declaration candidate.
    pub(crate) fn decl_key(&self, index: usize) -> Option<String> {
        match self.slots[index].body.as_ref() {
            Some(KindBody::KeyDeclared(body)) => Some(body.key.clone()),
            _ => None,
        }
    }

    /// Evaluates one declaration candidate's trust condition and, when the
    /// declaration is valid, registers its key; returns the newly trusted key.
    fn try_trust_candidate(&mut self, index: usize) -> Option<String> {
        let Some(KindBody::KeyDeclared(body)) = self.slots[index].body.clone() else {
            self.slots[index].decl_issue = DeclIssue::BodyInvalid;
            return None;
        };
        let Some(decl) = self.slots[index].decl.clone() else {
            self.slots[index].decl_issue = DeclIssue::BodyInvalid;
            return None;
        };
        // Window ordering is part of the body check (§9.1 rule 5).
        if let (Some(from), Some(until)) = (decl.valid_from, decl.valid_until) {
            if from > until {
                self.slots[index].decl_issue = DeclIssue::Validity;
                return None;
            }
        }
        let record = self.slots[index].record.clone()?;
        let digest_string = self.slots[index].digest.clone()?;
        let message = digest::record_signature_message(&digest_string);
        let self_signature_valid =
            self.declaration_self_signature_valid(&record, &decl, &body.key, &message);
        if !self_signature_valid {
            self.slots[index].decl_issue = DeclIssue::SelfSignature;
            return None;
        }
        if self.trusted.contains_key(&body.key) {
            self.slots[index].decl_issue = DeclIssue::None;
            return Some(body.key);
        }
        let is_human_org = matches!(decl.class.as_str(), "human" | "organization");
        let is_keyset = self.slots[index].source == SlotSource::Keyset;
        if is_human_org {
            // The local keyset is the verifier's trust statement (§5.3, R2): a
            // valid human/organization keyset declaration is a root and needs no
            // cosignature. A container/target declaration needs a cosignature by
            // an already trusted human/organization key.
            if is_keyset {
                self.insert_trusted(&body.key, &decl);
                self.slots[index].decl_issue = DeclIssue::None;
                return Some(body.key);
            }
            let cosigned = self.declaration_cosigned_by_trusted(&record, &message, &body.key);
            if cosigned {
                self.insert_trusted(&body.key, &decl);
                self.slots[index].decl_issue = DeclIssue::None;
                return Some(body.key);
            }
            self.slots[index].decl_issue = DeclIssue::UntrustedSelfAttested;
            return None;
        }
        // Automated declaration (§9.1 rules 3–4).
        let Some(owner) = decl.owner.clone() else {
            self.slots[index].decl_issue = DeclIssue::OwnerMissing;
            return None;
        };
        let owner_class = self.declared_class_any(&owner);
        match owner_class {
            None => {
                self.slots[index].decl_issue = DeclIssue::OwnerUnknown;
                return None;
            }
            Some(class) if !matches!(class.as_str(), "human" | "organization") => {
                self.slots[index].decl_issue = DeclIssue::OwnerMissing;
                return None;
            }
            Some(_) => {}
        }
        let owner_cosigned = self.declaration_owner_cosigned(&record, &message, &owner);
        if !owner_cosigned {
            self.slots[index].decl_issue = DeclIssue::NotCosigned;
            return None;
        }
        if !self.trusted.contains_key(&owner) {
            self.slots[index].decl_issue = DeclIssue::OwnerUntrusted;
            return None;
        }
        self.insert_trusted(&body.key, &decl);
        self.slots[index].decl_issue = DeclIssue::None;
        Some(body.key)
    }

    fn insert_trusted(&mut self, key: &str, decl: &DeclInfo) {
        self.trusted.insert(
            key.to_owned(),
            TrustedKey {
                class: decl.class.clone(),
                public_key: decl.public_key,
                valid_from: decl.valid_from,
                valid_until: decl.valid_until,
            },
        );
    }

    /// Class of a key according to any parseable declaration in the context
    /// (regardless of trust), or from explicit rotation material.
    pub(crate) fn declared_class_any(&self, key: &str) -> Option<String> {
        for slot in &self.slots {
            if let Some(KindBody::KeyDeclared(body)) = slot.body.as_ref() {
                if body.key == key {
                    let class = &body.key_type;
                    if !class.is_empty() {
                        return Some(class.clone());
                    }
                }
            }
        }
        self.rotation_material
            .get(key)
            .map(|material| material.class.clone())
    }

    fn declaration_self_signature_valid(
        &self,
        record: &RecordFile,
        decl: &DeclInfo,
        declared_key: &str,
        message: &[u8],
    ) -> bool {
        let Ok(Some(entries)) = envelope::parse_sigs(&record.object) else {
            return false;
        };
        entries.iter().any(|entry| {
            entry.known_algorithm
                && entry.key == declared_key
                && ed25519::verify(&decl.public_key, &entry.decoded_value, message).is_ok()
        })
    }

    fn declaration_cosigned_by_trusted(
        &mut self,
        record: &RecordFile,
        message: &[u8],
        declared_key: &str,
    ) -> bool {
        let Ok(Some(entries)) = envelope::parse_sigs(&record.object) else {
            return false;
        };
        for entry in entries {
            if !entry.known_algorithm || entry.key == declared_key {
                continue;
            }
            let Some(trusted) = self.trusted.get(&entry.key).cloned() else {
                continue;
            };
            if !matches!(trusted.class.as_str(), "human" | "organization") {
                continue;
            }
            if ed25519::verify(&trusted.public_key, &entry.decoded_value, message).is_ok() {
                return true;
            }
        }
        false
    }

    fn declaration_owner_cosigned(
        &mut self,
        record: &RecordFile,
        message: &[u8],
        owner: &str,
    ) -> bool {
        let Ok(Some(entries)) = envelope::parse_sigs(&record.object) else {
            return false;
        };
        let owner_public_key = self
            .trusted
            .get(owner)
            .map(|trusted| trusted.public_key)
            .or_else(|| self.declaration_public_key(owner));
        let Some(owner_public_key) = owner_public_key else {
            return false;
        };
        entries.iter().any(|entry| {
            entry.known_algorithm
                && entry.key == owner
                && ed25519::verify(&owner_public_key, &entry.decoded_value, message).is_ok()
        })
    }

    fn declaration_public_key(&self, key: &str) -> Option<[u8; 32]> {
        for slot in &self.slots {
            if let Some(KindBody::KeyDeclared(body)) = slot.body.as_ref() {
                if body.key == key {
                    if let Ok(public_key) =
                        <Vec<u8> as TryInto<[u8; 32]>>::try_into(body.public_key.clone())
                    {
                        return Some(public_key);
                    }
                }
            }
        }
        None
    }

    fn collect_rotation_material(&mut self) {
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
            if let Ok(public_key) =
                <Vec<u8> as TryInto<[u8; 32]>>::try_into(body.new_public_key.clone())
            {
                self.rotation_material
                    .entry(body.new_key.clone())
                    .or_insert(RotationMaterial {
                        public_key,
                        class: class.clone(),
                    });
            }
            if let Some(old_public_key) = &body.old_public_key {
                if let Ok(public_key) =
                    <Vec<u8> as TryInto<[u8; 32]>>::try_into(old_public_key.clone())
                {
                    self.rotation_material
                        .entry(body.old_key.clone())
                        .or_insert(RotationMaterial { public_key, class });
                }
            }
        }
    }

    /// Class of a key if it is available (trusted declaration or explicit
    /// rotation material).
    #[must_use]
    pub(crate) fn key_class(&self, key: &str) -> Option<String> {
        self.trusted
            .get(key)
            .map(|trusted| trusted.class.clone())
            .or_else(|| {
                self.rotation_material
                    .get(key)
                    .map(|material| material.class.clone())
            })
    }
}

// ---------------------------------------------------------------------------
// Signature checking and key lifecycle (§3.4, §9.4)
// ---------------------------------------------------------------------------

/// Key material resolved for one signature.
struct SignatureMaterial {
    public_key: [u8; 32],
    class: Option<String>,
    /// Validity window from the governing trusted declaration, when the
    /// material came from one.
    window: Option<(Option<Timestamp>, Option<Timestamp>)>,
    /// Provenance of the material.
    source: MaterialSource,
}

impl World {
    /// Resolves public-key material for `key_id`.
    ///
    /// Priority: explicit self material supplied by the record under
    /// verification (a declaration states its own key, a rotation states both,
    /// §9.5), then the governing trusted declaration, then explicit rotation
    /// material. An untrusted declaration never makes a key usable (§9.4/R2).
    fn resolve_signature_material(
        &self,
        key_id: &str,
        self_material: Option<&[u8]>,
        allow_untrusted_declaration: bool,
    ) -> Option<SignatureMaterial> {
        if let Some(bytes) = self_material {
            if bytes.len() == 32 {
                let mut public_key = [0u8; 32];
                public_key.copy_from_slice(bytes);
                return Some(SignatureMaterial {
                    public_key,
                    class: self.key_class(key_id),
                    window: None,
                    source: MaterialSource::SelfRecord,
                });
            }
        }
        if let Some(trusted) = self.trusted.get(key_id) {
            return Some(SignatureMaterial {
                public_key: trusted.public_key,
                class: Some(trusted.class.clone()),
                window: Some((trusted.valid_from, trusted.valid_until)),
                source: MaterialSource::TrustedDeclaration,
            });
        }
        if let Some(material) = self.rotation_material.get(key_id) {
            return Some(SignatureMaterial {
                public_key: material.public_key,
                class: Some(material.class.clone()),
                window: None,
                source: MaterialSource::Rotation,
            });
        }
        if allow_untrusted_declaration {
            // Manifest attestation signatures (§11.3) are satisfied by a
            // signature by a *declared* key; the declaration need not be a
            // trust root (a container declaration that is E_KEY_UNTRUSTED still
            // declares the key that signed the manifest).
            return self
                .declaration_public_key(key_id)
                .map(|public_key| SignatureMaterial {
                    public_key,
                    class: self.declared_class_any(key_id),
                    window: None,
                    source: MaterialSource::UntrustedDeclaration,
                });
        }
        None
    }

    /// Checks one signature through the context: key resolution, the §3.4
    /// crypto profile, and the §9.4 key-lifecycle effects at the claimed time.
    ///
    /// `self_material` is key material supplied by the record being verified
    /// (declaration key, rotation old/new keys); `manifest` selects the
    /// attestation-file error mapping of a manifest signature;
    /// `ignore_revocation_for` suppresses revocation effects for the key of a
    /// revocation record itself (§9.5, self-evidencing).
    #[allow(clippy::too_many_arguments)] // mirrors the §3.4/§9.4 check list
    pub(crate) fn check_signature(
        &mut self,
        key_id: &str,
        signature: &[u8],
        message: &[u8],
        claimed_at: Timestamp,
        self_material: Option<&[u8]>,
        manifest: bool,
        ignore_revocation_for: Option<&str>,
        allow_untrusted_declaration: bool,
    ) -> SignatureResolution {
        if signature.len() != 64 {
            let code = if manifest {
                e::MANIFEST_SCHEMA
            } else {
                e::ENV_SIG_VALUE
            };
            return SignatureResolution::invalid(code);
        }
        let Some(material) = self.resolve_signature_material(
            key_id,
            self_material,
            manifest || allow_untrusted_declaration,
        ) else {
            return SignatureResolution {
                state: SigState::Unverified(e::KEY_UNKNOWN),
                key_class: self.declared_class_any(key_id),
                material_source: None,
                material_from_context: false,
            };
        };
        let material_source = Some(material.source);
        let material_from_context = material.source != MaterialSource::SelfRecord;
        if let Err(code) = ed25519::verify(&material.public_key, signature, message) {
            let mapped = if manifest {
                e::MANIFEST_SIG_INVALID
            } else {
                code
            };
            return SignatureResolution {
                state: SigState::Invalid(mapped),
                key_class: material.class.clone(),
                material_source,
                material_from_context,
            };
        }
        if let Some((Some(valid_from), _)) = material.window {
            if claimed_at < valid_from {
                return SignatureResolution {
                    state: SigState::Invalid(e::KEY_EXPIRED),
                    key_class: material.class,
                    material_source,
                    material_from_context,
                };
            }
        }
        if let Some((_, Some(valid_until))) = material.window {
            if claimed_at > valid_until {
                return SignatureResolution {
                    state: SigState::Invalid(e::KEY_EXPIRED),
                    key_class: material.class,
                    material_source,
                    material_from_context,
                };
            }
        }
        if ignore_revocation_for != Some(key_id) {
            if let Some((reason, effective_at)) = self.key_revocation_state(key_id) {
                match reason {
                    RevokeReason::Compromise => {
                        let boundary_us = effective_at.to_unix_millis() * 1_000;
                        let bounds = self.evidence.rescue_bounds_us();
                        if bounds.iter().any(|bound| *bound < boundary_us) {
                            return SignatureResolution {
                                state: SigState::Valid,
                                key_class: material.class,
                                material_source,
                                material_from_context,
                            };
                        }
                        if self.evidence.has_receipts() && bounds.is_empty() {
                            return SignatureResolution {
                                state: SigState::Unverified(e::TS_UNTRUSTED),
                                key_class: material.class,
                                material_source,
                                material_from_context,
                            };
                        }
                        return SignatureResolution {
                            state: SigState::Invalid(e::KEY_COMPROMISED),
                            key_class: material.class,
                            material_source,
                            material_from_context,
                        };
                    }
                    RevokeReason::Retired | RevokeReason::Other => {
                        if claimed_at >= effective_at {
                            return SignatureResolution {
                                state: SigState::Invalid(e::KEY_REVOKED),
                                key_class: material.class,
                                material_source,
                                material_from_context,
                            };
                        }
                    }
                }
            }
        }
        SignatureResolution {
            state: SigState::Valid,
            key_class: material.class,
            material_source,
            material_from_context,
        }
    }

    /// The most recent valid key revocation that applies to `key_id`, if any.
    ///
    /// Revocation records are self-evidencing (§9.5), so their own verdict is
    /// evaluated; a revocation record that is not individually valid has no
    /// effect.
    fn key_revocation_state(&mut self, key_id: &str) -> Option<(RevokeReason, Timestamp)> {
        let mut candidates: Vec<usize> = Vec::new();
        for (index, slot) in self.slots.iter().enumerate() {
            if slot.source == SlotSource::Keyset {
                continue;
            }
            if slot.kind() != Some("weave.key.revoked") {
                continue;
            }
            let Some(KindBody::KeyRevoked(body)) = slot.body.as_ref() else {
                continue;
            };
            if body.key == key_id {
                candidates.push(index);
            }
        }
        let mut best: Option<(RevokeReason, Timestamp)> = None;
        for index in candidates {
            let verdict = self.evaluate(index).verdict;
            if verdict != Verdict::Valid {
                continue;
            }
            let Some(KindBody::KeyRevoked(body)) = self.slots[index].body.clone() else {
                continue;
            };
            let replace = match &best {
                None => true,
                Some((reason, _)) => {
                    // Compromise dominates retired evidence.
                    *reason != RevokeReason::Compromise && body.reason == RevokeReason::Compromise
                }
            };
            if replace {
                best = Some((body.reason, body.effective_at));
            }
        }
        best
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
        let lookup = (reference.origin.project.clone(), reference.id.clone());
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
        let lookup = (reference.origin.project.clone(), reference.id.clone());
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
                self.grant_chain_check(index, 0)?;
            }
            _ => return Err(e::GRANT_UNRESOLVED),
        }
        self.grant_chain_validity(index, at)?;
        let _ = actor;
        Ok(UsableGrant { spec })
    }

    /// Checks the delegation-chain structure of `slot` against its parents
    /// (§5.5.2 steps 1–5, 7).
    fn grant_chain_check(&mut self, slot: usize, depth: usize) -> Result<(), Code> {
        if depth > crate::limits::MAX_GRANT_CHAIN {
            return Err(e::GRANT_UNRESOLVED);
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
            "human" | "organization" => Ok(()),
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
                self.grant_chain_check(parent_slot, depth + 1)
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
            if slot.source == SlotSource::Keyset {
                continue;
            }
            if slot.kind() != Some("weave.grant") {
                continue;
            }
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
        !revocation_slots.is_empty()
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
            if slot.source == SlotSource::Keyset {
                continue;
            }
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
    /// Checks the manifest attestation signature obligation (§11.3).
    ///
    /// `manifest_digest` is the §2.4 digest string computed by the container
    /// layer; `created_at` is the manifest's claimed creation time, which is the
    /// time used for key-lifecycle effects (§9.4).
    pub fn check_manifest_signatures(
        &mut self,
        signatures: &[SigEntry],
        manifest_digest: &str,
        created_at: &Timestamp,
    ) -> ManifestSigOutcome {
        let message = digest::manifest_signature_message(manifest_digest);
        let mut outcome = ManifestSigOutcome::default();
        let mut any_verified = false;
        let mut unknown_key = false;
        let mut ignored = 0usize;
        for entry in signatures {
            if !entry.known_algorithm {
                ignored += 1;
                continue;
            }
            let resolution = self.check_signature(
                &entry.key,
                &entry.decoded_value,
                &message,
                *created_at,
                None,
                true,
                None,
                true,
            );
            match resolution.state {
                SigState::Valid => any_verified = true,
                SigState::Invalid(code) => outcome.invalid_errors.push(code),
                SigState::Unverified(code) => {
                    if code == e::KEY_UNKNOWN {
                        unknown_key = true;
                    }
                    outcome.unverifiable_errors.push(code);
                }
            }
        }
        let _ = ignored;
        outcome.verified = any_verified;
        if !outcome.invalid_errors.is_empty() {
            outcome.invalid_errors.sort_unstable();
            outcome.invalid_errors.dedup();
            return outcome;
        }
        if any_verified {
            return outcome;
        }
        // No verifiable required signature: unverifiable, never valid.
        if unknown_key {
            outcome.unverifiable_errors.push(e::KEY_UNKNOWN);
        } else if outcome.unverifiable_errors.is_empty() {
            outcome.unverifiable_errors.push(e::SIG_UNVERIFIABLE);
        }
        outcome.unverifiable_errors.sort_unstable();
        outcome.unverifiable_errors.dedup();
        outcome
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
            let lookup = (erased_ref.origin.project.clone(), erased_ref.id.clone());
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
            let lookup = (placeholder.origin.project.clone(), placeholder.id.clone());
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
            "human" | "organization" => {}
            "agent" => self.grant_chain_check(index, 0)?,
            _ => return Err(e::GRANT_UNRESOLVED),
        }
        self.grant_chain_validity(index, at)
    }

    /// The revoker keys authorised for a grant by §5.5.4: the explicit
    /// `grant.revocation` list when present, otherwise the granter's key and its
    /// explicit rotation successors (depth at most 8).
    pub(crate) fn authorised_revoker_keys(&self, grant_slot: usize) -> Vec<String> {
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
        // Explicit rotation successors only, bounded and cycle-safe.
        let mut edges: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for slot in &self.slots {
            if slot.kind() != Some("weave.key.rotated") {
                continue;
            }
            if let Some(KindBody::KeyRotated(rotated)) = slot.body.as_ref() {
                edges
                    .entry(rotated.old_key.clone())
                    .or_default()
                    .push(rotated.new_key.clone());
            }
        }
        let mut frontier = vec![granter];
        let mut seen: BTreeSet<String> = authorised.iter().cloned().collect();
        for _ in 0..=crate::limits::MAX_GRANT_CHAIN {
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
