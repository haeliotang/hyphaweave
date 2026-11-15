// SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
// SPDX-License-Identifier: Apache-2.0

//! Single-record target verification and the per-record pipeline of §14.5.
//!
//! The pipeline order is fixed: (1) parse and canonical form, (2) envelope
//! structure, (3) `sigs` presence/format, (4) key resolution, (5) Ed25519
//! verification and key-lifecycle effects, (6) kind body schema, (7) kind
//! semantics, (8) actor/authorisation, (9) labels, (10) references. Exactly one
//! error is reported: the first failing check. Notices are accumulated.
//!
//! Container cross-record checks are layered on top by
//! [`crate::context::World::container_cross_checks`]; container-level checks are
//! in [`crate::container`].

use std::collections::BTreeMap;

use crate::b64;
use crate::context::{DeclIssue, SigState, World};
use crate::digest;
use crate::envelope::{
    self, Envelope, ParsedRecord, RecordFile, RefObject, SIGNER_CONSTRAINED_KINDS,
};
use crate::error_codes::{e, n, Code};
use crate::kinds::{GrantActionKind, KindBody, RevokeReason};
use crate::options::{UsageError, VerifyOptions};
use crate::report::{
    AttestationReport, InputIdentity, RecordReport, RefReport, Report, SigReportEntry, Summary,
    Target, Verdict, VerdictCounts,
};

/// Verifies one standalone record file.
///
/// # Errors
/// Returns a [`UsageError`] when the keyset input is not structurally valid.
pub fn verify_record_target(bytes: &[u8], options: &VerifyOptions) -> Result<Report, UsageError> {
    let parsed = envelope::parse_record_file(bytes);
    let mut world = World::from_results(vec![parsed], options)?;
    let evaluated = world.evaluate_all();
    let record = evaluated.first().cloned().unwrap_or_else(|| {
        let mut report = world.empty_report(0);
        report.verdict = Verdict::Invalid;
        report
    });
    let records = vec![record];
    let limitations = crate::limitations::compute(&records, None, world.limitation_facts(true));
    let verdict = records[0].verdict;
    let summary = count_verdicts(&records);
    // §14.6 (T16): an oversize record target has no input identity; the
    // caller reads at most MAX_RECORD_BYTES + 1 bytes and never hashes the
    // whole file.
    let input = if bytes.len() > crate::limits::MAX_RECORD_BYTES {
        InputIdentity::unknown()
    } else {
        InputIdentity::of_bytes(bytes)
    };
    Ok(Report {
        checks_disabled: options.checks_disabled(),
        report_version: crate::REPORT_VERSION.to_owned(),
        spec: crate::SPEC.to_owned(),
        target: Target::Record,
        verdict,
        input,
        records,
        container: None,
        summary: Summary::Verdicts(summary),
        limitations,
        cases: Vec::new(),
        verifier: crate::report::VerifierInfo {
            name: crate::VERIFIER_NAME.to_owned(),
            version: crate::VERIFIER_VERSION.to_owned(),
        },
    })
}

/// Counts record verdicts.
pub(crate) fn count_verdicts(records: &[RecordReport]) -> VerdictCounts {
    let mut counts = VerdictCounts::default();
    for record in records {
        match record.verdict {
            Verdict::Valid => counts.valid += 1,
            Verdict::Invalid => counts.invalid += 1,
            Verdict::Unverifiable => counts.unverifiable += 1,
            Verdict::Erased => counts.erased += 1,
        }
    }
    counts
}

/// Verdict effect of an error code per `spec/error-codes.md`.
#[must_use]
pub(crate) fn effect(code: Code) -> Verdict {
    match code {
        e::SIG_UNVERIFIABLE
        | e::KEY_UNKNOWN
        | e::KEY_UNTRUSTED
        | e::GRANT_UNRESOLVED
        | e::GRANT_REVOKED
        | e::GRANT_EXPIRED
        | e::TS_UNTRUSTED => Verdict::Unverifiable,
        _ => Verdict::Invalid,
    }
}

/// Signature facts collected by checks (3)–(5).
struct SigFacts {
    states: Vec<SigReportEntry>,
    /// Cryptographically valid signature keys -> declared class (when known).
    valid_keys: BTreeMap<String, Option<String>>,
    /// Known-algorithm entries.
    known_count: usize,
    /// Keys with no usable material (undeclared or untrusted declarations).
    unknown_keys: Vec<String>,
    /// First invalid known-algorithm signature in array order.
    first_invalid: Option<Code>,
    /// First unverifiable known-algorithm signature in array order whose code
    /// is not `E_KEY_UNKNOWN` (for example `E_TS_UNTRUSTED` from the §9.4
    /// compromise rule).
    first_unverifiable: Option<Code>,
    /// An actor-key signature was established from context declarations (the
    /// reference report calls this trust-on-first-use).
    tofu: bool,
}

impl SigFacts {
    fn any_valid(&self, key: &str) -> bool {
        self.valid_keys.contains_key(key)
    }

    fn has_verifiable_known_signature(&self) -> bool {
        !self.valid_keys.is_empty()
    }

    fn any_valid_of_class(&self, wanted: &[&str]) -> bool {
        self.valid_keys
            .values()
            .any(|class| matches!(class.as_deref(), Some(class) if wanted.contains(&class)))
    }

    fn class_of(&self, key: &str) -> Option<&str> {
        self.valid_keys.get(key).and_then(|class| class.as_deref())
    }

    fn only_self_signature(&self, key: &str) -> bool {
        self.valid_keys.len() == 1 && self.valid_keys.contains_key(key)
    }
}

/// The per-record pipeline of §14.5, invoked through [`World::evaluate`].
pub(crate) fn evaluate_normalized(world: &mut World, index: usize) -> RecordReport {
    let mut report = world.empty_report(index);
    let Some(record) = world.record_of(index).cloned() else {
        let code = world.slot(index).parse_error.unwrap_or(e::JSON_INVALID);
        report.verdict = if world.options.skipped(code) {
            Verdict::Valid
        } else {
            effect(code)
        };
        report.errors = vec![code];
        return report;
    };

    if let ParsedRecord::Invalid(partial) = &record.parsed {
        // Check (2) failed: report the received metadata and the first code.
        report.errors = vec![partial.code];
        report.verdict = if world.options.skipped(partial.code) {
            Verdict::Valid
        } else {
            effect(partial.code)
        };
        return report;
    }

    if let ParsedRecord::Erased(placeholder) = &record.parsed {
        let mut notices: Vec<Code> = Vec::new();
        let resolution = world.resolve(&placeholder.attestation);
        report.attestation = Some(AttestationReport {
            digest: placeholder.attestation.digest.clone(),
            state: resolution.state.to_owned(),
        });
        match resolution.state {
            "missing" => notices.push(n::REF_MISSING),
            "unverifiable" => notices.push(n::REF_UNVERIFIABLE),
            _ => {}
        }
        report.verdict = Verdict::Erased;
        notices.sort_unstable();
        notices.dedup();
        report.notices = notices;
        return report;
    }

    let Some(envelope) = record.envelope().cloned() else {
        return report;
    };
    let mut notices: Vec<Code> = Vec::new();

    // (3) `sigs` presence and format (§4.3) and the §4.4 absence rule.
    let signer_constrained = SIGNER_CONSTRAINED_KINDS.contains(&envelope.kind.as_str());
    let signature_required = envelope.stage == "accepted" || signer_constrained;
    let raw_sigs = record.object.get("sigs");
    let absent_or_empty = match raw_sigs {
        None => true,
        Some(value) => value
            .as_array()
            .is_some_and(<[crate::value::Value]>::is_empty),
    };
    if signature_required && absent_or_empty && !world.options.skipped(e::SIG_REQUIRED) {
        return finish(
            world,
            report,
            index,
            Some(e::SIG_REQUIRED),
            notices,
            Vec::new(),
            Vec::new(),
        );
    }
    let sigs = match envelope::parse_sigs(&record.object) {
        Ok(sigs) => sigs.unwrap_or_default(),
        Err(code) => {
            if world.options.skipped(code) {
                Vec::new()
            } else {
                return finish(
                    world,
                    report,
                    index,
                    Some(code),
                    notices,
                    Vec::new(),
                    Vec::new(),
                );
            }
        }
    };
    // §14.5 ordering exceptions (T1, T13): the key-material structure of a
    // key declaration or rotation is decided before any key resolution,
    // signature verification or trust judgement.
    if let Some(code) = crate::kinds::key_material_structural_error(&envelope) {
        if !world.options.skipped(code) {
            return finish(
                world,
                report,
                index,
                Some(code),
                notices,
                Vec::new(),
                Vec::new(),
            );
        }
    }

    // (4)/(5) key resolution, Ed25519 verification, key lifecycle.
    let facts = collect_signatures(world, index, &record, &envelope, &sigs);
    if facts.tofu {
        // §14.6/§14.9 (T10, U6): at least one of this record's signature
        // checks was context-trusted, even if the record then fails.
        notices.push(n::KEY_TOFU);
    }

    // §14.5 steps (4)/(5), §4.4 step 2 (S2-FIX1/T2): the record's code is
    // chosen invalid-first. The first entry in array order with an invalid
    // outcome (a §3.4 failure or an invalid §9.4 outcome) decides; only when
    // no entry is invalid does an unresolved key give `E_KEY_UNKNOWN`, and
    // only then the first unverifiable §9.4 outcome. `N_KEY_UNDECLARED`
    // states a fact about an entry ("a signing key has no declaration in the
    // verification context"), so it is reported whichever code decides; it is
    // paired with `E_KEY_UNKNOWN` only when that code is the record's.
    if !facts.unknown_keys.is_empty() && !world.options.skipped(e::KEY_UNKNOWN) {
        notices.push(n::KEY_UNDECLARED);
    }
    if let Some(code) = facts.first_invalid {
        if !world.options.skipped(code) {
            return finish(
                world,
                report,
                index,
                Some(code),
                notices,
                facts.states,
                Vec::new(),
            );
        }
    }
    if !facts.unknown_keys.is_empty() && !world.options.skipped(e::KEY_UNKNOWN) {
        // §3.6: an entry whose key cannot be established is not ignored.
        return finish(
            world,
            report,
            index,
            Some(e::KEY_UNKNOWN),
            notices,
            facts.states,
            Vec::new(),
        );
    }
    if let Some(code) = facts.first_unverifiable {
        if !world.options.skipped(code) {
            return finish(
                world,
                report,
                index,
                Some(code),
                notices,
                facts.states,
                Vec::new(),
            );
        }
    }

    // Ordinary records: required-signer failure is reported immediately after
    // (5), before the kind body check (§14.5, §4.4).
    if !signer_constrained && signature_required && !facts.any_valid(&envelope.actor.key) {
        let code = if facts.has_verifiable_known_signature() {
            e::SIG_REQUIRED
        } else {
            e::SIG_UNVERIFIABLE
        };
        if !world.options.skipped(code) {
            return finish(
                world,
                report,
                index,
                Some(code),
                notices,
                facts.states,
                Vec::new(),
            );
        }
    }

    // (6) kind body schema.
    let body = match world.body_of(index).cloned() {
        Some(body) => body,
        None => {
            let code = world.body_error(index).unwrap_or(e::KIND_BODY_SCHEMA);
            if !world.options.skipped(code) {
                return finish(
                    world,
                    report,
                    index,
                    Some(code),
                    notices,
                    facts.states,
                    Vec::new(),
                );
            }
            KindBody::Opaque
        }
    };

    // (7) kind semantics.
    match check_kind_semantics(
        world,
        index,
        &record,
        &envelope,
        &body,
        &facts,
        &mut notices,
    ) {
        Ok(()) => {}
        Err(code) => {
            if !world.options.skipped(code) {
                return finish(
                    world,
                    report,
                    index,
                    Some(code),
                    notices,
                    facts.states,
                    Vec::new(),
                );
            }
        }
    }

    // (8) actor and authorisation.
    match check_actor(world, &envelope, &facts, &mut notices) {
        Ok(()) => {}
        Err(code) => {
            if !world.options.skipped(code) {
                return finish(
                    world,
                    report,
                    index,
                    Some(code),
                    notices,
                    facts.states,
                    Vec::new(),
                );
            }
        }
    }

    // (9) labels, consent and propagation.
    match check_labels(world, &record, &envelope, &mut notices) {
        Ok(()) => {}
        Err(code) => {
            if !world.options.skipped(code) {
                return finish(
                    world,
                    report,
                    index,
                    Some(code),
                    notices,
                    facts.states,
                    Vec::new(),
                );
            }
        }
    }

    // (10) reference resolution and kind contradictions.
    let (refs, reference_result) = check_references(world, &envelope, &mut notices);
    if let Err(code) = reference_result {
        if !world.options.skipped(code) {
            return finish(
                world,
                report,
                index,
                Some(code),
                notices,
                facts.states,
                refs,
            );
        }
    }

    // §4.4 human-signature notice: no valid signature by a key *declared*
    // `human` in the verification context (its governing class, §5.3);
    // explicit rotation material is not a declaration.
    if envelope.stage == "accepted"
        && !facts
            .valid_keys
            .keys()
            .any(|key| world.governing_class_of(key) == Some("human"))
    {
        notices.push(n::NO_HUMAN_SIGNATURE);
    }
    // §7.3 opaque-kind notice (the report marks an opaque kind on an otherwise
    // valid record).
    if !envelope::is_registered_kind(&envelope.kind) {
        notices.push(n::KIND_UNKNOWN_OPAQUE);
    }

    finish(world, report, index, None, notices, facts.states, refs)
}

fn finish(
    _world: &World,
    mut report: RecordReport,
    _index: usize,
    error: Option<Code>,
    mut notices: Vec<Code>,
    sig_states: Vec<SigReportEntry>,
    refs: Vec<RefReport>,
) -> RecordReport {
    report.sigs = sig_states;
    report.refs = refs;
    notices.sort_unstable();
    notices.dedup();
    report.notices = notices;
    match error {
        Some(code) => {
            report.verdict = effect(code);
            report.errors = vec![code];
        }
        None => report.verdict = Verdict::Valid,
    }
    report
}

/// Checks (4) and (5): resolves each known-algorithm signature's key material,
/// verifies the signature and applies the §9.4 key-lifecycle effects.
fn collect_signatures(
    world: &mut World,
    index: usize,
    record: &RecordFile,
    envelope: &Envelope,
    sigs: &[envelope::SigEntry],
) -> SigFacts {
    let message = digest::record_signature_message(&record.digest());
    let mut facts = SigFacts {
        states: Vec::new(),
        valid_keys: BTreeMap::new(),
        known_count: 0,
        unknown_keys: Vec::new(),
        first_invalid: None,
        first_unverifiable: None,
        tofu: false,
    };
    // §9.5 (T9/U3): a key-revocation record is judged against the key state
    // of the valid revocations ordered strictly before it.
    let cutoff = if envelope.kind == "weave.key.revoked" {
        world.order_key(index)
    } else {
        None
    };
    // §5.3, §9.4 (S2-FIX1/Q2): the keys whose signatures fail a §9.4 effect
    // are recorded for the admission of a key-lifecycle record as a material
    // source; while that admission is decided, the subject key's own
    // signature (a rotation's `new_key`) is exempt from §9.4.
    let mut lifecycle_failed: Vec<String> = Vec::new();
    let exempt_key = if world.exempt_subject == Some(index) {
        envelope.body.get_str("new_key").map(str::to_owned)
    } else {
        None
    };
    for entry in sigs {
        if !entry.known_algorithm {
            facts.states.push(SigReportEntry {
                key: entry.key.clone(),
                state: "ignored".to_owned(),
            });
            continue;
        }
        facts.known_count += 1;
        let self_material = self_material_for(record, &entry.key);
        // A declaration's cosignatures may be made by keys that are declared
        // but not (yet) trusted: §4.4 reserves E_KEY_UNKNOWN for undeclared
        // keys, and the declaration's own trust outcome is decided by §9.1
        // rule 4 (pinned by key-lifecycle/nonmonotonic-closure-class-conflict).
        let owner_cosignature = envelope.kind == "weave.key.declared";
        let resolution = world.check_signature(&crate::context::SigCheck {
            key_id: &entry.key,
            signature: &entry.decoded_value,
            message: &message,
            claimed_at: envelope.recorded_at,
            self_material: self_material.as_deref(),
            manifest: false,
            revocation_cutoff: cutoff.as_ref(),
            allow_untrusted_declaration: owner_cosignature,
        });
        let lifecycle_outcome = match &resolution.state {
            SigState::Invalid(code) => {
                matches!(*code, e::KEY_EXPIRED | e::KEY_REVOKED | e::KEY_COMPROMISED)
            }
            SigState::Unverified(code) => *code == e::TS_UNTRUSTED,
            SigState::Valid => false,
        };
        if lifecycle_outcome {
            lifecycle_failed.push(entry.key.clone());
        }
        let state = if lifecycle_outcome && exempt_key.as_deref() == Some(entry.key.as_str()) {
            SigState::Valid
        } else {
            resolution.state
        };
        if resolution.material_from_context
            && (entry.key == envelope.actor.key
                || !matches!(
                    envelope.kind.as_str(),
                    "weave.key.declared" | "weave.key.rotated" | "weave.key.revoked"
                ))
        {
            facts.tofu = true;
        }
        match &state {
            SigState::Valid => {
                facts
                    .valid_keys
                    .insert(entry.key.clone(), resolution.key_class.clone());
                facts.states.push(SigReportEntry {
                    key: entry.key.clone(),
                    state: "valid".to_owned(),
                });
            }
            SigState::Invalid(code) => {
                if facts.first_invalid.is_none() {
                    facts.first_invalid = Some(*code);
                }
                // A cryptographically valid signature whose key state fails
                // (§9.4 expiry/revocation/compromise) is reported as
                // `unverified`: the signature itself verified, the key state is
                // what could not be established as valid at the claimed time.
                let state = if matches!(*code, e::KEY_EXPIRED | e::KEY_REVOKED | e::KEY_COMPROMISED)
                {
                    "unverified"
                } else {
                    "invalid"
                };
                facts.states.push(SigReportEntry {
                    key: entry.key.clone(),
                    state: state.to_owned(),
                });
            }
            SigState::Unverified(code) => {
                if *code == e::KEY_UNKNOWN {
                    facts.unknown_keys.push(entry.key.clone());
                } else if facts.first_unverifiable.is_none() {
                    // §9.4 case 2 (E_TS_UNTRUSTED) and similar established-key
                    // outcomes: unverifiable, but not an unknown-key failure.
                    facts.first_unverifiable = Some(*code);
                }
                facts.states.push(SigReportEntry {
                    key: entry.key.clone(),
                    state: "unverified".to_owned(),
                });
            }
        }
    }
    if world.exempt_subject != Some(index) {
        world.slots[index].lifecycle_failed = lifecycle_failed;
    }
    facts
}

/// Key material supplied by the record under verification (§9.5, §9.2 rule 5).
fn self_material_for(record: &RecordFile, key: &str) -> Option<Vec<u8>> {
    let body = record.object.get_object("body")?;
    match record.kind() {
        "weave.key.declared" => {
            if body.get_str("key") == Some(key) {
                let text = body.get_str("public_key")?;
                b64::decode_exact(text, 32).ok()
            } else {
                None
            }
        }
        "weave.key.rotated" => {
            // The explicit material is usable for the named key only when it
            // actually hashes to that key id (§9.2 rule 2: a contradiction is
            // E_KEY_ROTATION_KEYS and must not be papered over). When the pair
            // is inconsistent, no self material is used at all; the signature
            // keys are then established from their declarations instead.
            let public_key_for = |id_member: &str, key_member: &str| {
                let id = body.get_str(id_member)?;
                let text = body.get_str(key_member)?;
                let bytes = b64::decode_exact(text, 32).ok()?;
                if digest::derive_key_id(&bytes) == id {
                    Some((id, bytes))
                } else {
                    None
                }
            };
            let new_binding = public_key_for("new_key", "new_public_key");
            let old_binding = match body.get_str("old_public_key") {
                Some(_) => public_key_for("old_key", "old_public_key"),
                None => None,
            };
            let old_consistent = body.get_str("old_public_key").is_none() || old_binding.is_some();
            let new_consistent = new_binding.is_some();
            if !new_consistent || !old_consistent {
                return None;
            }
            if new_binding.as_ref().is_some_and(|(id, _)| *id == key) {
                return new_binding.map(|(_, bytes)| bytes);
            }
            old_binding
                .filter(|(id, _)| *id == key)
                .map(|(_, bytes)| bytes)
        }
        _ => None,
    }
}

/// §5.4 stage-to-action mapping for agent grant coverage.
fn stage_action(stage: &str) -> Option<&'static str> {
    match stage {
        "proposed" => Some("propose"),
        "accepted" => Some("accept"),
        "rejected" => Some("reject"),
        "withdrawn" => Some("withdraw"),
        "superseded" => Some("supersede"),
        _ => None,
    }
}

/// Check (7): kind semantic rules that cannot be decided by the body schema
/// alone (signer obligations, delegation chains, signer tables).
fn check_kind_semantics(
    world: &mut World,
    index: usize,
    record: &RecordFile,
    envelope: &Envelope,
    body: &KindBody,
    facts: &SigFacts,
    notices: &mut Vec<Code>,
) -> Result<(), Code> {
    let _ = record;
    match body {
        KindBody::Opaque => Ok(()),
        KindBody::KeyDeclared(declared) => {
            if !facts.has_verifiable_known_signature() {
                // §4.4 step 5, §14.5 (S2-FIX1/Q3): the signer rule and the
                // trust that needs a verified cosignature are not evaluated;
                // the rules that consult other records (owner, governing
                // class) are, and the step-5 code comes last.
                if let Some(code) = world.decl_issue_without_signatures(index) {
                    return Err(code);
                }
                return Err(e::SIG_UNVERIFIABLE);
            }
            if !facts.any_valid(&declared.key) {
                return Err(e::KEY_DECLARED_NOT_SELF_SIGNED);
            }
            match world.decl_issue(index) {
                DeclIssue::None => Ok(()),
                DeclIssue::SelfSignature => Err(e::KEY_DECLARED_NOT_SELF_SIGNED),
                DeclIssue::BodyInvalid => Err(e::KEY_VALIDITY),
                DeclIssue::OwnerMissing => Err(e::KEY_OWNER_MISSING),
                DeclIssue::OwnerUnknown => Err(e::KEY_UNKNOWN),
                DeclIssue::OwnerUntrusted => Err(e::KEY_UNTRUSTED),
                DeclIssue::NotCosigned => Err(e::KEY_DECLARED_NOT_COSIGNED),
                DeclIssue::ClassConflict => Err(e::KEY_CLASS_CONFLICT),
                DeclIssue::UntrustedSelfAttested => {
                    if facts.only_self_signature(&declared.key) {
                        notices.push(n::SELF_ATTESTED_ROOT_KEY);
                    }
                    Err(e::KEY_UNTRUSTED)
                }
            }
        }
        KindBody::KeyRotated(rotated) => {
            let old_valid = facts.any_valid(&rotated.old_key);
            let new_valid = facts.any_valid(&rotated.new_key);
            if !old_valid || !new_valid {
                return Err(if facts.has_verifiable_known_signature() {
                    e::KEY_ROTATION_SIGS
                } else {
                    e::SIG_UNVERIFIABLE
                });
            }
            for key in [&rotated.old_key, &rotated.new_key] {
                if let Some(class) = facts.class_of(key) {
                    if class != envelope.actor.actor_type {
                        return Err(e::ACTOR_KEY_TYPE_MISMATCH);
                    }
                }
            }
            Ok(())
        }
        KindBody::KeyRevoked(revoked) => {
            let signer_ok = match revoked.reason {
                RevokeReason::Compromise => facts.any_valid_of_class(&["human", "organization"]),
                RevokeReason::Retired | RevokeReason::Other => {
                    facts.any_valid(&revoked.key)
                        || facts.any_valid_of_class(&["human", "organization"])
                }
            };
            if signer_ok {
                Ok(())
            } else if facts.has_verifiable_known_signature() {
                Err(e::KEY_REVOKE_SIGNER)
            } else {
                Err(e::SIG_UNVERIFIABLE)
            }
        }
        KindBody::Grant(grant) => match grant.action {
            GrantActionKind::Grant => {
                if !facts.has_verifiable_known_signature() {
                    // §4.4 step 5 (S2-FIX1/Q3, weave.grant page): the granter
                    // signer rule is not evaluated; the delegated-chain checks
                    // run, and the step-5 code waits until they all passed.
                    world.check_grant_record_chain(index, envelope.recorded_at)?;
                    return Err(e::SIG_UNVERIFIABLE);
                }
                if !facts.any_valid(&envelope.actor.key) {
                    return Err(e::GRANT_GRANTER);
                }
                world.check_grant_record_chain(index, envelope.recorded_at)
            }
            GrantActionKind::Revoke => {
                // §5.5.4 order: the revoked grant reference is checked before
                // the signer-authority rule.
                let Some(revoke) = grant.revoke.as_ref() else {
                    return Err(e::GRANT_SCHEMA);
                };
                // §5.5.4: the reference MUST resolve (§6.3 `found`: present,
                // matching digest, valid) to an authorising weave.grant (F53).
                let resolution = world.resolve(&revoke.revokes);
                let target = match (resolution.state, resolution.target_slot) {
                    ("found", Some(target)) => target,
                    _ => return Err(e::GRANT_REVOKE_REF),
                };
                if world.record_of(target).map(RecordFile::kind) != Some("weave.grant") {
                    return Err(e::GRANT_REVOKE_REF);
                }
                // The target must be an authorising grant, not a revocation
                // record (§5.5.4: "a weave.grant record" that authorises).
                match world.body_of(target) {
                    Some(KindBody::Grant(body)) if body.action == GrantActionKind::Grant => {}
                    _ => return Err(e::GRANT_REVOKE_REF),
                }
                if !facts.any_valid(&envelope.actor.key) {
                    return Err(if facts.has_verifiable_known_signature() {
                        e::GRANT_REVOKE_SIGNER
                    } else {
                        e::SIG_UNVERIFIABLE
                    });
                }
                let authorised = world.authorised_revoker_keys(target);
                let signer_ok = facts
                    .valid_keys
                    .keys()
                    .any(|key| authorised.iter().any(|allowed| allowed == key));
                if signer_ok {
                    Ok(())
                } else {
                    Err(e::GRANT_REVOKE_SIGNER)
                }
            }
        },
        KindBody::ConsentGranted(_) => check_consent_signer(envelope, facts),
        KindBody::ConsentRevoked(revoked) => {
            // §14.5 (S2-FIX1/Q3): the `actor.type` rule and the signer rule,
            // then the lookup of the revoked consent; a §4.4 step-5 outcome
            // is reported only after that lookup passed.
            let signer = check_consent_signer(envelope, facts);
            if signer != Err(e::SIG_UNVERIFIABLE) {
                signer?;
            }
            let resolution = world.resolve(&revoked.revokes);
            let Some(target) = resolution.target_slot else {
                return Err(e::CONSENT_REVOKE_REF);
            };
            if resolution.target_kind.as_deref() != Some("weave.consent.granted") {
                return Err(e::CONSENT_REVOKE_REF);
            }
            let _ = target;
            signer
        }
        KindBody::Erasure(erasure) => {
            // Order inside step (7) (weave.erasure page, S2-FIX1/Q1, Q3): an
            // agent without `actor.grant` or a program/device without
            // `body.basis` (and any other actor type); the signer rule; the
            // lookup of the authorising grant in two tiers and its coverage
            // of the actor key, the kind and the actions; the validity of the
            // grant chain at `recorded_at` last. A §4.4 step-5 outcome is
            // reported only after all of them passed.
            let step5 = !facts.has_verifiable_known_signature();
            let basis = match envelope.actor.actor_type.as_str() {
                "human" | "organization" => None,
                "agent" => Some(envelope.actor.grant.as_ref().ok_or(e::ERASE_ACTOR)?),
                "program" | "device" => Some(erasure.basis.as_ref().ok_or(e::ERASE_ACTOR)?),
                _ => return Err(e::ERASE_ACTOR),
            };
            if !step5 && !facts.any_valid(&envelope.actor.key) {
                return Err(e::ERASE_ACTOR);
            }
            if let Some(reference) = basis {
                // A grant record that is present but itself invalid is a
                // disallowed basis; one that cannot be established gives the
                // grant codes (unverifiable).
                if world.reference_target_invalid(reference) {
                    return Err(e::ERASE_ACTOR);
                }
                let (grant_index, spec) = world.grant_resolve(reference)?;
                let covered = if envelope.actor.actor_type == "agent" {
                    spec.kinds.iter().any(|kind| kind == "weave.erasure")
                        && spec.actions.iter().any(|action| action == "erase")
                        && spec.actions.iter().any(|action| action == "accept")
                } else {
                    spec.actions.iter().any(|action| action == "erase")
                };
                if spec.grantee_key != envelope.actor.key || !covered {
                    return Err(e::ERASE_ACTOR);
                }
                world.grant_usable_at(grant_index, envelope.recorded_at)?;
            }
            if step5 {
                return Err(e::SIG_UNVERIFIABLE);
            }
            Ok(())
        }
    }
}

fn check_consent_signer(envelope: &Envelope, facts: &SigFacts) -> Result<(), Code> {
    if !matches!(envelope.actor.actor_type.as_str(), "human" | "organization") {
        return Err(e::ACTOR_KEY_TYPE_MISMATCH);
    }
    if facts.any_valid_of_class(&["human", "organization"]) {
        Ok(())
    } else if facts.has_verifiable_known_signature() {
        Err(e::ACTOR_KEY_TYPE_MISMATCH)
    } else {
        Err(e::SIG_UNVERIFIABLE)
    }
}

/// Check (8): actor compatibility, extra-signature rules and agent grant
/// coverage (§5.1, §5.2, §5.4).
fn check_actor(
    world: &mut World,
    envelope: &Envelope,
    facts: &SigFacts,
    _notices: &mut Vec<Code>,
) -> Result<(), Code> {
    // actor.key class must be compatible with actor.type (§5.1).
    if let Some(class) = world.key_class(&envelope.actor.key) {
        if class != envelope.actor.actor_type {
            return Err(e::ACTOR_KEY_TYPE_MISMATCH);
        }
    }
    let lifecycle_kind = matches!(
        envelope.kind.as_str(),
        "weave.key.declared" | "weave.key.rotated" | "weave.key.revoked"
    );
    // Human/organization keys only sign human/organization acts (§5.2), except
    // the key-lifecycle kinds whose pages permit owner co-signatures.
    if !lifecycle_kind {
        let human_signature = facts.valid_keys.iter().any(|(key, class)| {
            key != &envelope.actor.key
                && matches!(class.as_deref(), Some("human" | "organization"))
                && !matches!(envelope.actor.actor_type.as_str(), "human" | "organization")
        });
        if human_signature {
            return Err(e::ACTOR_HUMAN_KEY);
        }
    }
    // For ordinary kinds every signing key's class must match actor.type (§5.1).
    if !SIGNER_CONSTRAINED_KINDS.contains(&envelope.kind.as_str()) {
        for class in facts.valid_keys.values().flatten() {
            if class != &envelope.actor.actor_type {
                return Err(e::ACTOR_KEY_TYPE_MISMATCH);
            }
        }
    }
    // Agent records need a covering grant for every stage (§5.4). Delegated
    // grant records are covered by the delegation-chain checks instead, and the
    // three key-lifecycle kinds are exempt from the agent-only envelope members
    // (§4.2 exception, Q28).
    if envelope.actor.actor_type == "agent" && !lifecycle_kind && envelope.kind != "weave.grant" {
        let Some(grant_ref) = envelope.actor.grant.as_ref() else {
            return Err(e::ENV_ACTOR_GRANT_MISSING);
        };
        // §5.4 (S2/F69): the coverage checks in the order of the list —
        // resolution, grantee, kind/action, then the chain's window and
        // revocation state at `recorded_at`.
        let (grant_index, spec) = world.grant_resolve(grant_ref)?;
        if spec.grantee_key != envelope.actor.key {
            return Err(e::GRANT_GRANTEE_MISMATCH);
        }
        let Some(action) = stage_action(&envelope.stage) else {
            return Err(e::GRANT_NOT_APPLICABLE);
        };
        if !spec.kinds.iter().any(|kind| kind == &envelope.kind)
            || !spec.actions.iter().any(|candidate| candidate == action)
        {
            return Err(e::GRANT_NOT_APPLICABLE);
        }
        world.grant_usable_at(grant_index, envelope.recorded_at)?;
    }
    Ok(())
}

/// Check (9): consent references/revocation and label propagation (§8.4, §8.6).
fn check_labels(
    world: &mut World,
    record: &RecordFile,
    envelope: &Envelope,
    notices: &mut Vec<Code>,
) -> Result<(), Code> {
    let _ = record;
    if let Some(labels) = &envelope.labels {
        if let Some(consent) = &labels.consent {
            let resolution = world.resolve(consent);
            match resolution.state {
                "found" => {
                    let Some(slot) = resolution.target_slot else {
                        return Ok(());
                    };
                    let kind = resolution.target_kind.clone().unwrap_or_default();
                    if kind != "weave.consent.granted" && kind != "weave.consent.revoked" {
                        return Err(e::REF_KIND_MISMATCH);
                    }
                    if kind == "weave.consent.revoked" {
                        if let Some(KindBody::ConsentRevoked(body)) = world.body_of(slot) {
                            if envelope.recorded_at >= body.effective_at {
                                return Err(e::CONSENT_REVOKED);
                            }
                        }
                    } else if world.consent_revoked_at(slot, envelope.recorded_at) {
                        return Err(e::CONSENT_REVOKED);
                    }
                }
                _ => notices.push(n::CONSENT_UNRESOLVED),
            }
        }
    }
    let own_rank = envelope
        .labels
        .as_ref()
        .and_then(|labels| labels.sensitivity_rank());
    for entry in &envelope.refs {
        if !matches!(
            entry.rel.as_str(),
            "derived_from" | "reshaped_from" | "migrated_from" | "correction_of"
        ) {
            continue;
        }
        let reference: &RefObject = &entry.reference;
        let resolution = world.resolve(reference);
        if resolution.state != "found" {
            notices.push(n::LABEL_PROPAGATION_UNCHECKED);
            continue;
        }
        if let Some(target_rank) = resolution.target_sensitivity {
            let violated = match own_rank {
                Some(rank) => rank < target_rank,
                None => target_rank > 0,
            };
            if violated {
                return Err(e::LABEL_DOWNGRADE);
            }
        }
    }
    Ok(())
}

/// Check (10): reference resolution states, notices and kind contradictions
/// (§6.3, §6.4).
fn check_references(
    world: &mut World,
    envelope: &Envelope,
    notices: &mut Vec<Code>,
) -> (Vec<RefReport>, Result<(), Code>) {
    let mut refs = Vec::with_capacity(envelope.refs.len());
    for (index, entry) in envelope.refs.iter().enumerate() {
        let resolution = world.resolve(&entry.reference);
        match resolution.state {
            "missing" => notices.push(n::REF_MISSING),
            "unverifiable" => notices.push(n::REF_UNVERIFIABLE),
            "found" => {
                if let (Some(claim), Some(actual)) = (
                    entry.reference.kind.as_deref(),
                    resolution.target_kind.as_deref(),
                ) {
                    if actual != "weave.erased" && claim != actual {
                        refs.push(RefReport {
                            index,
                            rel: entry.rel.clone(),
                            state: resolution.state.to_owned(),
                        });
                        return (refs, Err(e::REF_KIND_MISMATCH));
                    }
                }
            }
            _ => {}
        }
        refs.push(RefReport {
            index,
            rel: entry.rel.clone(),
            state: resolution.state.to_owned(),
        });
    }
    (refs, Ok(()))
}
