// SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
// SPDX-License-Identifier: Apache-2.0

//! The report's `limitations` array (§14.6, §14.9, S12, T12).
//!
//! `limitations` is a sorted, unique array of the closed `L_*` identifiers and
//! nothing else. Every identifier has an if-and-only-if emission condition on
//! a decidable fact of the report; when a condition cannot be determined the
//! identifier is not reported. The conditions are evaluated here, once, from
//! the finished report plus the few facts that are not visible in it.

use crate::error_codes::{l, n, Code};
use crate::report::{ContainerReport, RecordReport, Verdict};

/// Facts that decide limitations but are not visible in the report fields.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LimitationFacts {
    /// A reported record (the record target, or a record of the container
    /// whose verdict is reported) carries a `labels` member.
    pub labels_present: bool,
    /// The verified input contains a `weave.erased` placeholder.
    pub placeholder_present: bool,
    /// The target is a single `weave.erased` record (no container context).
    pub standalone_placeholder: bool,
    /// A context-trusted check outside the records: the manifest signature or a
    /// supplied previous container's manifest signature (§14.9 TOFU predicate).
    pub context_trusted_outside_records: bool,
    /// `--previous` was supplied, the previous-manifest-chain stage ran and the
    /// supplied previous's manifest signature verified (§11.5, W5).
    pub previous_content_unverified: bool,
}

/// Computes the §14.9 identifiers for a record or container report.
#[must_use]
pub fn compute(
    records: &[RecordReport],
    container: Option<&ContainerReport>,
    facts: LimitationFacts,
) -> Vec<String> {
    let mut out: Vec<Code> = vec![l::OFFLINE_CONTEXT];
    if let Some(container) = container {
        if matches!(container.level_claimed.as_deref(), Some("L1" | "L2")) {
            out.push(l::CHAIN_CLAIM_UNVERIFIED);
        }
        if container.notices.contains(&n::PREVIOUS_SIG_UNVERIFIED) {
            out.push(l::PREVIOUS_SIG_UNVERIFIED);
        }
        if container
            .timestamps
            .iter()
            .any(|receipt| receipt.state == "present-unverified")
        {
            out.push(l::TSA_TRUST_UNVERIFIED);
        }
    }
    if facts.previous_content_unverified {
        out.push(l::PREVIOUS_CONTENT_UNVERIFIED);
    }
    if facts.context_trusted_outside_records
        || records
            .iter()
            .any(|record| record.notices.contains(&n::KEY_TOFU))
    {
        out.push(l::KEY_TRUST_TOFU);
    }
    if facts.placeholder_present {
        out.push(l::ERASED_PLACEHOLDER);
    }
    if facts.standalone_placeholder {
        out.push(l::ERASED_STANDALONE);
    }
    if facts.labels_present {
        out.push(l::LABELS_ARE_CLAIMS);
    }
    if records
        .iter()
        .any(|record| record.kind_known == Some(false) && record.verdict == Verdict::Valid)
    {
        out.push(l::UNKNOWN_KIND_OPAQUE);
    }
    if records
        .iter()
        .any(|record| record.notices.contains(&n::LABEL_PROPAGATION_UNCHECKED))
    {
        out.push(l::LABEL_PROPAGATION_UNCHECKED);
    }
    out.sort_unstable();
    out.dedup();
    out.into_iter().map(str::to_owned).collect()
}
