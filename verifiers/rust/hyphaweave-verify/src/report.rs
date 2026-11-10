// SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
// SPDX-License-Identifier: Apache-2.0

//! Report data model (§14.6).
//!
//! The shape of the report is normative; the exact byte formatting is produced
//! by [`crate::report_json`] (sorted keys, two-space indent, ASCII-only JSON,
//! exactly one trailing LF). Fields whose value could not be determined because
//! the input failed earlier in the check order are `None` and render as JSON
//! `null`; a report never invents a value.

use crate::error_codes::Code;

/// The four record/container verdicts (§14.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Verdict {
    /// Every applicable check passed.
    Valid,
    /// At least one error was found.
    Invalid,
    /// No error, but a condition could not be established from the input.
    Unverifiable,
    /// A structurally sound `weave.erased` placeholder.
    Erased,
}

impl Verdict {
    /// Report spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::Invalid => "invalid",
            Self::Unverifiable => "unverifiable",
            Self::Erased => "erased",
        }
    }
}

/// Report target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    /// A single record file.
    Record,
    /// A container directory or zip.
    Container,
    /// A conformance-vector directory.
    Vectors,
}

impl Target {
    /// Report spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Record => "record",
            Self::Container => "container",
            Self::Vectors => "vectors",
        }
    }
}

/// An origin object as it appears in a report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OriginReport {
    /// Project slug.
    pub project: String,
    /// Key id of the origin instance.
    pub instance: String,
}

/// One reference-resolution entry of a record report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefReport {
    /// Zero-based position in the record's `refs` array.
    pub index: usize,
    /// Relation word.
    pub rel: String,
    /// One of `found`, `moved`, `missing`, `erased`, `unverifiable`.
    pub state: String,
}

/// One signature entry state of a record report (§14.6: `valid`, `invalid`,
/// `unverified`, `ignored`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigReportEntry {
    /// Key id named by the signature entry.
    pub key: String,
    /// Entry state.
    pub state: String,
}

/// A record report entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordReport {
    /// Record digest (own digest; for a placeholder, the digest over the
    /// placeholder object, not its `digest` member).
    pub digest: Option<String>,
    /// Envelope `id`.
    pub id: Option<String>,
    /// Envelope `kind`.
    pub kind: Option<String>,
    /// Envelope `stage`; `None` for a `weave.erased` placeholder.
    pub stage: Option<String>,
    /// Envelope `origin`.
    pub origin: Option<OriginReport>,
    /// Whether the kind is registered by the implemented specification version.
    pub kind_known: Option<bool>,
    /// Record verdict.
    pub verdict: Verdict,
    /// Sorted, unique error codes.
    pub errors: Vec<Code>,
    /// Sorted, unique notices.
    pub notices: Vec<Code>,
    /// Reference resolutions in `refs` order (empty for placeholders).
    pub refs: Vec<RefReport>,
    /// Signature entry states in `sigs` order.
    pub sigs: Vec<SigReportEntry>,
    /// For a placeholder: its attestation reference resolution.
    pub attestation: Option<AttestationReport>,
}

/// Attestation reference state reported for a `weave.erased` placeholder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttestationReport {
    /// Digest string carried by the placeholder's `attestation` reference.
    pub digest: String,
    /// One of the five resolution states.
    pub state: String,
}

/// Integrity-chain report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainReport {
    /// `absent` for L0, `unverified` for L1/L2.
    pub status: String,
}

/// One timestamp receipt report entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TimestampReport {
    /// Zero-based index in the attestation file's `timestamps` array.
    pub index: usize,
    /// Container-relative receipt path.
    pub path: Option<String>,
    /// `verified`, `present-unverified` or `invalid`.
    pub state: String,
    /// `genTime` as a TS literal, when the receipt parsed far enough.
    pub gen_time: Option<String>,
}

/// Container report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContainerReport {
    /// Manifest `created_at`.
    pub created_at: Option<String>,
    /// Computed manifest digest.
    pub manifest_digest: Option<String>,
    /// Manifest's claimed level.
    pub level_claimed: Option<String>,
    /// Always `"L0"` in H0 once a supported manifest was parsed (§11.4).
    pub level_verified: Option<String>,
    /// True only for a fully verified L2 timestamp chain with a matching anchor.
    pub anchor_verified: Option<bool>,
    /// Chain report: `absent` for L0, `unverified` for L1/L2.
    pub chain: Option<ChainReport>,
    /// `previous_manifest.digest`, when the manifest parsed.
    pub previous_manifest_digest: Option<String>,
    /// Number of records in the manifest.
    pub record_count: Option<u64>,
    /// Sorted, unique container-level error codes.
    pub errors: Vec<Code>,
    /// Sorted, unique container-level notices.
    pub notices: Vec<Code>,
    /// Timestamp receipts in attestation order.
    pub timestamps: Vec<TimestampReport>,
}

/// Outcome counts for a record/container report.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VerdictCounts {
    /// Verdict count.
    pub valid: u64,
    /// Verdict count.
    pub invalid: u64,
    /// Verdict count.
    pub unverifiable: u64,
    /// Verdict count.
    pub erased: u64,
}

/// Outcome counts for the `vectors` target.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VectorCounts {
    /// Number of cases found.
    pub case_count: u64,
    /// Cases whose conclusion matched `expected.json`.
    pub matched: u64,
    /// Cases whose conclusion did not match.
    pub mismatched: u64,
}

/// The `summary` member of a report; its shape depends on the target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Summary {
    /// Record/container verdict counts.
    Verdicts(VerdictCounts),
    /// Conformance-vector case counts.
    Vectors(VectorCounts),
}

/// One per-case result of the `vectors` target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VectorCaseReport {
    /// Case id (`<category>/<case-id>`).
    pub id: String,
    /// True when the case matched its `expected.json`.
    pub matched: bool,
    /// Verdict stated by `expected.json`.
    pub expected: String,
    /// Verdict produced by this verifier.
    pub actual: String,
}

/// An input identity (`input.sha256` / `input.size`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InputIdentity {
    /// `sha256:<hex>` of the target bytes (see §14.6 for directory containers:
    /// the manifest digest and manifest byte size).
    pub sha256: String,
    /// Byte size of the identified input.
    pub size: u64,
}

/// The verifier identity block of a report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifierInfo {
    /// Implementation name.
    pub name: String,
    /// Implementation version.
    pub version: String,
}

/// A complete verifier report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    /// Test-only skipped-check codes echoed from `WEAVE_VERIFY_SKIP_CHECKS`.
    pub checks_disabled: Vec<Code>,
    /// Report version, `"1"`.
    pub report_version: String,
    /// Specification identifier, `"weave-record/1"`.
    pub spec: String,
    /// Report target.
    pub target: Target,
    /// Top-level verdict.
    pub verdict: Verdict,
    /// Input identity.
    pub input: InputIdentity,
    /// Record reports (one for a record target; manifest order for containers).
    pub records: Vec<RecordReport>,
    /// Container report; present only for a container target.
    pub container: Option<ContainerReport>,
    /// Summary counts.
    pub summary: Summary,
    /// What was not verified (§14.9); each entry is prose, never a passed check.
    pub limitations: Vec<String>,
    /// Per-case results; only for the `vectors` target.
    pub cases: Vec<VectorCaseReport>,
    /// Implementation identity.
    pub verifier: VerifierInfo,
}
