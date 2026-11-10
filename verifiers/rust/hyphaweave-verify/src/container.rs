// SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
// SPDX-License-Identifier: Apache-2.0

//! Container verification (§11).
//!
//! This module performs the container-level checks of §14.5 in the fixed order:
//! entry enumeration/safety, manifest parse and canonical form, manifest
//! structure, manifest digest, manifest signature, level/chain completeness,
//! records listing and per-record verification, cross-record state, blobs,
//! previous-manifest chain, timestamps, aggregation.
//!
//! Per-record verification and cross-record state are delegated to
//! [`crate::context`]; timestamp verification to [`crate::timestamp`].
//! Directory enumeration is sorted so the verdict never depends on filesystem
//! order, and zip decompression is bounded while streaming.
//!
//! Report fields that cannot be determined because an earlier check failed are
//! `None`/empty, never invented. A container-level invalid error found before
//! the records stage stops the run and reports `records: []` with exactly one
//! container error (§14.5). Errors found by the records *listing* stage make
//! the container invalid without pretending to have verified the listed
//! records, so the `records[]` entries are reported as invalid with what is
//! known from the manifest (a record whose file is missing is still listed).

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::context::World;
use crate::digest;
use crate::envelope::{self, RecordFile, SigEntry};
use crate::error_codes::{e, n, Code};
use crate::json;
use crate::limits;
use crate::options::{ContainerInput, UsageError, VerifyOptions};
use crate::patterns;
use crate::report::{
    ChainReport, ContainerReport, InputIdentity, OriginReport, RecordReport, Report, Summary,
    Target, TimestampReport, Verdict, VerdictCounts, VerifierInfo,
};
use crate::time::Timestamp;
use crate::timestamp::{self, AttestationTimestamp, ChainEvidence, ReceiptState};
use crate::value::{Object, Value};
use crate::zip;

/// Relative path of the manifest (§11.1).
const MANIFEST_PATH: &str = "manifest.json";
/// Relative path of the attestation file (§11.3).
const SIGFILE_PATH: &str = "signatures/manifest.sig.json";
/// Relative path of the embedded previous manifest (§11.5).
const PREVIOUS_MANIFEST_PATH: &str = "previous/manifest.json";
/// The only `format` value defined by this specification version.
const FORMAT: &str = "weave-record/1";

/// Verifies one container target.
///
/// # Errors
/// Returns a [`UsageError`] for I/O problems reading the container; container
/// *content* defects are reported in the `Report`, not as `Err`.
pub fn verify_container(
    input: &ContainerInput,
    options: &VerifyOptions,
) -> Result<Report, UsageError> {
    let mut run = Run::new(options);

    // ------------------------------------------------------------------
    // Materialise the container: directory enumeration, zip reader, or the
    // in-memory file map. Entry count and uncompressed bytes are bounded
    // while reading (§13); zip entry safety defects are classified by the
    // reader, path safety below.
    // ------------------------------------------------------------------
    let (materialised, archive_identity) = match input {
        ContainerInput::Directory(root) => match read_directory(root) {
            Ok(materialised) => (materialised, None),
            Err(ReadFailure::Usage(error)) => return Err(error),
            Err(ReadFailure::Content { code, partial }) => {
                let identity = manifest_identity(&partial.files);
                if options.skipped(code) {
                    (Materialised::default(), Some(identity))
                } else {
                    return Ok(run.fail(code, identity));
                }
            }
        },
        ContainerInput::Zip(bytes) => {
            let identity = InputIdentity {
                sha256: digest::sha256_digest_string(bytes),
                size: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
            };
            match zip::read_zip(bytes) {
                Ok(files) => {
                    let readable_present = files
                        .keys()
                        .any(|path| path == "readable" || path.starts_with("readable/"));
                    (
                        Materialised {
                            files,
                            readable_present,
                            total_bytes: 0,
                        },
                        Some(identity),
                    )
                }
                Err(code) => {
                    if options.skipped(code) {
                        (Materialised::default(), Some(identity))
                    } else {
                        return Ok(run.fail(code, identity));
                    }
                }
            }
        }
        ContainerInput::Files(files) => {
            let readable_present = files
                .keys()
                .any(|path| path == "readable" || path.starts_with("readable/"));
            (
                Materialised {
                    files: files.clone(),
                    readable_present,
                    total_bytes: 0,
                },
                None,
            )
        }
    };

    let identity = archive_identity.unwrap_or_else(|| manifest_identity(&materialised.files));

    // §13: entry count and total uncompressed bytes for the in-memory forms
    // (the zip reader enforces the same limits while inflating; a directory
    // reader enforces them while reading).
    if !matches!(input, ContainerInput::Zip(_)) {
        let total: u64 = materialised
            .files
            .values()
            .map(|bytes| u64::try_from(bytes.len()).unwrap_or(u64::MAX))
            .fold(0u64, u64::saturating_add);
        for code in [
            (materialised.files.len() > limits::MAX_CONTAINER_ENTRIES)
                .then_some(e::CONTAINER_SIZE),
            (total > limits::MAX_CONTAINER_UNCOMPRESSED_BYTES).then_some(e::CONTAINER_SIZE),
        ]
        .into_iter()
        .flatten()
        {
            if !options.skipped(code) {
                return Ok(run.fail(code, identity));
            }
        }
    }

    // ------------------------------------------------------------------
    // (1) Entry enumeration / safety and closed layout (§11.1, §11.9).
    // ------------------------------------------------------------------
    let (layout, layout_error) = classify_layout(&materialised, options);
    if layout.readable_present {
        // §11.8: informational only; the directory is never parsed or hashed.
        run.container.notices.push(n::READABLE_PRESENT);
    }
    if let Some(code) = layout_error {
        return Ok(run.fail(code, identity));
    }

    // ------------------------------------------------------------------
    // (2) Manifest parse and canonical file form (§1.8), (3) manifest
    // structure (§11.2, §11.2.1).
    // ------------------------------------------------------------------
    let Some(manifest_bytes) = layout.manifest.as_deref() else {
        if options.skipped(e::MANIFEST_MISSING) {
            return Ok(run.finish(identity, Vec::new()));
        }
        return Ok(run.fail(e::MANIFEST_MISSING, identity));
    };
    let manifest_object = match json::parse_canonical_object(manifest_bytes, limits::MAX_MANIFEST_BYTES)
    {
        Ok(object) => object,
        Err(code) => {
            if options.skipped(code) {
                return Ok(run.finish(identity, Vec::new()));
            }
            return Ok(run.fail(code, identity));
        }
    };
    let canonical_manifest = json::canonical_object_bytes(&manifest_object);
    let manifest_digest = digest::manifest_digest(&canonical_manifest);
    run.container.manifest_digest = Some(manifest_digest.clone());
    let manifest = match parse_manifest(&manifest_object, options) {
        Ok(manifest) => manifest,
        Err(code) => {
            if options.skipped(code) {
                run.container.manifest_digest = Some(manifest_digest);
                return Ok(run.finish(identity, Vec::new()));
            }
            return Ok(run.fail(code, identity));
        }
    };
    run.container.created_at = Some(manifest.created_at.to_ts_string());
    run.container.level_claimed = Some(manifest.level.as_str().to_owned());
    // §11.4: once a supported manifest was parsed the reported verified level is
    // always L0; the claimed level and the internal chain claim are separate.
    run.container.level_verified = Some("L0".to_owned());
    run.container.anchor_verified = Some(false);
    run.container.chain = Some(ChainReport {
        status: match manifest.level {
            Level::L0 => "absent",
            Level::L1 | Level::L2 => "unverified",
        }
        .to_owned(),
    });
    run.container.previous_manifest_digest = manifest.previous_manifest.clone();
    run.container.record_count = Some(u64::try_from(manifest.records.len()).unwrap_or(u64::MAX));

    // ------------------------------------------------------------------
    // (4) Manifest digest and the attestation file (§11.3).
    // ------------------------------------------------------------------
    let Some(sigfile_bytes) = layout.sigfile.as_deref() else {
        // The layout requires the attestation file; without it the manifest has
        // no signature at all.
        if options.skipped(e::MANIFEST_SCHEMA) {
            return Ok(run.finish(identity, Vec::new()));
        }
        return Ok(run.fail(e::MANIFEST_SCHEMA, identity));
    };
    let sigfile_object =
        match json::parse_canonical_object(sigfile_bytes, limits::MAX_SIGFILE_BYTES) {
            Ok(object) => object,
            Err(code) => {
                if options.skipped(code) {
                    return Ok(run.finish(identity, Vec::new()));
                }
                return Ok(run.fail(code, identity));
            }
        };
    let attestation = match parse_attestation(
        &sigfile_object,
        &manifest,
        &manifest_digest,
        &layout,
        options,
    ) {
        Ok(attestation) => attestation,
        Err(code) => {
            if options.skipped(code) {
                return Ok(run.finish(identity, Vec::new()));
            }
            return Ok(run.fail(code, identity));
        }
    };

    // Parse the listed record files early: the manifest signature must be
    // checked against the key state the container's own records establish, and
    // the same parse results are reused by the records stage. Parse failures
    // are reported later, not here.
    let entries = build_entries(&manifest.records, &layout.records);
    let results: Vec<Result<RecordFile, Code>> = entries
        .iter()
        .map(|entry| match &entry.parsed {
            Some(result) => result.clone(),
            None => Err(e::JSON_INVALID),
        })
        .collect();
    let mut world = World::from_results(results, options)?;

    // ------------------------------------------------------------------
    // Timestamp chain (§12). Verified before evaluation so the §9.4
    // compromise rule and the manifest signature check can use the evidence;
    // the verdict effects are reported in the §14.5 (11) position below.
    // ------------------------------------------------------------------
    let evidence = verify_timestamps(
        &attestation.timestamps,
        &manifest_digest,
        &materialised.files,
        options,
    )?;
    run.container.anchor_verified = Some(evidence.anchor_verified);
    run.container.timestamps = timestamp_reports(&attestation.timestamps, &evidence);
    world.set_timestamp_evidence(evidence.clone());

    // ------------------------------------------------------------------
    // (5) Manifest signature (§11.3, §4.4).
    // ------------------------------------------------------------------
    if !attestation.signatures.is_empty() {
        let outcome = world.check_manifest_signatures(
            &attestation.signatures,
            &manifest_digest,
            &manifest.created_at,
        );
        for notice in &outcome.notices {
            if !options.skipped(notice) {
                run.container.notices.push(notice);
            }
        }
        if !outcome.invalid_errors.is_empty() {
            let code = *outcome
                .invalid_errors
                .iter()
                .filter(|code| !options.skipped(code))
                .min()
                .unwrap_or(&e::MANIFEST_SIG_INVALID);
            if !options.skipped(code) {
                return Ok(run.fail(code, identity));
            }
        } else {
            let mut any_unverifiable = false;
            for code in &outcome.unverifiable_errors {
                if options.skipped(code) {
                    continue;
                }
                any_unverifiable = true;
                run.container.errors.push(code);
            }
            if any_unverifiable {
                run.limitations.push(
                    "the manifest signature could not be verified from the available key material"
                        .to_owned(),
                );
            } else if !outcome.verified
                && outcome.invalid_errors.is_empty()
                && !options.skipped(e::SIG_UNVERIFIABLE)
                && !options.skipped(e::KEY_UNKNOWN)
            {
                // Defensive: a non-empty signature list that establishes
                // nothing is unverifiable, never silently passed (§11.3).
                run.container.errors.push(e::SIG_UNVERIFIABLE);
                run.limitations.push(
                    "the manifest signature could not be verified from the available key material"
                        .to_owned(),
                );
            }
        }
    }

    // ------------------------------------------------------------------
    // (6) Level and chain completeness (§11.2, §11.4).
    // ------------------------------------------------------------------
    match check_level_and_chain(&manifest) {
        Ok(()) => {
            if manifest.level != Level::L0 {
                run.container.notices.push(n::CHAIN_CLAIM_UNVERIFIED);
                run.limitations.push(
                    "the internal hash-chain head and record positions are an unverified claim; \
                     level_verified is reported as L0"
                        .to_owned(),
                );
            }
        }
        Err(code) => {
            if !options.skipped(code) {
                return Ok(run.fail(code, identity));
            }
        }
    }

    // ------------------------------------------------------------------
    // (7) Records listing and per-record verification (§11.2.1, §11.6).
    // ------------------------------------------------------------------
    let mut listing_errors: Vec<Code> = Vec::new();
    for entry in &entries {
        if let Some(code) = entry.error {
            if !options.skipped(code) {
                listing_errors.push(code);
            }
        }
    }
    let listed_paths: BTreeSet<&str> = entries.iter().map(|entry| entry.path.as_str()).collect();
    if layout
        .records
        .keys()
        .any(|path| !listed_paths.contains(path.as_str()))
        && !options.skipped(e::MANIFEST_RECORD_EXTRA)
    {
        listing_errors.push(e::MANIFEST_RECORD_EXTRA);
    }
    listing_errors.sort_unstable();
    listing_errors.dedup();
    if !listing_errors.is_empty() {
        // The records listing is inconsistent: the container is invalid and
        // no per-record verification result is claimed. Report one entry per
        // manifest record (§14.6 never omits a record the manifest requires).
        run.container.errors.extend(listing_errors);
        let records: Vec<RecordReport> = entries.iter().map(synthetic_record).collect();
        return Ok(run.finish(identity, records));
    }

    let mut records = world.evaluate_all();
    let cross = world.container_cross_checks();
    merge_cross_checks(&cross, &mut run.container, &mut records);

    // ------------------------------------------------------------------
    // (9) Blobs (§11.7).
    // ------------------------------------------------------------------
    for code in check_blobs(manifest.blobs.as_deref(), &layout.blobs) {
        if !options.skipped(code) {
            run.container.errors.push(code);
        }
    }

    // ------------------------------------------------------------------
    // (10) Previous-manifest chain (§11.5), including `--previous`.
    // ------------------------------------------------------------------
    let previous = check_previous_chain(&manifest, &layout, options)?;
    for code in previous.0 {
        if !options.skipped(code) {
            run.container.errors.push(code);
        }
    }
    for notice in previous.1 {
        if !options.skipped(notice) {
            run.container.notices.push(notice);
        }
    }

    // ------------------------------------------------------------------
    // (11) Timestamp outcomes and the container verdict (§12.5).
    // ------------------------------------------------------------------
    for code in timestamp_effects(&evidence) {
        if !options.skipped(code) {
            run.container.errors.push(code);
        }
    }
    if manifest.level == Level::L2 {
        if evidence.anchor_verified {
            run.limitations.push(
                "RFC 3161 receipts prove that a timestamp authority signed the manifest digest; \
                 they do not prove that the content is true"
                    .to_owned(),
            );
        } else {
            run.limitations.push(
                "no complete RFC 3161 timestamp chain verified against a supplied trust anchor; \
                 the L2 claim is unverified (anchor_verified is false)"
                    .to_owned(),
            );
        }
    }
    if manifest.previous_manifest.is_some() {
        run.limitations.push(
            "the embedded previous manifest's own signature was not re-verified \
             (N_PREVIOUS_SIG_UNVERIFIED)"
                .to_owned(),
        );
    }

    // ------------------------------------------------------------------
    // (12) Aggregation and report.
    // ------------------------------------------------------------------
    Ok(run.finish(identity, records))
}

// ---------------------------------------------------------------------------
// Report assembly
// ---------------------------------------------------------------------------

/// Accumulates the container report and limitations while the checks run.
struct Run<'a> {
    options: &'a VerifyOptions,
    container: ContainerReport,
    limitations: Vec<String>,
}

impl<'a> Run<'a> {
    fn new(options: &'a VerifyOptions) -> Self {
        Self {
            options,
            container: ContainerReport {
                created_at: None,
                manifest_digest: None,
                level_claimed: None,
                level_verified: None,
                anchor_verified: None,
                chain: None,
                previous_manifest_digest: None,
                record_count: None,
                errors: Vec::new(),
                notices: Vec::new(),
                timestamps: Vec::new(),
            },
            limitations: Vec::new(),
        }
    }

    /// A report for a container-level invalid failure: `records: []` and
    /// exactly one container error (§14.5).
    fn fail(mut self, code: Code, input: InputIdentity) -> Report {
        if !self.options.skipped(code) {
            self.container.errors.push(code);
        }
        self.finish(input, Vec::new())
    }

    /// Final report; sorts and dedupes codes, computes the verdict and summary.
    fn finish(mut self, input: InputIdentity, mut records: Vec<RecordReport>) -> Report {
        sort_unique(&mut self.container.errors);
        sort_unique(&mut self.container.notices);
        for record in &mut records {
            sort_unique(&mut record.errors);
            sort_unique(&mut record.notices);
        }
        let verdict = aggregate_verdict(&self.container.errors, &records);
        let summary = Summary::Verdicts(count_verdicts(&records));
        Report {
            checks_disabled: skipped_codes(self.options),
            report_version: crate::REPORT_VERSION.to_owned(),
            spec: crate::SPEC.to_owned(),
            target: Target::Container,
            verdict,
            input,
            records,
            container: Some(self.container),
            summary,
            limitations: self.limitations,
            cases: Vec::new(),
            verifier: VerifierInfo {
                name: crate::VERIFIER_NAME.to_owned(),
                version: crate::VERIFIER_VERSION.to_owned(),
            },
        }
    }
}

/// §14.4: the error codes that mean `unverifiable`, never `invalid`.
fn is_unverifiable_code(code: Code) -> bool {
    matches!(
        code,
        e::KEY_UNKNOWN
            | e::KEY_UNTRUSTED
            | e::SIG_UNVERIFIABLE
            | e::GRANT_UNRESOLVED
            | e::GRANT_REVOKED
            | e::GRANT_EXPIRED
            | e::TS_UNTRUSTED
    )
}

/// Verdict precedence: invalid over unverifiable over valid (§14.3). A
/// container is never `erased` at the top level.
fn aggregate_verdict(container_errors: &[Code], records: &[RecordReport]) -> Verdict {
    let mut invalid = container_errors
        .iter()
        .any(|code| !is_unverifiable_code(code));
    let mut unverifiable = container_errors
        .iter()
        .any(|code| is_unverifiable_code(code));
    for record in records {
        match record.verdict {
            Verdict::Invalid => invalid = true,
            Verdict::Unverifiable => unverifiable = true,
            Verdict::Valid | Verdict::Erased => {}
        }
    }
    if invalid {
        Verdict::Invalid
    } else if unverifiable {
        Verdict::Unverifiable
    } else {
        Verdict::Valid
    }
}

/// Summary counts of the per-record verdicts (§14.6).
fn count_verdicts(records: &[RecordReport]) -> VerdictCounts {
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

/// §14.7: echoes the sorted skipped-check list as registry codes.
fn skipped_codes(options: &VerifyOptions) -> Vec<Code> {
    options
        .skip_checks
        .iter()
        .filter_map(|text| {
            crate::error_codes::ALL_ERROR_CODES
                .iter()
                .chain(crate::error_codes::ALL_NOTICES.iter())
                .copied()
                .find(|code| *code == text.as_str())
        })
        .collect()
}

/// Sorts and deduplicates a code list (reports use sorted unique codes).
fn sort_unique(codes: &mut Vec<Code>) {
    codes.sort_unstable();
    codes.dedup();
}

// ---------------------------------------------------------------------------
// Materialisation (§11.1, §11.9, §13)
// ---------------------------------------------------------------------------

/// A materialised container: relative path -> bytes plus the observed
/// `readable/` presence (§11.8) and the running byte total.
#[derive(Default)]
struct Materialised {
    files: BTreeMap<String, Vec<u8>>,
    readable_present: bool,
    total_bytes: u64,
}

/// A directory read failure: I/O is a usage error, content defects are
/// reported. The partially materialised container is kept so `input` identity
/// can still be computed when the manifest was already read.
enum ReadFailure {
    Usage(UsageError),
    Content {
        code: Code,
        partial: Box<Materialised>,
    },
}

fn content_failure(code: Code, materialised: &Materialised) -> ReadFailure {
    ReadFailure::Content {
        code,
        partial: Box::new(Materialised {
            files: materialised.files.clone(),
            readable_present: materialised.readable_present,
            total_bytes: materialised.total_bytes,
        }),
    }
}

/// Reads a directory container recursively in sorted relative-path order.
fn read_directory(root: &Path) -> Result<Materialised, ReadFailure> {
    let metadata = std::fs::symlink_metadata(root).map_err(|error| {
        ReadFailure::Usage(UsageError(format!(
            "cannot read container directory {root:?}: {error}"
        )))
    })?;
    if !metadata.is_dir() {
        return Err(ReadFailure::Usage(UsageError(format!(
            "container path {root:?} is not a directory"
        ))));
    }
    let mut materialised = Materialised::default();
    walk_directory(root, "", &mut materialised)?;
    Ok(materialised)
}

fn walk_directory(
    directory: &Path,
    prefix: &str,
    materialised: &mut Materialised,
) -> Result<(), ReadFailure> {
    let reader = std::fs::read_dir(directory).map_err(|error| {
        ReadFailure::Usage(UsageError(format!(
            "cannot read container directory {directory:?}: {error}"
        )))
    })?;
    let mut names: Vec<std::ffi::OsString> = Vec::new();
    for entry in reader {
        let entry = entry.map_err(|error| {
            ReadFailure::Usage(UsageError(format!(
                "cannot read container directory {directory:?}: {error}"
            )))
        })?;
        names.push(entry.file_name());
    }
    // Deterministic traversal: the verdict never depends on filesystem order.
    names.sort();
    for name in names {
        let Some(name) = name.to_str() else {
            return Err(content_failure(e::CONTAINER_ENTRY, materialised));
        };
        let relative = if prefix.is_empty() {
            name.to_owned()
        } else {
            format!("{prefix}/{name}")
        };
        let path = directory.join(name);
        let metadata = std::fs::symlink_metadata(&path).map_err(|error| {
            ReadFailure::Usage(UsageError(format!("cannot inspect {path:?}: {error}")))
        })?;
        let readable = relative == "readable" || relative.starts_with("readable/");
        // §11.8: `readable/` is ignored entirely — not read, not hashed, not
        // trusted. Only its presence is noted.
        if readable {
            materialised.readable_present = true;
            continue;
        }
        if metadata.file_type().is_symlink() {
            // §11.1: all entries are ordinary files.
            return Err(content_failure(e::CONTAINER_ENTRY, materialised));
        }
        if metadata.is_dir() {
            walk_directory(&path, &relative, materialised)?;
            continue;
        }
        if !metadata.is_file() {
            return Err(content_failure(e::CONTAINER_ENTRY, materialised));
        }
        if materialised.files.len() >= limits::MAX_CONTAINER_ENTRIES {
            return Err(content_failure(e::CONTAINER_SIZE, materialised));
        }
        let bytes = std::fs::read(&path).map_err(|error| {
            ReadFailure::Usage(UsageError(format!("cannot read {path:?}: {error}")))
        })?;
        let length = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        let total = materialised.total_bytes.saturating_add(length);
        if total > limits::MAX_CONTAINER_UNCOMPRESSED_BYTES {
            return Err(content_failure(e::CONTAINER_SIZE, materialised));
        }
        materialised.total_bytes = total;
        materialised.files.insert(relative, bytes);
    }
    Ok(())
}

/// §14.6/Q27: a directory (or materialised-files) container is identified by
/// the manifest digest and the manifest byte size.
fn manifest_identity(files: &BTreeMap<String, Vec<u8>>) -> InputIdentity {
    match files.get(MANIFEST_PATH) {
        Some(bytes) => {
            // The §2.4 digest is over the canonical bytes without the optional
            // trailing LF; the canonical file form guarantees those are the
            // received bytes minus at most one LF, which is also the best
            // effort available for a manifest that fails the checks.
            let without_lf = match bytes.split_last() {
                Some((&b'\n', head)) => head,
                _ => bytes.as_slice(),
            };
            InputIdentity {
                sha256: digest::manifest_digest(without_lf),
                size: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
            }
        }
        None => InputIdentity {
            sha256: digest::sha256_digest_string(b""),
            size: 0,
        },
    }
}

// ---------------------------------------------------------------------------
// Entry enumeration and layout (§11.1, §11.8, §11.9)
// ---------------------------------------------------------------------------

/// The closed container layout after entry-safety classification.
#[derive(Default)]
struct Layout {
    manifest: Option<Vec<u8>>,
    sigfile: Option<Vec<u8>>,
    previous_manifest: Option<Vec<u8>>,
    timestamps: BTreeMap<String, Vec<u8>>,
    records: BTreeMap<String, Vec<u8>>,
    blobs: BTreeMap<String, Vec<u8>>,
    readable_present: bool,
}

/// True when a path is a safe container-relative path: no absolute prefix, no
/// `.`/`..`/empty segments, no NUL bytes.
fn is_safe_relative_path(path: &str) -> bool {
    if path.is_empty() || path.starts_with('/') || path.contains('\0') {
        return false;
    }
    for segment in path.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return false;
        }
    }
    true
}

/// Classifies every entry into the closed layout, returning the first
/// non-skipped layout error (§11.1, §11.9).
fn classify_layout(
    materialised: &Materialised,
    options: &VerifyOptions,
) -> (Layout, Option<Code>) {
    let mut layout = Layout {
        readable_present: materialised.readable_present,
        ..Layout::default()
    };
    let mut error: Option<Code> = None;
    for (path, bytes) in &materialised.files {
        let violation = if !is_safe_relative_path(path) {
            Some(e::CONTAINER_ENTRY)
        } else {
            classify_one(path, bytes, &mut layout)
        };
        let Some(code) = violation else {
            continue;
        };
        if !options.skipped(code) {
            error.get_or_insert(code);
        }
    }
    (layout, error)
}

fn classify_one(path: &str, bytes: &[u8], layout: &mut Layout) -> Option<Code> {
    if path == MANIFEST_PATH {
        layout.manifest = Some(bytes.to_vec());
        return None;
    }
    if let Some(rest) = path.strip_prefix("signatures/") {
        if !rest.contains('/') {
            if rest == "manifest.sig.json" {
                layout.sigfile = Some(bytes.to_vec());
                return None;
            }
            if is_timestamp_file_name(rest) {
                layout.timestamps.insert(path.to_owned(), bytes.to_vec());
                return None;
            }
            if is_tsa_cert_file_name(rest) {
                // §11.3: transport convenience, never trusted on its own.
                return None;
            }
        }
        return Some(e::CONTAINER_ENTRY);
    }
    if let Some(rest) = path.strip_prefix("previous/") {
        if !rest.contains('/') && rest == "manifest.json" {
            layout.previous_manifest = Some(bytes.to_vec());
            return None;
        }
        return Some(e::CONTAINER_ENTRY);
    }
    if let Some(rest) = path.strip_prefix("records/") {
        if !rest.contains('/') && is_record_file_name(rest) {
            layout.records.insert(path.to_owned(), bytes.to_vec());
            return None;
        }
        // §11.1 special case: an extra file in `records/` keeps the content code.
        return Some(e::MANIFEST_RECORD_EXTRA);
    }
    if let Some(rest) = path.strip_prefix("blobs/") {
        if let Some(hex) = rest.strip_prefix("sha256/") {
            if !hex.contains('/') && is_lower_hex_64(hex) {
                layout.blobs.insert(path.to_owned(), bytes.to_vec());
                return None;
            }
        }
        // §11.1 special case: an extra file in `blobs/` keeps the content code.
        return Some(e::MANIFEST_BLOB);
    }
    if path == "readable" || path.starts_with("readable/") {
        layout.readable_present = true;
        return None;
    }
    Some(e::CONTAINER_ENTRY)
}

/// True for `<64 lowercase hex>.json` (§11.6).
fn is_record_file_name(name: &str) -> bool {
    match name.strip_suffix(".json") {
        Some(hex) => is_lower_hex_64(hex),
        None => false,
    }
}

/// True for `<64 lowercase hex>`.
fn is_lower_hex_64(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// True for `timestamp-<n>.tsr` with `<n>` a decimal integer >= 1 and no
/// leading zero (§11.1).
fn is_timestamp_file_name(name: &str) -> bool {
    match name.strip_prefix("timestamp-").and_then(|rest| rest.strip_suffix(".tsr")) {
        Some(number) => is_positive_decimal(number),
        None => false,
    }
}

/// True for `tsa-cert-<n>.pem` with the same `<n>` form (§11.1).
fn is_tsa_cert_file_name(name: &str) -> bool {
    match name
        .strip_prefix("tsa-cert-")
        .and_then(|rest| rest.strip_suffix(".pem"))
    {
        Some(number) => is_positive_decimal(number),
        None => false,
    }
}

/// True for a decimal integer >= 1 with no leading zero.
fn is_positive_decimal(text: &str) -> bool {
    !text.is_empty()
        && text.bytes().all(|byte| byte.is_ascii_digit())
        && !(text.starts_with('0') && text.len() > 1)
        && text != "0"
}

// ---------------------------------------------------------------------------
// Manifest structure (§11.2, §11.2.1)
// ---------------------------------------------------------------------------

/// Integrity level claimed by the manifest (§11.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Level {
    L0,
    L1,
    L2,
}

impl Level {
    fn as_str(self) -> &'static str {
        match self {
            Self::L0 => "L0",
            Self::L1 => "L1",
            Self::L2 => "L2",
        }
    }
}

/// Manifest origin object (§4.1); kept for the §11.5 same-origin rule.
#[derive(Clone, Debug, PartialEq, Eq)]
struct OriginInfo {
    project: String,
    instance: String,
}

/// A `manifest.records[]` entry (§11.2.1).
#[derive(Clone, Debug)]
struct ManifestRecordEntry {
    id: String,
    kind: String,
    digest: String,
    chain_index: Option<i64>,
}

/// A `manifest.blobs[]` entry (§11.7).
#[derive(Clone, Debug)]
struct BlobEntry {
    digest: String,
    size: u64,
}

/// The parsed and structurally validated manifest.
#[derive(Clone, Debug)]
struct Manifest {
    origin: Option<OriginInfo>,
    created_at: Timestamp,
    level: Level,
    records: Vec<ManifestRecordEntry>,
    previous_manifest: Option<String>,
    chain: Option<String>,
    blobs: Option<Vec<BlobEntry>>,
}

/// Parses and validates `manifest.json` (§11.2, §11.2.1).
///
/// The first non-skipped violation is returned; a skipped violation is treated
/// as passed with a conservative fallback so the §14.7 hook never panics.
fn parse_manifest(object: &Object, options: &VerifyOptions) -> Result<Manifest, Code> {
    const MEMBERS: [&str; 9] = [
        "format",
        "manifest_version",
        "origin",
        "created_at",
        "level",
        "records",
        "previous_manifest",
        "chain",
        "blobs",
    ];
    // Closed object.
    if let Some(_unknown) = object.first_unknown(MEMBERS) {
        if !options.skipped(e::MANIFEST_SCHEMA) {
            return Err(e::MANIFEST_SCHEMA);
        }
    }
    for required in [
        "format",
        "manifest_version",
        "origin",
        "created_at",
        "level",
        "records",
        "previous_manifest",
    ] {
        if !object.contains(required) && !options.skipped(e::MANIFEST_SCHEMA) {
            return Err(e::MANIFEST_SCHEMA);
        }
    }

    // format (§11.2).
    if object.get_str("format") != Some(FORMAT) && !options.skipped(e::MANIFEST_FORMAT) {
        return Err(e::MANIFEST_FORMAT);
    }

    // manifest_version (§11.2): version 1 is the only supported integer.
    match object.get_i64("manifest_version") {
        Some(1) => {}
        Some(_) => {
            if !options.skipped(e::MANIFEST_VERSION) {
                return Err(e::MANIFEST_VERSION);
            }
        }
        None => {
            if !options.skipped(e::MANIFEST_SCHEMA) {
                return Err(e::MANIFEST_SCHEMA);
            }
        }
    }

    // origin (§4.1); malformed is a manifest schema error.
    let origin = match object.get("origin").and_then(parse_origin_object) {
        Some(origin) => Some(origin),
        None => {
            if !options.skipped(e::MANIFEST_SCHEMA) {
                return Err(e::MANIFEST_SCHEMA);
            }
            None
        }
    };

    // created_at (§2.8).
    let created_at = match object
        .get_str("created_at")
        .and_then(Timestamp::parse)
    {
        Some(time) => time,
        None => {
            if !options.skipped(e::MANIFEST_SCHEMA) {
                return Err(e::MANIFEST_SCHEMA);
            }
            Timestamp::parse("1970-01-01T00:00:00.000Z").expect("epoch literal")
        }
    };

    // level (§11.4).
    let level = match object.get_str("level") {
        Some("L0") => Level::L0,
        Some("L1") => Level::L1,
        Some("L2") => Level::L2,
        _ => {
            if !options.skipped(e::MANIFEST_LEVEL) {
                return Err(e::MANIFEST_LEVEL);
            }
            Level::L0
        }
    };

    // records (§11.2.1): a sorted, unique array of 1..=MAX_RECORDS closed
    // entries with valid grammars and sha256 digests.
    let records = parse_manifest_records(object, options)?;

    // previous_manifest (§11.5): null or exactly {"digest": <digest string>}.
    let previous_manifest = match object.get("previous_manifest") {
        Some(Value::Null) => None,
        Some(value) => match parse_previous_manifest(value) {
            Some(digest_string) => Some(digest_string),
            None => {
                if !options.skipped(e::MANIFEST_SCHEMA) {
                    return Err(e::MANIFEST_SCHEMA);
                }
                None
            }
        },
        None => {
            if !options.skipped(e::MANIFEST_SCHEMA) {
                return Err(e::MANIFEST_SCHEMA);
            }
            None
        }
    };

    // chain (§11.2): absent or null, or exactly {"algorithm":"sha256",
    // "head":<digest string>}. Missing/duplicate chain_index for L1/L2 is a
    // separate check (§14.5 (6), E_MANIFEST_L1_NO_POSITION).
    let chain = match object.get("chain") {
        None | Some(Value::Null) => None,
        Some(value) => match parse_chain_claim(value) {
            Some(head) => Some(head),
            None => {
                if !options.skipped(e::MANIFEST_SCHEMA) {
                    return Err(e::MANIFEST_SCHEMA);
                }
                None
            }
        },
    };

    // blobs (§11.7): array of closed {digest,size} objects, sorted ascending by
    // digest, unique digests, sha256 only, at most MAX_BLOBS.
    let blobs = match object.get("blobs") {
        None => None,
        Some(value) => match parse_blobs(value, options) {
            Ok(blobs) => Some(blobs),
            Err(code) => {
                if !options.skipped(code) {
                    return Err(code);
                }
                None
            }
        },
    };

    Ok(Manifest {
        origin,
        created_at,
        level,
        records,
        previous_manifest,
        chain,
        blobs,
    })
}

fn parse_origin_object(value: &Value) -> Option<OriginInfo> {
    let object = value.as_object()?;
    const MEMBERS: [&str; 2] = ["project", "instance"];
    if object.len() != MEMBERS.len() || object.first_unknown(MEMBERS).is_some() {
        return None;
    }
    if !MEMBERS.iter().all(|member| object.contains(member)) {
        return None;
    }
    let project = object.get_str("project")?;
    if !patterns::is_project_slug(project) {
        return None;
    }
    let instance = object.get_str("instance")?;
    if !digest::is_valid_key_id(instance) {
        return None;
    }
    Some(OriginInfo {
        project: project.to_owned(),
        instance: instance.to_owned(),
    })
}

fn parse_previous_manifest(value: &Value) -> Option<String> {
    let object = value.as_object()?;
    const MEMBERS: [&str; 1] = ["digest"];
    if object.len() != 1 || object.first_unknown(MEMBERS).is_some() || !object.contains("digest") {
        return None;
    }
    let digest_string = object.get_str("digest")?;
    digest::parse_digest_string(digest_string)?;
    Some(digest_string.to_owned())
}

fn parse_chain_claim(value: &Value) -> Option<String> {
    let object = value.as_object()?;
    const MEMBERS: [&str; 2] = ["algorithm", "head"];
    if object.len() != MEMBERS.len() || object.first_unknown(MEMBERS).is_some() {
        return None;
    }
    if object.get_str("algorithm") != Some("sha256") {
        return None;
    }
    let head = object.get_str("head")?;
    if !digest::is_sha256_digest(head) {
        return None;
    }
    Some(head.to_owned())
}

/// Parses `manifest.records` (§11.2.1).
fn parse_manifest_records(
    object: &Object,
    options: &VerifyOptions,
) -> Result<Vec<ManifestRecordEntry>, Code> {
    let Some(value) = object.get("records") else {
        if options.skipped(e::MANIFEST_SCHEMA) {
            return Ok(Vec::new());
        }
        return Err(e::MANIFEST_SCHEMA);
    };
    let Some(array) = value.as_array() else {
        if options.skipped(e::MANIFEST_RECORDS) || options.skipped(e::MANIFEST_SCHEMA) {
            return Ok(Vec::new());
        }
        return Err(e::MANIFEST_RECORDS);
    };
    if array.is_empty() || array.len() > limits::MAX_RECORDS {
        if !options.skipped(e::MANIFEST_RECORDS) {
            return Err(e::MANIFEST_RECORDS);
        }
    }
    let mut entries = Vec::with_capacity(array.len());
    for item in array {
        match parse_manifest_record(item) {
            Some(entry) => entries.push(entry),
            None => {
                if !options.skipped(e::MANIFEST_RECORDS) {
                    return Err(e::MANIFEST_RECORDS);
                }
            }
        }
    }
    // Sorted ascending by digest, unique digests.
    for window in entries.windows(2) {
        if json::utf16_cmp(&window[0].digest, &window[1].digest) != std::cmp::Ordering::Less
            && !options.skipped(e::MANIFEST_RECORDS)
        {
            return Err(e::MANIFEST_RECORDS);
        }
    }
    Ok(entries)
}

fn parse_manifest_record(value: &Value) -> Option<ManifestRecordEntry> {
    let object = value.as_object()?;
    const MEMBERS: [&str; 4] = ["id", "kind", "digest", "chain_index"];
    if object.first_unknown(MEMBERS).is_some() {
        return None;
    }
    let id = object.get_str("id")?;
    if !patterns::is_envelope_id(id) {
        return None;
    }
    let kind = object.get_str("kind")?;
    if !patterns::is_kind_name(kind) {
        return None;
    }
    let digest_string = object.get_str("digest")?;
    // §11.2.1: a container must list verifiable sha256 digests.
    if !digest::is_sha256_digest(digest_string) {
        return None;
    }
    let chain_index = match object.get("chain_index") {
        None => None,
        Some(value) => {
            let index = value.as_i64()?;
            if index < 0 {
                return None;
            }
            Some(index)
        }
    };
    Some(ManifestRecordEntry {
        id: id.to_owned(),
        kind: kind.to_owned(),
        digest: digest_string.to_owned(),
        chain_index,
    })
}

/// Parses and validates `manifest.blobs` (§11.7).
fn parse_blobs(value: &Value, options: &VerifyOptions) -> Result<Vec<BlobEntry>, Code> {
    let Some(array) = value.as_array() else {
        return Err(e::MANIFEST_SCHEMA);
    };
    if array.len() > limits::MAX_BLOBS {
        // §13 fixes the limit-to-code mapping: MAX_BLOBS is E_MANIFEST_SCHEMA.
        return Err(e::MANIFEST_SCHEMA);
    }
    let mut blobs = Vec::with_capacity(array.len());
    for item in array {
        let Some(object) = item.as_object() else {
            if options.skipped(e::MANIFEST_SCHEMA) {
                continue;
            }
            return Err(e::MANIFEST_SCHEMA);
        };
        const MEMBERS: [&str; 2] = ["digest", "size"];
        if object.len() != MEMBERS.len()
            || object.first_unknown(MEMBERS).is_some()
            || !MEMBERS.iter().all(|member| object.contains(member))
        {
            if options.skipped(e::MANIFEST_SCHEMA) {
                continue;
            }
            return Err(e::MANIFEST_SCHEMA);
        }
        let Some(digest_string) = object.get_str("digest") else {
            if options.skipped(e::MANIFEST_SCHEMA) {
                continue;
            }
            return Err(e::MANIFEST_SCHEMA);
        };
        if digest::parse_digest_string(digest_string).is_none() {
            if options.skipped(e::MANIFEST_SCHEMA) {
                continue;
            }
            return Err(e::MANIFEST_SCHEMA);
        }
        let Some(size) = object.get_i64("size") else {
            if options.skipped(e::MANIFEST_SCHEMA) {
                continue;
            }
            return Err(e::MANIFEST_SCHEMA);
        };
        if size < 0 {
            if options.skipped(e::MANIFEST_SCHEMA) {
                continue;
            }
            return Err(e::MANIFEST_SCHEMA);
        }
        // §11.7: H0 blobs are sha256-only; unsupported algorithms are
        // E_MANIFEST_BLOB.
        if !digest::is_sha256_digest(digest_string) {
            if options.skipped(e::MANIFEST_BLOB) {
                continue;
            }
            return Err(e::MANIFEST_BLOB);
        }
        blobs.push(BlobEntry {
            digest: digest_string.to_owned(),
            size: u64::try_from(size).unwrap_or(0),
        });
    }
    // Sorted ascending by digest, unique digests.
    for window in blobs.windows(2) {
        if json::utf16_cmp(&window[0].digest, &window[1].digest) != std::cmp::Ordering::Less {
            if options.skipped(e::MANIFEST_BLOB) {
                return Ok(Vec::new());
            }
            return Err(e::MANIFEST_BLOB);
        }
    }
    Ok(blobs)
}

// ---------------------------------------------------------------------------
// Attestation file (§11.3)
// ---------------------------------------------------------------------------

/// The parsed attestation file: signature entries plus timestamp inventory.
struct Attestation {
    signatures: Vec<SigEntry>,
    timestamps: Vec<AttestationTimestamp>,
}

/// Parses the attestation file and checks its inventory (§11.3): closed
/// object, format, digest, signature array grammar, timestamp list grammar and
/// the level-specific timestamp completeness rules.
fn parse_attestation(
    object: &Object,
    manifest: &Manifest,
    manifest_digest: &str,
    layout: &Layout,
    options: &VerifyOptions,
) -> Result<Attestation, Code> {
    const MEMBERS: [&str; 4] = ["digest", "format", "signatures", "timestamps"];
    if object.first_unknown(MEMBERS).is_some() && !options.skipped(e::MANIFEST_SCHEMA) {
        return Err(e::MANIFEST_SCHEMA);
    }
    for required in MEMBERS {
        if !object.contains(required) && !options.skipped(e::MANIFEST_SCHEMA) {
            return Err(e::MANIFEST_SCHEMA);
        }
    }

    if object.get_str("format") != Some(FORMAT) && !options.skipped(e::MANIFEST_SCHEMA) {
        return Err(e::MANIFEST_SCHEMA);
    }

    // The declared digest must be a digest string and equal the §2.4 manifest
    // digest (checked before signature verification, §14.5 (4)).
    match object.get_str("digest") {
        Some(declared) => {
            if digest::parse_digest_string(declared).is_none()
                && !options.skipped(e::MANIFEST_SCHEMA)
            {
                return Err(e::MANIFEST_SCHEMA);
            }
            if declared != manifest_digest && !options.skipped(e::MANIFEST_DIGEST) {
                return Err(e::MANIFEST_DIGEST);
            }
        }
        None => {
            if !options.skipped(e::MANIFEST_SCHEMA) {
                return Err(e::MANIFEST_SCHEMA);
            }
        }
    }

    // Signature array grammar (§4.3 used by §11.3).
    let signatures = match object.get("signatures") {
        Some(value) => match envelope::parse_signature_array(value) {
            Ok(entries) => entries,
            Err(code) => {
                if !options.skipped(code) {
                    return Err(code);
                }
                Vec::new()
            }
        },
        None => {
            if !options.skipped(e::MANIFEST_SCHEMA) {
                return Err(e::MANIFEST_SCHEMA);
            }
            Vec::new()
        }
    };

    // Timestamp inventory (Q21: the member is mandatory, possibly empty).
    let mut timestamps = match object.get("timestamps") {
        Some(value) => match parse_timestamp_entries(value, options) {
            Ok(entries) => entries,
            Err(code) => {
                if !options.skipped(code) {
                    return Err(code);
                }
                Vec::new()
            }
        },
        None => {
            if !options.skipped(e::MANIFEST_SCHEMA) {
                return Err(e::MANIFEST_SCHEMA);
            }
            Vec::new()
        }
    };

    // Level-specific completeness (§11.3, §12.5).
    match manifest.level {
        Level::L0 | Level::L1 => {
            if !timestamps.is_empty() && !options.skipped(e::MANIFEST_LEVEL) {
                return Err(e::MANIFEST_LEVEL);
            }
        }
        Level::L2 => {
            if timestamps.is_empty() && !options.skipped(e::MANIFEST_L2_NO_TIMESTAMP) {
                return Err(e::MANIFEST_L2_NO_TIMESTAMP);
            }
        }
    }

    // Every listed `.tsr` must exist and hash to its listed digest, and every
    // `.tsr` file in `signatures/` must be listed (`E_TS_FILE`, §11.3).
    let mut tsr_problem = false;
    let mut verified_entries = Vec::with_capacity(timestamps.len());
    for entry in &timestamps {
        match layout.timestamps.get(&entry.path) {
            Some(bytes) => {
                if digest::sha256_digest_string(bytes) != entry.digest {
                    tsr_problem = true;
                } else {
                    verified_entries.push(entry.clone());
                }
            }
            None => tsr_problem = true,
        }
    }
    for path in layout.timestamps.keys() {
        if !timestamps.iter().any(|entry| &entry.path == path) {
            tsr_problem = true;
        }
    }
    if tsr_problem {
        if !options.skipped(e::TS_FILE) {
            return Err(e::TS_FILE);
        }
        // The chain cannot be verified against the promised receipt bytes.
        timestamps.clear();
    } else {
        timestamps = verified_entries;
    }

    Ok(Attestation {
        signatures,
        timestamps,
    })
}

/// Parses `timestamps[]` (§11.3): closed entries sorted by path, unique paths
/// and digests, valid path/digest grammars.
fn parse_timestamp_entries(
    value: &Value,
    options: &VerifyOptions,
) -> Result<Vec<AttestationTimestamp>, Code> {
    let Some(array) = value.as_array() else {
        return Err(e::MANIFEST_SCHEMA);
    };
    let mut entries = Vec::with_capacity(array.len());
    for item in array {
        match parse_timestamp_entry(item) {
            Some(entry) => entries.push(entry),
            None => {
                if !options.skipped(e::MANIFEST_SCHEMA) {
                    return Err(e::MANIFEST_SCHEMA);
                }
            }
        }
    }
    for window in entries.windows(2) {
        if json::utf16_cmp(&window[0].path, &window[1].path) != std::cmp::Ordering::Less
            || window[0].digest == window[1].digest
        {
            if !options.skipped(e::MANIFEST_SCHEMA) {
                return Err(e::MANIFEST_SCHEMA);
            }
        }
    }
    Ok(entries)
}

fn parse_timestamp_entry(value: &Value) -> Option<AttestationTimestamp> {
    let object = value.as_object()?;
    const MEMBERS: [&str; 3] = ["digest", "path", "renews"];
    if object.len() != MEMBERS.len()
        || object.first_unknown(MEMBERS).is_some()
        || !MEMBERS.iter().all(|member| object.contains(member))
    {
        return None;
    }
    let digest_string = object.get_str("digest")?;
    if !digest::is_sha256_digest(digest_string) {
        return None;
    }
    let path = object.get_str("path")?;
    let Some(name) = path.strip_prefix("signatures/") else {
        return None;
    };
    if name.contains('/') || !is_timestamp_file_name(name) {
        return None;
    }
    let renews = match object.get("renews")? {
        Value::Null => None,
        Value::Str(text) => Some(text.clone()),
        _ => return None,
    };
    Some(AttestationTimestamp {
        digest: digest_string.to_owned(),
        path: path.to_owned(),
        renews,
    })
}

// ---------------------------------------------------------------------------
// Timestamp chain (§12)
// ---------------------------------------------------------------------------

/// Verifies the renewal chain (§12.4). L0/L1 containers list no receipts and
/// get empty evidence; nothing touches the timestamp parser in that case.
fn verify_timestamps(
    entries: &[AttestationTimestamp],
    manifest_digest: &str,
    files: &BTreeMap<String, Vec<u8>>,
    options: &VerifyOptions,
) -> Result<ChainEvidence, UsageError> {
    if entries.is_empty() {
        return Ok(ChainEvidence::none());
    }
    let anchors = if options.tsa_trust.is_empty() {
        Vec::new()
    } else {
        timestamp::load_trust_anchors(&options.tsa_trust)?
    };
    let raw_manifest_digest = digest::sha256_digest_bytes(manifest_digest).unwrap_or([0u8; 32]);
    Ok(timestamp::verify_chain(
        entries,
        &raw_manifest_digest,
        files,
        &anchors,
    ))
}

/// One `container.timestamps[]` report entry per attestation entry (§14.6).
fn timestamp_reports(
    entries: &[AttestationTimestamp],
    evidence: &ChainEvidence,
) -> Vec<TimestampReport> {
    entries
        .iter()
        .enumerate()
        .map(|(index, entry)| {
            let receipt = evidence.receipts.get(index);
            let state = match receipt {
                Some(receipt) => match receipt.state {
                    ReceiptState::Verified => "verified",
                    ReceiptState::PresentUnverified => "present-unverified",
                    ReceiptState::Invalid => "invalid",
                },
                None => "invalid",
            };
            TimestampReport {
                index,
                path: Some(entry.path.clone()),
                state: state.to_owned(),
                gen_time: receipt
                    .and_then(|receipt| receipt.gen_time)
                    .map(Timestamp::to_ts_string),
            }
        })
        .collect()
}

/// §12.5: the container-level effects of the timestamp outcomes. Checks 1–14
/// make the container invalid; an all-checks-1–14-pass but untrusted chain
/// makes it unverifiable.
fn timestamp_effects(evidence: &ChainEvidence) -> Vec<Code> {
    if let Some(chain_error) = evidence.chain_error {
        return vec![chain_error];
    }
    let mut codes = Vec::new();
    let mut any_invalid = false;
    for receipt in &evidence.receipts {
        if receipt.state == ReceiptState::Invalid {
            any_invalid = true;
            if let Some(code) = receipt.error {
                codes.push(code);
            }
        }
    }
    if !any_invalid && evidence.receipts.iter().any(|receipt| receipt.state == ReceiptState::PresentUnverified) {
        codes.push(e::TS_UNTRUSTED);
    }
    codes
}

// ---------------------------------------------------------------------------
// Level and chain completeness (§11.2, §11.4)
// ---------------------------------------------------------------------------

/// §14.5 (6): level/chain structure completeness.
fn check_level_and_chain(manifest: &Manifest) -> Result<(), Code> {
    match manifest.level {
        Level::L0 => {
            // L0 is the level without an internal chain claim (§11.2).
            if manifest.chain.is_some() {
                return Err(e::MANIFEST_LEVEL);
            }
        }
        Level::L1 | Level::L2 => {
            if manifest.chain.is_none() {
                return Err(e::MANIFEST_L1_NO_HEAD);
            }
            // §11.2.1: `chain_index` is required and unique for L1/L2.
            let mut seen: BTreeSet<i64> = BTreeSet::new();
            for entry in &manifest.records {
                match entry.chain_index {
                    Some(index) if seen.insert(index) => {}
                    Some(_) | None => return Err(e::MANIFEST_L1_NO_POSITION),
                }
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Records listing (§11.6)
// ---------------------------------------------------------------------------

/// One manifest record entry together with the outcome of reading its file.
struct EntryState {
    entry: ManifestRecordEntry,
    /// Container-relative file path derived from the entry digest.
    path: String,
    /// Result of [`envelope::parse_record_file`] when the file is present; the
    /// error code is passed to the world so the per-record report carries the
    /// real first failing check.
    parsed: Option<Result<RecordFile, Code>>,
    /// The first container-level records-listing error for this entry.
    error: Option<Code>,
}

fn entry_file_path(digest_string: &str) -> Option<String> {
    let hex = digest_string.strip_prefix("sha256:")?;
    Some(format!("records/{hex}.json"))
}

/// Reads every manifest-listed record file and checks the §11.6 listing
/// consistency for it. Content defects of the *record itself* are left to the
/// per-record pipeline; parse failures that make the digest uncomputable and
/// digest/metadata mismatches are container errors.
fn build_entries(
    records: &[ManifestRecordEntry],
    record_files: &BTreeMap<String, Vec<u8>>,
) -> Vec<EntryState> {
    records
        .iter()
        .map(|entry| {
            let path = entry_file_path(&entry.digest).unwrap_or_default();
            let Some(bytes) = record_files.get(&path) else {
                return EntryState {
                    entry: entry.clone(),
                    path,
                    parsed: None,
                    error: Some(e::MANIFEST_RECORD_MISSING),
                };
            };
            let object = match json::parse_canonical_object(bytes, limits::MAX_RECORD_BYTES) {
                Ok(object) => object,
                Err(code) => {
                    // The digest cannot be computed from a file that is not
                    // canonical JSON; §13 keeps its own size code.
                    let mapped = if code == e::JSON_SIZE {
                        e::JSON_SIZE
                    } else {
                        e::MANIFEST_RECORD_DIGEST
                    };
                    return EntryState {
                        entry: entry.clone(),
                        path,
                        parsed: None,
                        error: Some(mapped),
                    };
                }
            };
            let computed = digest::record_digest(&object);
            let mut error = None;
            if computed != entry.digest {
                error = Some(e::MANIFEST_RECORD_DIGEST);
            } else if object.get_str("id") != Some(entry.id.as_str())
                || object.get_str("kind") != Some(entry.kind.as_str())
            {
                error = Some(e::MANIFEST_RECORDS);
            }
            EntryState {
                entry: entry.clone(),
                path,
                parsed: Some(envelope::parse_record_file(bytes)),
                error,
            }
        })
        .collect()
}

/// A `records[]` entry for a container whose records listing is inconsistent:
/// nothing is claimed verified, the manifest metadata is reported, and the
/// entry carries the container code that concerns it where known.
fn synthetic_record(entry: &EntryState) -> RecordReport {
    let mut errors = Vec::new();
    if let Some(code) = entry.error {
        errors.push(code);
    }
    RecordReport {
        digest: Some(entry.entry.digest.clone()),
        id: Some(entry.entry.id.clone()),
        kind: Some(entry.entry.kind.clone()),
        stage: None,
        origin: None,
        kind_known: Some(envelope::is_registered_kind(&entry.entry.kind)),
        verdict: Verdict::Invalid,
        errors,
        notices: Vec::new(),
        refs: Vec::new(),
        sigs: Vec::new(),
        attestation: None,
    }
}

/// §14.5 (8): merges the context's cross-record outcomes into the reports.
fn merge_cross_checks(
    cross: &crate::context::CrossCheckOutcome,
    container: &mut ContainerReport,
    records: &mut [RecordReport],
) {
    for code in &cross.container_errors {
        container.errors.push(code);
    }
    for code in &cross.container_notices {
        container.notices.push(code);
    }
    for (index, code) in &cross.record_errors {
        if let Some(report) = records.get_mut(*index) {
            report.errors.push(code);
            if is_unverifiable_code(code) {
                if report.verdict == Verdict::Valid {
                    report.verdict = Verdict::Unverifiable;
                }
            } else {
                report.verdict = Verdict::Invalid;
            }
        }
    }
    for (index, code) in &cross.record_notices {
        if let Some(report) = records.get_mut(*index) {
            report.notices.push(code);
        }
    }
}

// ---------------------------------------------------------------------------
// Blobs (§11.7)
// ---------------------------------------------------------------------------

/// §14.5 (9): the blob inventory must agree exactly with `manifest.blobs`.
fn check_blobs(listed: Option<&[BlobEntry]>, files: &BTreeMap<String, Vec<u8>>) -> Vec<Code> {
    let mut errors = Vec::new();
    match listed {
        None => {
            // A present `blobs/` directory must have a non-empty listing.
            if !files.is_empty() {
                errors.push(e::MANIFEST_BLOB);
            }
        }
        Some(blobs) => {
            let mut expected: BTreeSet<String> = BTreeSet::new();
            for blob in blobs {
                let Some(hex) = blob.digest.strip_prefix("sha256:") else {
                    errors.push(e::MANIFEST_BLOB);
                    continue;
                };
                let path = format!("blobs/sha256/{hex}");
                match files.get(&path) {
                    Some(bytes) => {
                        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) != blob.size
                            || digest::sha256_digest_string(bytes) != blob.digest
                            || blob.size > limits::MAX_BLOB_BYTES
                        {
                            errors.push(e::MANIFEST_BLOB);
                        }
                    }
                    None => errors.push(e::MANIFEST_BLOB),
                }
                expected.insert(path);
            }
            if files.keys().any(|path| !expected.contains(path)) {
                errors.push(e::MANIFEST_BLOB);
            }
        }
    }
    errors.sort_unstable();
    errors.dedup();
    errors
}

// ---------------------------------------------------------------------------
// Previous-manifest chain (§11.5)
// ---------------------------------------------------------------------------

/// §14.5 (10): embedded previous-manifest chain and the `--previous` check.
fn check_previous_chain(
    manifest: &Manifest,
    layout: &Layout,
    options: &VerifyOptions,
) -> Result<(Vec<Code>, Vec<Code>), UsageError> {
    let mut errors = Vec::new();
    let mut notices = Vec::new();
    match &manifest.previous_manifest {
        None => {
            // §11.5: with a null `previous_manifest`, `previous/` must be
            // absent or empty.
            if layout.previous_manifest.is_some() {
                errors.push(e::MANIFEST_CHAIN_UNEXPECTED);
            }
        }
        Some(expected_digest) => {
            match layout.previous_manifest.as_deref() {
                None => errors.push(e::MANIFEST_CHAIN_MISSING),
                Some(bytes) => {
                    match previous_manifest_matches(bytes, expected_digest, manifest) {
                        Ok(()) => {
                            // §11.5: the embedded previous manifest's own
                            // signature is not re-verified by default.
                            notices.push(n::PREVIOUS_SIG_UNVERIFIED);
                        }
                        Err(code) => errors.push(code),
                    }
                }
            }
        }
    }
    // `--previous <dir>`: the supplied previous container's manifest digest
    // must equal `manifest.previous_manifest.digest` (§11.5).
    if let Some(previous_input) = &options.previous {
        let previous_files = match previous_input {
            ContainerInput::Directory(root) => match read_directory(root) {
                Ok(materialised) => materialised.files,
                Err(ReadFailure::Usage(error)) => return Err(error),
                Err(ReadFailure::Content { partial, .. }) => partial.files,
            },
            ContainerInput::Zip(bytes) => zip::read_zip(bytes).unwrap_or_default(),
            ContainerInput::Files(files) => files.clone(),
        };
        let matches = match previous_files.get(MANIFEST_PATH) {
            Some(bytes) => {
                let without_lf = match bytes.split_last() {
                    Some((&b'\n', head)) => head,
                    _ => bytes.as_slice(),
                };
                let computed = digest::manifest_digest(without_lf);
                manifest.previous_manifest.as_deref() == Some(computed.as_str())
            }
            None => false,
        };
        if !matches {
            errors.push(e::MANIFEST_CHAIN);
        }
    }
    errors.sort_unstable();
    errors.dedup();
    Ok((errors, notices))
}

/// Validates an embedded `previous/manifest.json` against the current manifest
/// (§11.5): canonical form, a supported manifest, the §2.4 digest match and the
/// same-publisher rule.
fn previous_manifest_matches(
    bytes: &[u8],
    expected_digest: &str,
    current: &Manifest,
) -> Result<(), Code> {
    let object = json::parse_canonical_object(bytes, limits::MAX_MANIFEST_BYTES)
        .map_err(|_| e::MANIFEST_CHAIN)?;
    if object.get_str("format") != Some(FORMAT)
        || object.get_i64("manifest_version") != Some(1)
    {
        return Err(e::MANIFEST_CHAIN);
    }
    // §11.5 [M-8]: the chain records the history of one publisher.
    let previous_origin = object
        .get("origin")
        .and_then(parse_origin_object)
        .ok_or(e::MANIFEST_CHAIN)?;
    if let Some(current_origin) = &current.origin {
        if &previous_origin != current_origin {
            return Err(e::MANIFEST_CHAIN);
        }
    }
    let canonical = json::canonical_object_bytes(&object);
    if digest::manifest_digest(&canonical) != expected_digest {
        return Err(e::MANIFEST_CHAIN);
    }
    Ok(())
}

