// SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
// SPDX-License-Identifier: Apache-2.0

//! Container verification (§11, §14.5).
//!
//! The container checks run in the fixed order of §14.5: (1) entry
//! enumeration and safety, (2) manifest parse and canonical form, (3) manifest
//! structure, (4) manifest digest, (5) manifest signature, (6) level/chain
//! completeness, (7) records listing and per-record verification, (8)
//! cross-record state, (9) blobs, (10) previous-manifest chain, (11)
//! timestamps, (12) aggregation.
//!
//! A container-level **invalid** error stops the pipeline at the stage where
//! it is found (W5): later stages report nothing, and an invalid error before
//! step (7) reports `records: []`. The failing stage reports every violation
//! it found (sorted, unique). An `unverifiable` container condition does not
//! stop the pipeline. Timestamps are verified early, because §9.4 uses them as
//! evidence, but are reported only when the pipeline reaches step (11).
//!
//! Reading is bounded (S4, §13): every file of a directory container is read
//! through a probe bounded by its class limit plus one byte, `readable/` is
//! never descended into, and the container byte total is accumulated while
//! reading; a zip is checked through phases 1–4 of §11.9 before anything is
//! decompressed, members are decompressed under their class cap, blobs are
//! hashed while streaming and `readable/**` is never decompressed.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::Path;

use crate::context::World;
use crate::digest;
use crate::envelope::{self, RecordFile, SigEntry};
use crate::error_codes::{e, n, Code};
use crate::json;
use crate::limitations::{self, LimitationFacts};
use crate::limits;
use crate::options::{ContainerInput, UsageError, VerifyOptions};
use crate::patterns;
use crate::report::{
    ChainReport, ContainerReport, InputIdentity, RecordReport, Report, Summary, Target,
    TimestampReport, Verdict, VerdictCounts, VerifierInfo,
};
use crate::time::Timestamp;
use crate::timestamp::{self, AttestationTimestamp, ChainEvidence, ReceiptState};
use crate::value::{Object, Value};
use crate::zip;

/// Relative path of the manifest (§11.1).
const MANIFEST_PATH: &str = "manifest.json";
/// Relative path of the manifest attestation file (§11.1).
const SIGFILE_PATH: &str = "signatures/manifest.sig.json";
/// The only `format` value defined by this specification version.
const FORMAT: &str = "weave-record/1";

// ---------------------------------------------------------------------------
// Step (1): materialised content
// ---------------------------------------------------------------------------

/// The bytes of one in-container file, read under its class limit.
#[derive(Clone, Debug, PartialEq, Eq)]
enum FileData {
    /// The file, within its class limit.
    Bytes(Vec<u8>),
    /// The file exceeds its §13 class limit; it was not read in full.
    Oversize,
}

/// A blob, hashed while streaming.
#[derive(Clone, Debug, PartialEq, Eq)]
enum BlobData {
    /// SHA-256 digest string and byte size.
    Hashed { digest: String, size: u64 },
    /// Above `MAX_BLOB_BYTES`.
    Oversize,
}

/// The closed container layout after step (1).
#[derive(Default)]
struct Content {
    manifest: Option<FileData>,
    sigfile: Option<FileData>,
    previous_manifest: Option<FileData>,
    timestamps: BTreeMap<String, FileData>,
    records: BTreeMap<String, FileData>,
    /// A file in `records/` whose name is not `<64 hex>.json` (§11.1: an extra
    /// record file, reported by the records listing at step (7)).
    records_extra: bool,
    /// Such a misnamed `records/` file is above `MAX_RECORD_BYTES` (F55: an
    /// unlisted or misnamed oversize file reports `E_JSON_SIZE` as well).
    records_extra_oversize: bool,
    blobs: BTreeMap<String, BlobData>,
    /// A file in `blobs/` outside `blobs/sha256/<64 hex>` (§11.1: reported by
    /// the blob stage, step (9)).
    blobs_extra: bool,
    /// A `blobs/` directory is present (§11.7: it requires a non-empty
    /// `manifest.blobs`), even when it holds no file.
    blobs_dir_present: bool,
    readable_present: bool,
}

/// The class of a container-relative path (§11.1) and its §13 read limit.
enum PathClass {
    Manifest,
    Sigfile,
    Timestamp,
    TsaCert,
    PreviousManifest,
    Record,
    RecordsExtra,
    Blob,
    BlobsExtra,
    Readable,
    Unknown,
}

fn classify_path(path: &str) -> PathClass {
    if path == MANIFEST_PATH {
        return PathClass::Manifest;
    }
    if path.starts_with("readable/") {
        return PathClass::Readable;
    }
    if let Some(rest) = path.strip_prefix("signatures/") {
        if !rest.contains('/') {
            if rest == "manifest.sig.json" {
                return PathClass::Sigfile;
            }
            if is_timestamp_file_name(rest) {
                return PathClass::Timestamp;
            }
            if is_tsa_cert_file_name(rest) {
                return PathClass::TsaCert;
            }
        }
        return PathClass::Unknown;
    }
    if path == "previous/manifest.json" {
        return PathClass::PreviousManifest;
    }
    if let Some(rest) = path.strip_prefix("records/") {
        if !rest.contains('/') && is_record_file_name(rest) {
            return PathClass::Record;
        }
        if !rest.contains('/') {
            return PathClass::RecordsExtra;
        }
        return PathClass::Unknown;
    }
    if let Some(rest) = path.strip_prefix("blobs/") {
        // §11.1 (S3): a file in `blobs/` or `blobs/sha256/` that is not a blob is
        // an extra blob file whatever its name (step (9), E_MANIFEST_BLOB); a
        // file one directory deeper lies in a directory the layout does not
        // list (`blobs/<other>/`, `blobs/sha256/<dir>/`), E_CONTAINER_ENTRY.
        // The directory walk already rejects those directories; this keeps the
        // zip form, which has no directory walk, judging the same way (§11.9).
        let name = rest.strip_prefix("sha256/").unwrap_or(rest);
        if name.contains('/') {
            return PathClass::Unknown;
        }
        if rest.len() > name.len() && is_lower_hex_64(name) {
            return PathClass::Blob;
        }
        return PathClass::BlobsExtra;
    }
    PathClass::Unknown
}

/// `MAX_RECORD_BYTES` as a byte count.
fn record_limit() -> u64 {
    u64::try_from(limits::MAX_RECORD_BYTES).unwrap_or(u64::MAX)
}

/// The §13 read limit of a file class.
fn class_limit(class: &PathClass) -> u64 {
    let limit = match class {
        PathClass::Manifest | PathClass::PreviousManifest => limits::MAX_MANIFEST_BYTES,
        PathClass::Sigfile => limits::MAX_SIGFILE_BYTES,
        PathClass::Timestamp => limits::MAX_TIMESTAMP_BYTES,
        PathClass::Record => limits::MAX_RECORD_BYTES,
        PathClass::Blob => return limits::MAX_BLOB_BYTES,
        _ => 0,
    };
    u64::try_from(limit).unwrap_or(u64::MAX)
}

/// True when a path is a safe container-relative path: no absolute prefix, no
/// `.`/`..`/empty segments, no NUL bytes, no backslash.
fn is_safe_relative_path(path: &str) -> bool {
    if path.is_empty() || path.starts_with('/') || path.contains('\0') || path.contains('\\') {
        return false;
    }
    path.split('/')
        .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
}

/// A step-(1) failure: the stage's codes and whether a `readable/` entry was
/// observed before it (§11.8, T12).
struct EnumerationFailure {
    codes: Vec<Code>,
    readable_observed: bool,
    /// `manifest.json` when it was read within its limit (§14.6 tier (b)).
    manifest: Option<FileData>,
}

/// Accumulates the container byte total while reading (§13, T15).
struct Budget {
    total: u64,
    exceeded: bool,
}

impl Budget {
    fn add(&mut self, bytes: u64) {
        self.total = self.total.saturating_add(bytes);
        if self.total > limits::MAX_CONTAINER_UNCOMPRESSED_BYTES {
            self.exceeded = true;
        }
    }
}

impl Content {
    fn store(&mut self, path: &str, class: &PathClass, data: FileData) {
        match class {
            PathClass::Manifest => self.manifest = Some(data),
            PathClass::Sigfile => self.sigfile = Some(data),
            PathClass::PreviousManifest => self.previous_manifest = Some(data),
            PathClass::Timestamp => {
                self.timestamps.insert(path.to_owned(), data);
            }
            PathClass::Record => {
                self.records.insert(path.to_owned(), data);
            }
            _ => {}
        }
    }
}

/// Step (1) for a directory container.
fn enumerate_directory(root: &Path) -> Result<Result<Content, EnumerationFailure>, UsageError> {
    let metadata = std::fs::symlink_metadata(root).map_err(|error| {
        UsageError(format!("cannot read container {}: {error}", root.display()))
    })?;
    if !metadata.is_dir() {
        return Err(UsageError(format!(
            "container path {} is not a directory",
            root.display()
        )));
    }
    let mut content = Content::default();
    let mut codes: BTreeSet<Code> = BTreeSet::new();
    let mut entries: usize = 0;
    let mut budget = Budget {
        total: 0,
        exceeded: false,
    };
    // Iterative, sorted walk: (absolute path, relative path).
    let mut stack: Vec<(std::path::PathBuf, String)> = vec![(root.to_path_buf(), String::new())];
    while let Some((directory, prefix)) = stack.pop() {
        let reader = std::fs::read_dir(&directory).map_err(|error| {
            UsageError(format!(
                "cannot read container directory {}: {error}",
                directory.display()
            ))
        })?;
        let mut names: Vec<std::ffi::OsString> = Vec::new();
        for entry in reader {
            let entry = entry.map_err(|error| {
                UsageError(format!(
                    "cannot read container directory {}: {error}",
                    directory.display()
                ))
            })?;
            names.push(entry.file_name());
        }
        names.sort();
        let mut subdirectories = Vec::new();
        for name in names {
            let Some(name) = name.to_str().map(str::to_owned) else {
                codes.insert(e::CONTAINER_ENTRY);
                continue;
            };
            let relative = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}/{name}")
            };
            let path = directory.join(&name);
            let metadata = std::fs::symlink_metadata(&path).map_err(|error| {
                UsageError(format!("cannot inspect {}: {error}", path.display()))
            })?;
            if relative == "readable" {
                // §11.8: `readable/` is never descended into, read, stat-ed
                // or counted; only its presence is noted.
                if metadata.is_dir() {
                    content.readable_present = true;
                } else {
                    codes.insert(e::CONTAINER_ENTRY);
                }
                continue;
            }
            if metadata.file_type().is_symlink() {
                codes.insert(e::CONTAINER_ENTRY);
                continue;
            }
            if metadata.is_dir() {
                let allowed = matches!(
                    (prefix.as_str(), name.as_str()),
                    ("", "signatures" | "previous" | "records" | "blobs") | ("blobs", "sha256")
                );
                if allowed {
                    if relative == "blobs" {
                        content.blobs_dir_present = true;
                    }
                    subdirectories.push((path, relative));
                } else {
                    codes.insert(e::CONTAINER_ENTRY);
                }
                continue;
            }
            if !metadata.is_file() {
                codes.insert(e::CONTAINER_ENTRY);
                continue;
            }
            entries += 1;
            if entries > limits::MAX_CONTAINER_ENTRIES {
                codes.insert(e::CONTAINER_SIZE);
                continue;
            }
            let class = classify_path(&relative);
            match class {
                PathClass::Unknown => {
                    codes.insert(e::CONTAINER_ENTRY);
                }
                PathClass::RecordsExtra => {
                    content.records_extra = true;
                    // §13: "MUST NOT rely on filesystem-reported sizes"; the
                    // file is read through a probe bounded by its class limit
                    // plus one byte (the bytes read count toward the container
                    // total like every other read), and only the size is kept
                    // (H1-FIX2B Z2, docs/h1-findings.md F55). Skipped once the
                    // enumeration has failed, as for the other classes.
                    if codes.is_empty()
                        && matches!(
                            read_bounded(&path, record_limit(), &mut budget)?,
                            FileData::Oversize
                        )
                    {
                        content.records_extra_oversize = true;
                    }
                }
                PathClass::BlobsExtra => content.blobs_extra = true,
                PathClass::TsaCert | PathClass::Readable => {}
                PathClass::Blob => {
                    if codes.is_empty() {
                        let blob = hash_file(&path, limits::MAX_BLOB_BYTES, &mut budget)?;
                        content.blobs.insert(relative, blob);
                    }
                }
                _ => {
                    // The manifest is always read (bounded), so the §14.6
                    // tier-(b) identity is available after a later failure.
                    if codes.is_empty() || matches!(class, PathClass::Manifest) {
                        let data = read_bounded(&path, class_limit(&class), &mut budget)?;
                        content.store(&relative, &class, data);
                    }
                }
            }
            if budget.exceeded {
                codes.insert(e::CONTAINER_SIZE);
            }
        }
        // Depth-first in sorted order.
        subdirectories.reverse();
        stack.extend(subdirectories);
    }
    if codes.is_empty() {
        Ok(Ok(content))
    } else {
        Ok(Err(EnumerationFailure {
            codes: codes.into_iter().collect(),
            readable_observed: content.readable_present,
            manifest: content.manifest,
        }))
    }
}

/// Reads one file through a probe bounded by `limit + 1` bytes (§13).
fn read_bounded(path: &Path, limit: u64, budget: &mut Budget) -> Result<FileData, UsageError> {
    let file = std::fs::File::open(path)
        .map_err(|error| UsageError(format!("cannot read {}: {error}", path.display())))?;
    let mut bytes = Vec::new();
    file.take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| UsageError(format!("cannot read {}: {error}", path.display())))?;
    budget.add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > limit {
        Ok(FileData::Oversize)
    } else {
        Ok(FileData::Bytes(bytes))
    }
}

/// Hashes one blob file while streaming, bounded by `limit + 1` bytes.
fn hash_file(path: &Path, limit: u64, budget: &mut Budget) -> Result<BlobData, UsageError> {
    use sha2::Digest;
    let file = std::fs::File::open(path)
        .map_err(|error| UsageError(format!("cannot read {}: {error}", path.display())))?;
    let mut reader = file.take(limit.saturating_add(1));
    let mut hasher = sha2::Sha256::new();
    let mut size: u64 = 0;
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|error| UsageError(format!("cannot read {}: {error}", path.display())))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        size += read as u64;
        budget.add(read as u64);
        if budget.exceeded {
            break;
        }
    }
    if size > limit {
        return Ok(BlobData::Oversize);
    }
    Ok(BlobData::Hashed {
        digest: format!("sha256:{}", digest::to_lower_hex(&hasher.finalize())),
        size,
    })
}

/// Step (1) for an in-memory file map (`ContainerInput::Files`).
fn enumerate_files(files: &BTreeMap<String, Vec<u8>>) -> Result<Content, EnumerationFailure> {
    let mut content = Content::default();
    let mut codes: BTreeSet<Code> = BTreeSet::new();
    let mut budget = Budget {
        total: 0,
        exceeded: false,
    };
    let mut entries = 0usize;
    for (path, bytes) in files {
        if !is_safe_relative_path(path) {
            codes.insert(e::CONTAINER_ENTRY);
            continue;
        }
        let class = classify_path(path);
        if matches!(class, PathClass::Readable) {
            content.readable_present = true;
            continue;
        }
        entries += 1;
        if path.starts_with("blobs/") {
            content.blobs_dir_present = true;
        }
        let length = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        match class {
            PathClass::Unknown => {
                codes.insert(e::CONTAINER_ENTRY);
            }
            PathClass::RecordsExtra => {
                content.records_extra = true;
                if length > record_limit() {
                    content.records_extra_oversize = true;
                }
            }
            PathClass::BlobsExtra => content.blobs_extra = true,
            PathClass::TsaCert | PathClass::Readable => {}
            PathClass::Blob => {
                budget.add(length.min(limits::MAX_BLOB_BYTES + 1));
                let blob = if length > limits::MAX_BLOB_BYTES {
                    BlobData::Oversize
                } else {
                    BlobData::Hashed {
                        digest: digest::sha256_digest_string(bytes),
                        size: length,
                    }
                };
                content.blobs.insert(path.clone(), blob);
            }
            _ => {
                let limit = class_limit(&class);
                budget.add(length.min(limit + 1));
                let data = if length > limit {
                    FileData::Oversize
                } else {
                    FileData::Bytes(bytes.clone())
                };
                content.store(path, &class, data);
            }
        }
    }
    if entries > limits::MAX_CONTAINER_ENTRIES || budget.exceeded {
        codes.insert(e::CONTAINER_SIZE);
    }
    if codes.is_empty() {
        Ok(content)
    } else {
        Err(EnumerationFailure {
            codes: codes.into_iter().collect(),
            readable_observed: content.readable_present,
            manifest: content.manifest,
        })
    }
}

/// Step (1) for a zip container (§11.9): phases 1–4, then entry names,
/// symbolic links and duplicates (`E_CONTAINER_ENTRY`), then the layout, and
/// only then bounded decompression of the members that are read.
fn enumerate_zip(bytes: &[u8]) -> Result<Content, EnumerationFailure> {
    let archive = match zip::open(bytes) {
        Ok(archive) => archive,
        Err(code) => {
            return Err(EnumerationFailure {
                codes: vec![code],
                readable_observed: false,
                manifest: None,
            })
        }
    };
    let mut content = Content::default();
    let mut codes: BTreeSet<Code> = BTreeSet::new();
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    // Entry checks in central-directory order. A zero-data directory entry
    // (a name ending `/`; the DOS directory attribute does not make one, FIX2)
    // is ignored for the layout and for whether `blobs/` is present (§11.9
    // rule 4), but it passes the path-safety, symbolic-link and duplicate-name
    // checks like any other entry (FIX1): `../x/` and `/abs/` are
    // E_CONTAINER_ENTRY. Its path is its name without the final `/`. A
    // `readable/` entry is "observed" once it passed its own checks, before
    // any failing entry (§11.8, T12).
    for entry in &archive.entries {
        let checked_name = if entry.is_directory {
            entry.name.strip_suffix('/').unwrap_or(&entry.name)
        } else {
            entry.name.as_str()
        };
        if !is_safe_relative_path(checked_name) || entry.is_symlink || !seen.insert(&entry.name) {
            codes.insert(e::CONTAINER_ENTRY);
            break;
        }
        if entry.is_directory {
            continue;
        }
        if entry.name.starts_with("readable/") {
            content.readable_present = true;
        }
    }
    if !codes.is_empty() {
        return Err(EnumerationFailure {
            codes: codes.into_iter().collect(),
            readable_observed: content.readable_present,
            manifest: None,
        });
    }
    for entry in &archive.entries {
        // §11.7 rule 3 with §11.9 rule 4 (FIX1): in the zip form `blobs/` is
        // present when a file lies in it; a zero-data directory entry (such
        // as `blobs/sha256/`) takes no part in the layout or in that question.
        // A zero-data `blobs/sha256` without the final `/` is a file, with or
        // without the DOS directory attribute (FIX2).
        if entry.is_directory {
            continue;
        }
        if entry.name.starts_with("blobs/") {
            content.blobs_dir_present = true;
        }
        let class = classify_path(&entry.name);
        match class {
            PathClass::Unknown => {
                codes.insert(e::CONTAINER_ENTRY);
            }
            PathClass::RecordsExtra => {
                content.records_extra = true;
                // The central directory's declared size; the member is not
                // decompressed (§11.9 W7: only listed content is read).
                if entry.uncompressed_size > record_limit() {
                    content.records_extra_oversize = true;
                }
            }
            PathClass::BlobsExtra => content.blobs_extra = true,
            PathClass::TsaCert | PathClass::Readable => {}
            PathClass::Blob => {
                use sha2::Digest;
                let mut hasher = sha2::Sha256::new();
                match archive.stream(entry, limits::MAX_BLOB_BYTES, |chunk| hasher.update(chunk)) {
                    Ok(()) => {
                        content.blobs.insert(
                            entry.name.clone(),
                            BlobData::Hashed {
                                digest: format!(
                                    "sha256:{}",
                                    digest::to_lower_hex(&hasher.finalize())
                                ),
                                size: entry.uncompressed_size,
                            },
                        );
                    }
                    Err(zip::MemberError::TooLarge) => {
                        content.blobs.insert(entry.name.clone(), BlobData::Oversize);
                    }
                    Err(zip::MemberError::Corrupt) => {
                        codes.insert(e::CONTAINER_ZIP);
                    }
                }
            }
            _ => match archive.read(entry, class_limit(&class)) {
                Ok(data) => content.store(&entry.name, &class, FileData::Bytes(data)),
                Err(zip::MemberError::TooLarge) => {
                    content.store(&entry.name, &class, FileData::Oversize);
                }
                Err(zip::MemberError::Corrupt) => {
                    codes.insert(e::CONTAINER_ZIP);
                }
            },
        }
    }
    if codes.is_empty() {
        Ok(content)
    } else {
        // §11.8 (S2-FIX2/U7): the central directory was read and the
        // `readable/` entries were seen, so a member-level failure here (a
        // CRC, for example) still reports `N_READABLE_PRESENT`; only a
        // failure to read the central directory itself (above) does not.
        Err(EnumerationFailure {
            codes: codes.into_iter().collect(),
            readable_observed: content.readable_present,
            manifest: None,
        })
    }
}

// ---------------------------------------------------------------------------
// The pipeline
// ---------------------------------------------------------------------------

/// Verifies one container target.
///
/// # Errors
/// Returns a [`UsageError`] for operator-input problems (keyset, trust
/// anchors) and I/O problems reading the container; container *content*
/// defects are reported in the `Report`.
pub fn verify_container(
    input: &ContainerInput,
    options: &VerifyOptions,
) -> Result<Report, UsageError> {
    // §14.1 (W4): operator inputs are checked before any stage runs.
    let anchors = if options.tsa_trust.is_empty() {
        Vec::new()
    } else {
        timestamp::load_trust_anchors(&options.tsa_trust)?
    };
    World::from_results(Vec::new(), options)?;

    let mut run = Run::new(options);
    let archive_identity = match input {
        ContainerInput::Zip(bytes) => Some(InputIdentity::of_bytes(bytes)),
        _ => None,
    };
    let is_archive = archive_identity.is_some();
    let mut identity = archive_identity.unwrap_or_else(InputIdentity::unknown);

    // (1) Entry enumeration and safety.
    let enumerated = match input {
        ContainerInput::Directory(root) => enumerate_directory(root)?,
        ContainerInput::Zip(bytes) => enumerate_zip(bytes),
        ContainerInput::Files(files) => enumerate_files(files),
    };
    let content = match enumerated {
        Ok(content) => content,
        Err(failure) => {
            if failure.readable_observed {
                run.container.notices.push(n::READABLE_PRESENT);
            }
            if !is_archive {
                // §14.6 tier (b): the raw manifest bytes when they were read
                // within their limit; otherwise null (tier (c)).
                identity = match &failure.manifest {
                    Some(FileData::Bytes(bytes)) => InputIdentity::of_bytes(bytes),
                    _ => InputIdentity::unknown(),
                };
            }
            return Ok(run.fail(&failure.codes, identity, LimitationFacts::default()));
        }
    };
    if content.readable_present {
        run.container.notices.push(n::READABLE_PRESENT);
    }

    // (2) Manifest bytes and canonical form.
    let manifest_bytes = match &content.manifest {
        None => return Ok(run.fail(&[e::MANIFEST_MISSING], identity, LimitationFacts::default())),
        Some(FileData::Oversize) => {
            return Ok(run.fail(&[e::JSON_SIZE], identity, LimitationFacts::default()))
        }
        Some(FileData::Bytes(bytes)) => bytes.as_slice(),
    };
    if !is_archive {
        identity = InputIdentity::of_bytes(manifest_bytes);
    }
    let manifest_object =
        match json::parse_canonical_object(manifest_bytes, limits::MAX_MANIFEST_BYTES) {
            Ok(object) => object,
            Err(code) => return Ok(run.fail(&[code], identity, LimitationFacts::default())),
        };
    // §11.5/§14.9 (T12): `previous_manifest` is non-null in the parsed
    // manifest, so the previous manifest's own signature is not re-verified
    // (unless a supplied `--previous` verifies it at step (10)); this is
    // reported even when a later check fails.
    run.previous_sig_unverified = manifest_object
        .get("previous_manifest")
        .is_some_and(|value| !value.is_null());
    let canonical_manifest = json::canonical_object_bytes(&manifest_object);
    let manifest_digest = digest::manifest_digest(&canonical_manifest);
    // (3) Manifest structure.
    let manifest = match parse_manifest(&manifest_object, options) {
        Ok(manifest) => manifest,
        Err(code) => return Ok(run.fail(&[code], identity, LimitationFacts::default())),
    };
    if !is_archive {
        identity = InputIdentity {
            sha256: Some(manifest_digest.clone()),
            size: Some(u64::try_from(manifest_bytes.len()).unwrap_or(u64::MAX)),
        };
    }
    run.container.manifest_digest = Some(manifest_digest.clone());
    run.container.created_at = Some(manifest.created_at.to_ts_string());
    run.container.level_claimed = Some(manifest.level.as_str().to_owned());
    run.container.previous_manifest_digest = manifest.previous_manifest.clone();
    run.container.record_count = Some(u64::try_from(manifest.records.len()).unwrap_or(u64::MAX));
    // §11.5/§14.9 (T12): the previous manifest's own signature is not
    // re-verified unless a supplied `--previous` verifies it at step (10).

    // (4) The attestation file and the manifest digest.
    let sigfile_bytes = match &content.sigfile {
        None => {
            return Ok(run.fail(
                &[e::MANIFEST_UNSIGNED],
                identity,
                LimitationFacts::default(),
            ))
        }
        Some(FileData::Oversize) => {
            return Ok(run.fail(&[e::JSON_SIZE], identity, LimitationFacts::default()))
        }
        Some(FileData::Bytes(bytes)) => bytes.as_slice(),
    };
    let sigfile_object =
        match json::parse_canonical_object(sigfile_bytes, limits::MAX_SIGFILE_BYTES) {
            Ok(object) => object,
            Err(code) => return Ok(run.fail(&[code], identity, LimitationFacts::default())),
        };
    let attestation = match parse_attestation(&sigfile_object, &manifest, &manifest_digest, options)
    {
        Ok(attestation) => attestation,
        Err(code) => return Ok(run.fail(&[code], identity, LimitationFacts::default())),
    };

    // The verification context: the manifest-listed records (in manifest
    // order) plus the keyset. Parse results are reused by step (7).
    let entries = build_entries(&manifest.records, &content.records);
    let results: Vec<Result<RecordFile, Code>> = entries
        .iter()
        .map(|entry| entry.parsed.clone().unwrap_or(Err(e::JSON_INVALID)))
        .collect();
    let listed: BTreeSet<&str> = entries.iter().map(|entry| entry.path.as_str()).collect();
    let extra_records: Vec<RecordFile> = content
        .records
        .iter()
        .filter(|(path, _)| !listed.contains(path.as_str()))
        .filter_map(|(_, data)| match data {
            FileData::Bytes(bytes) => envelope::parse_record_file(bytes).ok(),
            FileData::Oversize => None,
        })
        .collect();
    let mut world = World::from_results_with_context(results, extra_records, options)?;
    world.set_container_context();

    // Timestamp evidence (§12), computed early for §9.4 and reported at (11).
    let raw_manifest_digest = digest::sha256_digest_bytes(&manifest_digest).unwrap_or([0u8; 32]);
    let timestamp_files: BTreeMap<String, Vec<u8>> = content
        .timestamps
        .iter()
        .filter_map(|(path, data)| match data {
            FileData::Bytes(bytes) => Some((path.clone(), bytes.clone())),
            FileData::Oversize => None,
        })
        .collect();
    let mut evidence = timestamp::verify_chain(
        &attestation.timestamps,
        &raw_manifest_digest,
        &timestamp_files,
        &anchors,
    );
    apply_receipt_inventory(&mut evidence, &attestation.timestamps, &content.timestamps);
    world.set_timestamp_evidence(evidence.clone());

    // (5) The manifest signature (§11.3).
    let outcome = world.check_manifest_signatures(
        &attestation.signatures,
        &manifest_digest,
        &manifest.created_at,
    );
    run.facts.context_trusted_outside_records |= outcome.context_trusted;
    match outcome.code {
        Some(code) if crate::record::effect(code) == Verdict::Invalid && !options.skipped(code) => {
            let facts = run.facts;
            return Ok(run.fail(&[code], identity, facts));
        }
        Some(code) if !options.skipped(code) => run.container.errors.push(code),
        _ => {}
    }

    // (6) Level and chain completeness.
    match check_level_and_chain(&manifest, &attestation.timestamps) {
        Ok(()) => {
            run.container.chain = Some(ChainReport {
                status: match manifest.level {
                    Level::L0 => "absent",
                    Level::L1 | Level::L2 => "unverified",
                }
                .to_owned(),
            });
            if manifest.level != Level::L0 {
                run.container.notices.push(n::CHAIN_CLAIM_UNVERIFIED);
            }
        }
        Err(code) => {
            if !options.skipped(code) {
                {
                    let facts = run.facts;
                    return Ok(run.fail(&[code], identity, facts));
                }
            }
        }
    }

    // (7) Records listing (§11.6): every independent violation together (U8).
    let mut listing: BTreeSet<Code> = BTreeSet::new();
    for entry in &entries {
        if let Some(code) = entry.error {
            listing.insert(code);
        }
    }
    let listed_paths: BTreeSet<&str> = entries.iter().map(|entry| entry.path.as_str()).collect();
    let unlisted: Vec<&FileData> = content
        .records
        .iter()
        .filter(|(path, _)| !listed_paths.contains(path.as_str()))
        .map(|(_, data)| data)
        .collect();
    if content.records_extra || !unlisted.is_empty() {
        listing.insert(e::MANIFEST_RECORD_EXTRA);
    }
    // An unlisted `records/` file above `MAX_RECORD_BYTES` is both an extra
    // file and a record file above its §13 class limit: §14.5 lists
    // `E_JSON_SIZE` "for record files above MAX_RECORD_BYTES" among the
    // independent violations of this phase without restricting it to listed
    // files (F55). That holds for a misnamed `records/` file too (H1-FIX2
    // gate 5; review B's wording for F55: "an unlisted or misnamed file").
    if content.records_extra_oversize
        || unlisted
            .iter()
            .any(|data| matches!(data, FileData::Oversize))
    {
        listing.insert(e::JSON_SIZE);
    }
    listing.retain(|code| !options.skipped(code));
    if !listing.is_empty() {
        let codes: Vec<Code> = listing.into_iter().collect();
        let facts = run.facts;
        return Ok(run.fail(&codes, identity, facts));
    }
    // Per-record verification.
    let mut records = world.evaluate_all();
    // (8) Cross-record state.
    let cross = world.container_cross_checks();
    merge_cross_checks(&cross, &mut run.container, &mut records);
    let facts = |run: &Run<'_>, world: &World| {
        let mut facts = world.limitation_facts(true);
        facts.context_trusted_outside_records = run.facts.context_trusted_outside_records;
        facts.previous_content_unverified = run.facts.previous_content_unverified;
        facts
    };
    if !cross.container_errors.is_empty() {
        let facts = facts(&run, &world);
        return Ok(run.finish(identity, records, facts));
    }
    // (9) Blobs.
    let blob_errors = check_blobs(
        manifest.blobs.as_deref(),
        &content.blobs,
        content.blobs_extra,
        content.blobs_dir_present,
    );
    let blob_errors: Vec<Code> = blob_errors
        .into_iter()
        .filter(|code| !options.skipped(code))
        .collect();
    if !blob_errors.is_empty() {
        run.container.errors.extend(blob_errors);
        let facts = facts(&run, &world);
        return Ok(run.finish(identity, records, facts));
    }
    // (10) Previous-manifest chain.
    let previous = previous_stage(&manifest, &content, &mut world, options)?;
    run.facts.context_trusted_outside_records |= previous.context_trusted;
    if previous.signature_verified {
        run.facts.previous_content_unverified = true;
        run.previous_sig_unverified = false;
    }
    if let Some(code) = previous.code {
        if !options.skipped(code) {
            run.container.errors.push(code);
            let facts = facts(&run, &world);
            return Ok(run.finish(identity, records, facts));
        }
    }
    // (11) Timestamps.
    run.container.timestamps = timestamp_reports(&attestation.timestamps, &evidence);
    run.container.anchor_verified = Some(evidence.anchor_verified);
    for code in evidence.reported_codes() {
        if !options.skipped(code) {
            run.container.errors.push(code);
        }
    }
    // (12) Aggregation.
    let facts = facts(&run, &world);
    Ok(run.finish(identity, records, facts))
}

/// §11.3: every `.tsr` file in `signatures/` must be listed, and a listed file
/// above `MAX_TIMESTAMP_BYTES` is `E_JSON_SIZE` (§13). Both are file checks of
/// the timestamp phase (W6): every listed receipt is then invalid.
fn apply_receipt_inventory(
    evidence: &mut ChainEvidence,
    listed: &[AttestationTimestamp],
    files: &BTreeMap<String, FileData>,
) {
    let unlisted = files
        .keys()
        .any(|path| !listed.iter().any(|entry| &entry.path == path));
    let oversize: Vec<bool> = listed
        .iter()
        .map(|entry| matches!(files.get(&entry.path), Some(FileData::Oversize)))
        .collect();
    if !unlisted && !oversize.iter().any(|flag| *flag) {
        return;
    }
    let mut receipts: Vec<timestamp::ReceiptOutcome> = listed
        .iter()
        .zip(&oversize)
        .map(|(entry, oversize)| timestamp::ReceiptOutcome {
            state: ReceiptState::Invalid,
            gen_time: None,
            accuracy_us: None,
            error: if *oversize {
                Some(e::JSON_SIZE)
            } else if files.contains_key(&entry.path) {
                evidence
                    .receipts
                    .iter()
                    .zip(listed)
                    .find(|(_, other)| other.path == entry.path)
                    .and_then(|(receipt, _)| receipt.error)
                    .filter(|code| matches!(*code, e::TS_FILE | e::JSON_SIZE))
            } else {
                Some(e::TS_FILE)
            },
        })
        .collect();
    if unlisted {
        if let Some(first) = receipts.first_mut() {
            first.error.get_or_insert(e::TS_FILE);
        } else {
            receipts.push(timestamp::ReceiptOutcome {
                state: ReceiptState::Invalid,
                gen_time: None,
                accuracy_us: None,
                error: Some(e::TS_FILE),
            });
        }
    }
    *evidence = ChainEvidence {
        receipts,
        chain_error: None,
        anchor_verified: false,
        none_listed: listed.is_empty(),
    };
}

// ---------------------------------------------------------------------------
// Report assembly
// ---------------------------------------------------------------------------

/// Accumulates the container report while the checks run.
struct Run<'a> {
    options: &'a VerifyOptions,
    container: ContainerReport,
    facts: LimitationFacts,
    previous_sig_unverified: bool,
}

impl<'a> Run<'a> {
    fn new(options: &'a VerifyOptions) -> Self {
        Self {
            options,
            // §14.6: these fields are always present; their defaults are the
            // honest "not determined" values, never an invented pass.
            container: ContainerReport {
                created_at: None,
                manifest_digest: None,
                level_claimed: None,
                level_verified: Some("L0".to_owned()),
                anchor_verified: Some(false),
                chain: Some(ChainReport {
                    status: "absent".to_owned(),
                }),
                previous_manifest_digest: None,
                record_count: Some(0),
                errors: Vec::new(),
                notices: Vec::new(),
                timestamps: Vec::new(),
            },
            facts: LimitationFacts::default(),
            previous_sig_unverified: false,
        }
    }

    /// A pre-record container-level failure: the stage's codes, `records: []`.
    fn fail(mut self, codes: &[Code], input: InputIdentity, facts: LimitationFacts) -> Report {
        for code in codes {
            if !self.options.skipped(code) {
                self.container.errors.push(code);
            }
        }
        self.finish(input, Vec::new(), facts)
    }

    /// The final report: sorts and dedupes codes, computes the verdict, the
    /// summary and the limitations.
    fn finish(
        mut self,
        input: InputIdentity,
        mut records: Vec<RecordReport>,
        facts: LimitationFacts,
    ) -> Report {
        if self.previous_sig_unverified {
            self.container.notices.push(n::PREVIOUS_SIG_UNVERIFIED);
        }
        sort_unique(&mut self.container.errors);
        sort_unique(&mut self.container.notices);
        for record in &mut records {
            sort_unique(&mut record.errors);
            sort_unique(&mut record.notices);
        }
        let verdict = aggregate_verdict(&self.container.errors, &records);
        let summary = Summary::Verdicts(count_verdicts(&records));
        let limitations = limitations::compute(&records, Some(&self.container), facts);
        Report {
            checks_disabled: self.options.checks_disabled(),
            report_version: crate::REPORT_VERSION.to_owned(),
            spec: crate::SPEC.to_owned(),
            target: Target::Container,
            verdict,
            input,
            records,
            container: Some(self.container),
            summary,
            limitations,
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
    crate::record::effect(code) == Verdict::Unverifiable
}

/// The container verdict: invalid beats unverifiable beats valid (erased
/// records are not failures).
fn aggregate_verdict(container_errors: &[Code], records: &[RecordReport]) -> Verdict {
    let mut verdict = Verdict::Valid;
    for code in container_errors {
        if is_unverifiable_code(code) {
            if verdict == Verdict::Valid {
                verdict = Verdict::Unverifiable;
            }
        } else {
            return Verdict::Invalid;
        }
    }
    for record in records {
        match record.verdict {
            Verdict::Invalid => return Verdict::Invalid,
            Verdict::Unverifiable => verdict = Verdict::Unverifiable,
            Verdict::Valid | Verdict::Erased => {}
        }
    }
    verdict
}

fn count_verdicts(records: &[RecordReport]) -> VerdictCounts {
    crate::record::count_verdicts(records)
}

fn sort_unique(codes: &mut Vec<Code>) {
    codes.sort_unstable();
    codes.dedup();
}

// ---------------------------------------------------------------------------
// Entry layout helpers (§11.1)
// ---------------------------------------------------------------------------

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
    match name
        .strip_prefix("timestamp-")
        .and_then(|rest| rest.strip_suffix(".tsr"))
    {
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
    let created_at = match object.get_str("created_at").and_then(Timestamp::parse) {
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
    if (array.is_empty() || array.len() > limits::MAX_RECORDS)
        && !options.skipped(e::MANIFEST_RECORDS)
    {
        return Err(e::MANIFEST_RECORDS);
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
    let timestamps = match object.get("timestamps") {
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

    // The level-specific timestamp completeness rules belong to step (6)
    // (`check_level_and_chain`).
    let _ = manifest;

    // The receipt-file inventory checks (§11.3: every listed `.tsr` exists and
    // hashes to its listed digest; every `.tsr` file is listed) belong to the
    // timestamps stage (§14.5 (11)), not to attestation parsing.
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
        if (json::utf16_cmp(&window[0].path, &window[1].path) != std::cmp::Ordering::Less
            || window[0].digest == window[1].digest)
            && !options.skipped(e::MANIFEST_SCHEMA)
        {
            return Err(e::MANIFEST_SCHEMA);
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
    let name = path.strip_prefix("signatures/")?;
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
// Level and chain completeness (§11.2, §11.4)
// ---------------------------------------------------------------------------

/// §14.5 (6): level/chain structure completeness.
fn check_level_and_chain(
    manifest: &Manifest,
    timestamps: &[AttestationTimestamp],
) -> Result<(), Code> {
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
    // §11.3, §12.5: `timestamps` is empty for L0/L1 and non-empty for L2.
    match manifest.level {
        Level::L0 | Level::L1 if !timestamps.is_empty() => Err(e::MANIFEST_LEVEL),
        Level::L2 if timestamps.is_empty() => Err(e::MANIFEST_L2_NO_TIMESTAMP),
        _ => Ok(()),
    }
}

// ---------------------------------------------------------------------------
// Records listing (§11.6)
// ---------------------------------------------------------------------------

/// One manifest-listed record and its listing state.
struct EntryState {
    /// `records/<hex>.json`.
    path: String,
    /// The parsed record file, when the listing found a file to parse.
    parsed: Option<Result<RecordFile, Code>>,
    /// The listing violation for this entry, if any.
    error: Option<Code>,
}

fn entry_file_path(digest_string: &str) -> Option<String> {
    let hex = digest_string.strip_prefix("sha256:")?;
    Some(format!("records/{hex}.json"))
}

/// Checks the §11.6 listing consistency of every manifest entry. A record file
/// above `MAX_RECORD_BYTES` is `E_JSON_SIZE` (T16, U8); a file whose digest
/// cannot be computed or does not match is `E_MANIFEST_RECORD_DIGEST`; an
/// `id`/`kind` mismatch is `E_MANIFEST_RECORDS`.
fn build_entries(
    records: &[ManifestRecordEntry],
    record_files: &BTreeMap<String, FileData>,
) -> Vec<EntryState> {
    records
        .iter()
        .map(|entry| {
            let path = entry_file_path(&entry.digest).unwrap_or_default();
            let bytes = match record_files.get(&path) {
                None => {
                    return EntryState {
                        path,
                        parsed: None,
                        error: Some(e::MANIFEST_RECORD_MISSING),
                    }
                }
                Some(FileData::Oversize) => {
                    return EntryState {
                        path,
                        parsed: Some(Err(e::JSON_SIZE)),
                        error: Some(e::JSON_SIZE),
                    }
                }
                Some(FileData::Bytes(bytes)) => bytes,
            };
            let object = match json::parse_canonical_object(bytes, limits::MAX_RECORD_BYTES) {
                Ok(object) => object,
                Err(code) => {
                    let mapped = if code == e::JSON_SIZE {
                        e::JSON_SIZE
                    } else {
                        e::MANIFEST_RECORD_DIGEST
                    };
                    return EntryState {
                        path,
                        parsed: Some(Err(code)),
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
                path,
                parsed: Some(envelope::parse_record_file(bytes)),
                error,
            }
        })
        .collect()
}

/// §14.5 (8): merges the context's cross-record outcomes into the reports.
fn merge_cross_checks(
    cross: &crate::context::CrossCheckOutcome,
    container: &mut ContainerReport,
    records: &mut [RecordReport],
) {
    container
        .errors
        .extend(cross.container_errors.iter().copied());
    container
        .notices
        .extend(cross.container_notices.iter().copied());
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
fn check_blobs(
    listed: Option<&[BlobEntry]>,
    files: &BTreeMap<String, BlobData>,
    extra: bool,
    directory_present: bool,
) -> Vec<Code> {
    let mut errors = Vec::new();
    if extra {
        errors.push(e::MANIFEST_BLOB);
    }
    // §11.7: a present `blobs/` directory requires a non-empty listing.
    if directory_present && listed.is_none_or(<[BlobEntry]>::is_empty) {
        errors.push(e::MANIFEST_BLOB);
    }
    match listed {
        None => {
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
                    Some(BlobData::Hashed { digest, size }) => {
                        if *size != blob.size
                            || *digest != blob.digest
                            || blob.size > limits::MAX_BLOB_BYTES
                        {
                            errors.push(e::MANIFEST_BLOB);
                        }
                    }
                    Some(BlobData::Oversize) | None => errors.push(e::MANIFEST_BLOB),
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
// Timestamps (§12) — report entries
// ---------------------------------------------------------------------------

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
            let (state, gen_time) = if evidence.chain_error.is_some() {
                ("invalid", None)
            } else {
                let state = match receipt.map(|receipt| receipt.state) {
                    Some(ReceiptState::Verified) => "verified",
                    Some(ReceiptState::PresentUnverified) => "present-unverified",
                    Some(ReceiptState::Invalid) | None => "invalid",
                };
                (
                    state,
                    receipt
                        .and_then(|receipt| receipt.gen_time)
                        .map(Timestamp::to_ts_string),
                )
            };
            TimestampReport {
                index,
                path: Some(entry.path.clone()),
                state: state.to_owned(),
                gen_time,
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Previous-manifest chain (§11.5, step (10))
// ---------------------------------------------------------------------------

/// What step (10) established.
struct PreviousOutcome {
    /// The first failing check of the W5 order, if any.
    code: Option<Code>,
    /// The supplied `--previous` manifest signature verified (§11.5, W1).
    signature_verified: bool,
    /// A supplied-previous signature check was context-trusted (§14.9).
    context_trusted: bool,
}

/// The two members read from a supplied previous container.
struct SuppliedMembers {
    manifest: Vec<u8>,
    sigfile: Vec<u8>,
}

/// Reads exactly `manifest.json` and `signatures/manifest.sig.json` from a
/// supplied previous container, each bounded by `MAX_MANIFEST_BYTES` (§11.5,
/// V3, W2). Any failure is `Err(())` (`E_MANIFEST_CHAIN`).
fn read_supplied_members(input: &ContainerInput) -> Result<SuppliedMembers, ()> {
    let limit = u64::try_from(limits::MAX_MANIFEST_BYTES).unwrap_or(u64::MAX);
    match input {
        ContainerInput::Directory(root) => {
            let member = |relative: &str| -> Result<Vec<u8>, ()> {
                let mut path = root.clone();
                let mut current = root.clone();
                for (index, part) in relative.split('/').enumerate() {
                    path = path.join(part);
                    current = current.join(part);
                    let metadata = std::fs::symlink_metadata(&current).map_err(|_| ())?;
                    let last = index + 1 == relative.split('/').count();
                    if metadata.file_type().is_symlink()
                        || (last && !metadata.is_file())
                        || (!last && !metadata.is_dir())
                    {
                        return Err(());
                    }
                }
                let mut budget = Budget {
                    total: 0,
                    exceeded: false,
                };
                match read_bounded(&path, limit, &mut budget) {
                    Ok(FileData::Bytes(bytes)) => Ok(bytes),
                    _ => Err(()),
                }
            };
            Ok(SuppliedMembers {
                manifest: member(MANIFEST_PATH)?,
                sigfile: member(SIGFILE_PATH)?,
            })
        }
        ContainerInput::Zip(bytes) => {
            // §11.9 rules 1–4 and the §13 limits apply to the whole archive.
            let archive = zip::open(bytes).map_err(|_| ())?;
            let member = |name: &str| -> Result<Vec<u8>, ()> {
                let matching: Vec<&zip::ZipEntry> = archive
                    .entries
                    .iter()
                    .filter(|entry| !entry.is_directory && entry.name == name)
                    .collect();
                match matching.as_slice() {
                    [entry] => archive.read(entry, limit).map_err(|_| ()),
                    _ => Err(()),
                }
            };
            Ok(SuppliedMembers {
                manifest: member(MANIFEST_PATH)?,
                sigfile: member(SIGFILE_PATH)?,
            })
        }
        ContainerInput::Files(files) => {
            let member = |name: &str| -> Result<Vec<u8>, ()> {
                let bytes = files.get(name).ok_or(())?;
                if bytes.len() > limits::MAX_MANIFEST_BYTES {
                    return Err(());
                }
                Ok(bytes.clone())
            };
            Ok(SuppliedMembers {
                manifest: member(MANIFEST_PATH)?,
                sigfile: member(SIGFILE_PATH)?,
            })
        }
    }
}

/// The supplied previous's identity and signature result (§11.5 W1/W5).
struct SuppliedPrevious {
    /// The §2.4 digest of the supplied previous manifest, when its identity
    /// and signatures passed.
    digest: Option<String>,
    signature_verified: bool,
    context_trusted: bool,
}

fn verify_supplied_previous(
    input: &ContainerInput,
    world: &mut World,
    options: &VerifyOptions,
) -> SuppliedPrevious {
    let failed = SuppliedPrevious {
        digest: None,
        signature_verified: false,
        context_trusted: false,
    };
    let Ok(members) = read_supplied_members(input) else {
        return failed;
    };
    let Ok(manifest_object) =
        json::parse_canonical_object(&members.manifest, limits::MAX_MANIFEST_BYTES)
    else {
        return failed;
    };
    let Ok(previous_manifest) = parse_manifest(&manifest_object, options) else {
        return failed;
    };
    let digest_string = digest::manifest_digest(&json::canonical_object_bytes(&manifest_object));
    let Ok(sig_object) = json::parse_canonical_object(&members.sigfile, limits::MAX_MANIFEST_BYTES)
    else {
        return failed;
    };
    let Ok(attestation) =
        parse_attestation(&sig_object, &previous_manifest, &digest_string, options)
    else {
        return failed;
    };
    let (verified, context_trusted) = world.check_previous_signatures(
        &attestation.signatures,
        &digest_string,
        previous_manifest.created_at,
    );
    SuppliedPrevious {
        digest: verified.then_some(digest_string),
        signature_verified: verified,
        context_trusted,
    }
}

/// Step (10) in the W5 order.
fn previous_stage(
    manifest: &Manifest,
    content: &Content,
    world: &mut World,
    options: &VerifyOptions,
) -> Result<PreviousOutcome, UsageError> {
    // The supplied previous is read and its signatures verified first.
    let supplied = options
        .previous
        .as_ref()
        .map(|input| verify_supplied_previous(input, world, options));
    let mut outcome = PreviousOutcome {
        code: None,
        signature_verified: supplied
            .as_ref()
            .is_some_and(|value| value.signature_verified),
        context_trusted: supplied.as_ref().is_some_and(|value| value.context_trusted),
    };
    let first = (|| -> Option<Code> {
        // (a) An embedded previous manifest above MAX_MANIFEST_BYTES.
        if matches!(content.previous_manifest, Some(FileData::Oversize)) {
            return Some(e::JSON_SIZE);
        }
        match &manifest.previous_manifest {
            // (b) A null chain.
            None => {
                if content.previous_manifest.is_some() {
                    return Some(e::MANIFEST_CHAIN_UNEXPECTED);
                }
                if supplied.is_some() {
                    return Some(e::MANIFEST_CHAIN);
                }
                None
            }
            // (c) The embedded manifest, (d) the supplied previous, (e) the
            // supplied digest comparison.
            Some(expected_digest) => {
                let Some(FileData::Bytes(bytes)) = &content.previous_manifest else {
                    return Some(e::MANIFEST_CHAIN_MISSING);
                };
                if previous_manifest_matches(bytes, expected_digest, manifest).is_err() {
                    return Some(e::MANIFEST_CHAIN);
                }
                if let Some(supplied) = &supplied {
                    match &supplied.digest {
                        None => return Some(e::MANIFEST_CHAIN),
                        Some(digest_string) if digest_string != expected_digest => {
                            return Some(e::MANIFEST_CHAIN)
                        }
                        Some(_) => {}
                    }
                }
                None
            }
        }
    })();
    outcome.code = first;
    Ok(outcome)
}

/// Validates an embedded `previous/manifest.json` (§11.5): canonical form, a
/// supported manifest, the same publisher and the §2.4 digest.
fn previous_manifest_matches(
    bytes: &[u8],
    expected_digest: &str,
    current: &Manifest,
) -> Result<(), Code> {
    let object = json::parse_canonical_object(bytes, limits::MAX_MANIFEST_BYTES)
        .map_err(|_| e::MANIFEST_CHAIN)?;
    if object.get_str("format") != Some(FORMAT) || object.get_i64("manifest_version") != Some(1) {
        return Err(e::MANIFEST_CHAIN);
    }
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
