// SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
// SPDX-License-Identifier: Apache-2.0

//! `hyphaweave-verify`: an independent verifier for `weave-record/1`.
//!
//! This crate is written from the specification and the conformance vectors
//! only; it never reads the Python reference verifier. It implements the record
//! envelope, the strict Ed25519 profile, references, labels and consent, key
//! lifecycle and grants, erasure, the L0/L1/L2 container format (including
//! RFC 3161 timestamp verification) and the report format of §14.
//!
//! The public API is deliberately small: three verification entry points that
//! take bytes or a container source plus [`VerifyOptions`], and return a
//! [`Report`] (or a [`UsageError`] for I/O/usage problems). A report can be
//! serialized with [`report_json::to_bytes`]. Everything is offline and
//! deterministic: the same input yields byte-identical reports on every machine.
//!
//! ```no_run
//! use hyphaweave_verify::{verify_record, report_json, VerifyOptions};
//!
//! let record_bytes = std::fs::read("record.json").unwrap();
//! let report = verify_record(&record_bytes, &VerifyOptions::new()).unwrap();
//! let output = report_json::to_bytes(&report);
//! ```

pub mod b64;
pub mod container;
pub mod context;
pub mod digest;
pub mod ed25519;
pub mod envelope;
pub mod error_codes;
pub mod json;
pub mod kinds;
pub mod labels;
pub mod limits;
pub mod options;
pub mod patterns;
pub mod record;
pub mod report;
pub mod report_json;
pub mod time;
pub mod timestamp;
pub mod value;
pub mod vectors;
pub mod zip;

use std::path::Path;

pub use options::{ContainerInput, UsageError, VerifyOptions};
pub use report::{
    ContainerReport, RecordReport, Report, Summary, Target, VectorCounts, Verdict, VerdictCounts,
};

/// Implementation name used in the report's `verifier` member.
pub const VERIFIER_NAME: &str = "hyphaweave-verify-rs";
/// Implementation version used in the report's `verifier` member.
pub const VERIFIER_VERSION: &str = env!("CARGO_PKG_VERSION");
/// Stable report version (§14.6).
pub const REPORT_VERSION: &str = "1";
/// Specification identifier this verifier implements.
pub const SPEC: &str = "weave-record/1";

/// Verifies one standalone record file.
///
/// # Errors
/// Returns a [`UsageError`] when the keyset input is not structurally valid or
/// an input cannot be read.
pub fn verify_record(bytes: &[u8], options: &VerifyOptions) -> Result<Report, UsageError> {
    record::verify_record_target(bytes, options)
}

/// Verifies one container target (directory, zip bytes, or materialised files).
///
/// # Errors
/// Returns a [`UsageError`] for I/O problems; container content defects are
/// reported in the returned [`Report`].
pub fn verify_container(
    input: ContainerInput,
    options: &VerifyOptions,
) -> Result<Report, UsageError> {
    container::verify_container(&input, options)
}

/// Runs every conformance case in `directory` and reports case counts.
///
/// # Errors
/// Returns a [`UsageError`] when the vectors directory cannot be read.
pub fn verify_vectors(directory: &Path, options: &VerifyOptions) -> Result<Report, UsageError> {
    vectors::verify_vectors(directory, options)
}
