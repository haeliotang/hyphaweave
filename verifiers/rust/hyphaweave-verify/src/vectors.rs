// SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
// SPDX-License-Identifier: Apache-2.0

//! Conformance-vector runner (§14.10, `vectors/README.md`).
//!
//! The runner discovers case directories in deterministic sorted order, reads
//! each `expected.json`, reproduces the case's command arguments, verifies the
//! case, and checks the conclusion:
//!
//! - `verdict` exact;
//! - `errors` as a set over the container's top-level and per-record errors;
//! - `notices` as a subset of the reported notices over the same union;
//! - `expected_digest` against `records[0].digest` for record targets;
//! - `expected_resolution` against `records[].refs[]` states;
//! - `expected_container` as a recursive subset match of the container object;
//! - `records` as per-id subset matches of record reports.
//!
//! Argument tokens in `expected.json`: `@keyset` -> the `keys/keyset` directory
//! of the enclosing vectors corpus; `@case` -> the case directory; anything else
//! is relative to the case directory. There is no network access and the runner
//! reads only the vector directory.

use std::path::Path;

use crate::options::{UsageError, VerifyOptions};
use crate::report::Report;

/// Runs every conformance case under `directory` and returns the `vectors`
/// report.
///
/// # Errors
/// Returns a [`UsageError`] when the directory or a case file cannot be read.
pub fn verify_vectors(
    _directory: &Path,
    _options: &VerifyOptions,
) -> Result<Report, UsageError> {
    todo!("vectors runner: implemented by the CLI workstream")
}
