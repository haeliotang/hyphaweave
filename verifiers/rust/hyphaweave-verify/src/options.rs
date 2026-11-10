// SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
// SPDX-License-Identifier: Apache-2.0

//! Verifier inputs and options.
//!
//! The library never reads environment variables on its own; the CLI builds
//! [`VerifyOptions`] from its command line (and, for the test-only skip hook,
//! from `WEAVE_VERIFY_SKIP_CHECKS`). The library API accepts raw bytes so that
//! a caller embedding the verifier (for example a mobile application) controls
//! all I/O.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::PathBuf;

use crate::error_codes::Code;

/// A container to verify.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContainerInput {
    /// A directory container. The library enumerates it recursively in sorted
    /// path order, so the verdict never depends on filesystem enumeration order.
    Directory(PathBuf),
    /// The bytes of a zip-form container.
    Zip(Vec<u8>),
    /// An already-materialised container: relative path -> bytes. Used by
    /// in-process conformance gates (byte-flip, ablation) and by embedders that
    /// receive the layout from elsewhere. Paths use `/` separators.
    Files(BTreeMap<String, Vec<u8>>),
}

/// Everything the verifier needs besides the target itself.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VerifyOptions {
    /// Error codes whose checks are treated as passed (test-only hook, §14.7).
    /// Unset or empty means normal operation. The report echoes the sorted list
    /// so a report can never be silently degraded.
    pub skip_checks: BTreeSet<String>,
    /// Raw bytes of the local keyset input (`--keys <dir>`): the top-level
    /// `*.json` records of that directory, in sorted file-name order.
    pub keyset: Vec<Vec<u8>>,
    /// L2 trust anchors (`--tsa-trust <pem>`): the file contents (PEM or DER).
    pub tsa_trust: Vec<Vec<u8>>,
    /// Optional previous container (`--previous <dir>`).
    pub previous: Option<ContainerInput>,
}

impl VerifyOptions {
    /// Creates empty options (no keyset, no trust anchors, no skipping).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// True when the named check is disabled by the test-only hook.
    #[must_use]
    pub fn skipped(&self, code: Code) -> bool {
        !self.skip_checks.is_empty() && self.skip_checks.contains(code)
    }
}

/// A usage or I/O error. The CLI exits with code 2 and writes no report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UsageError(pub String);

impl fmt::Display for UsageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for UsageError {}
