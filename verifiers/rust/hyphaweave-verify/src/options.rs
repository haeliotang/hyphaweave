// SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
// SPDX-License-Identifier: Apache-2.0

//! Verifier inputs and options.
//!
//! The library never reads environment variables on its own; the CLI builds
//! [`VerifyOptions`] from its command line (and, for the test-only skip hook,
//! from `WEAVE_VERIFY_SKIP_CHECKS` when `--test-hooks` is given, §14.7). The
//! library API accepts raw bytes so that a caller embedding the verifier (for
//! example a mobile application) controls all I/O.
//!
//! The §14.7 check-skip hook exists only when the crate is built with the
//! `test-hooks` cargo feature (R3): a default build has no `skip_checks` field
//! at all, so an embedder cannot disable a check by accident.

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
    /// Empty means normal operation. The report echoes the sorted registered
    /// codes in `checks_disabled`, so a report can never be silently degraded.
    /// Only present with the `test-hooks` cargo feature.
    #[cfg(feature = "test-hooks")]
    pub skip_checks: BTreeSet<String>,
    /// Raw bytes of the local keyset input (`--keys <dir>`): the top-level
    /// `*.json` records of that directory, in sorted file-name order.
    pub keyset: Vec<Vec<u8>>,
    /// L2 trust anchors (`--tsa-trust <pem>`): the file contents (PEM or DER).
    pub tsa_trust: Vec<Vec<u8>>,
    /// Optional previous container (`--previous <dir|zip>`).
    pub previous: Option<ContainerInput>,
}

impl VerifyOptions {
    /// Creates empty options (no keyset, no trust anchors, no skipping).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// True when the named check is disabled by the test-only hook. Always
    /// false without the `test-hooks` feature.
    #[must_use]
    pub fn skipped(&self, code: Code) -> bool {
        #[cfg(feature = "test-hooks")]
        {
            !self.skip_checks.is_empty() && self.skip_checks.contains(code)
        }
        #[cfg(not(feature = "test-hooks"))]
        {
            let _ = code;
            false
        }
    }

    /// The report's `checks_disabled` (§14.6): the sorted, unique registered
    /// `E_*` codes of the active hook; empty unless the hook is active.
    #[must_use]
    pub fn checks_disabled(&self) -> Vec<Code> {
        #[cfg(feature = "test-hooks")]
        {
            crate::error_codes::ALL_ERROR_CODES
                .iter()
                .copied()
                .filter(|code| self.skip_checks.contains(*code))
                .collect::<BTreeSet<Code>>()
                .into_iter()
                .collect()
        }
        #[cfg(not(feature = "test-hooks"))]
        {
            Vec::new()
        }
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
