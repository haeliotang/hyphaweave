// SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
// SPDX-License-Identifier: Apache-2.0

//! Single-record target verification pipeline.
//!
//! A record target's verification context is the target record itself plus the
//! local keyset records (§0.2, §5.3). This module builds that context, runs the
//! §14.5 per-record pipeline and assembles the report.

use crate::options::{UsageError, VerifyOptions};
use crate::report::Report;

/// Verifies one standalone record file.
///
/// # Errors
/// Returns a [`UsageError`] when the keyset input is not structurally valid.
pub fn verify_record_target(
    _bytes: &[u8],
    _options: &VerifyOptions,
) -> Result<Report, UsageError> {
    todo!("record target: implemented by the lead")
}
