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

use crate::options::{ContainerInput, UsageError, VerifyOptions};
use crate::report::Report;

/// Verifies one container target.
///
/// # Errors
/// Returns a [`UsageError`] for I/O problems reading the container; container
/// *content* defects are reported in the `Report`, not as `Err`.
pub fn verify_container(
    _input: &ContainerInput,
    _options: &VerifyOptions,
) -> Result<Report, UsageError> {
    todo!("container verification: implemented by the container workstream")
}
