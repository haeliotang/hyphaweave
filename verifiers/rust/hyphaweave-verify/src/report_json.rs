// SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
// SPDX-License-Identifier: Apache-2.0

//! Report serialization (§14.6).
//!
//! The report bytes are fixed: one JSON object on standard output, UTF-8,
//! **sorted keys**, **two spaces of indentation**, **ASCII-only output**
//! (`ensure_ascii`, so every non-ASCII scalar is a `\uXXXX` escape including
//! surrogate pairs) and exactly **one trailing LF**. No absolute paths,
//! usernames, hostnames, current times, randomness or environment values.

use crate::report::Report;

/// Serializes a report to its normative bytes.
#[must_use]
pub fn to_bytes(_report: &Report) -> Vec<u8> {
    todo!("report serialization: implemented by the CLI workstream")
}
