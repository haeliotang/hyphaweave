// SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
// SPDX-License-Identifier: Apache-2.0

//! Minimal pure-Rust zip reader for the zip form of a container (§11.9).
//!
//! Only the stored (0) and deflated (8) methods are supported. Entry names are
//! returned exactly as stored; safety and layout checks stay in
//! [`crate::container`] so that the deterministic split between
//! `E_CONTAINER_ENTRY` and `E_CONTAINER_ZIP` is made in one place.
//!
//! Interface contract (see ARCHITECTURE.md):
//! `read_zip` returns the container entries as `relative path -> bytes`, or the
//! §11.9 error code: `E_CONTAINER_ZIP` for a corrupt archive, unsupported
//! compression, an encrypted entry or a data descriptor/CRC problem, and
//! `E_CONTAINER_SIZE` when the entry count or uncompressed total exceeds the
//! §13 limits (checked while inflating, never after materialising).

use std::collections::BTreeMap;

use crate::error_codes::Code;

/// Reads a zip-form container into `relative path -> bytes`.
///
/// # Errors
/// Returns `E_CONTAINER_ZIP` or `E_CONTAINER_SIZE`.
pub fn read_zip(_bytes: &[u8]) -> Result<BTreeMap<String, Vec<u8>>, Code> {
    todo!("zip reader: implemented by the container workstream")
}
