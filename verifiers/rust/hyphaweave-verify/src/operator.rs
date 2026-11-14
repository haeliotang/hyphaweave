// SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
// SPDX-License-Identifier: Apache-2.0

//! Operator inputs (§14.1, W4, X3).
//!
//! `--keys`, `--tsa-trust` and `--previous` are inputs supplied by the
//! operator, not evidence under verification. They are read and checked
//! before any stage of the target's pipeline runs, and every failure is a
//! usage error (exit 2, no report) that names the option and the file.
//!
//! The kind of every operator path is established with `lstat` before it is
//! opened; a symbolic link is resolved and its target judged the same way, so
//! a FIFO, a device, a socket or a dangling link is rejected without ever
//! opening it (a FIFO can never block the verifier). Every read is bounded.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::limits;
use crate::options::{ContainerInput, UsageError};

/// The kind of an operator path after resolving symbolic links.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Directory,
    RegularFile,
    Other,
}

/// `lstat`s `path` and, for a symbolic link, judges the resolved target.
fn kind_of(option: &str, path: &Path) -> Result<Kind, UsageError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| UsageError(format!("{option} {}: {error}", path.display())))?;
    let metadata = if metadata.file_type().is_symlink() {
        fs::metadata(path).map_err(|error| {
            UsageError(format!(
                "{option} {}: dangling symbolic link ({error})",
                path.display()
            ))
        })?
    } else {
        metadata
    };
    Ok(if metadata.is_dir() {
        Kind::Directory
    } else if metadata.is_file() {
        Kind::RegularFile
    } else {
        Kind::Other
    })
}

/// Reads a regular file with the bound `limit`; a larger file is `Ok(None)`.
fn read_limited(option: &str, path: &Path, limit: usize) -> Result<Option<Vec<u8>>, UsageError> {
    let file = fs::File::open(path)
        .map_err(|error| UsageError(format!("{option} {}: {error}", path.display())))?;
    let mut bytes = Vec::new();
    file.take(u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| UsageError(format!("{option} {}: {error}", path.display())))?;
    if bytes.len() > limit {
        Ok(None)
    } else {
        Ok(Some(bytes))
    }
}

/// Loads `--keys <dir>`: every top-level entry whose name ends in `.json`
/// (dot-prefixed names included), sorted by file name (§14.1, W10/L6). An
/// entry with such a name that is not a regular file is a usage error. Each
/// file is read with the bound `MAX_RECORD_BYTES + 1`; an oversize file then
/// fails the structural group (`E_JSON_SIZE`), which is a usage error too.
///
/// # Errors
/// A [`UsageError`] naming `--keys` and the offending path.
pub fn load_keyset(directory: &Path) -> Result<Vec<Vec<u8>>, UsageError> {
    if kind_of("--keys", directory)? != Kind::Directory {
        return Err(UsageError(format!(
            "--keys {}: not a directory",
            directory.display()
        )));
    }
    let entries = fs::read_dir(directory)
        .map_err(|error| UsageError(format!("--keys {}: {error}", directory.display())))?;
    let mut files: Vec<PathBuf> = Vec::new();
    for entry in entries {
        let entry = entry
            .map_err(|error| UsageError(format!("--keys {}: {error}", directory.display())))?;
        let name = entry.file_name();
        if name.to_string_lossy().ends_with(".json") {
            files.push(entry.path());
        }
    }
    files.sort_by(|left, right| left.file_name().cmp(&right.file_name()));
    let mut keyset = Vec::with_capacity(files.len());
    for path in files {
        if kind_of("--keys", &path)? != Kind::RegularFile {
            return Err(UsageError(format!(
                "--keys {}: not a regular file",
                path.display()
            )));
        }
        let bytes = match read_limited("--keys", &path, limits::MAX_RECORD_BYTES)? {
            Some(bytes) => bytes,
            None => {
                return Err(UsageError(format!(
                    "--keys {}: larger than the record size limit",
                    path.display()
                )))
            }
        };
        keyset.push(bytes);
    }
    Ok(keyset)
}

/// Reads `--tsa-trust <pem>` with the bound `MAX_TIMESTAMP_BYTES` (X3). The
/// content itself is checked by [`crate::timestamp::load_trust_anchors`].
///
/// # Errors
/// A [`UsageError`] for a non-regular, unreadable or oversize file.
pub fn read_tsa_trust(path: &Path) -> Result<Vec<u8>, UsageError> {
    if kind_of("--tsa-trust", path)? != Kind::RegularFile {
        return Err(UsageError(format!(
            "--tsa-trust {}: not a regular file",
            path.display()
        )));
    }
    let bytes =
        read_limited("--tsa-trust", path, limits::MAX_TIMESTAMP_BYTES)?.ok_or_else(|| {
            UsageError(format!(
                "--tsa-trust {}: larger than {} bytes",
                path.display(),
                limits::MAX_TIMESTAMP_BYTES
            ))
        })?;
    crate::timestamp::load_trust_anchors(std::slice::from_ref(&bytes))
        .map_err(|error| UsageError(format!("{} ({})", error.0, path.display())))?;
    Ok(bytes)
}

/// Opens `--previous <dir|zip>` (§11.5, §14.1): a directory or a regular file
/// (read as a zip). Its *content* is chain evidence judged at step (10)
/// (`E_MANIFEST_CHAIN`), never a usage error.
///
/// # Errors
/// A [`UsageError`] for a missing, unreadable or non-regular path.
pub fn open_previous(path: &Path) -> Result<ContainerInput, UsageError> {
    match kind_of("--previous", path)? {
        Kind::Directory => Ok(ContainerInput::Directory(path.to_path_buf())),
        Kind::RegularFile => fs::read(path)
            .map(ContainerInput::Zip)
            .map_err(|error| UsageError(format!("--previous {}: {error}", path.display()))),
        Kind::Other => Err(UsageError(format!(
            "--previous {}: not a directory or regular file",
            path.display()
        ))),
    }
}

/// Reads a record target with the bound `MAX_RECORD_BYTES + 1` (§14.6, T16):
/// an oversize record is reported as `E_JSON_SIZE` without reading or hashing
/// the whole file.
///
/// # Errors
/// A [`UsageError`] for a non-regular or unreadable file.
pub fn read_record_target(path: &Path) -> Result<Vec<u8>, UsageError> {
    if kind_of("record", path)? != Kind::RegularFile {
        return Err(UsageError(format!(
            "{}: not a regular file",
            path.display()
        )));
    }
    let file =
        fs::File::open(path).map_err(|error| UsageError(format!("{}: {error}", path.display())))?;
    let mut bytes = Vec::new();
    file.take(u64::try_from(limits::MAX_RECORD_BYTES).unwrap_or(u64::MAX) + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| UsageError(format!("{}: {error}", path.display())))?;
    Ok(bytes)
}

/// Opens a container target: a directory, or a regular file read as a zip.
///
/// # Errors
/// A [`UsageError`] for a missing, unreadable or non-regular path.
pub fn open_container(path: &Path) -> Result<ContainerInput, UsageError> {
    match kind_of("container", path)? {
        Kind::Directory => Ok(ContainerInput::Directory(path.to_path_buf())),
        Kind::RegularFile => fs::read(path)
            .map(ContainerInput::Zip)
            .map_err(|error| UsageError(format!("{}: {error}", path.display()))),
        Kind::Other => Err(UsageError(format!(
            "{}: not a directory or regular file",
            path.display()
        ))),
    }
}
