// SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
// SPDX-License-Identifier: Apache-2.0

//! Minimal pure-Rust zip reader for the zip form of a container (§11.9).
//!
//! Only the stored (0) and deflated (8) methods are supported. Entry names are
//! returned exactly as stored; *path* safety and the remaining layout checks
//! stay in [`crate::container`] so that the deterministic split between
//! `E_CONTAINER_ENTRY` and `E_CONTAINER_ZIP` is made in one place.
//!
//! The reader itself classifies the entry-level defects that cannot survive
//! materialisation: a duplicate entry name or a symbolic-link entry is
//! `E_CONTAINER_ENTRY` (§11.9), while a corrupt archive, an encrypted entry, an
//! unsupported compression method, zip64 metadata, a mismatched name/size/CRC or
//! an out-of-bounds structure is `E_CONTAINER_ZIP`. The uncompressed total and
//! the entry count are enforced while streaming, against the §13 limits
//! (`E_CONTAINER_SIZE`), and decompression is bounded by the size the central
//! directory declares so a hostile archive can never inflate past the budget.

use std::collections::BTreeMap;

use miniz_oxide::inflate::decompress_to_vec_with_limit;

use crate::error_codes::{e, Code};
use crate::limits;

/// End of central directory record signature.
const EOCD_SIGNATURE: u32 = 0x0605_4b50;
/// Zip64 end of central directory locator signature (unsupported).
const ZIP64_LOCATOR_SIGNATURE: u32 = 0x0706_4b50;
/// Zip64 end of central directory record signature (unsupported).
const ZIP64_EOCD_SIGNATURE: u32 = 0x0606_4b50;
/// Central directory file header signature.
const CENTRAL_SIGNATURE: u32 = 0x0201_4b50;
/// Local file header signature.
const LOCAL_SIGNATURE: u32 = 0x0403_4b50;

/// Size of the fixed end-of-central-directory record (without the comment).
const EOCD_FIXED: usize = 22;
/// Maximum length of the archive comment (a `u16`).
const MAX_COMMENT: usize = 65_535;
/// Size of the fixed central directory file header (without name/extra/comment).
const CENTRAL_FIXED: usize = 46;
/// Size of the fixed local file header (without name/extra).
const LOCAL_FIXED: usize = 30;

/// Reads a zip-form container into `relative path -> bytes`.
///
/// # Errors
/// Returns `E_CONTAINER_ENTRY` for a duplicate entry name or a symbolic-link
/// entry, `E_CONTAINER_ZIP` for an archive that is corrupt or unsupported
/// (encryption, unknown method, zip64, out-of-bounds structure, CRC/size
/// mismatch), and `E_CONTAINER_SIZE` when the entry count or uncompressed total
/// exceeds the §13 limits.
pub fn read_zip(bytes: &[u8]) -> Result<BTreeMap<String, Vec<u8>>, Code> {
    let eocd = find_eocd(bytes)?;
    let disk_number = u16_at(bytes, eocd + 4).ok_or(e::CONTAINER_ZIP)?;
    let cd_disk = u16_at(bytes, eocd + 6).ok_or(e::CONTAINER_ZIP)?;
    let entries_this_disk = u16_at(bytes, eocd + 8).ok_or(e::CONTAINER_ZIP)?;
    let entries_total = u16_at(bytes, eocd + 10).ok_or(e::CONTAINER_ZIP)?;
    let cd_size = u32_at(bytes, eocd + 12).ok_or(e::CONTAINER_ZIP)?;
    let cd_offset = u32_at(bytes, eocd + 16).ok_or(e::CONTAINER_ZIP)?;

    // Only single-disk archives are supported, and zip64 (which changes every
    // offset/size field to a wider encoding) is rejected as unreadable here.
    if disk_number != 0 || cd_disk != 0 {
        return Err(e::CONTAINER_ZIP);
    }
    if entries_total == 0xFFFF
        || cd_size == 0xFFFF_FFFF
        || cd_offset == 0xFFFF_FFFF
        || (eocd >= 20 && u32_at(bytes, eocd - 20) == Some(ZIP64_LOCATOR_SIGNATURE))
        || u32_at(bytes, 0) == Some(ZIP64_EOCD_SIGNATURE)
    {
        return Err(e::CONTAINER_ZIP);
    }
    if entries_total != entries_this_disk {
        return Err(e::CONTAINER_ZIP);
    }
    let entries_total = usize::from(entries_total);
    if entries_total > limits::MAX_CONTAINER_ENTRIES {
        return Err(e::CONTAINER_SIZE);
    }
    let cd_offset = usize::try_from(cd_offset).map_err(|_| e::CONTAINER_ZIP)?;
    let cd_size = usize::try_from(cd_size).map_err(|_| e::CONTAINER_ZIP)?;
    let cd_end = cd_offset.checked_add(cd_size).ok_or(e::CONTAINER_ZIP)?;
    if cd_end > eocd || cd_end > bytes.len() {
        return Err(e::CONTAINER_ZIP);
    }

    let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut total_uncompressed: u64 = 0;
    let mut position = cd_offset;
    for _ in 0..entries_total {
        let header = slice(bytes, position, CENTRAL_FIXED).ok_or(e::CONTAINER_ZIP)?;
        if u32_at(header, 0) != Some(CENTRAL_SIGNATURE) {
            return Err(e::CONTAINER_ZIP);
        }
        let version_made_by = u16_at(header, 4).ok_or(e::CONTAINER_ZIP)?;
        let flags = u16_at(header, 8).ok_or(e::CONTAINER_ZIP)?;
        let method = u16_at(header, 10).ok_or(e::CONTAINER_ZIP)?;
        let crc = u32_at(header, 16).ok_or(e::CONTAINER_ZIP)?;
        let compressed_size = u32_at(header, 20).ok_or(e::CONTAINER_ZIP)?;
        let uncompressed_size = u32_at(header, 24).ok_or(e::CONTAINER_ZIP)?;
        let name_length = usize::from(u16_at(header, 28).ok_or(e::CONTAINER_ZIP)?);
        let extra_length = usize::from(u16_at(header, 30).ok_or(e::CONTAINER_ZIP)?);
        let comment_length = usize::from(u16_at(header, 32).ok_or(e::CONTAINER_ZIP)?);
        let start_disk = u16_at(header, 34).ok_or(e::CONTAINER_ZIP)?;
        let external_attributes = u32_at(header, 38).ok_or(e::CONTAINER_ZIP)?;
        let local_offset = u32_at(header, 42).ok_or(e::CONTAINER_ZIP)?;

        if start_disk != 0 {
            return Err(e::CONTAINER_ZIP);
        }
        // §11.9: encrypted entries are E_CONTAINER_ZIP (flag bit 0).
        if flags & 0x0001 != 0 {
            return Err(e::CONTAINER_ZIP);
        }
        // §11.9: entries may be stored or deflated; anything else is unsupported.
        if method != 0 && method != 8 {
            return Err(e::CONTAINER_ZIP);
        }
        if compressed_size == 0xFFFF_FFFF
            || uncompressed_size == 0xFFFF_FFFF
            || local_offset == 0xFFFF_FFFF
        {
            return Err(e::CONTAINER_ZIP);
        }
        let variable_length = name_length
            .checked_add(extra_length)
            .and_then(|value| value.checked_add(comment_length))
            .ok_or(e::CONTAINER_ZIP)?;
        let record_end = position
            .checked_add(CENTRAL_FIXED)
            .and_then(|value| value.checked_add(variable_length))
            .ok_or(e::CONTAINER_ZIP)?;
        let name_bytes =
            slice(bytes, position + CENTRAL_FIXED, name_length).ok_or(e::CONTAINER_ZIP)?;
        if record_end > cd_end {
            return Err(e::CONTAINER_ZIP);
        }

        // Unix-made entries carrying the symbolic-link file type are rejected
        // during entry enumeration (§11.9).
        let host_system = version_made_by >> 8;
        let unix_mode = external_attributes >> 16;
        let is_unix = host_system == 3;
        let is_symlink = is_unix && unix_mode & 0xF000 == 0xA000;
        let is_directory = name_bytes.last() == Some(&b'/')
            || (host_system == 0 && (external_attributes & 0x10) != 0);
        position = record_end;
        if is_directory {
            // §11.9: directory entries are ignored.
            continue;
        }
        if is_symlink {
            return Err(e::CONTAINER_ENTRY);
        }
        let name = std::str::from_utf8(name_bytes).map_err(|_| e::CONTAINER_ENTRY)?;
        if name.is_empty() {
            return Err(e::CONTAINER_ENTRY);
        }
        // Duplicate entry names are an entry-safety violation (§11.9), and a
        // map cannot represent them faithfully.
        if files.contains_key(name) {
            return Err(e::CONTAINER_ENTRY);
        }

        let actual = read_entry_data(
            bytes,
            local_offset,
            name,
            method,
            compressed_size,
            uncompressed_size,
            &mut total_uncompressed,
        )?;
        if crc32(&actual) != crc {
            return Err(e::CONTAINER_ZIP);
        }
        files.insert(name.to_owned(), actual);
    }
    // The central directory must be walked exactly once; slack bytes indicate a
    // structure the reader did not understand.
    if position != cd_end {
        return Err(e::CONTAINER_ZIP);
    }
    Ok(files)
}

/// Reads and decompresses one entry, enforcing the §13 uncompressed budget.
fn read_entry_data(
    bytes: &[u8],
    local_offset: u32,
    cd_name: &str,
    method: u16,
    compressed_size: u32,
    uncompressed_size: u32,
    total_uncompressed: &mut u64,
) -> Result<Vec<u8>, Code> {
    let local_offset = usize::try_from(local_offset).map_err(|_| e::CONTAINER_ZIP)?;
    let header = slice(bytes, local_offset, LOCAL_FIXED).ok_or(e::CONTAINER_ZIP)?;
    if u32_at(header, 0) != Some(LOCAL_SIGNATURE) {
        return Err(e::CONTAINER_ZIP);
    }
    let flags = u16_at(header, 6).ok_or(e::CONTAINER_ZIP)?;
    if flags & 0x0001 != 0 {
        return Err(e::CONTAINER_ZIP);
    }
    let local_method = u16_at(header, 8).ok_or(e::CONTAINER_ZIP)?;
    if local_method != method {
        return Err(e::CONTAINER_ZIP);
    }
    let name_length = usize::from(u16_at(header, 26).ok_or(e::CONTAINER_ZIP)?);
    let extra_length = usize::from(u16_at(header, 28).ok_or(e::CONTAINER_ZIP)?);
    let local_name =
        slice(bytes, local_offset + LOCAL_FIXED, name_length).ok_or(e::CONTAINER_ZIP)?;
    if local_name != cd_name.as_bytes() {
        return Err(e::CONTAINER_ZIP);
    }
    let data_start = local_offset
        .checked_add(LOCAL_FIXED)
        .and_then(|value| value.checked_add(name_length))
        .and_then(|value| value.checked_add(extra_length))
        .ok_or(e::CONTAINER_ZIP)?;
    let compressed_size = usize::try_from(compressed_size).map_err(|_| e::CONTAINER_ZIP)?;
    let data_end = data_start
        .checked_add(compressed_size)
        .ok_or(e::CONTAINER_ZIP)?;
    let data = bytes.get(data_start..data_end).ok_or(e::CONTAINER_ZIP)?;

    let declared = u64::from(uncompressed_size);
    let remaining = limits::MAX_CONTAINER_UNCOMPRESSED_BYTES
        .checked_sub(*total_uncompressed)
        .ok_or(e::CONTAINER_SIZE)?;
    if declared > remaining {
        // The archive itself declares an output larger than the §13 budget;
        // this is a size-limit violation, not a corruption.
        return Err(e::CONTAINER_SIZE);
    }

    let actual = if method == 0 {
        // Stored: the two sizes must agree, and the bytes are the output.
        if declared != u64::try_from(compressed_size).map_err(|_| e::CONTAINER_ZIP)? {
            return Err(e::CONTAINER_ZIP);
        }
        data.to_vec()
    } else {
        // Deflated: bound the output by the declared size; a stream that wants
        // to produce more is corrupt (or a bomb) and is rejected without ever
        // materialising more than the declaration allows.
        let limit = usize::try_from(declared).map_err(|_| e::CONTAINER_SIZE)?;
        decompress_to_vec_with_limit(data, limit).map_err(|_| e::CONTAINER_ZIP)?
    };
    if u64::try_from(actual.len()).unwrap_or(u64::MAX) != declared {
        return Err(e::CONTAINER_ZIP);
    }
    *total_uncompressed = total_uncompressed.saturating_add(declared);
    if *total_uncompressed > limits::MAX_CONTAINER_UNCOMPRESSED_BYTES {
        return Err(e::CONTAINER_SIZE);
    }
    Ok(actual)
}

/// Finds the end-of-central-directory record, validating the optional comment.
fn find_eocd(bytes: &[u8]) -> Result<usize, Code> {
    if bytes.len() < EOCD_FIXED {
        return Err(e::CONTAINER_ZIP);
    }
    let lowest = bytes.len().saturating_sub(EOCD_FIXED + MAX_COMMENT);
    let mut candidate = bytes.len() - EOCD_FIXED;
    loop {
        if u32_at(bytes, candidate) == Some(EOCD_SIGNATURE) {
            let comment_length =
                usize::from(u16_at(bytes, candidate + 20).ok_or(e::CONTAINER_ZIP)?);
            if candidate + EOCD_FIXED + comment_length == bytes.len() {
                return Ok(candidate);
            }
        }
        if candidate == lowest {
            return Err(e::CONTAINER_ZIP);
        }
        candidate -= 1;
    }
}

/// A bounds-checked slice.
fn slice(bytes: &[u8], offset: usize, length: usize) -> Option<&[u8]> {
    let end = offset.checked_add(length)?;
    bytes.get(offset..end)
}

/// Reads a little-endian `u16`, if the range is in bounds.
fn u16_at(bytes: &[u8], offset: usize) -> Option<u16> {
    let chunk = slice(bytes, offset, 2)?;
    Some(u16::from_le_bytes([chunk[0], chunk[1]]))
}

/// Reads a little-endian `u32`, if the range is in bounds.
fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    let chunk = slice(bytes, offset, 4)?;
    Some(u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
}

/// CRC-32 (IEEE 802.3), as used by the zip format.
fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One synthetic archive entry for the builder below.
    struct TestEntry<'a> {
        name: &'a str,
        data: &'a [u8],
        deflate: bool,
        flags: u16,
        version_made_by: u16,
        external_attributes: u32,
        /// Override the uncompressed size written to the central directory.
        declared_uncompressed: Option<u32>,
    }

    impl<'a> TestEntry<'a> {
        fn stored(name: &'a str, data: &'a [u8]) -> Self {
            Self {
                name,
                data,
                deflate: false,
                flags: 0,
                version_made_by: 20,
                external_attributes: 0,
                declared_uncompressed: None,
            }
        }

        fn deflated(name: &'a str, data: &'a [u8]) -> Self {
            Self {
                deflate: true,
                ..Self::stored(name, data)
            }
        }
    }

    /// Builds a zip archive with the given entries (no data descriptors).
    fn make_zip(entries: &[TestEntry<'_>]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut central = Vec::new();
        let mut count: u16 = 0;
        for entry in entries {
            count = count.checked_add(1).expect("entry count fits");
            let name = entry.name.as_bytes();
            let stored = if entry.deflate {
                miniz_oxide::deflate::compress_to_vec(entry.data, 6)
            } else {
                entry.data.to_vec()
            };
            let crc = crc32(entry.data);
            let method: u16 = if entry.deflate { 8 } else { 0 };
            let compressed_size = u32::try_from(stored.len()).expect("size fits");
            let uncompressed_size = entry
                .declared_uncompressed
                .unwrap_or_else(|| u32::try_from(entry.data.len()).expect("size fits"));
            let offset = u32::try_from(out.len()).expect("offset fits");

            out.extend_from_slice(&LOCAL_SIGNATURE.to_le_bytes());
            out.extend_from_slice(&20u16.to_le_bytes()); // version needed
            out.extend_from_slice(&entry.flags.to_le_bytes());
            out.extend_from_slice(&method.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes()); // modification time
            out.extend_from_slice(&0u16.to_le_bytes()); // modification date
            out.extend_from_slice(&crc.to_le_bytes());
            out.extend_from_slice(&compressed_size.to_le_bytes());
            out.extend_from_slice(&uncompressed_size.to_le_bytes());
            out.extend_from_slice(&u16::try_from(name.len()).expect("name fits").to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes()); // extra field length
            out.extend_from_slice(name);
            out.extend_from_slice(&stored);

            central.extend_from_slice(&CENTRAL_SIGNATURE.to_le_bytes());
            central.extend_from_slice(&entry.version_made_by.to_le_bytes());
            central.extend_from_slice(&20u16.to_le_bytes()); // version needed
            central.extend_from_slice(&entry.flags.to_le_bytes());
            central.extend_from_slice(&method.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes()); // time
            central.extend_from_slice(&0u16.to_le_bytes()); // date
            central.extend_from_slice(&crc.to_le_bytes());
            central.extend_from_slice(&compressed_size.to_le_bytes());
            central.extend_from_slice(&uncompressed_size.to_le_bytes());
            central.extend_from_slice(&u16::try_from(name.len()).expect("name fits").to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes()); // extra length
            central.extend_from_slice(&0u16.to_le_bytes()); // comment length
            central.extend_from_slice(&0u16.to_le_bytes()); // disk start
            central.extend_from_slice(&0u16.to_le_bytes()); // internal attributes
            central.extend_from_slice(&entry.external_attributes.to_le_bytes());
            central.extend_from_slice(&offset.to_le_bytes());
            central.extend_from_slice(name);
        }
        let central_offset = u32::try_from(out.len()).expect("offset fits");
        let central_size = u32::try_from(central.len()).expect("size fits");
        out.extend_from_slice(&central);
        out.extend_from_slice(&EOCD_SIGNATURE.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // disk number
        out.extend_from_slice(&0u16.to_le_bytes()); // central directory disk
        out.extend_from_slice(&count.to_le_bytes());
        out.extend_from_slice(&count.to_le_bytes());
        out.extend_from_slice(&central_size.to_le_bytes());
        out.extend_from_slice(&central_offset.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // comment length
        out
    }

    /// Offset of the central directory record for the entry named `name`.
    fn central_offset(zip: &[u8], name: &str) -> usize {
        let eocd = find_eocd(zip).expect("eocd");
        let mut position = u32_at(zip, eocd + 16).expect("cd offset") as usize;
        loop {
            let name_length = u16_at(zip, position + 28).expect("name length") as usize;
            let extra = u16_at(zip, position + 30).expect("extra") as usize;
            let comment = u16_at(zip, position + 32).expect("comment") as usize;
            let current = &zip[position + CENTRAL_FIXED..position + CENTRAL_FIXED + name_length];
            if current == name.as_bytes() {
                return position;
            }
            position += CENTRAL_FIXED + name_length + extra + comment;
        }
    }

    #[test]
    fn reads_stored_entries() {
        let zip = make_zip(&[
            TestEntry::stored("a.txt", b"hello"),
            TestEntry::stored("dir/b.bin", &[0u8, 1, 2, 3]),
        ]);
        let files = read_zip(&zip).expect("valid archive");
        assert_eq!(files.get("a.txt").map(Vec::as_slice), Some(&b"hello"[..]));
        assert_eq!(
            files.get("dir/b.bin").map(Vec::as_slice),
            Some(&[0, 1, 2, 3][..])
        );
    }

    #[test]
    fn reads_deflated_entries() {
        let payload = b"weave-record/1 deflate payload ".repeat(200);
        let zip = make_zip(&[TestEntry::deflated("manifest.json", &payload)]);
        let files = read_zip(&zip).expect("valid archive");
        assert_eq!(
            files.get("manifest.json").map(Vec::as_slice),
            Some(payload.as_slice())
        );
    }

    #[test]
    fn empty_archive_is_empty_container() {
        let zip = make_zip(&[]);
        assert!(read_zip(&zip).expect("valid archive").is_empty());
    }

    #[test]
    fn directory_entries_are_ignored() {
        let zip = make_zip(&[
            TestEntry::stored("records/", b""),
            TestEntry::stored("manifest.json", b"{}"),
        ]);
        let files = read_zip(&zip).expect("valid archive");
        assert_eq!(files.len(), 1);
        assert!(files.contains_key("manifest.json"));
    }

    #[test]
    fn traversal_names_are_returned_for_the_container_layer() {
        // Path safety is the container's job (§11.9 split): the reader must not
        // silently rewrite or drop the stored name.
        let zip = make_zip(&[TestEntry::stored("../escape.json", b"x")]);
        let files = read_zip(&zip).expect("readable archive");
        assert!(files.contains_key("../escape.json"));
    }

    #[test]
    fn duplicate_entry_names_are_entry_errors() {
        let zip = make_zip(&[
            TestEntry::stored("a.txt", b"one"),
            TestEntry::stored("a.txt", b"two"),
        ]);
        assert_eq!(read_zip(&zip), Err(e::CONTAINER_ENTRY));
    }

    #[test]
    fn symlink_entries_are_entry_errors() {
        let mut entry = TestEntry::stored("link", b"/etc/passwd");
        entry.version_made_by = (3 << 8) | 20; // Unix
        entry.external_attributes = 0o120777 << 16; // S_IFLNK | 0777
        let zip = make_zip(&[entry]);
        assert_eq!(read_zip(&zip), Err(e::CONTAINER_ENTRY));
    }

    #[test]
    fn encrypted_entries_are_archive_errors() {
        let mut entry = TestEntry::stored("a.txt", b"secret");
        entry.flags = 0x0001;
        let zip = make_zip(&[entry]);
        assert_eq!(read_zip(&zip), Err(e::CONTAINER_ZIP));
    }

    #[test]
    fn unsupported_compression_is_an_archive_error() {
        let zip = make_zip(&[TestEntry::stored("a.txt", b"hello")]);
        let offset = central_offset(&zip, "a.txt");
        // Patch both the local header and the central directory method to 12
        // (bzip2), which this reader does not support.
        let mut patched = zip.clone();
        patched[offset + 10..offset + 12].copy_from_slice(&12u16.to_le_bytes());
        let local_offset = u32_at(&patched, offset + 42).expect("local offset") as usize;
        patched[local_offset + 8..local_offset + 10].copy_from_slice(&12u16.to_le_bytes());
        assert_eq!(read_zip(&patched), Err(e::CONTAINER_ZIP));
    }

    #[test]
    fn crc_mismatch_is_an_archive_error() {
        let zip = make_zip(&[TestEntry::stored("a.txt", b"hello")]);
        let mut patched = zip.clone();
        // The data of "a.txt" starts after the 30-byte local header and the name.
        patched[30 + 5] ^= 0x01;
        assert_eq!(read_zip(&patched), Err(e::CONTAINER_ZIP));
    }

    #[test]
    fn deflated_size_lie_is_an_archive_error() {
        let payload = b"abc".repeat(100);
        let mut entry = TestEntry::deflated("a.bin", &payload);
        entry.declared_uncompressed = Some(10);
        let zip = make_zip(&[entry]);
        assert_eq!(read_zip(&zip), Err(e::CONTAINER_ZIP));
    }

    #[test]
    fn corrupt_deflate_stream_is_an_archive_error() {
        let payload = b"abcdefgh".repeat(50);
        let zip = make_zip(&[TestEntry::deflated("a.bin", &payload)]);
        let mut patched = zip.clone();
        // Corrupt the first byte of the deflate stream (after local header and
        // the 5-byte name).
        patched[30 + 5] ^= 0xFF;
        assert_eq!(read_zip(&patched), Err(e::CONTAINER_ZIP));
    }

    #[test]
    fn declared_oversized_entry_is_a_size_error() {
        let mut entry = TestEntry::stored("a.bin", b"x");
        entry.declared_uncompressed =
            Some(u32::try_from(limits::MAX_CONTAINER_UNCOMPRESSED_BYTES).unwrap() + 1);
        let zip = make_zip(&[entry]);
        assert_eq!(read_zip(&zip), Err(e::CONTAINER_SIZE));
    }

    #[test]
    fn truncated_archive_is_an_archive_error() {
        let zip = make_zip(&[TestEntry::stored("a.txt", b"hello")]);
        assert_eq!(read_zip(&zip[..zip.len() - 1]), Err(e::CONTAINER_ZIP));
        assert_eq!(read_zip(b"PK"), Err(e::CONTAINER_ZIP));
    }

    #[test]
    fn zip64_archive_is_rejected() {
        let zip = make_zip(&[TestEntry::stored("a.txt", b"hello")]);
        let mut patched = zip.clone();
        let eocd = find_eocd(&patched).expect("eocd");
        patched[eocd + 10..eocd + 12].copy_from_slice(&0xFFFFu16.to_le_bytes());
        patched[eocd + 8..eocd + 10].copy_from_slice(&0xFFFFu16.to_le_bytes());
        assert_eq!(read_zip(&patched), Err(e::CONTAINER_ZIP));
    }

    #[test]
    fn multi_disk_archive_is_rejected() {
        let zip = make_zip(&[TestEntry::stored("a.txt", b"hello")]);
        let mut patched = zip.clone();
        let eocd = find_eocd(&patched).expect("eocd");
        patched[eocd + 4..eocd + 6].copy_from_slice(&1u16.to_le_bytes());
        assert_eq!(read_zip(&patched), Err(e::CONTAINER_ZIP));
    }

    #[test]
    fn crc32_matches_known_vector() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0);
    }
}
