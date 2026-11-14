// SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
// SPDX-License-Identifier: Apache-2.0

//! Pure-Rust zip structure parser for the zip form of a container (§11.9).
//!
//! The verdict must not depend on a standard-library zip reader (T6), so the
//! archive structure is parsed here from the bytes, in the fixed order of the
//! §11.9 checks (W7):
//!
//! 1. locate the end-of-central-directory record (it ends exactly at the last
//!    input byte; a ZIP64 sentinel requires a locator pointing at a well-formed
//!    ZIP64 EOCD that ends exactly at the locator; the central directory lies
//!    inside the file; a non-empty archive starts with a local header at
//!    offset 0) — `E_CONTAINER_ZIP`;
//! 2. parse the central directory (framing, ZIP64 extended information, a
//!    decodable name, records filling the declared size exactly and matching
//!    the EOCD entry count) — `E_CONTAINER_ZIP`;
//! 3. the §13 limits: entry count (all entries) and the sum of the declared
//!    uncompressed sizes (`readable/**` and directory entries excluded) —
//!    `E_CONTAINER_SIZE`, and nothing later is checked;
//! 4. every remaining structural rule: archive comment, single volume, EOCD
//!    and ZIP64 consistency, per-entry version needed, disk start, method,
//!    encryption and entry classes, local headers and data descriptors against
//!    the central directory, and the byte coverage — `E_CONTAINER_ZIP`.
//!
//! ZIP64 archives are accepted (S5). Entry names, symbolic links and duplicate
//! names are judged by the container layer afterwards (`E_CONTAINER_ENTRY`).
//! Member content is decompressed lazily and only on request, under a bounded
//! output cap; `readable/**` members are never decompressed or CRC-checked
//! (§11.8). A decompression failure is reported to the caller, never a crash.

use miniz_oxide::inflate::stream::{inflate, InflateState};
use miniz_oxide::{DataFormat, MZFlush, MZStatus};

use crate::error_codes::{e, Code};
use crate::limits;

const EOCD_SIGNATURE: u32 = 0x0605_4b50;
const ZIP64_LOCATOR_SIGNATURE: u32 = 0x0706_4b50;
const ZIP64_EOCD_SIGNATURE: u32 = 0x0606_4b50;
const CENTRAL_SIGNATURE: u32 = 0x0201_4b50;
const LOCAL_SIGNATURE: u32 = 0x0403_4b50;
const DESCRIPTOR_SIGNATURE: u32 = 0x0807_4b50;
const EOCD_FIXED: usize = 22;
const ZIP64_LOCATOR_SIZE: usize = 20;
const ZIP64_EOCD_FIXED: usize = 56;
const CENTRAL_FIXED: usize = 46;
const LOCAL_FIXED: usize = 30;
const MAX_COMMENT: usize = 65_535;
const ZIP64_EXTRA_ID: u16 = 0x0001;

/// One central-directory entry after phases 1–4.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZipEntry {
    /// The decoded entry name.
    pub name: String,
    /// True for a directory entry (name ending `/`, or the DOS directory
    /// attribute) with zero data; ignored by the layout (§11.9 rule 4).
    pub is_directory: bool,
    /// True for a Unix symbolic-link entry.
    pub is_symlink: bool,
    /// Compression method (0 stored, 8 deflated).
    pub method: u16,
    /// CRC-32 from the central directory.
    pub crc32: u32,
    /// Declared compressed size.
    pub compressed_size: u64,
    /// Declared uncompressed size.
    pub uncompressed_size: u64,
    /// Offset of the entry data in the archive.
    data_start: usize,
}

/// A parsed archive whose structure passed phases 1–4.
#[derive(Debug)]
pub struct ZipArchive<'a> {
    bytes: &'a [u8],
    /// Every central-directory entry, in central-directory order.
    pub entries: Vec<ZipEntry>,
}

/// Why a member could not be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemberError {
    /// The declared uncompressed size exceeds the caller's cap; nothing was
    /// decompressed.
    TooLarge,
    /// The member's data is corrupt: a DEFLATE failure, a size that contradicts
    /// the declaration, or a CRC-32 mismatch (§11.9 V1).
    Corrupt,
}

/// A central-directory record before the remaining rules of phase 4.
struct CentralRecord {
    name_bytes: Vec<u8>,
    name: String,
    version_needed: u16,
    flags: u16,
    method: u16,
    crc32: u32,
    compressed_size: u64,
    uncompressed_size: u64,
    disk_start: u32,
    local_offset: u64,
    external_attributes: u32,
    version_made_by: u16,
    zip64: bool,
}

fn slice(bytes: &[u8], offset: usize, length: usize) -> Option<&[u8]> {
    bytes.get(offset..offset.checked_add(length)?)
}

fn u16_at(bytes: &[u8], offset: usize) -> Option<u16> {
    let chunk = slice(bytes, offset, 2)?;
    Some(u16::from_le_bytes([chunk[0], chunk[1]]))
}

fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    let chunk = slice(bytes, offset, 4)?;
    Some(u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
}

fn u64_at(bytes: &[u8], offset: usize) -> Option<u64> {
    let chunk = slice(bytes, offset, 8)?;
    let mut array = [0u8; 8];
    array.copy_from_slice(chunk);
    Some(u64::from_le_bytes(array))
}

fn to_usize(value: u64) -> Result<usize, Code> {
    usize::try_from(value).map_err(|_| e::CONTAINER_ZIP)
}

/// The EOCD and optional ZIP64 records located in phase 1.
struct EndRecords {
    eocd: usize,
    disk_number: u16,
    cd_disk: u16,
    entries_this_disk: u16,
    entries_total: u16,
    cd_size32: u32,
    cd_offset32: u32,
    comment_length: usize,
    zip64: Option<Zip64End>,
    /// Where the central directory must end: the ZIP64 EOCD record when
    /// present, otherwise the EOCD.
    cd_end_bound: usize,
    cd_offset: usize,
    cd_size: usize,
    total_entries: u64,
}

struct Zip64End {
    disk_number: u32,
    cd_disk: u32,
    entries_this_disk: u64,
    entries_total: u64,
    locator_disk: u32,
    locator_total_disks: u32,
}

/// Phase 1: locate the EOCD (and the ZIP64 records).
fn locate_end(bytes: &[u8]) -> Result<EndRecords, Code> {
    if bytes.len() < EOCD_FIXED {
        return Err(e::CONTAINER_ZIP);
    }
    // The EOCD must end exactly at the last input byte.
    let lowest = bytes.len().saturating_sub(EOCD_FIXED + MAX_COMMENT);
    let mut candidate = bytes.len() - EOCD_FIXED;
    let eocd = loop {
        if u32_at(bytes, candidate) == Some(EOCD_SIGNATURE) {
            let comment = usize::from(u16_at(bytes, candidate + 20).ok_or(e::CONTAINER_ZIP)?);
            if candidate + EOCD_FIXED + comment == bytes.len() {
                break candidate;
            }
        }
        if candidate == lowest {
            return Err(e::CONTAINER_ZIP);
        }
        candidate -= 1;
    };
    let field16 = |offset| u16_at(bytes, eocd + offset).ok_or(e::CONTAINER_ZIP);
    let field32 = |offset| u32_at(bytes, eocd + offset).ok_or(e::CONTAINER_ZIP);
    let disk_number = field16(4)?;
    let cd_disk = field16(6)?;
    let entries_this_disk = field16(8)?;
    let entries_total = field16(10)?;
    let cd_size32 = field32(12)?;
    let cd_offset32 = field32(16)?;
    let comment_length = usize::from(field16(20)?);
    let uses_sentinel = entries_this_disk == 0xFFFF
        || entries_total == 0xFFFF
        || cd_size32 == 0xFFFF_FFFF
        || cd_offset32 == 0xFFFF_FFFF;
    let locator = eocd
        .checked_sub(ZIP64_LOCATOR_SIZE)
        .filter(|&offset| u32_at(bytes, offset) == Some(ZIP64_LOCATOR_SIGNATURE));
    let mut zip64 = None;
    let (cd_end_bound, cd_offset, cd_size, total_entries) = match locator {
        Some(locator) => {
            let locator_disk = u32_at(bytes, locator + 4).ok_or(e::CONTAINER_ZIP)?;
            let record = to_usize(u64_at(bytes, locator + 8).ok_or(e::CONTAINER_ZIP)?)?;
            let locator_total_disks = u32_at(bytes, locator + 16).ok_or(e::CONTAINER_ZIP)?;
            // A well-formed ZIP64 EOCD record that ends exactly at the locator.
            if u32_at(bytes, record) != Some(ZIP64_EOCD_SIGNATURE) {
                return Err(e::CONTAINER_ZIP);
            }
            let record_size = to_usize(u64_at(bytes, record + 4).ok_or(e::CONTAINER_ZIP)?)?;
            if record_size < ZIP64_EOCD_FIXED - 12
                || record
                    .checked_add(12)
                    .and_then(|end| end.checked_add(record_size))
                    != Some(locator)
            {
                return Err(e::CONTAINER_ZIP);
            }
            let disk = u32_at(bytes, record + 16).ok_or(e::CONTAINER_ZIP)?;
            let cd_disk64 = u32_at(bytes, record + 20).ok_or(e::CONTAINER_ZIP)?;
            let this_disk = u64_at(bytes, record + 24).ok_or(e::CONTAINER_ZIP)?;
            let total = u64_at(bytes, record + 32).ok_or(e::CONTAINER_ZIP)?;
            let size = to_usize(u64_at(bytes, record + 40).ok_or(e::CONTAINER_ZIP)?)?;
            let offset = to_usize(u64_at(bytes, record + 48).ok_or(e::CONTAINER_ZIP)?)?;
            zip64 = Some(Zip64End {
                disk_number: disk,
                cd_disk: cd_disk64,
                entries_this_disk: this_disk,
                entries_total: total,
                locator_disk,
                locator_total_disks,
            });
            (record, offset, size, total)
        }
        None => {
            if uses_sentinel {
                // A sentinel needs a ZIP64 locator.
                return Err(e::CONTAINER_ZIP);
            }
            (
                eocd,
                to_usize(u64::from(cd_offset32))?,
                to_usize(u64::from(cd_size32))?,
                u64::from(entries_total),
            )
        }
    };
    // The central directory lies inside the file.
    if cd_offset
        .checked_add(cd_size)
        .is_none_or(|end| end > cd_end_bound)
    {
        return Err(e::CONTAINER_ZIP);
    }
    // A non-empty archive starts with a local file header at offset 0.
    if (total_entries > 0 || cd_size > 0) && u32_at(bytes, 0) != Some(LOCAL_SIGNATURE) {
        return Err(e::CONTAINER_ZIP);
    }
    Ok(EndRecords {
        eocd,
        disk_number,
        cd_disk,
        entries_this_disk,
        entries_total,
        cd_size32,
        cd_offset32,
        comment_length,
        zip64,
        cd_end_bound,
        cd_offset,
        cd_size,
        total_entries,
    })
}

/// Reads a ZIP64 extended-information extra field for the fields that carry a
/// sentinel, in the APPNOTE order: uncompressed size, compressed size, local
/// header offset, disk start.
fn zip64_fields(extra: &[u8], wanted: [bool; 4]) -> Option<[Option<u64>; 4]> {
    let mut position = 0usize;
    while position + 4 <= extra.len() {
        let id = u16_at(extra, position)?;
        let size = usize::from(u16_at(extra, position + 2)?);
        let data = slice(extra, position + 4, size)?;
        if id == ZIP64_EXTRA_ID {
            let mut out = [None; 4];
            let mut cursor = 0usize;
            for (index, needed) in wanted.iter().enumerate() {
                if !needed {
                    continue;
                }
                if index == 3 {
                    out[index] = Some(u64::from(u32_at(data, cursor)?));
                    cursor += 4;
                } else {
                    out[index] = Some(u64_at(data, cursor)?);
                    cursor += 8;
                }
            }
            return Some(out);
        }
        position += 4 + size;
    }
    if wanted.iter().any(|needed| *needed) {
        None
    } else {
        Some([None; 4])
    }
}

/// Decodes an entry name: UTF-8 when general-purpose bit 11 is set; otherwise
/// each byte maps to one scalar value (an injective mapping, so duplicate
/// detection and path checks are byte-faithful). `None` when not decodable.
fn decode_name(bytes: &[u8], flags: u16) -> Option<String> {
    if flags & 0x0800 != 0 || bytes.is_ascii() {
        return std::str::from_utf8(bytes).ok().map(str::to_owned);
    }
    Some(bytes.iter().map(|&byte| char::from(byte)).collect())
}

/// Phase 2: parse every central-directory record.
fn parse_central_directory(bytes: &[u8], end: &EndRecords) -> Result<Vec<CentralRecord>, Code> {
    let mut records = Vec::new();
    let mut position = end.cd_offset;
    let cd_end = end.cd_offset + end.cd_size;
    while position < cd_end {
        let header = slice(bytes, position, CENTRAL_FIXED).ok_or(e::CONTAINER_ZIP)?;
        if position + CENTRAL_FIXED > cd_end || u32_at(header, 0) != Some(CENTRAL_SIGNATURE) {
            return Err(e::CONTAINER_ZIP);
        }
        let field16 = |offset| u16_at(header, offset).ok_or(e::CONTAINER_ZIP);
        let field32 = |offset| u32_at(header, offset).ok_or(e::CONTAINER_ZIP);
        let version_made_by = field16(4)?;
        let version_needed = field16(6)?;
        let flags = field16(8)?;
        let method = field16(10)?;
        let crc32 = field32(16)?;
        let compressed32 = field32(20)?;
        let uncompressed32 = field32(24)?;
        let name_length = usize::from(field16(28)?);
        let extra_length = usize::from(field16(30)?);
        let comment_length = usize::from(field16(32)?);
        let disk_start16 = field16(34)?;
        let external_attributes = field32(38)?;
        let local_offset32 = field32(42)?;
        let record_end = position + CENTRAL_FIXED + name_length + extra_length + comment_length;
        if record_end > cd_end {
            return Err(e::CONTAINER_ZIP);
        }
        let name_bytes = slice(bytes, position + CENTRAL_FIXED, name_length)
            .ok_or(e::CONTAINER_ZIP)?
            .to_vec();
        let extra = slice(bytes, position + CENTRAL_FIXED + name_length, extra_length)
            .ok_or(e::CONTAINER_ZIP)?;
        let wanted = [
            uncompressed32 == 0xFFFF_FFFF,
            compressed32 == 0xFFFF_FFFF,
            local_offset32 == 0xFFFF_FFFF,
            disk_start16 == 0xFFFF,
        ];
        let fields = zip64_fields(extra, wanted).ok_or(e::CONTAINER_ZIP)?;
        let zip64 = wanted.iter().any(|needed| *needed);
        let name = decode_name(&name_bytes, flags).ok_or(e::CONTAINER_ZIP)?;
        records.push(CentralRecord {
            name_bytes,
            name,
            version_needed,
            flags,
            method,
            crc32,
            compressed_size: fields[1].unwrap_or(u64::from(compressed32)),
            uncompressed_size: fields[0].unwrap_or(u64::from(uncompressed32)),
            disk_start: fields[3].map_or(u32::from(disk_start16), |value| {
                u32::try_from(value).unwrap_or(u32::MAX)
            }),
            local_offset: fields[2].unwrap_or(u64::from(local_offset32)),
            external_attributes,
            version_made_by,
            zip64,
        });
        position = record_end;
    }
    if position != cd_end || u64::try_from(records.len()).ok() != Some(end.total_entries) {
        return Err(e::CONTAINER_ZIP);
    }
    Ok(records)
}

fn is_readable(name: &str) -> bool {
    name.starts_with("readable/")
}

fn is_directory_record(record: &CentralRecord) -> bool {
    record.name.ends_with('/') || record.external_attributes & 0x10 != 0
}

/// Parses an archive through phases 1–4 of §11.9 (W7).
///
/// # Errors
/// `E_CONTAINER_ZIP` for a phase 1, 2 or 4 failure and `E_CONTAINER_SIZE` for
/// a phase 3 (§13) failure.
pub fn open(bytes: &[u8]) -> Result<ZipArchive<'_>, Code> {
    // Phase 1.
    let end = locate_end(bytes)?;
    // Phase 2.
    let records = parse_central_directory(bytes, &end)?;
    // Phase 3: the §13 limits; nothing after this phase is checked.
    if records.len() > limits::MAX_CONTAINER_ENTRIES {
        return Err(e::CONTAINER_SIZE);
    }
    let declared_total = records
        .iter()
        .filter(|record| !is_readable(&record.name) && !is_directory_record(record))
        .fold(0u64, |total, record| {
            total.saturating_add(record.uncompressed_size)
        });
    if declared_total > limits::MAX_CONTAINER_UNCOMPRESSED_BYTES {
        return Err(e::CONTAINER_SIZE);
    }
    // Phase 4.
    let entries = remaining_rules(bytes, &end, &records)?;
    Ok(ZipArchive { bytes, entries })
}

/// Phase 4: every remaining structural rule (§11.9 rules 1–4).
fn remaining_rules(
    bytes: &[u8],
    end: &EndRecords,
    records: &[CentralRecord],
) -> Result<Vec<ZipEntry>, Code> {
    let actual = records.len();
    // Archive comment.
    if end.comment_length != 0 {
        return Err(e::CONTAINER_ZIP);
    }
    // Single volume (rule 3).
    if end.disk_number != 0 || end.cd_disk != 0 {
        return Err(e::CONTAINER_ZIP);
    }
    let count_ok = |field: u16| -> bool {
        usize::from(field) == actual || (field == 0xFFFF && end.zip64.is_some())
    };
    if !count_ok(end.entries_this_disk) || !count_ok(end.entries_total) {
        return Err(e::CONTAINER_ZIP);
    }
    let size_ok = |field: u32, value: usize| -> bool {
        usize::try_from(field).ok() == Some(value) || (field == 0xFFFF_FFFF && end.zip64.is_some())
    };
    if !size_ok(end.cd_size32, end.cd_size) || !size_ok(end.cd_offset32, end.cd_offset) {
        return Err(e::CONTAINER_ZIP);
    }
    if let Some(zip64) = &end.zip64 {
        if zip64.disk_number != 0
            || zip64.cd_disk != 0
            || zip64.locator_disk != 0
            || zip64.locator_total_disks != 1
            || usize::try_from(zip64.entries_this_disk).ok() != Some(actual)
            || usize::try_from(zip64.entries_total).ok() != Some(actual)
        {
            return Err(e::CONTAINER_ZIP);
        }
    }
    // Per entry (rules 1 and 4), then the byte coverage (rule 2).
    let mut spans: Vec<(usize, usize)> = Vec::with_capacity(records.len());
    let mut entries = Vec::with_capacity(records.len());
    for record in records {
        if record.version_needed > 63 || record.disk_start != 0 {
            return Err(e::CONTAINER_ZIP);
        }
        if record.method != 0 && record.method != 8 {
            return Err(e::CONTAINER_ZIP);
        }
        // Encryption: traditional (bit 0) and strong encryption (bit 6).
        if record.flags & 0x0041 != 0 {
            return Err(e::CONTAINER_ZIP);
        }
        let carries_data = record.compressed_size != 0 || record.uncompressed_size != 0;
        let is_directory = is_directory_record(record);
        if is_directory && carries_data {
            return Err(e::CONTAINER_ZIP);
        }
        let (data_start, span_end) = check_local_header(bytes, record)?;
        spans.push((to_usize(record.local_offset)?, span_end));
        let host = record.version_made_by >> 8;
        let unix_mode = record.external_attributes >> 16;
        entries.push(ZipEntry {
            name: record.name.clone(),
            is_directory,
            is_symlink: host == 3 && unix_mode & 0xF000 == 0xA000,
            method: record.method,
            crc32: record.crc32,
            compressed_size: record.compressed_size,
            uncompressed_size: record.uncompressed_size,
            data_start,
        });
    }
    // Rule 2: every byte has a home, in physical offset order.
    spans.sort_unstable();
    let mut expected_start = 0usize;
    for (start, span_end) in &spans {
        if *start != expected_start {
            return Err(e::CONTAINER_ZIP);
        }
        expected_start = *span_end;
    }
    if expected_start != end.cd_offset || end.cd_offset + end.cd_size != end.cd_end_bound {
        return Err(e::CONTAINER_ZIP);
    }
    if end.zip64.is_none() && end.cd_end_bound != end.eocd {
        return Err(e::CONTAINER_ZIP);
    }
    Ok(entries)
}

/// Rule 1: the local header agrees with the central directory; returns the
/// data start and the end of the entry (data plus data descriptor).
fn check_local_header(bytes: &[u8], record: &CentralRecord) -> Result<(usize, usize), Code> {
    let offset = to_usize(record.local_offset)?;
    let header = slice(bytes, offset, LOCAL_FIXED).ok_or(e::CONTAINER_ZIP)?;
    if u32_at(header, 0) != Some(LOCAL_SIGNATURE) {
        return Err(e::CONTAINER_ZIP);
    }
    let field16 = |position| u16_at(header, position).ok_or(e::CONTAINER_ZIP);
    let field32 = |position| u32_at(header, position).ok_or(e::CONTAINER_ZIP);
    let flags = field16(6)?;
    let method = field16(8)?;
    let crc32 = field32(14)?;
    let compressed32 = field32(18)?;
    let uncompressed32 = field32(22)?;
    let name_length = usize::from(field16(26)?);
    let extra_length = usize::from(field16(28)?);
    let name = slice(bytes, offset + LOCAL_FIXED, name_length).ok_or(e::CONTAINER_ZIP)?;
    let extra =
        slice(bytes, offset + LOCAL_FIXED + name_length, extra_length).ok_or(e::CONTAINER_ZIP)?;
    if name != record.name_bytes.as_slice() || flags != record.flags || method != record.method {
        return Err(e::CONTAINER_ZIP);
    }
    let data_start = offset + LOCAL_FIXED + name_length + extra_length;
    let data_end = data_start
        .checked_add(to_usize(record.compressed_size)?)
        .ok_or(e::CONTAINER_ZIP)?;
    if data_end > bytes.len() {
        return Err(e::CONTAINER_ZIP);
    }
    if flags & 0x0008 != 0 {
        // Data descriptor: the local CRC and sizes are zero, and the
        // descriptor (optionally signed) carries the central values.
        if crc32 != 0 || compressed32 != 0 || uncompressed32 != 0 {
            return Err(e::CONTAINER_ZIP);
        }
        let mut position = data_end;
        if u32_at(bytes, position) == Some(DESCRIPTOR_SIGNATURE) {
            position += 4;
        }
        let descriptor_crc = u32_at(bytes, position).ok_or(e::CONTAINER_ZIP)?;
        let (compressed, uncompressed, length) = if record.zip64 {
            (
                u64_at(bytes, position + 4).ok_or(e::CONTAINER_ZIP)?,
                u64_at(bytes, position + 12).ok_or(e::CONTAINER_ZIP)?,
                20,
            )
        } else {
            (
                u64::from(u32_at(bytes, position + 4).ok_or(e::CONTAINER_ZIP)?),
                u64::from(u32_at(bytes, position + 8).ok_or(e::CONTAINER_ZIP)?),
                12,
            )
        };
        if descriptor_crc != record.crc32
            || compressed != record.compressed_size
            || uncompressed != record.uncompressed_size
        {
            return Err(e::CONTAINER_ZIP);
        }
        return Ok((data_start, position + length));
    }
    let wanted = [
        uncompressed32 == 0xFFFF_FFFF,
        compressed32 == 0xFFFF_FFFF,
        false,
        false,
    ];
    let fields = zip64_fields(extra, wanted).ok_or(e::CONTAINER_ZIP)?;
    let local_compressed = fields[1].unwrap_or(u64::from(compressed32));
    let local_uncompressed = fields[0].unwrap_or(u64::from(uncompressed32));
    if crc32 != record.crc32
        || local_compressed != record.compressed_size
        || local_uncompressed != record.uncompressed_size
    {
        return Err(e::CONTAINER_ZIP);
    }
    Ok((data_start, data_end))
}

impl ZipArchive<'_> {
    /// Streams the decompressed content of `entry` to `sink` in bounded
    /// chunks, never producing more than the declared size, and checks the
    /// size and CRC-32. `cap` bounds the declared size before anything is
    /// decompressed.
    ///
    /// # Errors
    /// [`MemberError::TooLarge`] when the declared size exceeds `cap`;
    /// [`MemberError::Corrupt`] for any decompression, size or CRC failure.
    pub fn stream(
        &self,
        entry: &ZipEntry,
        cap: u64,
        mut sink: impl FnMut(&[u8]),
    ) -> Result<(), MemberError> {
        if entry.uncompressed_size > cap {
            return Err(MemberError::TooLarge);
        }
        let length = usize::try_from(entry.compressed_size).map_err(|_| MemberError::Corrupt)?;
        let data = slice(self.bytes, entry.data_start, length).ok_or(MemberError::Corrupt)?;
        let mut crc = Crc32::new();
        let mut produced: u64 = 0;
        let mut emit = |chunk: &[u8]| {
            crc.update(chunk);
            sink(chunk);
        };
        if entry.method == 0 {
            if entry.compressed_size != entry.uncompressed_size {
                return Err(MemberError::Corrupt);
            }
            for chunk in data.chunks(64 * 1024) {
                emit(chunk);
            }
            produced = entry.uncompressed_size;
        } else {
            let mut state = InflateState::new_boxed(DataFormat::Raw);
            let mut input = data;
            let mut buffer = vec![0u8; 64 * 1024];
            loop {
                let result = inflate(&mut state, input, &mut buffer, MZFlush::None);
                input = &input[result.bytes_consumed..];
                produced = produced.saturating_add(result.bytes_written as u64);
                if produced > entry.uncompressed_size {
                    return Err(MemberError::Corrupt);
                }
                emit(&buffer[..result.bytes_written]);
                match result.status {
                    Ok(MZStatus::StreamEnd) => break,
                    Ok(_) => {
                        if result.bytes_consumed == 0 && result.bytes_written == 0 {
                            // No progress: truncated stream.
                            return Err(MemberError::Corrupt);
                        }
                    }
                    Err(_) => return Err(MemberError::Corrupt),
                }
            }
            if !input.is_empty() {
                return Err(MemberError::Corrupt);
            }
        }
        if produced != entry.uncompressed_size || crc.finish() != entry.crc32 {
            return Err(MemberError::Corrupt);
        }
        Ok(())
    }

    /// Decompresses `entry` into memory under `cap` (see [`Self::stream`]).
    ///
    /// # Errors
    /// As [`Self::stream`].
    pub fn read(&self, entry: &ZipEntry, cap: u64) -> Result<Vec<u8>, MemberError> {
        let mut out = Vec::new();
        self.stream(entry, cap, |chunk| out.extend_from_slice(chunk))?;
        Ok(out)
    }
}

/// Table-driven CRC-32 (IEEE 802.3), as used by the zip format.
struct Crc32 {
    value: u32,
}

impl Crc32 {
    fn new() -> Self {
        Self { value: 0xFFFF_FFFF }
    }

    fn table() -> &'static [u32; 256] {
        static TABLE: std::sync::OnceLock<[u32; 256]> = std::sync::OnceLock::new();
        TABLE.get_or_init(|| {
            let mut table = [0u32; 256];
            for (index, slot) in table.iter_mut().enumerate() {
                let mut crc = index as u32;
                for _ in 0..8 {
                    crc = if crc & 1 != 0 {
                        (crc >> 1) ^ 0xEDB8_8320
                    } else {
                        crc >> 1
                    };
                }
                *slot = crc;
            }
            table
        })
    }

    fn update(&mut self, data: &[u8]) {
        let table = Self::table();
        for &byte in data {
            self.value =
                table[((self.value ^ u32::from(byte)) & 0xFF) as usize] ^ (self.value >> 8);
        }
    }

    fn finish(&self) -> u32 {
        !self.value
    }
}

/// CRC-32 of a byte string (used by tests and the in-crate archive builder).
#[must_use]
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = Crc32::new();
    crc.update(data);
    crc.finish()
}
