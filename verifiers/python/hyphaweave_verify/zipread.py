# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0

"""Version-independent ZIP structure parser for container inputs (spec §11.9, T6).

The verifier parses the archive bytes itself: stdlib ``zipfile`` tolerance differs
between Python versions (notably around ZIP64 end-of-central-directory records),
so it must not decide a verdict. This module validates the complete structure:

* end-of-central-directory record (EOCD) at EOF with an empty comment;
* ZIP64 EOCD record + locator and ZIP64 central-directory extra fields, with
  entry counts, central-directory size/offset and every byte accounted for;
* central-directory entries parsed one by one (no whole-directory read);
* local file headers compared field by field against the central directory, or,
  with the data-descriptor flag, the data descriptor compared instead;
* every byte has a home: the first local header at offset 0, contiguous
  entries, the central directory immediately after the last entry, no gaps,
  overlaps or padding;
* bounded decompression (STORED copy / raw DEFLATE) with CRC-32 and declared
  size verification.

Structural violations raise :class:`ZipStructureError` with ``E_CONTAINER_ZIP``.
Per-entry path/type checks stay in :mod:`container`.
"""

from __future__ import annotations

import binascii
import hashlib
import struct
import zlib
from dataclasses import dataclass
from typing import BinaryIO, Iterator

from .errors import WeaveError

LOCAL_HEADER = b"PK\x03\x04"
CENTRAL_HEADER = b"PK\x01\x02"
END_OF_CENTRAL_DIRECTORY = b"PK\x05\x06"
ZIP64_END_OF_CENTRAL_DIRECTORY = b"PK\x06\x06"
ZIP64_LOCATOR = b"PK\x06\x07"
DATA_DESCRIPTOR = b"PK\x07\x08"

_LOCAL_HEADER_SIZE = 30
_CENTRAL_HEADER_SIZE = 46
_EOCD_SIZE = 22
_ZIP64_EOCD_MIN_SIZE = 56
_ZIP64_LOCATOR_SIZE = 20
_MAX_COMMENT = 65535

#: Decompression output chunk; memory stays bounded for blob streaming.
_READ_CHUNK = 1 << 20

FLAG_ENCRYPTED = 0x0001
FLAG_DATA_DESCRIPTOR = 0x0008
FLAG_UTF8 = 0x0800
METHOD_STORED = 0
METHOD_DEFLATED = 8


class ZipStructureError(WeaveError):
    """A structural archive violation: always ``E_CONTAINER_ZIP``."""

    def __init__(self, detail: str) -> None:
        super().__init__("E_CONTAINER_ZIP", detail)


class ZipLimitError(ZipStructureError):
    """The archive exceeds a §13 entry-count or declared-total limit (V7/L7).

    It is a structural failure of the zip framing *class*, but the container
    layer reports it as the size error ``E_CONTAINER_SIZE`` (the caller maps it);
    a previous container maps it to ``E_MANIFEST_CHAIN`` like every other
    structural failure of the supplied previous.
    """


@dataclass(frozen=True)
class ZipEntry:
    """One central-directory entry plus its validated location in the archive."""

    raw_name: bytes
    name: str
    flags: int
    method: int
    crc: int
    compressed_size: int
    uncompressed_size: int
    local_offset: int
    data_offset: int
    entry_end: int
    external_attr: int
    is_directory: bool
    has_data_descriptor: bool

    @property
    def unix_mode(self) -> int:
        return self.external_attr >> 16


@dataclass(frozen=True)
class ZipArchive:
    """A fully structure-validated archive."""

    entries: tuple[ZipEntry, ...]
    has_zip64: bool


# ---------------------------------------------------------------------------
# Low-level readers
# ---------------------------------------------------------------------------


def _read_exact(handle: BinaryIO, length: int) -> bytes:
    data = handle.read(length)
    if len(data) != length:
        raise ZipStructureError("unexpected end of zip structure")
    return data


def _decode_name(raw_name: bytes, flags: int) -> str:
    """Decode an entry name: UTF-8 when flagged, CP437 otherwise (APPNOTE)."""
    try:
        if flags & FLAG_UTF8:
            return raw_name.decode("utf-8")
        return raw_name.decode("cp437")
    except UnicodeDecodeError as error:
        raise ZipStructureError("zip entry name is not decodable") from error


def _iter_extra_fields(extra: bytes) -> Iterator[tuple[int, bytes]]:
    cursor = 0
    while cursor < len(extra):
        if cursor + 4 > len(extra):
            raise ZipStructureError("truncated extra field header")
        field_id, size = struct.unpack_from("<HH", extra, cursor)
        cursor += 4
        if cursor + size > len(extra):
            raise ZipStructureError("truncated extra field data")
        yield field_id, extra[cursor : cursor + size]
        cursor += size


# ---------------------------------------------------------------------------
# End of central directory and ZIP64
# ---------------------------------------------------------------------------


def _find_eocd(handle: BinaryIO, size: int) -> tuple[int, int]:
    """Locate the EOCD whose declared comment ends exactly at EOF."""
    window = min(size, _MAX_COMMENT + _EOCD_SIZE)
    handle.seek(size - window)
    tail = handle.read(window)
    position = tail.rfind(END_OF_CENTRAL_DIRECTORY)
    while position >= 0:
        if position + _EOCD_SIZE <= len(tail):
            comment_length = struct.unpack_from("<H", tail, position + 20)[0]
            if position + _EOCD_SIZE + comment_length == len(tail):
                return size - window + position, comment_length
        position = tail.rfind(END_OF_CENTRAL_DIRECTORY, 0, position)
    raise ZipStructureError("end-of-central-directory record not found")


@dataclass(frozen=True)
class _EndRecord:
    count_disk: int
    count_total: int
    cd_size: int
    cd_offset: int
    zip64_eocd_offset: int | None
    has_zip64: bool


def _read_end_records(handle: BinaryIO, eocd_offset: int) -> _EndRecord:
    handle.seek(eocd_offset)
    record = _read_exact(handle, _EOCD_SIZE)
    if record[:4] != END_OF_CENTRAL_DIRECTORY:
        raise ZipStructureError("bad end-of-central-directory signature")
    this_disk = struct.unpack_from("<H", record, 4)[0]
    central_directory_disk = struct.unpack_from("<H", record, 6)[0]
    count_disk = struct.unpack_from("<H", record, 8)[0]
    count_total = struct.unpack_from("<H", record, 10)[0]
    cd_size = struct.unpack_from("<I", record, 12)[0]
    cd_offset = struct.unpack_from("<I", record, 16)[0]
    # U9/§11.9 rule 3: single-volume archives only; both EOCD disk numbers are 0.
    if this_disk != 0 or central_directory_disk != 0:
        raise ZipStructureError("EOCD disk numbers are non-zero (multi-volume archive)")
    needs_zip64 = (
        count_disk == 0xFFFF
        or count_total == 0xFFFF
        or cd_size == 0xFFFFFFFF
        or cd_offset == 0xFFFFFFFF
    )
    locator_offset = eocd_offset - _ZIP64_LOCATOR_SIZE
    locator = b""
    if locator_offset >= 0:
        handle.seek(locator_offset)
        locator = _read_exact(handle, _ZIP64_LOCATOR_SIZE)
    if not locator.startswith(ZIP64_LOCATOR):
        if needs_zip64:
            raise ZipStructureError("ZIP64 sentinel without a ZIP64 locator")
        if count_disk != count_total:
            raise ZipStructureError("EOCD disk and total entry counts differ")
        return _EndRecord(count_disk, count_total, cd_size, cd_offset, None, False)
    disk_number = struct.unpack_from("<I", locator, 4)[0]
    zip64_eocd_offset = struct.unpack_from("<Q", locator, 8)[0]
    total_disks = struct.unpack_from("<I", locator, 16)[0]
    # U9: the locator names disk 0 for the ZIP64 EOCD and a single-volume
    # archive has exactly one disk.
    if disk_number != 0:
        raise ZipStructureError("ZIP64 locator names a non-zero disk")
    if total_disks != 1:
        raise ZipStructureError("ZIP64 locator is not a single-volume archive")
    if zip64_eocd_offset + _ZIP64_EOCD_MIN_SIZE > locator_offset:
        raise ZipStructureError("ZIP64 EOCD offset is outside the archive")
    handle.seek(zip64_eocd_offset)
    zip64 = _read_exact(handle, _ZIP64_EOCD_MIN_SIZE)
    if zip64[:4] != ZIP64_END_OF_CENTRAL_DIRECTORY:
        raise ZipStructureError("bad ZIP64 end-of-central-directory signature")
    zip64_size = struct.unpack_from("<Q", zip64, 4)[0]
    if zip64_size < 44:
        raise ZipStructureError("ZIP64 EOCD record is too short")
    if zip64_eocd_offset + 12 + zip64_size != locator_offset:
        raise ZipStructureError("ZIP64 EOCD does not end at its locator")
    version_made = struct.unpack_from("<H", zip64, 12)[0]
    version_needed = struct.unpack_from("<H", zip64, 14)[0]
    disk = struct.unpack_from("<I", zip64, 16)[0]
    cd_disk = struct.unpack_from("<I", zip64, 20)[0]
    zip64_count_disk = struct.unpack_from("<Q", zip64, 24)[0]
    zip64_count_total = struct.unpack_from("<Q", zip64, 32)[0]
    zip64_cd_size = struct.unpack_from("<Q", zip64, 40)[0]
    zip64_cd_offset = struct.unpack_from("<Q", zip64, 48)[0]
    if disk != 0 or cd_disk != 0:
        raise ZipStructureError("ZIP64 EOCD names a non-zero disk")
    if (version_made & 0xFF) > 63 or version_needed > 63:
        raise ZipStructureError("ZIP64 version fields are out of range")
    if zip64_count_disk != zip64_count_total:
        raise ZipStructureError("ZIP64 disk and total entry counts differ")
    if count_total not in (0xFFFF, zip64_count_total):
        raise ZipStructureError("EOCD entry count contradicts the ZIP64 EOCD")
    if count_disk not in (0xFFFF, zip64_count_total):
        raise ZipStructureError("EOCD disk entry count contradicts the ZIP64 EOCD")
    if cd_size not in (0xFFFFFFFF, zip64_cd_size):
        raise ZipStructureError("EOCD central-directory size contradicts the ZIP64 EOCD")
    if cd_offset not in (0xFFFFFFFF, zip64_cd_offset):
        raise ZipStructureError("EOCD central-directory offset contradicts the ZIP64 EOCD")
    return _EndRecord(
        count_disk=zip64_count_total,
        count_total=zip64_count_total,
        cd_size=zip64_cd_size,
        cd_offset=zip64_cd_offset,
        zip64_eocd_offset=zip64_eocd_offset,
        has_zip64=True,
    )


def _check_prefix(
    handle: BinaryIO, size: int, eocd_offset: int, end_record: _EndRecord
) -> None:
    """The archive must start at byte 0 with a local header (or an empty EOCD)."""
    if end_record.count_total and end_record.cd_offset != 0:
        # A non-empty archive: the first local header must be at offset 0.
        handle.seek(0)
        if _read_exact(handle, 4) != LOCAL_HEADER:
            raise ZipStructureError("bytes before the first local file header")
        return
    if size == _EOCD_SIZE and eocd_offset == 0:
        if end_record.count_total != 0 or end_record.cd_offset != 0:
            raise ZipStructureError("empty EOCD archive declares entries")
        return
    raise ZipStructureError("archive does not start with a local file header")


# ---------------------------------------------------------------------------
# Central directory
# ---------------------------------------------------------------------------


def _resolve_zip64_central(
    *, uncompressed_size: int, compressed_size: int, local_offset: int, extra: bytes
) -> tuple[int, int, int]:
    """Apply the ZIP64 extended-information extra field to central fields."""
    size64 = uncompressed_size == 0xFFFFFFFF
    comp64 = compressed_size == 0xFFFFFFFF
    offset64 = local_offset == 0xFFFFFFFF
    if not (size64 or comp64 or offset64):
        return (uncompressed_size, compressed_size, local_offset)
    for field_id, field_data in _iter_extra_fields(extra):
        if field_id != 0x0001:
            continue
        cursor = 0
        if size64:
            if cursor + 8 > len(field_data):
                raise ZipStructureError("truncated ZIP64 extra field (uncompressed size)")
            uncompressed_size = struct.unpack_from("<Q", field_data, cursor)[0]
            cursor += 8
        if comp64:
            if cursor + 8 > len(field_data):
                raise ZipStructureError("truncated ZIP64 extra field (compressed size)")
            compressed_size = struct.unpack_from("<Q", field_data, cursor)[0]
            cursor += 8
        if offset64:
            if cursor + 8 > len(field_data):
                raise ZipStructureError("truncated ZIP64 extra field (local offset)")
            local_offset = struct.unpack_from("<Q", field_data, cursor)[0]
        return (uncompressed_size, compressed_size, local_offset)
    raise ZipStructureError("ZIP64 sentinel without a ZIP64 extra field")


def _parse_central_directory(
    handle: BinaryIO, end_record: _EndRecord
) -> list[ZipEntry]:
    count = end_record.count_total
    cd_offset = end_record.cd_offset
    end = cd_offset + end_record.cd_size
    entries: list[ZipEntry] = []
    position = cd_offset
    for _ in range(count):
        if position + _CENTRAL_HEADER_SIZE > end:
            raise ZipStructureError("central directory entry runs past the directory")
        handle.seek(position)
        header = _read_exact(handle, _CENTRAL_HEADER_SIZE)
        if header[:4] != CENTRAL_HEADER:
            raise ZipStructureError("bad central-directory entry signature")
        version_needed, flags, method = struct.unpack_from("<HHH", header, 6)
        disk_number_start = struct.unpack_from("<H", header, 34)[0]
        crc, compressed_size, uncompressed_size = struct.unpack_from("<III", header, 16)
        name_length, extra_length, comment_length = struct.unpack_from("<HHH", header, 28)
        external_attr = struct.unpack_from("<I", header, 38)[0]
        local_offset = struct.unpack_from("<I", header, 42)[0]
        variable_length = name_length + extra_length + comment_length
        if position + _CENTRAL_HEADER_SIZE + variable_length > end:
            raise ZipStructureError("central directory entry runs past the directory")
        handle.seek(position + _CENTRAL_HEADER_SIZE)
        raw_name = _read_exact(handle, name_length)
        extra = _read_exact(handle, extra_length)
        _read_exact(handle, comment_length)
        if version_needed > 63:
            raise ZipStructureError("unsupported zip version needed to extract")
        if disk_number_start != 0:
            # V6/§11.9: single-volume archives only; no entry starts on another disk.
            raise ZipStructureError("central directory entry names a non-zero disk")
        if method not in (METHOD_STORED, METHOD_DEFLATED) and not (flags & FLAG_ENCRYPTED):
            raise ZipStructureError("unsupported compression method")
        uncompressed_size, compressed_size, local_offset = _resolve_zip64_central(
            uncompressed_size=uncompressed_size,
            compressed_size=compressed_size,
            local_offset=local_offset,
            extra=extra,
        )
        entries.append(
            ZipEntry(
                raw_name=raw_name,
                name=_decode_name(raw_name, flags),
                flags=flags,
                method=method,
                crc=crc,
                compressed_size=compressed_size,
                uncompressed_size=uncompressed_size,
                local_offset=local_offset,
                data_offset=0,
                entry_end=0,
                external_attr=external_attr,
                is_directory=raw_name.endswith(b"/"),
                has_data_descriptor=bool(flags & FLAG_DATA_DESCRIPTOR),
            )
        )
        position += _CENTRAL_HEADER_SIZE + variable_length
    if position != end:
        raise ZipStructureError("central directory size does not match its entries")
    return entries


# ---------------------------------------------------------------------------
# Local headers, data descriptors and byte coverage
# ---------------------------------------------------------------------------


def _apply_local_zip64(
    *, uncompressed_size: int, compressed_size: int, extra: bytes
) -> tuple[int, int]:
    size64 = uncompressed_size == 0xFFFFFFFF
    comp64 = compressed_size == 0xFFFFFFFF
    if not (size64 or comp64):
        return (uncompressed_size, compressed_size)
    for field_id, field_data in _iter_extra_fields(extra):
        if field_id != 0x0001:
            continue
        cursor = 0
        if size64:
            if cursor + 8 > len(field_data):
                raise ZipStructureError("truncated local ZIP64 extra field")
            uncompressed_size = struct.unpack_from("<Q", field_data, cursor)[0]
            cursor += 8
        if comp64:
            if cursor + 8 > len(field_data):
                raise ZipStructureError("truncated local ZIP64 extra field")
            compressed_size = struct.unpack_from("<Q", field_data, cursor)[0]
        return (uncompressed_size, compressed_size)
    raise ZipStructureError("ZIP64 sentinel without a local ZIP64 extra field")


def _validate_local_headers(
    handle: BinaryIO, entries: list[ZipEntry], cd_offset: int
) -> list[ZipEntry]:
    resolved: list[ZipEntry] = []
    for entry in entries:
        handle.seek(entry.local_offset)
        header = _read_exact(handle, _LOCAL_HEADER_SIZE)
        if header[:4] != LOCAL_HEADER:
            raise ZipStructureError("bad local file header signature")
        version_needed, flags, method = struct.unpack_from("<HHH", header, 4)
        crc, compressed_size, uncompressed_size = struct.unpack_from("<III", header, 14)
        name_length, extra_length = struct.unpack_from("<HH", header, 26)
        handle.seek(entry.local_offset + _LOCAL_HEADER_SIZE)
        raw_name = _read_exact(handle, name_length)
        extra = _read_exact(handle, extra_length)
        local_uncompressed, local_compressed = _apply_local_zip64(
            uncompressed_size=uncompressed_size,
            compressed_size=compressed_size,
            extra=extra,
        )
        if raw_name != entry.raw_name:
            raise ZipStructureError("local header filename contradicts the central directory")
        if flags != entry.flags:
            raise ZipStructureError("local header flags contradict the central directory")
        if method != entry.method:
            raise ZipStructureError("local header method contradicts the central directory")
        data_offset = entry.local_offset + _LOCAL_HEADER_SIZE + name_length + extra_length
        data_end = data_offset + entry.compressed_size
        if data_end > cd_offset:
            raise ZipStructureError("zip entry data overlaps the central directory")
        if entry.has_data_descriptor:
            if (crc, local_compressed, local_uncompressed) != (0, 0, 0):
                raise ZipStructureError(
                    "a data-descriptor entry has non-zero sizes in its local header"
                )
            entry_end = _validate_data_descriptor(handle, entry, data_end, cd_offset)
        else:
            if crc != entry.crc:
                raise ZipStructureError("local header CRC contradicts the central directory")
            if local_compressed != entry.compressed_size:
                raise ZipStructureError(
                    "local header compressed size contradicts the central directory"
                )
            if local_uncompressed != entry.uncompressed_size:
                raise ZipStructureError(
                    "local header uncompressed size contradicts the central directory"
                )
            entry_end = data_end
        resolved.append(
            ZipEntry(
                raw_name=entry.raw_name,
                name=entry.name,
                flags=entry.flags,
                method=entry.method,
                crc=entry.crc,
                compressed_size=entry.compressed_size,
                uncompressed_size=entry.uncompressed_size,
                local_offset=entry.local_offset,
                data_offset=data_offset,
                entry_end=entry_end,
                external_attr=entry.external_attr,
                is_directory=entry.is_directory,
                has_data_descriptor=entry.has_data_descriptor,
            )
        )
    return resolved


def _validate_data_descriptor(
    handle: BinaryIO, entry: ZipEntry, data_end: int, cd_offset: int
) -> int:
    """Validate the data descriptor after an entry's data; return its end offset."""
    if data_end + 12 > cd_offset:
        raise ZipStructureError("truncated data descriptor")
    handle.seek(data_end)
    head = _read_exact(handle, 4)
    if head == DATA_DESCRIPTOR:
        if data_end + 16 > cd_offset:
            raise ZipStructureError("truncated data descriptor")
        values = _read_exact(handle, 12)
        end = data_end + 16
    else:
        values = head + _read_exact(handle, 8)
        end = data_end + 12
    descriptor_crc, descriptor_compressed, descriptor_uncompressed = struct.unpack(
        "<III", values
    )
    if descriptor_crc != entry.crc:
        raise ZipStructureError("data descriptor CRC contradicts the central directory")
    if descriptor_compressed != entry.compressed_size:
        raise ZipStructureError(
            "data descriptor compressed size contradicts the central directory"
        )
    if descriptor_uncompressed != entry.uncompressed_size:
        raise ZipStructureError(
            "data descriptor uncompressed size contradicts the central directory"
        )
    return end


def _validate_byte_coverage(entries: list[ZipEntry], end_record: _EndRecord) -> None:
    """Every byte before the central directory belongs to exactly one entry."""
    # The ZIP64 EOCD and its locator follow the central directory, so the byte
    # coverage boundary is always the central-directory start.
    boundary = end_record.cd_offset
    order = sorted(entries, key=lambda entry: entry.local_offset)
    expected = 0
    for entry in order:
        if entry.local_offset != expected:
            raise ZipStructureError("gap, padding or overlap between zip entries")
        if entry.entry_end < entry.data_offset:
            raise ZipStructureError("zip entry ends before its data")
        expected = entry.entry_end
    if expected != boundary:
        raise ZipStructureError("central directory does not immediately follow the last entry")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def declared_uncompressed_total(entries: "list[ZipEntry] | tuple[ZipEntry, ...]") -> int:
    """Declared uncompressed bytes under §13 (V7/spec §13).

    Directory entries never carry data, and ``readable/**`` entries are never
    read, hashed or counted (§11.8/§11.9/§13), so both are excluded from the
    declared byte total. The entry **count** still includes every zip entry.
    """
    return sum(
        entry.uncompressed_size
        for entry in entries
        if not entry.is_directory and not _is_readable_entry(entry.name)
    )


def _is_readable_entry(name: str) -> bool:
    return name == "readable" or name.startswith("readable/")


def parse_zip(
    handle: BinaryIO,
    *,
    max_entries: int | None = None,
    max_declared_total: int | None = None,
) -> ZipArchive:
    """Parse and structure-validate an archive read from ``handle``.

    ``handle`` must be seekable. Structural violations raise
    :class:`ZipStructureError` (``E_CONTAINER_ZIP``). The §13 limits, when
    supplied, are checked right after the central directory is parsed and
    **before** the remaining structural rules (V7/L7: a zip that is both
    over-limit and structurally invalid reports the size limit); they raise
    :class:`ZipLimitError`.
    """
    handle.seek(0, 2)
    size = handle.tell()
    if size < _EOCD_SIZE:
        raise ZipStructureError("file is too short to be a zip archive")
    eocd_offset, comment_length = _find_eocd(handle, size)
    if comment_length != 0:
        raise ZipStructureError("a non-empty archive comment is not accepted")
    if eocd_offset + _EOCD_SIZE != size:
        raise ZipStructureError("trailing bytes after the end-of-central-directory")
    end_record = _read_end_records(handle, eocd_offset)
    if end_record.cd_offset + end_record.cd_size > size:
        raise ZipStructureError("central directory extends past the end of the file")
    _check_prefix(handle, size, eocd_offset, end_record)
    entries = _parse_central_directory(handle, end_record)
    # V7/L7: the §13 limits run before the remaining structural rules so a zip
    # that is both over-limit and structurally invalid reports the size limit.
    if max_entries is not None and len(entries) > max_entries:
        raise ZipLimitError("zip entry count exceeds MAX_CONTAINER_ENTRIES")
    if (
        max_declared_total is not None
        and declared_uncompressed_total(entries) > max_declared_total
    ):
        raise ZipLimitError(
            "declared uncompressed total exceeds MAX_CONTAINER_UNCOMPRESSED_BYTES"
        )
    entries = _validate_local_headers(handle, entries, end_record.cd_offset)
    _validate_byte_coverage(entries, end_record)
    return ZipArchive(entries=tuple(entries), has_zip64=end_record.has_zip64)


def entry_container_end(zip_archive: ZipArchive) -> int:  # pragma: no cover - helper
    """Return the end offset of the last entry (the central directory start)."""
    return max((entry.entry_end for entry in zip_archive.entries), default=0)


# ---------------------------------------------------------------------------
# Content access
# ---------------------------------------------------------------------------


def read_entry_data(handle: BinaryIO, entry: ZipEntry) -> bytes:
    """Read, decompress and CRC-check one entry; returns its bytes."""
    data = b"".join(_iter_entry_chunks(handle, entry))
    if len(data) != entry.uncompressed_size:
        raise ZipStructureError("decompressed size contradicts the central directory")
    return data


def digest_entry(handle: BinaryIO, entry: ZipEntry) -> tuple[str, int]:
    """Stream one entry, verify CRC/sizes and return ``(sha256_hex, size)``."""
    digest = hashlib.sha256()
    size = 0
    for chunk in _iter_entry_chunks(handle, entry):
        digest.update(chunk)
        size += len(chunk)
    if size != entry.uncompressed_size:
        raise ZipStructureError("decompressed size contradicts the central directory")
    return digest.hexdigest(), size


def _iter_entry_chunks(handle: BinaryIO, entry: ZipEntry):
    if entry.flags & FLAG_ENCRYPTED:
        raise ZipStructureError("encrypted entries are not supported")
    if entry.method not in (METHOD_STORED, METHOD_DEFLATED):
        raise ZipStructureError("unsupported compression method")
    if entry.compressed_size == 0 and entry.uncompressed_size == 0:
        if entry.crc != 0:
            raise ZipStructureError("empty entry has a non-zero CRC")
        return
    handle.seek(entry.data_offset)
    remaining_compressed = entry.compressed_size
    produced = 0
    crc = 0
    if entry.method == METHOD_STORED:
        if entry.compressed_size != entry.uncompressed_size:
            raise ZipStructureError("stored entry sizes differ")
        while remaining_compressed:
            chunk = handle.read(min(_READ_CHUNK, remaining_compressed))
            if not chunk:
                raise ZipStructureError("truncated stored entry")
            remaining_compressed -= len(chunk)
            produced += len(chunk)
            if produced > entry.uncompressed_size:
                raise ZipStructureError("stored entry exceeds its declared size")
            crc = binascii.crc32(chunk, crc)
            yield chunk
        if produced != entry.uncompressed_size:
            raise ZipStructureError("decompressed size contradicts the central directory")
        if crc & 0xFFFFFFFF != entry.crc:
            raise ZipStructureError("entry CRC-32 does not verify")
        return
    # V1/X1: an untrusted deflate stream must never escape as a crash. This is the
    # one sanctioned broad catch in the verifier: every exception raised while
    # inflating a member becomes a zip-structure failure. It covers the target
    # container and the previous container alike because both read members only
    # through this single helper.
    decompressor = zlib.decompressobj(-15)
    try:
        while remaining_compressed:
            chunk = handle.read(min(_READ_CHUNK, remaining_compressed))
            if not chunk:
                raise ZipStructureError("truncated deflate stream")
            remaining_compressed -= len(chunk)
            pending = chunk
            while pending:
                # Never decompress beyond the declared size (bomb defence).
                limit = min(_READ_CHUNK, entry.uncompressed_size - produced + 1)
                out = decompressor.decompress(pending, max(1, limit))
                pending = decompressor.unconsumed_tail
                if out:
                    produced += len(out)
                    if produced > entry.uncompressed_size:
                        raise ZipStructureError(
                            "deflate stream exceeds its declared uncompressed size"
                        )
                    crc = binascii.crc32(out, crc)
                    yield out
                if decompressor.unused_data:
                    raise ZipStructureError(
                        "compressed stream ends before its declared size"
                    )
        tail = decompressor.flush()
        if tail:
            produced += len(tail)
            if produced > entry.uncompressed_size:
                raise ZipStructureError(
                    "deflate stream exceeds its declared uncompressed size"
                )
            crc = binascii.crc32(tail, crc)
            yield tail
        if not decompressor.eof:
            raise ZipStructureError("truncated deflate stream")
        if decompressor.unused_data or decompressor.unconsumed_tail:
            raise ZipStructureError("compressed stream does not match its declared size")
    except ZipStructureError:
        raise
    except Exception as error:  # noqa: BLE001 - untrusted stream boundary (V1)
        raise ZipStructureError("deflate stream cannot be decoded") from error
    if produced != entry.uncompressed_size:
        raise ZipStructureError("decompressed size contradicts the central directory")
    if crc & 0xFFFFFFFF != entry.crc:
        raise ZipStructureError("entry CRC-32 does not verify")
