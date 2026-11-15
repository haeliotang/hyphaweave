# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0

"""Container reading and verification (spec §11; deterministic order §14.5 steps 1-12).

A container is a directory or its zip with the layout of spec §11.1. This module
enumerates entries safely (path traversal, duplicates, symlinks, encryption and
resource limits are rejected before use), validates the manifest and its
attestation, verifies records, applies the cross-record state rules (erasure,
label export refusal, idempotency duplicates), checks blobs, the previous
manifest chain and L2 timestamps, then aggregates a deterministic report.

Everything is offline, bounded and deterministic: entry order is sorted, the
report never contains absolute paths, and a malformed input never raises out of
:func:`verify_container` (it becomes an ``invalid`` report).
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from . import (
    canonical,
    encoding,
    kinds,
    manifest as manifest_module,
    refs,
    timestamps as timestamps_module,
    verifier,
    zipread,
)
from . import errors as report_errors
from . import operator_input
from .errors import CheckSkipper, UsageError, WeaveError
from .report import (
    LIMITATION_ERASED_PLACEHOLDER,
    LIMITATION_LABELS_ARE_CLAIMS,
    LIMITATION_OFFLINE_CONTEXT,
    LIMITATION_PREVIOUS_SIG,
    LIMITATION_PREVIOUS_CONTENT,
    LIMITATION_TOFU,
    LIMITATION_TSA_TRUST,
    LIMITATION_CHAIN_CLAIM,
    container_verdict,
    limitation_list,
    record_entry,
    record_limitations,
    record_verdict,
)
from .timestamps import (
    STATE_PRESENT_UNVERIFIED,
    verify_timestamp_archive,
)
from . import keys as keys_module
from .keys import VerifiedTimestamp

MAX_CONTAINER_ENTRIES = 200_000
MAX_CONTAINER_UNCOMPRESSED_BYTES = 1_073_741_824
MAX_BLOB_BYTES = 1_073_741_824

_RECORDS_FILE = re.compile(r"^records/([0-9a-f]{64})\.json$")
_BLOBS_FILE = re.compile(r"^blobs/sha256/([0-9a-f]{64})$")
_TIMESTAMP_FILE = re.compile(r"^signatures/timestamp-[1-9][0-9]*\.tsr$")
_TSA_CERT_FILE = re.compile(r"^signatures/tsa-cert-[1-9][0-9]*\.pem$")

ALLOWED_DIRECTORIES = frozenset(
    {"signatures", "records", "blobs", "blobs/sha256", "previous", "readable"}
)


@dataclass
class ContainerInput:
    """The container content tree plus its deterministic input identity.

    Only *small consumed* files are materialised (manifest, attestation,
    record files, embedded previous manifest, TSA certificates as presence
    markers); class-limit overflows are recorded in ``oversized`` instead of
    aborting the read (T16), and blobs are streamed to their digest and size.
    ``input_sha256``/``input_size`` stay ``None`` for a directory container whose
    ``manifest.json`` is absent or over its size limit (S14).
    """

    files: dict[str, bytes]
    blobs: dict[str, tuple[str, int]] = field(default_factory=dict)
    #: Known-class files whose declared/streamed size exceeded their §13 class
    #: limit while reading; the bytes were not materialised and the value is the
    #: error code for that class (T16). The file is reported at its pipeline
    #: stage: attestation, previous manifest, records listing or timestamps.
    oversized: dict[str, str] = field(default_factory=dict)
    error: str | None = None
    input_sha256: str | None = None
    input_size: int | None = None
    is_zip: bool = False
    readable_present: bool = False
    directory_entries: set[str] = field(default_factory=set)
    oversized_timestamps: frozenset[str] = frozenset()


#: Streamed read chunk.
_READ_CHUNK_BYTES = 1 << 20


def _read_capped(handle, limit: int) -> tuple[bytes, int, bool]:
    """Read a binary stream with a hard stop at ``limit + 1`` bytes (§13/S4)."""
    kept = bytearray()
    while True:
        chunk = handle.read(_READ_CHUNK_BYTES)
        if not chunk:
            break
        kept.extend(chunk)
        if len(kept) > limit:
            return bytes(kept[: limit + 1]), limit + 1, True
    return bytes(kept), len(kept), False


def _stream_sha256(handle, limit: int | None = None) -> tuple[str, int, bool]:
    """Hash a binary stream without materialising it; stop after ``limit + 1``."""
    digest = hashlib.sha256()
    total = 0
    while True:
        chunk = handle.read(_READ_CHUNK_BYTES)
        if not chunk:
            break
        digest.update(chunk)
        total += len(chunk)
        if limit is not None and total > limit:
            return digest.hexdigest(), total, True
    return digest.hexdigest(), total, False


def _file_class_limit(relative_path: str) -> int | None:
    """§13 class limit for a container path, or ``None`` when it has no class."""
    if _RECORDS_FILE.fullmatch(relative_path) or relative_path.startswith("records/"):
        return verifier.MAX_RECORD_BYTES
    if relative_path in ("manifest.json", "previous/manifest.json"):
        return manifest_module.MAX_MANIFEST_BYTES
    if relative_path == "signatures/manifest.sig.json":
        return manifest_module.MAX_SIGFILE_BYTES
    if _TIMESTAMP_FILE.fullmatch(relative_path):
        return timestamps_module.MAX_TIMESTAMP_BYTES
    if _BLOBS_FILE.fullmatch(relative_path):
        return MAX_BLOB_BYTES
    return None


def _class_size_code(relative_path: str) -> str:
    """The §13 violation code for a file that exceeds its class limit (T16)."""
    if _BLOBS_FILE.fullmatch(relative_path):
        return "E_MANIFEST_BLOB"
    return "E_JSON_SIZE"


def read_container(path: Path) -> ContainerInput:
    """Read a directory or zip container within the resource limits.

    Returns the collected files (paths are POSIX-style relative paths), the
    first structural error encountered, and any class-limit overflows. Never
    raises for malformed input; reads are bounded per §13/S4 (never a full read
    before the size check, never a whole-archive or whole-blob materialisation).
    """
    try:
        if not path.exists():
            return ContainerInput(files={}, error="E_MANIFEST_MISSING")
        if path.is_dir():
            return _read_directory_container(path)
        is_zip = path.is_file() and _looks_like_zip(path)
    except OSError:
        return ContainerInput(files={}, error="E_CONTAINER_ZIP")
    if is_zip:
        return _read_zip_container(path)
    # S2/F40 (§14.6): a file target is a zip container whatever its first
    # bytes; its input identity is the archive bytes, even when the archive
    # does not start with a zip signature (prefix bytes, §11.9 phase 1).
    try:
        if path.is_file():
            with path.open("rb") as handle:
                sha_hex, archive_size, _truncated = _stream_sha256(handle)
            return ContainerInput(
                files={},
                error="E_CONTAINER_ZIP",
                input_sha256="sha256:" + sha_hex,
                input_size=archive_size,
                is_zip=True,
            )
    except OSError:
        pass
    return ContainerInput(files={}, error="E_CONTAINER_ZIP")


def _looks_like_zip(path: Path) -> bool:
    """Cheap signature probe; the full validation happens in :mod:`zipread`."""
    try:
        with path.open("rb") as handle:
            head = handle.read(4)
    except OSError:
        return False
    return head in (
        zipread.LOCAL_HEADER,
        zipread.END_OF_CENTRAL_DIRECTORY,
        zipread.ZIP64_END_OF_CENTRAL_DIRECTORY,
    )


def _read_directory_container(path: Path) -> ContainerInput:
    files: dict[str, bytes] = {}
    blobs: dict[str, tuple[str, int]] = {}
    oversized: dict[str, str] = {}
    directory_entries: set[str] = set()
    error: str | None = None
    readable_present = False
    total = 0
    count = 0
    # §14.6/S14: a directory container's input identity is the raw
    # manifest.json digest and byte size whenever those bytes can be read within
    # the MAX_MANIFEST_BYTES class limit — even when the manifest is structurally
    # invalid. Only an absent, unreadable or oversized manifest leaves the
    # identity null, so the manifest is read before the rest of the tree.
    manifest_path = path / "manifest.json"
    manifest_identity: tuple[str, int] | None = None
    manifest_preloaded = False
    try:
        manifest_stat = manifest_path.lstat()
    except OSError:
        manifest_stat = None
    if manifest_stat is not None and stat.S_ISREG(manifest_stat.st_mode):
        try:
            with manifest_path.open("rb") as handle:
                manifest_bytes, manifest_size, manifest_truncated = _read_capped(
                    handle, manifest_module.MAX_MANIFEST_BYTES
                )
        except OSError:
            manifest_bytes, manifest_size, manifest_truncated = b"", 0, False
        else:
            if manifest_truncated:
                return ContainerInput(
                    files={},
                    error="E_JSON_SIZE",
                    input_sha256=None,
                    input_size=None,
                )
            manifest_identity = (
                "sha256:" + hashlib.sha256(manifest_bytes).hexdigest(),
                manifest_size,
            )
            files["manifest.json"] = manifest_bytes
            total += manifest_size
            manifest_preloaded = True
    for root, dirnames, filenames in os.walk(path, followlinks=False):
        root_path = Path(root)
        dirnames.sort()
        relative_root = root_path.relative_to(path).as_posix()
        if relative_root == ".":
            relative_root = ""
        for directory_name in dirnames:
            directory_path = root_path / directory_name
            relative_directory = (
                f"{relative_root}/{directory_name}" if relative_root else directory_name
            )
            if directory_path.is_symlink():
                error = error or "E_CONTAINER_ENTRY"
            directory_entries.add(relative_directory)
        for filename in sorted(filenames):
            relative_path = f"{relative_root}/{filename}" if relative_root else filename
            if relative_path == "manifest.json" and manifest_preloaded:
                # L6/§13: the entry count covers all files, including the
                # already-read manifest.json.
                count += 1
                if count > MAX_CONTAINER_ENTRIES:
                    error = error or "E_CONTAINER_SIZE"
                    break
                continue
            count += 1
            if count > MAX_CONTAINER_ENTRIES:
                error = error or "E_CONTAINER_SIZE"
                break
            file_path = root_path / filename
            try:
                file_stat = file_path.lstat()
            except OSError:
                error = error or "E_CONTAINER_ENTRY"
                continue
            if stat.S_ISLNK(file_stat.st_mode) or not stat.S_ISREG(file_stat.st_mode):
                error = error or "E_CONTAINER_ENTRY"
                continue
            if relative_path == "readable" or relative_path.startswith("readable/"):
                # spec §11.8/§13: readable/ is ignored entirely; never read and
                # never counted (T15: the total counts streamed bytes only).
                readable_present = True
                continue
            if _TSA_CERT_FILE.fullmatch(relative_path):
                # Transport-only file that is never trusted on its own (§12.3):
                # only its presence matters, and it is not counted (T15).
                files[relative_path] = b""
                continue
            limit = _file_class_limit(relative_path)
            if limit is None:
                # Outside the layout: presence marker only, never read.
                files[relative_path] = b""
                continue
            try:
                with file_path.open("rb") as handle:
                    if _BLOBS_FILE.fullmatch(relative_path):
                        digest_hex, size, truncated = _stream_sha256(
                            handle, min(limit, MAX_BLOB_BYTES)
                        )
                        if truncated:
                            blobs[relative_path] = (digest_hex, size)
                        else:
                            blobs[relative_path] = (digest_hex, size)
                            total += size
                        if total > MAX_CONTAINER_UNCOMPRESSED_BYTES:
                            error = error or "E_CONTAINER_SIZE"
                            break
                        continue
                    data, size, truncated = _read_capped(handle, limit)
            except OSError:
                error = error or "E_CONTAINER_ENTRY"
                continue
            total += size
            if total > MAX_CONTAINER_UNCOMPRESSED_BYTES:
                error = error or "E_CONTAINER_SIZE"
                break
            if truncated:
                # T16: a non-manifest class overflow does not abort the read; the
                # file is reported at its pipeline stage.
                oversized[relative_path] = _class_size_code(relative_path)
                continue
            files[relative_path] = data
        if error == "E_CONTAINER_SIZE":
            break
    oversized_timestamps = frozenset(
        path for path, code in oversized.items() if _TIMESTAMP_FILE.fullmatch(path)
    )
    return ContainerInput(
        files=files,
        blobs=blobs,
        oversized=oversized,
        error=error,
        input_sha256=manifest_identity[0] if manifest_identity is not None else None,
        input_size=manifest_identity[1] if manifest_identity is not None else None,
        readable_present=readable_present,
        directory_entries=directory_entries,
        oversized_timestamps=oversized_timestamps,
    )


def _read_zip_container(path: Path) -> ContainerInput:
    """Read a zip container with the self-contained parser (:mod:`zipread`, T6).

    The archive identity is streamed before parsing; structural violations are
    fatal ``E_CONTAINER_ZIP``, class-limit overflows are recorded for their
    pipeline stage (T16), and ``readable/`` entries are never decompressed.
    """
    try:
        with path.open("rb") as handle:
            sha_hex, archive_size, _truncated = _stream_sha256(handle)
    except OSError:
        return ContainerInput(files={}, error="E_CONTAINER_ZIP")
    input_sha = "sha256:" + sha_hex
    files: dict[str, bytes] = {}
    blobs: dict[str, tuple[str, int]] = {}
    oversized: dict[str, str] = {}
    directory_entries: set[str] = set()
    seen_names: set[str] = set()
    readable_present = False
    error: str | None = None
    actual_total = 0
    try:
        with path.open("rb") as handle:
            # V7/W7: the parser locates the EOCD, frames the central directory,
            # checks the §13 limits and only then applies the remaining
            # structural rules (including rule 4 for every entry, W2).
            archive = zipread.parse_zip(
                handle,
                max_entries=MAX_CONTAINER_ENTRIES,
                max_declared_total=MAX_CONTAINER_UNCOMPRESSED_BYTES,
            )
            # S2/F49 (§11.9 W7): entry paths, symbolic links and duplicate
            # names are judged for *every* entry before any member content is
            # decompressed or CRC-checked, so an entry-check failure is reported
            # as E_CONTAINER_ENTRY even when another member's data is damaged.
            entry_error: str | None = None
            precheck_names: set[str] = set()
            for entry in archive.entries:
                if entry.is_directory:
                    continue
                if (
                    stat.S_ISLNK(entry.unix_mode)
                    or not _is_safe_relative_path(entry.name)
                    or entry.name in precheck_names
                ):
                    entry_error = "E_CONTAINER_ENTRY"
                    precheck_names.add(entry.name)
                    continue
                precheck_names.add(entry.name)
                # §14.6 N_READABLE_PRESENT: only an entry that passed its own
                # entry checks is an observed readable/ entry (T6, F32).
                if entry.name == "readable" or entry.name.startswith("readable/"):
                    readable_present = True
            if entry_error is not None:
                return ContainerInput(
                    files={},
                    error=entry_error,
                    input_sha256=input_sha,
                    input_size=archive_size,
                    is_zip=True,
                    readable_present=readable_present,
                )
            for entry in archive.entries:
                name = entry.name
                if entry.is_directory:
                    # W2: §11.9 rule 4 (entry classes) is enforced by the shared
                    # parser for every entry, target and previous alike.
                    directory_entries.add(name.rstrip("/"))
                    continue
                if stat.S_ISLNK(entry.unix_mode):
                    error = error or "E_CONTAINER_ENTRY"
                    continue
                if not _is_safe_relative_path(name):
                    error = error or "E_CONTAINER_ENTRY"
                    continue
                if name in seen_names:
                    # T6 rule 4: duplicate names are E_CONTAINER_ENTRY even for
                    # readable/ entries; skipping decompression does not skip this.
                    error = error or "E_CONTAINER_ENTRY"
                    continue
                seen_names.add(name)
                if name == "readable" or name.startswith("readable/"):
                    # T6: readable/ entries still passed the path/symlink/duplicate
                    # checks above, but are never decompressed or CRC-checked.
                    readable_present = True
                    continue
                if _TSA_CERT_FILE.fullmatch(name):
                    files[name] = b""
                    continue
                limit = _file_class_limit(name)
                if limit is None:
                    files[name] = b""
                    continue
                if entry.uncompressed_size > limit:
                    oversized[name] = _class_size_code(name)
                    continue
                if _BLOBS_FILE.fullmatch(name):
                    digest_hex, size = zipread.digest_entry(handle, entry)
                    blobs[name] = (digest_hex, size)
                    actual_total += size
                    if actual_total > MAX_CONTAINER_UNCOMPRESSED_BYTES:
                        return ContainerInput(
                            files={}, error="E_CONTAINER_SIZE",
                            input_sha256=input_sha, input_size=archive_size, is_zip=True,
                        )
                    continue
                data = zipread.read_entry_data(handle, entry)
                files[name] = data
                actual_total += len(data)
                if actual_total > MAX_CONTAINER_UNCOMPRESSED_BYTES:
                    return ContainerInput(
                        files={}, error="E_CONTAINER_SIZE",
                        input_sha256=input_sha, input_size=archive_size, is_zip=True,
                    )
    except zipread.ZipLimitError:
        # V7/L7: the §13 limits are size errors, not structural zip errors.
        return ContainerInput(
            files={},
            error="E_CONTAINER_SIZE",
            input_sha256=input_sha,
            input_size=archive_size,
            is_zip=True,
        )
    except zipread.ZipStructureError as structure_error:
        return ContainerInput(
            files={},
            error=structure_error.code,
            input_sha256=input_sha,
            input_size=archive_size,
            is_zip=True,
        )
    except (OSError, ValueError, EOFError, zlib.error):  # pragma: no cover
        return ContainerInput(
            files={}, error="E_CONTAINER_ZIP",
            input_sha256=input_sha, input_size=archive_size, is_zip=True,
        )
    oversized_timestamps = frozenset(
        entry_name for entry_name in oversized if _TIMESTAMP_FILE.fullmatch(entry_name)
    )
    return ContainerInput(
        files=files,
        blobs=blobs,
        oversized=oversized,
        error=error,
        input_sha256=input_sha,
        input_size=archive_size,
        is_zip=True,
        readable_present=readable_present,
        directory_entries=directory_entries,
        oversized_timestamps=oversized_timestamps,
    )


def _is_safe_relative_path(name: str) -> bool:
    if not name or name.startswith("/") or "\\" in name or "\x00" in name:
        return False
    if name.endswith("/"):
        return False
    segments = name.split("/")
    for segment in segments:
        if segment in ("", ".", ".."):
            return False
    return True


# ---------------------------------------------------------------------------
# Layout validation (spec §14.5 step 1)
# ---------------------------------------------------------------------------


def _validate_layout(container: ContainerInput) -> None:
    """Reject entries outside the allowed layout (spec §11.1).

    Files inside ``records/`` and ``blobs/`` are checked by the later
    manifest-consistency rules (``E_MANIFEST_RECORD_EXTRA``/``E_MANIFEST_BLOB``
    cover malformed file names there); everything else is a container-entry
    error.
    """
    for relative_path in sorted(container.files):
        if relative_path == "manifest.json":
            continue
        if relative_path == "signatures/manifest.sig.json":
            continue
        if _TIMESTAMP_FILE.fullmatch(relative_path):
            continue
        if _TSA_CERT_FILE.fullmatch(relative_path):
            continue
        if relative_path == "previous/manifest.json":
            continue
        if relative_path.startswith("readable/"):
            continue
        if relative_path.startswith("records/"):
            if "/" in relative_path[len("records/"):]:
                raise WeaveError("E_CONTAINER_ENTRY", "nested directory inside records/")
            continue
        if relative_path.startswith("blobs/"):
            remainder = relative_path[len("blobs/"):]
            if "/" in remainder and not remainder.startswith("sha256/"):
                raise WeaveError("E_CONTAINER_ENTRY", "unknown directory inside blobs/")
            if remainder.startswith("sha256/") and "/" in remainder[len("sha256/"):]:
                raise WeaveError("E_CONTAINER_ENTRY", "nested directory inside blobs/sha256/")
            continue
        raise WeaveError("E_CONTAINER_ENTRY", "entry outside the allowed container layout")
    for directory in sorted(container.directory_entries):
        if directory in ALLOWED_DIRECTORIES:
            continue
        if directory.startswith("readable/"):
            continue
        raise WeaveError("E_CONTAINER_ENTRY", "directory outside the allowed container layout")


# ---------------------------------------------------------------------------
# Manifest signature key candidates
# ---------------------------------------------------------------------------


def _candidate_manifest_keys(
    container_records: list[verifier.LoadedRecord],
    keyset_views: list[verifier.RecordView],
) -> tuple[dict[str, bytes], dict[str, str]]:
    """Keys usable for manifest-signature verification before record verdicts exist.

    Keys come from (a) the externally supplied keyset (already verified), and
    (b) structurally valid key-lifecycle records inside the container itself.
    A record's *validity* can only be established later, but the manifest
    signature is checked at step 5, so only key material whose key-id derivation
    matches its declared public key is used.
    """
    candidates: dict[str, bytes] = {}
    #: T10: material admitted from the local keyset is not context-trusted; a
    #: declaration that only exists in the container/target is.
    sources: dict[str, str] = {}
    keyset_context = verifier.Context()
    for view in keyset_views:
        keyset_context.register(view)
    keyset_context.rebuild()
    for key_id, declaration in keyset_context.key_state.declarations.items():
        candidates[key_id] = declaration.public_key
        sources[key_id] = "keyset"
    for record in container_records:
        value = record.value
        try:
            envelope = verifier.envelope_module.validate_envelope(value)
        except WeaveError:
            continue
        body = envelope.body
        try:
            if envelope.kind == kinds.KIND_DECLARED:
                raw = verifier.decode_public_key_material(body.get("public_key"))
                if encoding.key_id_from_public_key(raw) == body.get("key"):
                    candidates.setdefault(body["key"], raw)
            elif envelope.kind == kinds.KIND_ROTATED:
                new_raw = verifier.decode_public_key_material(body.get("new_public_key"))
                if encoding.key_id_from_public_key(new_raw) == body.get("new_key"):
                    candidates.setdefault(body["new_key"], new_raw)
                if body.get("old_public_key") is not None:
                    old_raw = verifier.decode_public_key_material(body["old_public_key"])
                    if encoding.key_id_from_public_key(old_raw) == body.get("old_key"):
                        candidates.setdefault(body["old_key"], old_raw)
        except WeaveError:
            continue
    for key_id in candidates:
        sources.setdefault(key_id, "context")
    return candidates, sources


# ---------------------------------------------------------------------------
# Container verification
# ---------------------------------------------------------------------------


@dataclass
class ContainerVerification:
    """Everything the report and the CLI need from a container verification."""

    report: dict[str, Any]
    errors: list[str]
    notices: list[str]
    record_views: list[verifier.RecordView]
    container: dict[str, Any]
    limitations: list[str]


def verify_container(
    path: Path,
    *,
    keyset_records: Iterable[verifier.LoadedRecord] = (),
    keyset_views: Iterable[verifier.RecordView] = (),
    tsa_trust: bytes | None = None,
    previous_container: Path | None = None,
    skipper: CheckSkipper | None = None,
) -> ContainerVerification:
    """Verify one container and return the report pieces (never raises for input)."""
    active_skipper = skipper if skipper is not None else CheckSkipper()
    keyset_loaded = list(keyset_records)
    keyset_verified = list(keyset_views)
    if previous_container is not None:
        _check_previous_path(previous_container)
    if tsa_trust is not None:
        # W4/§14.1: --tsa-trust is operator input exactly like --keys: a file
        # that is not a bundle of well-formed PEM certificates is a usage error
        # (exit 2, no report), decided before any container stage runs.
        timestamps_module.parse_trust_anchors(tsa_trust)
    container_input = read_container(path)
    container: dict[str, Any] = _empty_container_report()
    errors: list[str] = []
    notices: list[str] = []
    limitations: list[str] = [LIMITATION_OFFLINE_CONTEXT]
    record_views: list[verifier.RecordView] = []
    limitations_iter = limitations
    #: T10: the manifest signature used context-declaration material.
    manifest_context_trusted = False
    #: T12 flags for conditions observed so far (undetermined => not reported).
    finish_flags: dict[str, bool] = {}

    # Step 1: entry enumeration and layout safety.
    if container_input.error is not None:
        errors.append(container_input.error)
        return _finish_container(
            container_input, container, errors, notices, [], limitations_iter, active_skipper,
            manifest_context_trusted=manifest_context_trusted,
            **finish_flags,
        )
    try:
        _validate_layout(container_input)
    except WeaveError as error:
        errors.append(error.code)
        return _finish_container(
            container_input, container, errors, notices, [], limitations_iter, active_skipper,
            manifest_context_trusted=manifest_context_trusted,
            **finish_flags,
        )
    if "manifest.json" not in container_input.files:
        errors.append("E_MANIFEST_MISSING")
        return _finish_container(
            container_input, container, errors, notices, [], limitations_iter, active_skipper,
            manifest_context_trusted=manifest_context_trusted,
            **finish_flags,
        )

    # Step 2-3: manifest canonical bytes and structure.
    manifest_bytes = container_input.files["manifest.json"]
    # The report's input identity follows spec §14.6 (report format): a directory
    # container is identified by its manifest digest (manifest byte count),
    # a zip container by the archive itself. Until the digest is known, fall
    # back to the raw manifest bytes' hash.
    if not container_input.is_zip:
        container_input.input_sha256 = "sha256:" + hashlib.sha256(manifest_bytes).hexdigest()
        container_input.input_size = len(manifest_bytes)
    try:
        if len(manifest_bytes) > manifest_module.MAX_MANIFEST_BYTES:
            raise WeaveError("E_JSON_SIZE", "manifest file exceeds the size limit")
        manifest_value = canonical.parse_file_bytes(
            manifest_bytes,
            max_bytes=manifest_module.MAX_MANIFEST_BYTES,
            require_object=True,
        )
        manifest = manifest_module.validate_manifest(manifest_value)
    except WeaveError as error:
        errors.append(error.code)
        container["created_at"] = None
        # T12: previous_manifest non-null is determinable from the parsed JSON
        # even when the manifest structure check fails.
        candidate_previous = (
            manifest_value.get("previous_manifest")
            if isinstance(locals().get("manifest_value"), dict)
            else None
        )
        if isinstance(candidate_previous, dict):
            finish_flags["previous_manifest_declared"] = True
        return _finish_container(
            container_input, container, errors, notices, [], limitations_iter, active_skipper,
            manifest_context_trusted=manifest_context_trusted,
            **finish_flags,
        )
    if manifest.previous_manifest_digest is not None:
        finish_flags["previous_manifest_declared"] = True
    container.update(
        {
            "anchor_verified": False,
            "created_at": manifest.created_at,
            "level_claimed": manifest.level,
            "level_verified": "L0",
            "record_count": len(manifest.records),
            "previous_manifest_digest": manifest.previous_manifest_digest,
        }
    )

    # Step 4-5: manifest digest and signature.
    try:
        manifest_digest = encoding.manifest_digest(canonical.canonicalize(manifest_value))
        container["manifest_digest"] = manifest_digest
        if not container_input.is_zip:
            container_input.input_sha256 = manifest_digest
            container_input.input_size = len(manifest_bytes)
        attestation = _load_attestation(container_input)
        if attestation.digest != manifest_digest:
            raise WeaveError("E_MANIFEST_DIGEST", "attestation digest does not match the manifest")
        if not attestation.signatures:
            raise WeaveError("E_MANIFEST_UNSIGNED", "manifest attestation has no signatures")
        manifest_candidates, manifest_candidate_sources = _candidate_manifest_keys(
            _load_container_records(container_input).records, keyset_verified
        )
        manifest_signature_keys = _verify_manifest_signatures(
            attestation.signatures,
            manifest_digest,
            manifest_candidates,
        )
        manifest_context_trusted = any(
            manifest_candidate_sources.get(key) == "context"
            for key in manifest_signature_keys
        )
    except WeaveError as error:
        if error.code in ("E_KEY_UNKNOWN", "E_SIG_UNVERIFIABLE") or active_skipper.skip_error(
            error.code
        ):
            # S7/§14.5: an *unverifiable* container condition does not stop record
            # processing; the manifest signature outcome is carried in
            # container.errors and the records pipeline still runs.
            errors.append(error.code)
            manifest_signature_keys = ()
        else:
            errors.append(error.code)
            return _finish_container(
                container_input, container, errors, notices, [], limitations_iter, active_skipper,
            manifest_context_trusted=manifest_context_trusted
            )

    # Step 6: level/chain completeness.
    try:
        manifest_module.check_level_completeness(manifest, len(attestation.timestamps))
    except WeaveError as error:
        errors.append(error.code)
        return _finish_container(
            container_input, container, errors, notices, [], limitations_iter, active_skipper,
            manifest_context_trusted=manifest_context_trusted,
            **finish_flags,
        )
    if manifest.chain is not None:
        container["chain"] = {"status": "unverified"}
        notices.append("N_CHAIN_CLAIM_UNVERIFIED")

    # Step 7: record listing consistency. S8.1: every independent listing defect
    # is reported (sorted), with records: []; the pre-record one-error rule is
    # unchanged for the other container checks.
    oversized_records = sorted(
        path
        for path in container_input.oversized
        if path.startswith("records/")
    )
    listing = _load_container_records(container_input)
    finish_flags["placeholder_seen"] = any(
        verifier.erase.looks_like_placeholder(record.value)
        for record in listing.records
        if isinstance(record.value, dict)
    )
    finish_flags["labels_seen"] = any(
        isinstance(record.value, dict) and "labels" in record.value
        for record in listing.records
    )
    listing_errors = _check_records_listing(manifest, listing, container_input)
    if oversized_records:
        # U8/T16: an oversize records/ file is one more independent violation of
        # the records-listing phase, reported together with MISSING/EXTRA/...;
        # the manifest-derived fields stay filled (T16 shape).
        listing_errors = sorted(
            set(listing_errors)
            | {container_input.oversized[path] for path in oversized_records}
        )
    if listing_errors:
        errors.extend(listing_errors)
        # L5/§14.6: once the manifest structure has passed, record_count is the
        # number of records listed in the manifest for every later failure; it is
        # only 0 when the failure is before the manifest structure stage.
        return _finish_container(
            container_input, container, errors, notices, [], limitations_iter, active_skipper,
            manifest_context_trusted=manifest_context_trusted,
            **finish_flags,
        )
    loaded_records = listing.records

    # Step 11 is computed before per-record verification: a verified L2
    # timestamp can rescue a key-compromise signature (S2). The *reported*
    # timestamp errors are still appended after the record pass, so the
    # deterministic container check order is unchanged.
    trust_fingerprints = None
    if tsa_trust is not None:
        # W4/§14.1: the anchors were validated as operator input before the
        # pipeline started; parsing them again cannot fail here.
        trust_fingerprints = timestamps_module.parse_trust_anchors(tsa_trust)
    archive = verify_timestamp_archive(
        listed=[
            {"path": entry.path, "digest": entry.digest, "renews": entry.renews}
            for entry in attestation.timestamps
        ],
        files=container_input.files,
        manifest_digest=manifest_digest,
        trust_anchor_fingerprints=trust_fingerprints,
        oversized=frozenset(
            path
            for path in container_input.oversized
            if _TIMESTAMP_FILE.fullmatch(path)
        ),
        present=frozenset(
            path
            for path in (*container_input.files, *container_input.oversized)
            if _TIMESTAMP_FILE.fullmatch(path)
        ),
    )
    # Rescue evidence keeps every verified receipt together with its
    # accuracy; the compromise rule is genTime + accuracy < effective_at (strict).
    verified_timestamps: tuple[VerifiedTimestamp, ...] = tuple(
        VerifiedTimestamp(
            gen_time=result.gen_time or "",
            gen_time_ms=result.gen_time_ms or 0,
            gen_time_us=result.gen_time_us
            if result.gen_time_us is not None
            else (result.gen_time_ms or 0) * 1000,
            accuracy_us=result.accuracy_us,
        )
        for result in archive.verified_results()
    )
    timestamp_evidence_present = bool(attestation.timestamps)
    # S2 for the manifest signature: judge it with the manifest timestamp chain.
    try:
        _check_manifest_signer_effects(
            manifest_signature_keys,
            _candidate_key_state(
                _load_container_records(container_input).records, keyset_verified
            ),
            manifest.created_at,
            verified_timestamps,
            timestamp_evidence_present,
        )
    except WeaveError as error:
        errors.append(error.code)
        return _finish_container(
            container_input, container, errors, notices, [], limitations_iter, active_skipper,
            manifest_context_trusted=manifest_context_trusted,
            **finish_flags,
        )

    # Step 7 (continued): per-record verification.
    record_views = verifier.verify_record_set(
        loaded_records,
        verified_timestamps=verified_timestamps,
        timestamp_evidence_present=timestamp_evidence_present,
        context_views=keyset_verified,
    )

    def _finish_after_records() -> ContainerVerification:
        """Report a container whose pipeline stopped after the record phase.

        W5/§14.5: a container-level invalid error stops the pipeline at the
        stage where it is found; later stages are not run, so they contribute
        no error, no timestamp entry and no limitation (the timestamp report
        fields keep their defaults). The record verdicts already produced are
        reported as usual.
        """
        _collect_record_limitations(record_views, limitations)
        return _finish_container(
            container_input,
            container,
            errors,
            notices,
            record_views,
            limitations,
            active_skipper,
            manifest_context_trusted=manifest_context_trusted,
            **finish_flags,
        )

    def _stops(codes: Iterable[str]) -> bool:
        """Whether a stage's errors stop the container pipeline (§14.5)."""
        return any(
            report_errors.ERROR_CODES.get(code) == report_errors.EFFECT_INVALID
            and not active_skipper.skip_error(code)
            for code in codes
        )

    # Step 8: cross-record state rules.
    container_errors_from_state, state_notices = _cross_record_checks(record_views)
    notices.extend(state_notices)
    if container_errors_from_state:
        errors.extend(container_errors_from_state)
        if _stops(container_errors_from_state):
            return _finish_after_records()

    # Step 9: blobs.
    try:
        _check_blobs(manifest, container_input)
    except WeaveError as error:
        errors.append(error.code)
        if _stops([error.code]):
            return _finish_after_records()

    # Step 10: previous manifest chain.
    try:
        _check_previous_manifest(
            manifest,
            container_input,
            previous_container,
            _PreviousLinkContext.build(
                listing.records, keyset_verified, record_views
            )
            if previous_container is not None
            else None,
            finish_flags,
        )
    except WeaveError as error:
        errors.append(error.code)
        if _stops([error.code]):
            return _finish_after_records()
    # Step 11: timestamps (verification was computed early for the compromise
    # rescue; the report fields and errors belong to this stage).
    container["timestamps"] = [
        result.to_report(index) for index, result in enumerate(archive.results)
    ]
    container["anchor_verified"] = bool(
        manifest.level == "L2" and archive.anchor_verified
    )
    for error_code in archive.errors:
        if error_code not in errors:
            errors.append(error_code)

    return _finish_after_records()


def _check_previous_path(previous_container: Path) -> None:
    """W4/§14.1: the ``--previous`` path is operator input checked up front.

    A path that does not exist or cannot be opened (a file that cannot be
    opened for reading, a directory that cannot be listed) is a usage/IO error
    naming the path: exit 2, no report. An openable path is evidence for the
    chain link and is judged at step (10) (§11.5, ``E_MANIFEST_CHAIN``).
    """
    # X3: lstat first; a FIFO, device or socket is a usage error before any
    # open (opening a FIFO for reading would block).
    kind = operator_input.path_kind(
        previous_container,
        "--previous",
        allowed=(operator_input.DIRECTORY, operator_input.FILE),
    )
    try:
        if kind == operator_input.DIRECTORY:
            with os.scandir(previous_container) as listing:
                next(iter(listing), None)
        else:
            with previous_container.open("rb"):
                pass
    except OSError as error:
        raise UsageError(
            "--previous %s cannot be opened: %s"
            % (previous_container, error.strerror or error)
        ) from error


def _empty_container_report() -> dict[str, Any]:
    return {
        "anchor_verified": False,
        "chain": {"status": "absent"},
        "created_at": None,
        "errors": [],
        "level_claimed": None,
        "level_verified": "L0",
        "manifest_digest": None,
        "notices": [],
        "previous_manifest_digest": None,
        "record_count": 0,
        "timestamps": [],
    }


def _finish_container(
    container_input: ContainerInput,
    container: dict[str, Any],
    errors: list[str],
    notices: list[str],
    record_views: list[verifier.RecordView],
    limitations: list[str],
    skipper: CheckSkipper,
    *,
    manifest_context_trusted: bool = False,
    previous_manifest_declared: bool = False,
    previous_signature_verified: bool = False,
    previous_content_unverified: bool = False,
    previous_context_trusted: bool = False,
    placeholder_seen: bool = False,
    labels_seen: bool = False,
) -> ContainerVerification:
    """Assemble the container report and verdict.

    T12: limitation and notice emission follows the §14.9 if-and-only-if rules;
    conditions that could not be determined because the pipeline stopped earlier
    are not reported. Notices that describe an observed input fact (an
    enumerated readable/ entry, a parsed previous_manifest) are kept even when a
    later container check fails.
    """
    if container_input.readable_present:
        notices.append("N_READABLE_PRESENT")
    if not previous_signature_verified and (
        previous_manifest_declared or container.get("previous_manifest_digest") is not None
    ):
        # V3/§14.9: a supplied previous whose manifest signature was re-verified
        # makes the previous signature verified, so the unverified-signature
        # notice and limitation are suppressed; an embedded-only previous (or an
        # unverified supplied one) still reports them.
        notices.append("N_PREVIOUS_SIG_UNVERIFIED")
        limitations.append(LIMITATION_PREVIOUS_SIG)
    if previous_content_unverified:
        # V3/§14.9: the supplied previous container's other content was not
        # verified; emitted whenever the previous identity was read and its
        # signature verified (regardless of later comparison/target failures).
        limitations.append(LIMITATION_PREVIOUS_CONTENT)
    if container.get("level_claimed") in ("L1", "L2"):
        # T12: the chain claim cannot be recomputed offline, regardless of any
        # later container failure.
        limitations.append(LIMITATION_CHAIN_CLAIM)
    if any(
        entry.get("state") == STATE_PRESENT_UNVERIFIED
        for entry in container.get("timestamps") or ()
    ):
        # U7/§14.9: iff at least one listed receipt is present-unverified (its
        # structure and CMS signature are fine but it is not verified-and-trusted,
        # or its accuracy is unusable). A receipt rejected by a structural/CMS/
        # format check reports its error code and does not itself trigger this.
        limitations.append(LIMITATION_TSA_TRUST)
    if placeholder_seen:
        limitations.append(LIMITATION_ERASED_PLACEHOLDER)
    if labels_seen:
        limitations.append(LIMITATION_LABELS_ARE_CLAIMS)
    if manifest_context_trusted or previous_context_trusted:
        # T10: the single TOFU predicate also covers the manifest signature;
        # W1: and a supplied previous's manifest signature verified at step (10).
        limitations.append(LIMITATION_TOFU)
    entries = []
    for view in record_views:
        entry = _record_report_entry(view)
        filtered_errors = [code for code in entry["errors"] if not skipper.skip_error(code)]
        entry["errors"] = sorted(set(filtered_errors))
        if view.placeholder is None:
            entry["verdict"] = record_verdict(filtered_errors)
        entries.append(entry)
    verdicts = [entry["verdict"] for entry in entries]
    filtered_container_errors = [code for code in errors if not skipper.skip_error(code)]
    verdict = container_verdict(errors=filtered_container_errors, record_verdicts=verdicts)
    container["errors"] = sorted(set(errors))
    container["notices"] = sorted(set(notices))
    report = {
        "checks_disabled": sorted(set(skipper.tokens)),
        "container": container,
        "input": {"sha256": container_input.input_sha256, "size": container_input.input_size},
        "limitations": limitation_list(limitations),
        "records": entries,
        "report_version": "1",
        "spec": "weave-record/1",
        "summary": _summary(verdicts),
        "target": "container",
        "verdict": verdict,
        "verifier": {"name": "hyphaweave-verify-python", "version": "0.1.0"},
    }
    return ContainerVerification(
        report=report,
        errors=container["errors"],
        notices=container["notices"],
        record_views=record_views,
        container=container,
        limitations=list(report["limitations"]),
    )


def _summary(verdicts: list[str]) -> dict[str, int]:
    summary = {"erased": 0, "invalid": 0, "unverifiable": 0, "valid": 0}
    for verdict in verdicts:
        summary[verdict] = summary.get(verdict, 0) + 1
    return summary


def _dedupe(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


def _record_report_entry(view: verifier.RecordView) -> dict[str, Any]:
    """Build one ``records[]`` entry from a verified record view."""
    envelope = view.envelope
    placeholder = view.placeholder
    raw_value = view.loaded.value if view.loaded is not None else None
    if placeholder is not None:
        record_id: str | None = placeholder.record_id
        kind: str | None = kinds.KIND_ERASED
        stage: str | None = None
        origin: dict[str, str] | None = placeholder.origin.to_json()
        kind_known = True
    elif envelope is not None:
        record_id = envelope.record_id
        kind = envelope.kind
        stage = envelope.stage
        origin = envelope.origin.to_json()
        kind_known = envelope.kind_known
    else:
        record_id = None
        kind = None
        stage = None
        origin = None
        kind_known = None  # F9: undetermined scalar -> null
        if isinstance(raw_value, dict):
            if isinstance(raw_value.get("id"), str):
                record_id = raw_value["id"]
            if isinstance(raw_value.get("kind"), str):
                kind = raw_value["kind"]
                kind_known = kinds.is_registered(kind)
            if isinstance(raw_value.get("stage"), str):
                stage = raw_value["stage"]
            raw_origin = raw_value.get("origin")
            if (
                isinstance(raw_origin, dict)
                and isinstance(raw_origin.get("project"), str)
                and isinstance(raw_origin.get("instance"), str)
            ):
                origin = {
                    "project": raw_origin["project"],
                    "instance": raw_origin["instance"],
                }
    entry = record_entry(
        digest=view.digest,
        record_id=record_id,
        kind=kind,
        stage=stage,
        origin=origin,
        kind_known=kind_known,
        verdict=view.verdict or "unverifiable",
        errors=view.errors,
        notices=view.notices,
        refs=view.refs,
        sigs=view.sigs,
        attestation=view.attestation,
    )
    return entry


# ---------------------------------------------------------------------------
# Manifest attestation and signatures
# ---------------------------------------------------------------------------


def _load_attestation(container_input: ContainerInput) -> manifest_module.ManifestAttestation:
    if "signatures/manifest.sig.json" in container_input.oversized:
        # T16: a class-limit overflow of the attestation file is reported at step
        # 5; the manifest fields stay filled and no record is processed.
        raise WeaveError(
            container_input.oversized["signatures/manifest.sig.json"],
            "manifest attestation exceeds its size limit",
        )
    raw = container_input.files.get("signatures/manifest.sig.json")
    if raw is None:
        raise WeaveError("E_MANIFEST_UNSIGNED", "container has no manifest attestation file")
    try:
        if len(raw) > manifest_module.MAX_SIGFILE_BYTES:
            raise WeaveError("E_JSON_SIZE", "manifest attestation exceeds the size limit")
        value = canonical.parse_file_bytes(
            raw,
            max_bytes=manifest_module.MAX_SIGFILE_BYTES,
            require_object=True,
        )
        return manifest_module.validate_attestation(value)
    except WeaveError:
        raise


def _verify_manifest_signatures(
    signatures: Iterable[manifest_module.ManifestSignature],
    manifest_digest: str,
    candidates: dict[str, bytes],
) -> tuple[str, ...]:
    """Verify the manifest CMS-less Ed25519 signatures; return the signer key ids."""
    message = encoding.manifest_sig_message(manifest_digest)
    signer_keys: list[str] = []
    known = [signature for signature in signatures if signature.is_ed25519]
    if not known:
        # Q13 symmetry: unknown-algorithm entries are ignored; with no verifiable
        # known-algorithm signature at all the manifest cannot be trusted.
        raise WeaveError(
            "E_SIG_UNVERIFIABLE",
            "manifest attestation has no known-algorithm signature",
        )
    for signature in known:
        material = candidates.get(signature.key)
        if material is None:
            raise WeaveError(
                "E_KEY_UNKNOWN", "manifest signature key is not declared in the context"
            )
        try:
            from . import ed25519

            ed25519.verify_signature(material, message, signature.raw)
        except WeaveError as error:
            raise WeaveError(
                "E_MANIFEST_SIG_INVALID", "manifest signature does not verify"
            ) from error
        signer_keys.append(signature.key)
    return tuple(signer_keys)


def _candidate_key_state(
    container_records: list[verifier.LoadedRecord],
    keyset_views: list[verifier.RecordView],
) -> keys_module.KeyState:
    """Key lifecycle state usable before record verdicts exist (manifest S2)."""
    state = keys_module.KeyState()
    keyset_context = verifier.Context()
    for view in keyset_views:
        keyset_context.register(view)
    keyset_context.rebuild()
    state = keyset_context.key_state
    for record in container_records:
        value = record.value
        if not isinstance(value, dict):
            continue
        try:
            envelope = verifier.envelope_module.validate_envelope(value)
        except WeaveError:
            continue
        if envelope.kind in (kinds.KIND_DECLARED, kinds.KIND_REVOKED):
            # F51/F61-2/F67 (§13, §15: a report, never a crash): a lifecycle
            # record whose body fails its kind schema (a missing ``key``,
            # ``key_type`` or ``effective_at``, or a malformed TS literal)
            # supplies no candidate state; its own verdict reports the error.
            # ``public_key`` is excluded here: §9.1 rule 1 owns that member.
            body_for_schema = dict(envelope.body)
            if envelope.kind == kinds.KIND_DECLARED:
                body_for_schema.setdefault("public_key", "")
            try:
                kinds.validate_body_schema(envelope.kind, body_for_schema)
            except WeaveError:
                continue
        if envelope.kind == kinds.KIND_DECLARED:
            try:
                public_key = verifier.decode_public_key_material(
                    envelope.body.get("public_key")
                )
            except WeaveError:
                continue
            try:
                state.add_declaration(
                    keys_module.KeyDeclaration(
                        key_id=envelope.body["key"],
                        key_type=envelope.body["key_type"],
                        public_key=public_key,
                        owner=envelope.body.get("owner"),
                        valid_from=envelope.body.get("valid_from"),
                        valid_until=envelope.body.get("valid_until"),
                        recorded_at=envelope.recorded_at,
                        record_digest=record.digest or "",
                    )
                )
            except WeaveError:
                continue
        elif envelope.kind == kinds.KIND_REVOKED:
            try:
                effective_at = envelope.body["effective_at"]
                state.add_revocation(
                    keys_module.KeyRevocation(
                        key_id=envelope.body["key"],
                        reason=envelope.body["reason"],
                        effective_at=effective_at,
                        effective_at_ms=keys_module._timestamp_ms(effective_at),
                        recorded_at=envelope.recorded_at,
                        record_digest=record.digest or "",
                    )
                )
            except WeaveError:
                continue
    return state


def _check_manifest_signer_effects(
    signer_keys: tuple[str, ...],
    key_state: keys_module.KeyState,
    created_at: str,
    verified_timestamps: tuple[VerifiedTimestamp, ...],
    timestamp_evidence_present: bool,
) -> None:
    """Apply key lifecycle effects to manifest signatures (compromise timing and timestamp accuracy)."""
    for key in signer_keys:
        key_state.check_signature_effects(
            key,
            created_at,
            verified_timestamps=verified_timestamps,
            timestamp_evidence_present=timestamp_evidence_present,
        )


# ---------------------------------------------------------------------------
# Records listing
# ---------------------------------------------------------------------------


@dataclass
class _RecordListing:
    records: list[verifier.LoadedRecord]
    by_path: dict[str, verifier.LoadedRecord]


def _load_container_records(container_input: ContainerInput) -> _RecordListing:
    """Parse every ``records/`` file; digest re-computation happens later."""
    records: list[verifier.LoadedRecord] = []
    by_path: dict[str, verifier.LoadedRecord] = {}
    for relative_path in sorted(container_input.files):
        if not relative_path.startswith("records/"):
            continue
        if not _RECORDS_FILE.fullmatch(relative_path):
            continue
        raw = container_input.files[relative_path]
        try:
            record = verifier.load_record_bytes(raw, source="container")
        except WeaveError as error:
            record = verifier.LoadedRecord(
                raw=raw, value=None, digest=None, source="container"
            )
            # S2/F60 (§1.9, §14.5 U8): nesting above MAX_JSON_DEPTH is a size
            # violation like any other; the records-listing phase reports it as
            # E_JSON_SIZE, not as an unconfirmable digest.
            record.size_violation = error.code == "E_JSON_SIZE"
        record.container_path = relative_path
        records.append(record)
        by_path[relative_path] = record
    return _RecordListing(records=records, by_path=by_path)


def _check_records_listing(
    manifest: manifest_module.Manifest, listing: _RecordListing, container_input: ContainerInput
) -> list[str]:
    """Check records/ contents against the manifest (spec §11.5/§11.6).

    S8.1: the checks in this phase report every independent defect, sorted and
    unique, instead of stopping at the first one; the caller reports
    ``records: []``.
    """
    errors: set[str] = set()
    listed = {entry.digest: entry for entry in manifest.records}
    listed_hex = {entry.digest.partition(":")[2] for entry in manifest.records}
    for relative_path in sorted(container_input.files):
        if not relative_path.startswith("records/"):
            continue
        if relative_path not in listing.by_path:
            # A records/ file whose name is not records/<sha256>.json.
            errors.add("E_MANIFEST_RECORD_EXTRA")
            continue
        record = listing.by_path[relative_path]
        match = _RECORDS_FILE.fullmatch(relative_path)
        if match is None:  # pragma: no cover - filtered by _load_container_records
            errors.add("E_MANIFEST_RECORD_EXTRA")
            continue
        if match.group(1) not in listed_hex:
            errors.add("E_MANIFEST_RECORD_EXTRA")
            if record.size_violation:
                errors.add("E_JSON_SIZE")
            continue
        if record.value is None or record.digest is None:
            errors.add("E_JSON_SIZE" if record.size_violation else "E_MANIFEST_RECORD_DIGEST")
            continue
        if match.group(1) != record.digest.partition(":")[2]:
            errors.add("E_MANIFEST_RECORD_DIGEST")
            continue
        record_entry = listed.get(record.digest)
        if record_entry is None:  # pragma: no cover - guarded by listed_hex
            errors.add("E_MANIFEST_RECORD_DIGEST")
            continue
        # The manifest entry's id/kind must equal the record's own id/kind
        # (spec §11.2.1/§11.6, Q22): a tampered entry that keeps the digest but
        # relabels the record is a manifest consistency error.
        value = record.value
        if not isinstance(value, dict):
            errors.add("E_MANIFEST_RECORD_DIGEST")
            continue
        if record_entry.id != value.get("id") or record_entry.kind != value.get("kind"):
            errors.add("E_MANIFEST_RECORDS")
    for relative_path in sorted(container_input.oversized):
        # S2/F55 (§11.6 item 5, §13, §14.5 U8): a records/ file is subject to
        # MAX_RECORD_BYTES whether or not it is listed; an unlisted or misnamed
        # oversize file reports E_MANIFEST_RECORD_EXTRA as well as E_JSON_SIZE.
        if not relative_path.startswith("records/"):
            continue
        match = _RECORDS_FILE.fullmatch(relative_path)
        if match is None or match.group(1) not in listed_hex:
            errors.add("E_MANIFEST_RECORD_EXTRA")
    for entry in manifest.records:
        expected_path = "records/%s.json" % entry.digest.partition(":")[2]
        if expected_path in listing.by_path:
            continue
        if expected_path in container_input.oversized:
            # U8: the file is present but exceeded MAX_RECORD_BYTES; that is
            # reported as E_JSON_SIZE by the caller, not as a missing file.
            continue
        errors.add("E_MANIFEST_RECORD_MISSING")
    return sorted(errors)


# ---------------------------------------------------------------------------
# Blobs, chain, timestamps
# ---------------------------------------------------------------------------


def _check_blobs(manifest: manifest_module.Manifest, container_input: ContainerInput) -> None:
    blob_files = dict(container_input.blobs)
    listed = {blob.digest: blob for blob in manifest.blobs}
    if not listed:
        if blob_files or "blobs" in container_input.directory_entries:
            raise WeaveError("E_MANIFEST_BLOB", "blobs directory present without listed blobs")
        return
    for digest, blob in listed.items():
        expected_path = "blobs/sha256/%s" % digest.partition(":")[2]
        streamed = blob_files.pop(expected_path, None)
        if streamed is None:
            raise WeaveError("E_MANIFEST_BLOB", "a listed blob file is missing")
        digest_hex, size = streamed
        if size != blob.size:
            raise WeaveError("E_MANIFEST_BLOB", "blob size does not match the manifest")
        if size > MAX_BLOB_BYTES:
            raise WeaveError("E_MANIFEST_BLOB", "blob exceeds the MAX_BLOB_BYTES limit")
        if "sha256:" + digest_hex != digest:
            raise WeaveError("E_MANIFEST_BLOB", "blob digest does not match the manifest")
    if blob_files:
        raise WeaveError("E_MANIFEST_BLOB", "blobs/ contains a file not listed in the manifest")


@dataclass(frozen=True)
class _PreviousLinkContext:
    """W1/§11.5: the target container's verification context for the link.

    ``candidates``/``sources`` are the §11.3 required-key material of the
    target (keyset plus the target's own ``weave.key.declared`` /
    ``weave.key.rotated`` records), as for the target manifest signature,
    except that a rotation record that is not valid supplies no material
    (S1-FIX5 X5④; the verdicts are known at step 10). ``key_state`` is the target's final key-lifecycle state (valid
    records only, keyset included) and ``trusted`` the key ids trusted in the
    target's final trust closure: a valid declaration (keyset root, or a
    context declaration admitted by the closure), or the ``old_key`` of a valid
    rotation record that lists ``old_public_key`` and whose ``new_key`` has a
    valid declaration. Declarations inside the previous container itself are
    never part of this context.
    """

    candidates: dict[str, bytes]
    sources: dict[str, str]
    key_state: keys_module.KeyState
    trusted: frozenset[str]

    @classmethod
    def build(
        cls,
        container_records: list[verifier.LoadedRecord],
        keyset_views: list[verifier.RecordView],
        record_views: list[verifier.RecordView],
    ) -> "_PreviousLinkContext":
        # S1-FIX5 X5④ (§11.5 rule 1, §5.3): the record verdicts exist at step
        # (10), and a rotation record that is not valid supplies no key material.
        invalid_rotations = {
            id(view.loaded)
            for view in record_views
            if view.envelope is not None
            and view.envelope.kind == kinds.KIND_ROTATED
            and view.verdict != "valid"
        }
        candidates, sources = _candidate_manifest_keys(
            [record for record in container_records if id(record) not in invalid_rotations],
            keyset_views,
        )
        context = verifier.Context()
        for view in keyset_views:
            context.register(view)
        for view in record_views:
            context.register(view)
        context.rebuild()
        key_state = context.key_state
        declared = frozenset(key_state.declarations)
        rotated_old = frozenset(
            rotation.old_key
            for rotation in key_state.rotations
            if rotation.old_public_key is not None and rotation.new_key in declared
        )
        return cls(
            candidates=candidates,
            sources=sources,
            key_state=key_state,
            trusted=declared | rotated_old,
        )


def _check_previous_manifest(
    manifest: manifest_module.Manifest,
    container_input: ContainerInput,
    previous_container: Path | None,
    link_context: "_PreviousLinkContext | None",
    finish_flags: dict[str, bool],
) -> None:
    """Step 10 (§11.5), in the fixed W5 order.

    When ``--previous`` is supplied, its identity is read and its signature
    verified first (W1): that outcome alone decides
    ``L_PREVIOUS_CONTENT_UNVERIFIED`` and the suppression of the
    ``*_PREVIOUS_SIG_UNVERIFIED`` pair, whatever else fails in this stage. The
    stage then reports its first failing check: embedded-manifest size,
    ``previous_manifest`` null versus present, the embedded manifest, the
    supplied previous's own failure, and finally the supplied digest
    comparison.
    """
    supplied_digest: str | None = None
    supplied_error: WeaveError | None = None
    if previous_container is not None:
        assert link_context is not None
        outcome: dict[str, bool] = {}
        try:
            supplied_digest = _read_previous_identity(
                previous_container, link_context, outcome
            )
        except WeaveError as error:
            supplied_error = error
        else:
            _mark_previous_verified(finish_flags)
        if outcome.get("context_trusted"):
            # W1/§14.9: a previous-signature equation verified with context
            # material is context-trusted (TOFU), even if the entry then fails
            # the trust or key-state rule (same as N_KEY_TOFU on records).
            finish_flags["previous_context_trusted"] = True
    if "previous/manifest.json" in container_input.oversized:
        # A-L7/T16: the embedded previous manifest exceeded MAX_MANIFEST_BYTES;
        # it is an E_JSON_SIZE container error at step 10, after the record pass.
        raise WeaveError(
            container_input.oversized["previous/manifest.json"],
            "embedded previous manifest exceeds its size limit",
        )
    embedded = container_input.files.get("previous/manifest.json")
    if manifest.previous_manifest_digest is None:
        if embedded is not None:
            raise WeaveError(
                "E_MANIFEST_CHAIN_UNEXPECTED",
                "previous_manifest is null but previous/manifest.json is present",
            )
        if "previous" in container_input.directory_entries and any(
            name.startswith("previous/") for name in container_input.files
        ):
            raise WeaveError(
                "E_MANIFEST_CHAIN_UNEXPECTED",
                "previous_manifest is null but previous/ contains a manifest",
            )
        if previous_container is not None:
            # V3/§11.5: a supplied previous with a null chain is a chain error
            # whether or not the supplied identity could be verified.
            raise WeaveError(
                "E_MANIFEST_CHAIN",
                "a previous container was supplied but previous_manifest is null",
            )
        return
    if embedded is None:
        raise WeaveError(
            "E_MANIFEST_CHAIN_MISSING", "previous_manifest is set but previous/manifest.json is absent"
        )
    try:
        value = canonical.parse_file_bytes(
            embedded,
            max_bytes=manifest_module.MAX_MANIFEST_BYTES,
            require_object=True,
        )
    except WeaveError as error:
        raise WeaveError("E_MANIFEST_CHAIN", "embedded previous manifest is malformed") from error
    if not isinstance(value, dict) or value.get("format") != "weave-record/1":
        raise WeaveError("E_MANIFEST_CHAIN", "embedded previous manifest is malformed")
    version = value.get("manifest_version")
    if isinstance(version, bool) or version != 1:
        raise WeaveError("E_MANIFEST_CHAIN", "unsupported previous manifest version")
    previous_origin = value.get("origin")
    if (
        not isinstance(previous_origin, dict)
        or previous_origin.get("project") != manifest.origin_project
        or previous_origin.get("instance") != manifest.origin_instance
    ):
        raise WeaveError(
            "E_MANIFEST_CHAIN", "previous manifest origin differs from the manifest origin"
        )
    digest = encoding.manifest_digest(canonical.canonicalize(value))
    if digest != manifest.previous_manifest_digest:
        raise WeaveError(
            "E_MANIFEST_CHAIN", "embedded previous manifest digest does not match"
        )
    if supplied_error is not None:
        raise supplied_error
    if previous_container is not None and supplied_digest != manifest.previous_manifest_digest:
        raise WeaveError(
            "E_MANIFEST_CHAIN", "--previous manifest digest does not match"
        )


def _mark_previous_verified(finish_flags: dict[str, bool]) -> None:
    """V3/§14.9: the supplied previous identity was read and its signature verified."""
    finish_flags["previous_signature_verified"] = True
    finish_flags["previous_content_unverified"] = True


# ---------------------------------------------------------------------------
# Supplied previous container: the narrowed chain link read (§11.5, V3)
# ---------------------------------------------------------------------------

#: The only two members read from a supplied previous container. Everything else
#: in it (records, blobs, readable/, extra files, attestation timestamps) is not
#: verified; the report says so with ``L_PREVIOUS_CONTENT_UNVERIFIED``.
_PREVIOUS_MANIFEST = "manifest.json"
_PREVIOUS_ATTESTATION = "signatures/manifest.sig.json"


def _read_previous_identity(
    previous_container: Path,
    link_context: _PreviousLinkContext,
    outcome: dict[str, bool] | None = None,
) -> str:
    """Read, validate and verify a supplied previous container's chain identity.

    V3/§11.5: exactly two members are read from the supplied previous container
    (directory or zip): ``manifest.json`` and its attestation
    ``signatures/manifest.sig.json``, each bounded by ``MAX_MANIFEST_BYTES``.
    The zip is parsed with the shared parser (every §11.9 framing and
    structural rule, W2); every other member is otherwise ignored.

    W1: the attestation's signatures are verified in the **target** container's
    verification context (:class:`_PreviousLinkContext`): every ``ed25519``
    entry must be made by a §11.3 required key of the target context, verify,
    belong to a key trusted in the target's final trust closure, and pass the
    §9.4 lifecycle rules at the previous manifest's ``created_at`` (no timestamp
    evidence is read from the previous container, so a compromise revocation of
    the signing key always breaks the link). Returns the previous manifest
    digest; ``outcome["context_trusted"]`` is set as soon as the signature
    equations verified with key material from the context rather than the
    keyset (TOFU), even if a later rule fails. Every failure is
    ``E_MANIFEST_CHAIN``.
    """
    try:
        manifest_bytes, attestation_bytes = _read_previous_members(previous_container)
        try:
            value = canonical.parse_file_bytes(
                manifest_bytes,
                max_bytes=manifest_module.MAX_MANIFEST_BYTES,
                require_object=True,
            )
        except WeaveError as error:
            raise WeaveError("E_MANIFEST_CHAIN", "--previous manifest is malformed") from error
        if not isinstance(value, dict):
            raise WeaveError("E_MANIFEST_CHAIN", "--previous manifest is malformed")
        try:
            previous_manifest = manifest_module.validate_manifest(value)
        except WeaveError as error:
            raise WeaveError(
                "E_MANIFEST_CHAIN", "--previous manifest is not a valid manifest"
            ) from error
        digest = encoding.manifest_digest(canonical.canonicalize(value))
        try:
            attestation_value = canonical.parse_file_bytes(
                attestation_bytes,
                max_bytes=manifest_module.MAX_SIGFILE_BYTES,
                require_object=True,
            )
        except WeaveError as error:
            raise WeaveError(
                "E_MANIFEST_CHAIN", "--previous manifest attestation is malformed"
            ) from error
        try:
            attestation = manifest_module.validate_attestation(attestation_value)
        except WeaveError as error:
            raise WeaveError(
                "E_MANIFEST_CHAIN", "--previous manifest attestation is malformed"
            ) from error
        if attestation.digest != digest:
            raise WeaveError(
                "E_MANIFEST_CHAIN",
                "--previous manifest attestation digest does not match",
            )
        try:
            signer_keys = _verify_manifest_signatures(
                attestation.signatures, digest, link_context.candidates
            )
        except WeaveError as error:
            raise WeaveError(
                "E_MANIFEST_CHAIN", "--previous manifest signature does not verify"
            ) from error
        if outcome is not None:
            outcome["context_trusted"] = any(
                link_context.sources.get(key) == "context" for key in signer_keys
            )
        for key in signer_keys:
            if key not in link_context.trusted:
                raise WeaveError(
                    "E_MANIFEST_CHAIN",
                    "--previous manifest signing key is not trusted in the target context",
                )
            try:
                link_context.key_state.check_signature_effects(
                    key,
                    previous_manifest.created_at,
                    verified_timestamps=(),
                    timestamp_evidence_present=False,
                    compromise_at_recorded_time=True,
                )
            except WeaveError as error:
                raise WeaveError(
                    "E_MANIFEST_CHAIN",
                    "--previous manifest signing key was not usable at its created_at",
                ) from error
    except UsageError:
        raise
    except WeaveError as error:
        if error.code == "E_MANIFEST_CHAIN":
            raise
        raise WeaveError(
            "E_MANIFEST_CHAIN", "--previous container is not a usable chain link"
        ) from error
    except (OSError, ValueError, EOFError) as error:
        raise WeaveError(
            "E_MANIFEST_CHAIN", "--previous container is unreadable"
        ) from error
    return digest


def _read_previous_members(previous_container: Path) -> tuple[bytes, bytes]:
    """Read the two chain-identity members from a previous directory or zip."""
    if previous_container.is_dir():
        return (
            _read_previous_regular_file(previous_container / _PREVIOUS_MANIFEST),
            _read_previous_regular_file(
                previous_container / _PREVIOUS_ATTESTATION
            ),
        )
    if not previous_container.is_file():
        # A symlink/special file is not a usable previous container.
        raise WeaveError(
            "E_MANIFEST_CHAIN", "--previous is not a usable container"
        )
    if not _looks_like_zip(previous_container):
        raise WeaveError(
            "E_MANIFEST_CHAIN", "--previous is not a usable container"
        )
    with previous_container.open("rb") as handle:
        try:
            archive = zipread.parse_zip(
                handle,
                max_entries=MAX_CONTAINER_ENTRIES,
                max_declared_total=MAX_CONTAINER_UNCOMPRESSED_BYTES,
            )
        except zipread.ZipLimitError as error:
            # V7/L7: the §13 limits are checked before locating the members; a
            # supplied previous maps every structural/framing failure to chain.
            raise WeaveError(
                "E_MANIFEST_CHAIN", "--previous container exceeds a size limit"
            ) from error
        manifest_entry = _exactly_one_previous_member(
            archive, _PREVIOUS_MANIFEST, "manifest.json"
        )
        attestation_entry = _exactly_one_previous_member(
            archive, _PREVIOUS_ATTESTATION, "signatures/manifest.sig.json"
        )
        for label, entry in (
            ("--previous manifest", manifest_entry),
            ("--previous manifest attestation", attestation_entry),
        ):
            if entry.uncompressed_size > manifest_module.MAX_MANIFEST_BYTES:
                raise WeaveError(
                    "E_MANIFEST_CHAIN", "%s exceeds the size limit" % label
                )
        return (
            zipread.read_entry_data(handle, manifest_entry),
            zipread.read_entry_data(handle, attestation_entry),
        )


def _exactly_one_previous_member(
    archive: zipread.ZipArchive, name: str, label: str
) -> zipread.ZipEntry:
    """V3: exactly one non-directory zip member with the required name."""
    matches = [
        entry
        for entry in archive.entries
        if entry.name == name and not entry.is_directory
    ]
    if len(matches) != 1:
        raise WeaveError(
            "E_MANIFEST_CHAIN",
            "--previous container must carry exactly one %s member" % label,
        )
    return matches[0]


def _read_previous_regular_file(path: Path) -> bytes:
    """Read one required previous member; it must be a regular file (V3)."""
    try:
        member_stat = path.lstat()
    except OSError as error:
        raise WeaveError(
            "E_MANIFEST_CHAIN", "--previous container is missing a required member"
        ) from error
    if stat.S_ISLNK(member_stat.st_mode) or not stat.S_ISREG(member_stat.st_mode):
        raise WeaveError(
            "E_MANIFEST_CHAIN",
            "--previous container member is not a regular file",
        )
    try:
        with path.open("rb") as handle:
            data, size, truncated = _read_capped(
                handle, manifest_module.MAX_MANIFEST_BYTES
            )
    except OSError as error:
        raise WeaveError(
            "E_MANIFEST_CHAIN", "--previous container is unreadable"
        ) from error
    if truncated or size > manifest_module.MAX_MANIFEST_BYTES:
        raise WeaveError(
            "E_MANIFEST_CHAIN", "--previous container member exceeds the size limit"
        )
    return data


# ---------------------------------------------------------------------------
# Cross-record state rules (spec §14.5 step 8)
# ---------------------------------------------------------------------------


def _cross_record_checks(
    record_views: list[verifier.RecordView],
) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    notices: list[str] = []

    # local-only must never be exported.
    for view in record_views:
        if view.envelope is not None and view.envelope.sensitivity == "local-only":
            errors.append("E_LABEL_LOCAL_ONLY_EXPORTED")
            break

    # idempotency duplicates are a notice, not an error (Q17).
    seen_idempotency: set[tuple[str, str, str, str]] = set()
    for view in record_views:
        envelope = view.envelope
        if envelope is None:
            continue
        idempotency_key = envelope.raw.get("actor", {}).get("idempotency_key")
        if not isinstance(idempotency_key, str):
            continue
        identity = (
            envelope.origin.project,
            envelope.origin.instance,
            envelope.actor_key,
            idempotency_key,
        )
        if identity in seen_idempotency:
            notices.append("N_IDEMPOTENCY_DUPLICATE")
            break
        seen_idempotency.add(identity)

    # Erasure cross-checks (spec §10.3).
    if not errors:
        errors.extend(_erasure_cross_checks(record_views))
    return errors, notices


def _erasure_cross_checks(record_views: list[verifier.RecordView]) -> list[str]:
    """§10.3 cross-checks; every rule is evaluated independently (S2/F48).

    §14.5: the failing stage reports every violation it finds, so a container
    can carry E_ERASE_DIGEST_MISMATCH, E_ERASE_ATTESTATION and
    E_ERASE_CONTRADICTION together. Only placeholders that pass §4.5 are
    placeholders here: a malformed one is an invalid record (F69).
    """
    found: set[str] = set()
    placeholders = [view for view in record_views if view.placeholder is not None]
    erasures = [
        view
        for view in record_views
        if view.envelope is not None and view.envelope.kind == kinds.KIND_ERASURE
    ]
    # Deterministic order: placeholders and erasures are already in manifest order.
    for erasure in erasures:
        body = erasure.envelope.body  # type: ignore[union-attr]
        if erasure.verdict != "valid":
            # The erasure record is already invalid with its own code (for
            # example E_KIND_BODY_SCHEMA for a missing body.erased, S7); the
            # container is invalid regardless, so the cross-check never crashes
            # on a member the record's own validation did not establish.
            continue
        erased_value = body.get("erased")
        try:
            reference = refs.validate_reference(erased_value)
        except WeaveError:
            continue
        matching = [
            placeholder
            for placeholder in placeholders
            if placeholder.placeholder is not None
            and placeholder.placeholder.origin == reference.origin
            and placeholder.placeholder.record_id == reference.id
        ]
        if not matching:
            found.add("E_ERASE_DIGEST_MISMATCH")
            continue
        placeholder = matching[0].placeholder
        assert placeholder is not None
        if placeholder.digest != reference.digest:
            found.add("E_ERASE_DIGEST_MISMATCH")
            continue
        # The placeholder's attestation must resolve back to this erasure record.
        attestation_reference = placeholder.attestation
        target_matches = (
            erasure.digest is not None
            and attestation_reference.digest == erasure.digest
            and attestation_reference.origin == erasure.envelope.origin  # type: ignore[union-attr]
            and attestation_reference.id == erasure.envelope.record_id  # type: ignore[union-attr]
        )
        if not target_matches:
            found.add("E_ERASE_ATTESTATION")
            continue
    for placeholder_view in placeholders:
        placeholder = placeholder_view.placeholder
        assert placeholder is not None
        resolved = _find_view(record_views, placeholder.attestation)
        if resolved is None or resolved.envelope is None:
            found.add("E_ERASE_ATTESTATION")
            continue
        if resolved.envelope.kind != kinds.KIND_ERASURE:
            found.add("E_ERASE_ATTESTATION")
            continue
        if resolved.digest != placeholder.attestation.digest:
            found.add("E_ERASE_ATTESTATION")
            continue
        if resolved.envelope.body.get("erased", {}).get("digest") != placeholder.digest:
            found.add("E_ERASE_DIGEST_MISMATCH")
            continue
    # The original live record must not also be present.
    for placeholder_view in placeholders:
        placeholder = placeholder_view.placeholder
        assert placeholder is not None
        for view in record_views:
            if view.placeholder is not None or view.envelope is None:
                continue
            if (
                view.envelope.origin == placeholder.origin
                and view.envelope.record_id == placeholder.record_id
                and view.digest == placeholder.digest
            ):
                found.add("E_ERASE_CONTRADICTION")
    origin_ids = [
        (placeholder_view.placeholder.origin, placeholder_view.placeholder.record_id)
        for placeholder_view in placeholders
        if placeholder_view.placeholder is not None
    ]
    if len(origin_ids) != len(set(origin_ids)):
        found.add("E_ERASE_CONTRADICTION")
    return sorted(found)


def _find_view(
    record_views: list[verifier.RecordView], reference: refs.Reference
) -> verifier.RecordView | None:
    for view in record_views:
        if view.envelope is not None:
            if (
                view.envelope.origin == reference.origin
                and view.envelope.record_id == reference.id
            ):
                return view
        elif view.placeholder is not None:
            if (
                view.placeholder.origin == reference.origin
                and view.placeholder.record_id == reference.id
            ):
                return view
    return None


def _collect_record_limitations(
    record_views: list[verifier.RecordView], limitations: list[str]
) -> None:
    """Add the record-derived limitation identifiers (same rule as a record target)."""
    for view in record_views:
        envelope = view.envelope
        limitations.extend(
            record_limitations(
                notices=view.notices,
                verdict=view.verdict or "unverifiable",
                kind_known=envelope.kind_known if envelope is not None else False,
                placeholder=view.placeholder is not None,
                has_labels=envelope is not None and envelope.labels is not None,
            )
        )
