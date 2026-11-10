# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0

"""Container reading and verification (spec §11; CONTRACT §14.6 steps 1-12).

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
import io
import os
import re
import stat
import zipfile
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from . import canonical, encoding, kinds, manifest as manifest_module, refs, verifier
from .errors import CheckSkipper, WeaveError
from .report import (
    LIMITATION_ERASED_PLACEHOLDER,
    LIMITATION_LABELS_ARE_CLAIMS,
    LIMITATION_OFFLINE_CONTEXT,
    LIMITATION_PREVIOUS_SIG,
    LIMITATION_TOFU,
    LIMITATION_TSA_TRUST,
    LIMITATION_UNKNOWN_KIND,
    LIMITATION_CHAIN_CLAIM,
    container_verdict,
    record_entry,
    record_verdict,
)
from .timestamps import (
    STATE_INVALID,
    STATE_PRESENT_UNVERIFIED,
    STATE_VERIFIED,
    TimestampArchive,
    verify_timestamp_archive,
)
from . import keys as keys_module
from .keys import VerifiedTimestamp

MAX_CONTAINER_ENTRIES = 200_000
MAX_CONTAINER_UNCOMPRESSED_BYTES = 1_073_741_824
MAX_BLOB_BYTES = 1_073_741_824

CONTAINER_INPUT_DOMAIN = b"weave-container/1/input\n"

_RECORDS_FILE = re.compile(r"^records/([0-9a-f]{64})\.json$")
_BLOBS_FILE = re.compile(r"^blobs/sha256/([0-9a-f]{64})$")
_TIMESTAMP_FILE = re.compile(r"^signatures/timestamp-[1-9][0-9]*\.tsr$")
_TSA_CERT_FILE = re.compile(r"^signatures/tsa-cert-[1-9][0-9]*\.pem$")

ALLOWED_DIRECTORIES = frozenset(
    {"signatures", "records", "blobs", "blobs/sha256", "previous", "readable"}
)


@dataclass
class ContainerInput:
    """The raw container content tree plus its deterministic input identity."""

    files: dict[str, bytes]
    error: str | None = None
    input_sha256: str = "sha256:" + "0" * 64
    input_size: int = 0
    is_zip: bool = False
    readable_present: bool = False
    directory_entries: set[str] = field(default_factory=set)


# ---------------------------------------------------------------------------
# Reading the container
# ---------------------------------------------------------------------------


def read_container(path: Path) -> ContainerInput:
    """Read a directory or zip container within the resource limits.

    Returns the collected files (paths are POSIX-style relative paths) and the
    first structural error encountered, if any. Never raises for malformed
    input.
    """
    try:
        if not path.exists():
            return ContainerInput(files={}, error="E_MANIFEST_MISSING")
        if path.is_dir():
            return _read_directory_container(path)
        is_zip = path.is_file() and zipfile.is_zipfile(path)
    except Exception:
        # A path that cannot be classified/read is treated as a broken container.
        return ContainerInput(files={}, error="E_CONTAINER_ZIP")
    if is_zip:
        return _read_zip_container(path)
    return ContainerInput(files={}, error="E_CONTAINER_ZIP")


def _content_tree_identity(files: dict[str, bytes]) -> tuple[str, int]:
    digest = hashlib.sha256()
    digest.update(CONTAINER_INPUT_DOMAIN)
    size = 0
    for relative_path in sorted(files):
        data = files[relative_path]
        size += len(data)
        digest.update(relative_path.encode("utf-8", "surrogatepass"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(data).digest())
    return "sha256:" + digest.hexdigest(), size


def _read_directory_container(path: Path) -> ContainerInput:
    files: dict[str, bytes] = {}
    directory_entries: set[str] = set()
    error: str | None = None
    total = 0
    count = 0
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
            count += 1
            if count > MAX_CONTAINER_ENTRIES:
                error = error or "E_CONTAINER_SIZE"
                break
            file_path = root_path / filename
            relative_path = f"{relative_root}/{filename}" if relative_root else filename
            try:
                file_stat = file_path.lstat()
            except OSError:
                error = error or "E_CONTAINER_ENTRY"
                continue
            if stat.S_ISLNK(file_stat.st_mode) or not stat.S_ISREG(file_stat.st_mode):
                error = error or "E_CONTAINER_ENTRY"
                continue
            total += file_stat.st_size
            if total > MAX_CONTAINER_UNCOMPRESSED_BYTES:
                error = error or "E_CONTAINER_SIZE"
                break
            try:
                files[relative_path] = file_path.read_bytes()
            except OSError:
                error = error or "E_CONTAINER_ENTRY"
        if error == "E_CONTAINER_SIZE":
            break
    input_sha, input_size = _content_tree_identity(files)
    readable_present = any(name.startswith("readable/") or name == "readable" for name in directory_entries) or any(
        name.startswith("readable/") for name in files
    )
    return ContainerInput(
        files=files,
        error=error,
        input_sha256=input_sha,
        input_size=input_size,
        readable_present=readable_present,
        directory_entries=directory_entries,
    )


def _read_zip_container(path: Path) -> ContainerInput:
    """Read a zip container; every structural/decoder failure maps to E_CONTAINER_ZIP.

    A corrupted archive can fail in many ways below ``zipfile``: truncation
    (``BadZipFile``), unsupported compression/zip versions (``NotImplementedError``),
    corrupt deflate streams (``zlib.error``), impossible offsets (``ValueError``),
    or I/O errors. None of these may escape as a Python traceback: they are all
    malformed-input conditions reported as ``E_CONTAINER_ZIP`` (invalid).
    """
    try:
        raw = path.read_bytes()
    except OSError:
        return ContainerInput(files={}, error="E_CONTAINER_ZIP")
    input_sha = "sha256:" + hashlib.sha256(raw).hexdigest()
    try:
        return _process_zip_bytes(raw, input_sha)
    except (zipfile.BadZipFile, NotImplementedError, zlib.error, ValueError, EOFError, OSError, RuntimeError):
        return ContainerInput(
            files={},
            error="E_CONTAINER_ZIP",
            input_sha256=input_sha,
            input_size=len(raw),
            is_zip=True,
        )
    except Exception:  # pragma: no cover - defensive: malformed input must not crash
        return ContainerInput(
            files={},
            error="E_CONTAINER_ZIP",
            input_sha256=input_sha,
            input_size=len(raw),
            is_zip=True,
        )


def _process_zip_bytes(raw: bytes, input_sha: str) -> ContainerInput:
    """Parse an archive whose bytes were already read (exceptions are mapped above)."""
    files: dict[str, bytes] = {}
    directory_entries: set[str] = set()
    error: str | None = None
    archive = zipfile.ZipFile(io.BytesIO(raw))
    with archive:
        try:
            infos = archive.infolist()
        except (zipfile.BadZipFile, ValueError, NotImplementedError, zlib.error):
            return ContainerInput(
                files={}, error="E_CONTAINER_ZIP", input_sha256=input_sha,
                input_size=len(raw), is_zip=True,
            )
        if len(infos) > MAX_CONTAINER_ENTRIES:
            error = "E_CONTAINER_SIZE"
            infos = infos[:0]
        declared_total = sum(info.file_size for info in infos)
        if declared_total > MAX_CONTAINER_UNCOMPRESSED_BYTES and error is None:
            error = "E_CONTAINER_SIZE"
            infos = infos[:0]
        for info in infos:
            name = info.filename
            if name.endswith("/"):
                directory_entries.add(name.rstrip("/"))
                continue
            unix_mode = info.external_attr >> 16
            if stat.S_ISLNK(unix_mode):
                error = error or "E_CONTAINER_ENTRY"
                continue
            if info.flag_bits & 0x1:
                error = error or "E_CONTAINER_ZIP"
                continue
            if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                error = error or "E_CONTAINER_ZIP"
                continue
            if not _is_safe_relative_path(name):
                error = error or "E_CONTAINER_ENTRY"
                continue
            if name in files:
                error = error or "E_CONTAINER_ENTRY"
                continue
            if info.file_size > MAX_CONTAINER_UNCOMPRESSED_BYTES:
                error = error or "E_CONTAINER_SIZE"
                continue
            try:
                data = archive.read(info)
            except (
                zipfile.BadZipFile,
                NotImplementedError,
                zlib.error,
                ValueError,
                EOFError,
                OSError,
                RuntimeError,
            ):
                error = error or "E_CONTAINER_ZIP"
                continue
            if len(data) > MAX_CONTAINER_UNCOMPRESSED_BYTES:
                error = error or "E_CONTAINER_SIZE"
                continue
            files[name] = data
    readable_present = any(
        name == "readable" or name.startswith("readable/") for name in directory_entries
    ) or any(name.startswith("readable/") for name in files)
    return ContainerInput(
        files=files,
        error=error,
        input_sha256=input_sha,
        input_size=len(raw),
        is_zip=True,
        readable_present=readable_present,
        directory_entries=directory_entries,
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
# Layout validation (CONTRACT §14.6 step 1)
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
        if _TIMESTAMP_FILE.match(relative_path):
            continue
        if _TSA_CERT_FILE.match(relative_path):
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
) -> dict[str, bytes]:
    """Keys usable for manifest-signature verification before record verdicts exist.

    Keys come from (a) the externally supplied keyset (already verified), and
    (b) structurally valid key-lifecycle records inside the container itself.
    A record's *validity* can only be established later, but the manifest
    signature is checked at step 5, so only key material whose key-id derivation
    matches its declared public key is used.
    """
    candidates: dict[str, bytes] = {}
    keyset_context = verifier.Context()
    for view in keyset_views:
        keyset_context.register(view)
    keyset_context.rebuild()
    for key_id, declaration in keyset_context.key_state.declarations.items():
        candidates[key_id] = declaration.public_key
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
    return candidates


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
    container_input = read_container(path)
    container: dict[str, Any] = _empty_container_report()
    errors: list[str] = []
    notices: list[str] = []
    limitations: list[str] = [LIMITATION_OFFLINE_CONTEXT]
    record_views: list[verifier.RecordView] = []
    limitations_iter = limitations

    # Step 1: entry enumeration and layout safety.
    if container_input.error is not None:
        errors.append(container_input.error)
        return _finish_container(
            container_input, container, errors, notices, [], limitations_iter, active_skipper
        )
    try:
        _validate_layout(container_input)
    except WeaveError as error:
        errors.append(error.code)
        return _finish_container(
            container_input, container, errors, notices, [], limitations_iter, active_skipper
        )
    if "manifest.json" not in container_input.files:
        errors.append("E_MANIFEST_MISSING")
        return _finish_container(
            container_input, container, errors, notices, [], limitations_iter, active_skipper
        )

    # Step 2-3: manifest canonical bytes and structure.
    manifest_bytes = container_input.files["manifest.json"]
    # The report's input identity follows CONTRACT §14.2/spec §14.6: a directory
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
        return _finish_container(
            container_input, container, errors, notices, [], limitations_iter, active_skipper
        )
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
        manifest_signature_keys = _verify_manifest_signatures(
            attestation.signatures,
            manifest_digest,
            _candidate_manifest_keys(
                _load_container_records(container_input).records, keyset_verified
            ),
        )
    except WeaveError as error:
        errors.append(error.code)
        return _finish_container(
            container_input, container, errors, notices, [], limitations_iter, active_skipper
        )

    # Step 6: level/chain completeness.
    try:
        manifest_module.check_level_completeness(manifest, len(attestation.timestamps))
    except WeaveError as error:
        errors.append(error.code)
        return _finish_container(
            container_input, container, errors, notices, [], limitations_iter, active_skipper
        )
    if manifest.chain is not None:
        container["chain"] = {"status": "unverified"}
        notices.append("N_CHAIN_CLAIM_UNVERIFIED")
        limitations.append(LIMITATION_CHAIN_CLAIM)

    # Step 7: record listing consistency.
    listing = _load_container_records(container_input)
    try:
        _check_records_listing(manifest, listing, container_input)
    except WeaveError as error:
        errors.append(error.code)
        return _finish_container(
            container_input, container, errors, notices, [], limitations_iter, active_skipper
        )
    loaded_records = listing.records

    # Step 11 is computed before per-record verification: a verified L2
    # timestamp can rescue a key-compromise signature (S2). The *reported*
    # timestamp errors are still appended after the record pass, so the
    # deterministic container check order is unchanged.
    trust_fingerprints = None
    if tsa_trust is not None:
        from .timestamps import parse_trust_anchors

        try:
            trust_fingerprints = parse_trust_anchors(tsa_trust)
        except WeaveError:
            trust_fingerprints = frozenset()
    archive = verify_timestamp_archive(
        listed=[
            {"path": entry.path, "digest": entry.digest, "renews": entry.renews}
            for entry in attestation.timestamps
        ],
        files=container_input.files,
        manifest_digest=manifest_digest,
        trust_anchor_fingerprints=trust_fingerprints,
    )
    container["timestamps"] = [
        result.to_report(index) for index, result in enumerate(archive.results)
    ]
    container["anchor_verified"] = bool(
        manifest.level == "L2" and archive.anchor_verified
    )
    if manifest.level == "L2" and not archive.anchor_verified:
        limitations.append(LIMITATION_TSA_TRUST)
    earliest_verified = archive.earliest_verified_gen_time_ms
    verified_timestamps: tuple[VerifiedTimestamp, ...] = ()
    if earliest_verified is not None:
        earliest_result = next(
            result
            for result in archive.results
            if result.gen_time_ms == earliest_verified
        )
        verified_timestamps = (
            VerifiedTimestamp(
                gen_time=earliest_result.gen_time or "",
                gen_time_ms=earliest_verified,
            ),
        )
    # S2 for the manifest signature: judge it with the manifest timestamp chain.
    try:
        _check_manifest_signer_effects(
            manifest_signature_keys,
            _candidate_key_state(
                _load_container_records(container_input).records, keyset_verified
            ),
            manifest.created_at,
            verified_timestamps,
        )
    except WeaveError as error:
        errors.append(error.code)
        return _finish_container(
            container_input, container, errors, notices, [], limitations_iter, active_skipper
        )

    # Step 7 (continued): per-record verification.
    record_views = verifier.verify_record_set(
        loaded_records,
        verified_timestamps=verified_timestamps,
        context_views=keyset_verified,
    )

    # Step 8: cross-record state rules.
    container_errors_from_state, state_notices = _cross_record_checks(record_views)
    if container_errors_from_state:
        errors.extend(container_errors_from_state)
    notices.extend(state_notices)

    # Step 9: blobs.
    try:
        _check_blobs(manifest, container_input)
    except WeaveError as error:
        errors.append(error.code)

    # Step 10: previous manifest chain.
    try:
        _check_previous_manifest(
            manifest, container_input, previous_container
        )
    except WeaveError as error:
        errors.append(error.code)
    if manifest.previous_manifest_digest is not None:
        notices.append("N_PREVIOUS_SIG_UNVERIFIED")
        limitations.append(LIMITATION_PREVIOUS_SIG)

    # Step 11: reported timestamp errors (verification was computed early for
    # the compromise rescue; the deterministic report order is kept here).
    for error_code in archive.errors:
        if error_code not in errors:
            errors.append(error_code)

    # Deterministic informational notices.
    if container_input.readable_present:
        notices.append("N_READABLE_PRESENT")

    # Record-level limitations that apply to what was seen.
    _collect_record_limitations(record_views, limitations)
    return _finish_container(
        container_input, container, errors, notices, record_views, limitations, active_skipper
    )


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
) -> ContainerVerification:
    """Assemble the container report and verdict."""
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
        "limitations": _dedupe(limitations),
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
        kind_known = False
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
) -> None:
    """Apply key lifecycle effects to manifest signatures (S2, Q20, M-2)."""
    for key in signer_keys:
        key_state.check_signature_effects(
            key, created_at, verified_timestamps=verified_timestamps
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
        if not _RECORDS_FILE.match(relative_path):
            continue
        raw = container_input.files[relative_path]
        try:
            record = verifier.load_record_bytes(raw, source="container")
        except WeaveError:
            record = verifier.LoadedRecord(
                raw=raw, value=None, digest=None, source="container"
            )
        record.container_path = relative_path
        records.append(record)
        by_path[relative_path] = record
    return _RecordListing(records=records, by_path=by_path)


def _check_records_listing(
    manifest: manifest_module.Manifest, listing: _RecordListing, container_input: ContainerInput
) -> None:
    """Check records/ contents against the manifest (spec §11.5)."""
    listed = {entry.digest: entry for entry in manifest.records}
    listed_hex = {entry.digest.partition(":")[2] for entry in manifest.records}
    for relative_path, record in sorted(listing.by_path.items()):
        match = _RECORDS_FILE.match(relative_path)
        if match is None:
            raise WeaveError("E_MANIFEST_RECORD_EXTRA", "malformed records/ file name")
        if match.group(1) not in listed_hex:
            raise WeaveError(
                "E_MANIFEST_RECORD_EXTRA", "records/ contains a file not listed in the manifest"
            )
        if record.value is None or record.digest is None:
            raise WeaveError("E_MANIFEST_RECORD_DIGEST", "record file is not canonical JSON")
        if match.group(1) != record.digest.partition(":")[2]:
            raise WeaveError(
                "E_MANIFEST_RECORD_DIGEST",
                "record digest does not match its file name",
            )
        if listed[record.digest].digest != record.digest:  # pragma: no cover - lookup by key
            raise WeaveError(
                "E_MANIFEST_RECORD_DIGEST",
                "record digest does not match the manifest entry",
            )
        # The manifest entry's id/kind must equal the record's own id/kind
        # (spec §11.2.1/§11.6, Q22): a tampered entry that keeps the digest but
        # relabels the record is a manifest consistency error.
        record_entry = listed[record.digest]
        value = record.value
        if not isinstance(value, dict):
            raise WeaveError("E_MANIFEST_RECORD_DIGEST", "record file is not an object")
        record_id = value.get("id")
        record_kind = value.get("kind")
        if record_entry.id != record_id or record_entry.kind != record_kind:
            raise WeaveError(
                "E_MANIFEST_RECORDS",
                "manifest entry id/kind does not match the record file",
            )
    for entry in manifest.records:
        expected_path = "records/%s.json" % entry.digest.partition(":")[2]
        if expected_path not in listing.by_path:
            raise WeaveError("E_MANIFEST_RECORD_MISSING", "a listed record file is missing")


# ---------------------------------------------------------------------------
# Blobs, chain, timestamps
# ---------------------------------------------------------------------------


def _check_blobs(manifest: manifest_module.Manifest, container_input: ContainerInput) -> None:
    blob_files = {
        relative_path: data
        for relative_path, data in container_input.files.items()
        if relative_path.startswith("blobs/")
    }
    listed = {blob.digest: blob for blob in manifest.blobs}
    if not listed:
        if blob_files or "blobs" in container_input.directory_entries:
            raise WeaveError("E_MANIFEST_BLOB", "blobs directory present without listed blobs")
        return
    for digest, blob in listed.items():
        expected_path = "blobs/sha256/%s" % digest.partition(":")[2]
        data = blob_files.pop(expected_path, None)
        if data is None:
            raise WeaveError("E_MANIFEST_BLOB", "a listed blob file is missing")
        if len(data) != blob.size:
            raise WeaveError("E_MANIFEST_BLOB", "blob size does not match the manifest")
        if len(data) > MAX_BLOB_BYTES:
            raise WeaveError("E_CONTAINER_SIZE", "blob exceeds the size limit")
        if "sha256:" + hashlib.sha256(data).hexdigest() != digest:
            raise WeaveError("E_MANIFEST_BLOB", "blob digest does not match the manifest")
    if blob_files:
        raise WeaveError("E_MANIFEST_BLOB", "blobs/ contains a file not listed in the manifest")


def _check_previous_manifest(
    manifest: manifest_module.Manifest,
    container_input: ContainerInput,
    previous_container: Path | None,
) -> None:
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
    if previous_container is not None:
        try:
            supplied = _read_previous_manifest_digest(previous_container)
        except WeaveError:
            raise
        except Exception as error:  # pragma: no cover - defensive
            raise WeaveError(
                "E_MANIFEST_CHAIN", "--previous container is unreadable"
            ) from error
        if supplied != manifest.previous_manifest_digest:
            raise WeaveError(
                "E_MANIFEST_CHAIN", "--previous manifest digest does not match"
            )


def _read_previous_manifest_digest(previous_container: Path) -> str:
    if not previous_container.exists():
        raise WeaveError("E_MANIFEST_CHAIN", "--previous container does not exist")
    if previous_container.is_dir():
        manifest_path = previous_container / "manifest.json"
    elif zipfile.is_zipfile(previous_container):
        try:
            with zipfile.ZipFile(previous_container) as archive:
                data = archive.read("manifest.json")
        except (
            KeyError,
            zipfile.BadZipFile,
            NotImplementedError,
            zlib.error,
            ValueError,
            EOFError,
            OSError,
            RuntimeError,
        ) as error:
            raise WeaveError("E_MANIFEST_CHAIN", "--previous container is unreadable") from error
        manifest_path = None
    else:
        manifest_path = previous_container
    if manifest_path is not None:
        try:
            data = manifest_path.read_bytes()
        except OSError as error:
            raise WeaveError("E_MANIFEST_CHAIN", "--previous container is unreadable") from error
    try:
        value = canonical.parse_file_bytes(
            data, max_bytes=manifest_module.MAX_MANIFEST_BYTES, require_object=True
        )
    except WeaveError as error:
        raise WeaveError("E_MANIFEST_CHAIN", "--previous manifest is malformed") from error
    if not isinstance(value, dict):
        raise WeaveError("E_MANIFEST_CHAIN", "--previous manifest is malformed")
    return encoding.manifest_digest(canonical.canonicalize(value))


# ---------------------------------------------------------------------------
# Cross-record state rules (CONTRACT §14.6 step 8)
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
        erase_error = _erasure_cross_checks(record_views)
        if erase_error is not None:
            errors.append(erase_error)
    return errors, notices


def _erasure_cross_checks(record_views: list[verifier.RecordView]) -> str | None:
    from .erase import looks_like_placeholder

    placeholders = [view for view in record_views if view.placeholder is not None]
    erasures = [
        view
        for view in record_views
        if view.envelope is not None and view.envelope.kind == kinds.KIND_ERASURE
    ]
    # Deterministic order: placeholders and erasures are already in manifest order.
    for erasure in erasures:
        body = erasure.envelope.body  # type: ignore[union-attr]
        reference = refs.validate_reference(body["erased"])
        matching = [
            placeholder
            for placeholder in placeholders
            if placeholder.placeholder is not None
            and placeholder.placeholder.origin == reference.origin
            and placeholder.placeholder.record_id == reference.id
        ]
        if not matching:
            return "E_ERASE_DIGEST_MISMATCH"
        placeholder = matching[0].placeholder
        assert placeholder is not None
        if placeholder.digest != reference.digest:
            return "E_ERASE_DIGEST_MISMATCH"
        # The placeholder's attestation must resolve back to this erasure record.
        attestation_reference = placeholder.attestation
        target_matches = (
            erasure.digest is not None
            and attestation_reference.digest == erasure.digest
            and attestation_reference.origin == erasure.envelope.origin  # type: ignore[union-attr]
            and attestation_reference.id == erasure.envelope.record_id  # type: ignore[union-attr]
        )
        if not target_matches:
            return "E_ERASE_ATTESTATION"
    for placeholder_view in placeholders:
        placeholder = placeholder_view.placeholder
        assert placeholder is not None
        resolved = _find_view(record_views, placeholder.attestation)
        if resolved is None or resolved.envelope is None:
            return "E_ERASE_ATTESTATION"
        if resolved.envelope.kind != kinds.KIND_ERASURE:
            return "E_ERASE_ATTESTATION"
        if resolved.digest != placeholder.attestation.digest:
            return "E_ERASE_ATTESTATION"
        if resolved.envelope.body.get("erased", {}).get("digest") != placeholder.digest:
            return "E_ERASE_DIGEST_MISMATCH"
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
                return "E_ERASE_CONTRADICTION"
    origin_ids = [
        (placeholder_view.placeholder.origin, placeholder_view.placeholder.record_id)
        for placeholder_view in placeholders
        if placeholder_view.placeholder is not None
    ]
    if len(origin_ids) != len(set(origin_ids)):
        return "E_ERASE_CONTRADICTION"
    return None


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
    if any(view.notices and "N_KEY_TOFU" in view.notices for view in record_views):
        limitations.append(LIMITATION_TOFU)
    if any(view.envelope is not None and not view.envelope.kind_known for view in record_views):
        limitations.append(LIMITATION_UNKNOWN_KIND)
    if any(view.placeholder is not None for view in record_views):
        limitations.append(LIMITATION_ERASED_PLACEHOLDER)
        limitations.append(LIMITATION_LABELS_ARE_CLAIMS)
    if any(
        view.envelope is not None and view.envelope.labels is not None for view in record_views
    ):
        limitations.append(LIMITATION_LABELS_ARE_CLAIMS)
