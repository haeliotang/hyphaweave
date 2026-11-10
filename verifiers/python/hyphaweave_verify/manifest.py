# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0

"""Container manifest and manifest-attestation validation (spec §11.2/§11.3).

Structure is validated in the deterministic order of CONTRACT §14.6: the manifest
object is closed and typed (``E_MANIFEST_SCHEMA`` etc.), level completeness is
checked separately so the first failing check yields one primary code, and the
attestation file is validated as a closed object with ordered signatures and
timestamp listings.

The manifest digest binds the exact canonical manifest bytes; a trailing LF is
tolerated by the canonical-file rule but is **not** part of the digest.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from . import encoding, grammar, kinds
from .errors import WeaveError
from .refs import validate_origin
from .times import is_valid_timestamp

MAX_MANIFEST_BYTES = 4_194_304
MAX_SIGFILE_BYTES = 1_048_576
MAX_RECORDS = 100_000
MAX_MANIFEST_SIGS = 16
MAX_BLOBS = 10_000

MANIFEST_MEMBERS = (
    "format",
    "manifest_version",
    "origin",
    "created_at",
    "level",
    "records",
    "previous_manifest",
    "chain",
    "blobs",
)
MANIFEST_REQUIRED = (
    "format",
    "manifest_version",
    "origin",
    "created_at",
    "level",
    "records",
    "previous_manifest",
)
RECORD_ENTRY_MEMBERS = ("id", "kind", "digest", "chain_index")
ATTESTATION_MEMBERS = ("format", "digest", "signatures", "timestamps")
ATTESTATION_SIG_MEMBERS = ("alg", "key", "value")
TIMESTAMP_ENTRY_MEMBERS = ("digest", "path")
BLOB_ENTRY_MEMBERS = ("digest", "size")

LEVELS = ("L0", "L1", "L2")
TIMESTAMP_PATH_PATTERN = re.compile(r"^signatures/timestamp-[1-9][0-9]*\.tsr$")


@dataclass(frozen=True)
class ManifestRecordEntry:
    id: str
    kind: str
    digest: str
    chain_index: int | None


@dataclass(frozen=True)
class BlobEntry:
    digest: str
    size: int


@dataclass
class Manifest:
    raw: dict[str, Any]
    format: str
    manifest_version: int
    origin_project: str
    origin_instance: str
    created_at: str
    level: str
    records: tuple[ManifestRecordEntry, ...]
    previous_manifest_digest: str | None
    chain: dict[str, str] | None
    blobs: tuple[BlobEntry, ...]


@dataclass(frozen=True)
class ManifestSignature:
    alg: str
    key: str
    value: str
    raw: bytes


@dataclass(frozen=True)
class ListedTimestamp:
    digest: str
    path: str


@dataclass
class ManifestAttestation:
    raw: dict[str, Any]
    digest: str
    signatures: tuple[ManifestSignature, ...]
    timestamps: tuple[ListedTimestamp, ...]


# ---------------------------------------------------------------------------
# Manifest structure (CONTRACT §14.6 step 3)
# ---------------------------------------------------------------------------


def _fail(code: str, detail: str) -> None:
    raise WeaveError(code, detail)


def validate_manifest(value: Any) -> Manifest:
    """Validate the closed manifest object structure."""
    if not isinstance(value, dict):
        _fail("E_MANIFEST_SCHEMA", "manifest must be an object")
    for member in MANIFEST_REQUIRED:
        if member not in value:
            _fail("E_MANIFEST_SCHEMA", "manifest is missing required member %r" % member)
    for member in value:
        if member not in MANIFEST_MEMBERS:
            _fail("E_MANIFEST_SCHEMA", "unknown member in manifest object")

    if value["format"] != "weave-record/1":
        _fail("E_MANIFEST_FORMAT", "manifest.format is not weave-record/1")

    version = value["manifest_version"]
    if isinstance(version, bool) or not isinstance(version, int):
        _fail("E_MANIFEST_SCHEMA", "manifest_version must be an integer")
    if version != 1:
        _fail("E_MANIFEST_VERSION", "unsupported manifest version")

    try:
        origin = validate_origin(value["origin"])
    except WeaveError as error:
        raise WeaveError("E_MANIFEST_SCHEMA", "malformed manifest origin") from error

    if not is_valid_timestamp(value["created_at"]):
        _fail("E_MANIFEST_SCHEMA", "manifest.created_at is not a TS literal")

    level = value["level"]
    if level not in LEVELS:
        _fail("E_MANIFEST_LEVEL", "manifest.level is not L0/L1/L2")

    records_value = value["records"]
    if not isinstance(records_value, list) or not 1 <= len(records_value) <= MAX_RECORDS:
        _fail("E_MANIFEST_RECORDS", "manifest.records must be an array of 1-100000 entries")
    records: list[ManifestRecordEntry] = []
    for entry in records_value:
        if not isinstance(entry, dict):
            _fail("E_MANIFEST_RECORDS", "manifest.records entry must be an object")
        for member in entry:
            if member not in RECORD_ENTRY_MEMBERS:
                _fail("E_MANIFEST_RECORDS", "unknown member in manifest.records entry")
        if "id" not in entry or "kind" not in entry or "digest" not in entry:
            _fail("E_MANIFEST_RECORDS", "manifest.records entry is missing a member")
        if not grammar.is_valid_id(entry["id"]):
            _fail("E_MANIFEST_RECORDS", "manifest.records id is not a valid id")
        if not kinds.is_kind_syntax(entry["kind"]):
            _fail("E_MANIFEST_RECORDS", "manifest.records kind is not a kind name")
        if not encoding.is_supported_digest(entry["digest"]):
            _fail("E_MANIFEST_RECORDS", "manifest.records digest is not a supported sha256 digest")
        chain_index = entry.get("chain_index")
        if chain_index is not None and (
            isinstance(chain_index, bool)
            or not isinstance(chain_index, int)
            or chain_index < 0
        ):
            _fail("E_MANIFEST_RECORDS", "manifest.records chain_index is invalid")
        records.append(
            ManifestRecordEntry(
                id=entry["id"],
                kind=entry["kind"],
                digest=entry["digest"],
                chain_index=chain_index,
            )
        )
    for previous, current in zip(records, records[1:]):
        if previous.digest >= current.digest:
            _fail(
                "E_MANIFEST_RECORDS",
                "manifest.records must be sorted by digest ascending with unique digests",
            )

    previous_value = value["previous_manifest"]
    if previous_value is not None:
        if not isinstance(previous_value, dict):
            _fail("E_MANIFEST_SCHEMA", "previous_manifest must be null or an object")
        for member in previous_value:
            if member != "digest":
                _fail("E_MANIFEST_SCHEMA", "previous_manifest is a closed object")
        if "digest" not in previous_value or not encoding.is_supported_digest(
            previous_value["digest"]
        ):
            _fail("E_MANIFEST_SCHEMA", "previous_manifest.digest is not a supported digest")
        previous_digest: str | None = previous_value["digest"]
    else:
        previous_digest = None

    chain_value = value.get("chain")
    chain: dict[str, str] | None
    if chain_value is None:
        chain = None
    else:
        if not isinstance(chain_value, dict):
            _fail("E_MANIFEST_SCHEMA", "manifest.chain must be null or an object")
        for member in chain_value:
            if member not in ("algorithm", "head"):
                _fail("E_MANIFEST_SCHEMA", "manifest.chain is a closed object")
        if "algorithm" not in chain_value or "head" not in chain_value:
            _fail("E_MANIFEST_SCHEMA", "manifest.chain is missing a member")
        if chain_value["algorithm"] != "sha256":
            _fail("E_MANIFEST_SCHEMA", "manifest.chain.algorithm must be sha256")
        if not encoding.is_supported_digest(chain_value["head"]):
            _fail("E_MANIFEST_SCHEMA", "manifest.chain.head is not a supported digest")
        chain = {"algorithm": "sha256", "head": chain_value["head"]}

    blobs_value = value.get("blobs", [])
    if not isinstance(blobs_value, list):
        _fail("E_MANIFEST_SCHEMA", "manifest.blobs must be an array")
    if len(blobs_value) > MAX_BLOBS:
        _fail("E_MANIFEST_SCHEMA", "manifest.blobs has too many entries")
    blobs: list[BlobEntry] = []
    for blob in blobs_value:
        if not isinstance(blob, dict):
            _fail("E_MANIFEST_SCHEMA", "manifest.blobs entry must be an object")
        for member in blob:
            if member not in BLOB_ENTRY_MEMBERS:
                _fail("E_MANIFEST_SCHEMA", "unknown member in manifest.blobs entry")
        if "digest" not in blob or "size" not in blob:
            _fail("E_MANIFEST_SCHEMA", "manifest.blobs entry is missing a member")
        if not encoding.is_supported_digest(blob["digest"]):
            _fail("E_MANIFEST_SCHEMA", "manifest.blobs digest is not a supported digest")
        size = blob["size"]
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            _fail("E_MANIFEST_SCHEMA", "manifest.blobs size is invalid")
        blobs.append(BlobEntry(digest=blob["digest"], size=size))
    for previous, current in zip(blobs, blobs[1:]):
        if previous.digest >= current.digest:
            _fail(
                "E_MANIFEST_SCHEMA",
                "manifest.blobs must be sorted by digest ascending with unique digests",
            )

    return Manifest(
        raw=value,
        format="weave-record/1",
        manifest_version=version,
        origin_project=origin.project,
        origin_instance=origin.instance,
        created_at=value["created_at"],
        level=level,
        records=tuple(records),
        previous_manifest_digest=previous_digest,
        chain=chain,
        blobs=tuple(blobs),
    )


# ---------------------------------------------------------------------------
# Level completeness (CONTRACT §14.6 step 6)
# ---------------------------------------------------------------------------


def check_level_completeness(manifest: Manifest, timestamps_listed: int) -> None:
    """Check level/chain completeness and timestamp-listing consistency."""
    if manifest.level == "L0":
        if manifest.chain is not None:
            _fail("E_MANIFEST_LEVEL", "an L0 manifest must not carry a chain")
        if timestamps_listed:
            _fail("E_MANIFEST_LEVEL", "an L0 manifest must not list timestamps")
        return
    if manifest.chain is None:
        _fail("E_MANIFEST_L1_NO_HEAD", "an L1/L2 manifest requires chain")
    seen: set[int] = set()
    for entry in manifest.records:
        if entry.chain_index is None or entry.chain_index in seen:
            _fail(
                "E_MANIFEST_L1_NO_POSITION",
                "every L1/L2 record entry requires a unique chain_index",
            )
        seen.add(entry.chain_index)
    if manifest.level == "L2" and timestamps_listed == 0:
        _fail("E_MANIFEST_L2_NO_TIMESTAMP", "an L2 manifest must list a timestamp")


# ---------------------------------------------------------------------------
# Manifest attestation file (spec §11.3)
# ---------------------------------------------------------------------------


def validate_attestation(value: Any) -> ManifestAttestation:
    """Validate ``signatures/manifest.sig.json`` structure."""
    if not isinstance(value, dict):
        _fail("E_MANIFEST_SCHEMA", "manifest attestation must be an object")
    for member in ATTESTATION_MEMBERS:
        if member not in value:
            _fail("E_MANIFEST_SCHEMA", "manifest attestation is missing a member")
    for member in value:
        if member not in ATTESTATION_MEMBERS:
            _fail("E_MANIFEST_SCHEMA", "unknown member in manifest attestation")
    if value["format"] != "weave-record/1":
        _fail("E_MANIFEST_SCHEMA", "manifest attestation format is not weave-record/1")
    if not encoding.is_supported_digest(value["digest"]):
        _fail("E_MANIFEST_SCHEMA", "manifest attestation digest is not a supported digest")

    signatures_value = value["signatures"]
    if not isinstance(signatures_value, list) or len(signatures_value) > MAX_MANIFEST_SIGS:
        _fail("E_MANIFEST_SCHEMA", "manifest attestation signatures is not an array")
    signatures: list[ManifestSignature] = []
    for entry in signatures_value:
        if not isinstance(entry, dict):
            _fail("E_MANIFEST_SCHEMA", "manifest signature entry must be an object")
        for member in entry:
            if member not in ATTESTATION_SIG_MEMBERS:
                _fail("E_MANIFEST_SCHEMA", "unknown member in manifest signature entry")
        if "alg" not in entry or "key" not in entry or "value" not in entry:
            _fail("E_MANIFEST_SCHEMA", "manifest signature entry is missing a member")
        if entry["alg"] != "ed25519":
            _fail("E_MANIFEST_SCHEMA", "manifest signature alg must be ed25519")
        if not encoding.is_key_id(entry["key"]):
            _fail("E_MANIFEST_SCHEMA", "manifest signature key is not a key id")
        try:
            raw = encoding.decode_base64url(entry["value"], 64)
        except (ValueError, TypeError) as error:
            raise WeaveError(
                "E_MANIFEST_SCHEMA", "manifest signature value is not 64 base64url bytes"
            ) from error
        signatures.append(
            ManifestSignature(
                alg=entry["alg"], key=entry["key"], value=entry["value"], raw=raw
            )
        )
    for previous, current in zip(signatures, signatures[1:]):
        if not previous.key < current.key:
            _fail(
                "E_MANIFEST_SCHEMA",
                "manifest signatures must be sorted by key with unique keys",
            )

    timestamps_value = value["timestamps"]
    if not isinstance(timestamps_value, list):
        _fail("E_MANIFEST_SCHEMA", "manifest attestation timestamps is not an array")
    timestamps: list[ListedTimestamp] = []
    for entry in timestamps_value:
        if not isinstance(entry, dict):
            _fail("E_MANIFEST_SCHEMA", "timestamp listing entry must be an object")
        for member in entry:
            if member not in TIMESTAMP_ENTRY_MEMBERS:
                _fail("E_MANIFEST_SCHEMA", "unknown member in timestamp listing entry")
        if "digest" not in entry or "path" not in entry:
            _fail("E_MANIFEST_SCHEMA", "timestamp listing entry is missing a member")
        if not encoding.is_supported_digest(entry["digest"]):
            _fail("E_MANIFEST_SCHEMA", "timestamp listing digest is not a supported digest")
        if not isinstance(entry["path"], str) or TIMESTAMP_PATH_PATTERN.match(entry["path"]) is None:
            _fail("E_MANIFEST_SCHEMA", "timestamp listing path is not signatures/timestamp-<n>.tsr")
        timestamps.append(ListedTimestamp(digest=entry["digest"], path=entry["path"]))
    for previous, current in zip(timestamps, timestamps[1:]):
        if previous.path >= current.path:
            _fail("E_MANIFEST_SCHEMA", "timestamp listings must be sorted by path")

    return ManifestAttestation(
        raw=value,
        digest=value["digest"],
        signatures=tuple(signatures),
        timestamps=tuple(timestamps),
    )
