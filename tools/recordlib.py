#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0

"""Record and container construction helpers for the conformance vectors.

This module is part of the *independent* vector-generation tooling: it builds
``weave-record/1`` envelopes, record digests, signatures and container
directory file maps from the contract text, using :mod:`wcj` (own WR-CJ) and
:mod:`keyutil` (own base64url/key-id helpers over ``cryptography``).  It never
imports the reference verifier.

The files produced for a container are returned as a mapping of POSIX relative
path -> bytes so that negative cases can tamper with individual entries before
the case directory is written by ``tools/gen_vectors.py``.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path
from typing import Any, Callable, Iterable, Sequence

_TOOLS_DIR = Path(__file__).resolve().parent
if str(_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOLS_DIR))

import keyutil
import wcj

REPO_ROOT = _TOOLS_DIR.parent
KEYS_DIR = REPO_ROOT / "vectors" / "keys"

# The examples in the specification use the project slug "example"; all test
# data is synthetic (CONTRACT §0).
PROJECT = "example"
FORMAT = "weave-record/1"

# Fixed timestamps used across the vectors (no wall clock anywhere).
T0 = "2026-11-01T00:00:00.000Z"
T1 = "2026-11-02T03:04:05.678Z"
T2 = "2026-11-03T06:07:08.900Z"
T3 = "2026-11-04T09:10:11.012Z"
T4 = "2026-11-05T12:13:14.015Z"
T5 = "2026-11-06T15:16:17.018Z"
T6 = "2026-11-07T18:19:20.021Z"
T7 = "2026-11-08T21:22:23.024Z"
T8 = "2026-11-09T01:02:03.045Z"
T9 = "2026-11-10T04:05:06.078Z"
EARLY = "2025-01-01T00:00:00.000Z"
LATE = "2099-12-31T23:59:59.999Z"
MAX_TS = "9999-12-31T23:59:59.999Z"
MIN_TS = "0000-01-01T00:00:00.000Z"

_KEY_CACHE: dict[str, keyutil.KeyMaterial] = {}


def key(name: str) -> keyutil.KeyMaterial:
    """Load (and cache) one synthetic test key by name."""
    if name not in _KEY_CACHE:
        _KEY_CACHE[name] = keyutil.load_key(KEYS_DIR, name)
    return _KEY_CACHE[name]


def kid(name: str) -> str:
    """Key id of one synthetic test key by name."""
    return key(name).key_id


def ktype(name: str) -> str:
    """Declared key class of one synthetic test key by name."""
    return key(name).key_type


# ---------------------------------------------------------------------------
# Payload builders
# ---------------------------------------------------------------------------


def origin(instance: str, project: str = PROJECT) -> dict[str, str]:
    return {"project": project, "instance": instance}


def make_ref(
    origin_instance: str,
    record_id: str,
    digest: str,
    *,
    kind: str | None = None,
    hints: list[str] | None = None,
    project: str = PROJECT,
) -> dict[str, Any]:
    value: dict[str, Any] = {
        "origin": origin(origin_instance, project),
        "id": record_id,
        "digest": digest,
    }
    if kind is not None:
        value["kind"] = kind
    if hints is not None:
        value["hints"] = hints
    return value


def actor(
    key_name: str,
    *,
    actor_type: str | None = None,
    model: str | None = None,
    on_behalf_of: str | None = None,
    grant: dict[str, Any] | None = None,
    idempotency_key: str | None = None,
) -> dict[str, Any]:
    value: dict[str, Any] = {
        "type": actor_type if actor_type is not None else ktype(key_name),
        "key": kid(key_name),
    }
    if model is not None:
        value["model"] = model
    if on_behalf_of is not None:
        value["on_behalf_of"] = on_behalf_of
    if grant is not None:
        value["grant"] = grant
    if idempotency_key is not None:
        value["idempotency_key"] = idempotency_key
    return value


def agent_actor(
    key_name: str = "agent-1",
    *,
    model: str = "example/model@1.2.3",
    on_behalf_of: str | None = None,
    grant: dict[str, Any] | None = None,
    idempotency_key: str = "idem-1",
) -> dict[str, Any]:
    return actor(
        key_name,
        model=model,
        on_behalf_of=on_behalf_of if on_behalf_of is not None else kid("human-1"),
        grant=grant,
        idempotency_key=idempotency_key,
    )


def build_record(
    *,
    kind: str,
    id: str,
    actor: dict[str, Any],
    body: dict[str, Any] | None = None,
    stage: str = "proposed",
    recorded_at: str = T0,
    occurred_at: str | None = None,
    refs: list[dict[str, Any]] | None = None,
    labels: dict[str, Any] | None = None,
    salt: str | None = None,
    origin_project: str = PROJECT,
    origin_instance: str | None = None,
) -> dict[str, Any]:
    """Build one normal record envelope (without ``sigs``)."""
    value: dict[str, Any] = {
        "format": FORMAT,
        "kind": kind,
        "origin": origin(
            origin_instance if origin_instance is not None else actor["key"],
            origin_project,
        ),
        "id": id,
        "stage": stage,
        "actor": actor,
        "recorded_at": recorded_at,
    }
    if occurred_at is not None:
        value["occurred_at"] = occurred_at
    if refs is not None:
        value["refs"] = refs
    if labels is not None:
        value["labels"] = labels
    if salt is not None:
        value["salt"] = salt
    value["body"] = body if body is not None else {}
    return value


def note(
    record_id: str,
    *,
    text: str = "synthetic test note",
    key_name: str = "human-1",
    stage: str = "proposed",
    recorded_at: str = T0,
    kind: str = "example.note",
    body: dict[str, Any] | None = None,
    actor_value: dict[str, Any] | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    """A small synthetic record of the unregistered kind ``example.note``.

    ``actor_value`` overrides the default actor derived from ``key_name``.
    """
    payload = {"text": text}
    if body:
        payload.update(body)
    return build_record(
        kind=kind,
        id=record_id,
        actor=actor_value if actor_value is not None else actor(key_name),
        body=payload,
        stage=stage,
        recorded_at=recorded_at,
        **kwargs,
    )


# ---------------------------------------------------------------------------
# Digests and signatures (independent construction)
# ---------------------------------------------------------------------------


def record_digest(record: dict[str, Any]) -> str:
    """Record digest per CONTRACT §3.1 (JCS of the record without ``sigs``)."""
    without_sigs = {name: value for name, value in record.items() if name != "sigs"}
    canonical = wcj.canonicalize(without_sigs)
    return wcj.sha256_digest(keyutil.DIGEST_DOMAIN + canonical)


def sig_message(record_or_digest: dict[str, Any] | str) -> bytes:
    digest = (
        record_or_digest
        if isinstance(record_or_digest, str)
        else record_digest(record_or_digest)
    )
    return keyutil.SIG_DOMAIN + digest.encode("ascii")


def sig_entry(record: dict[str, Any], key_name: str) -> dict[str, str]:
    material = key(key_name)
    value = material.sign(sig_message(record))
    return {"alg": "ed25519", "key": material.key_id, "value": keyutil.b64url_encode(value)}


def signed(record: dict[str, Any], key_names: str | Sequence[str]) -> dict[str, Any]:
    """Return a copy of *record* with sorted ``sigs`` from the given keys."""
    names = [key_names] if isinstance(key_names, str) else list(key_names)
    entries = [sig_entry(record, name) for name in names]
    entries.sort(key=lambda entry: entry["key"])
    result = dict(record)
    result["sigs"] = entries
    return result


def sig_message_for_manifest(manifest_digest_value: str) -> bytes:
    return keyutil.MANIFEST_DOMAIN + manifest_digest_value.encode("ascii")


def manifest_digest(manifest_bytes: bytes) -> str:
    """Manifest digest per CONTRACT §3.3 over canonical file bytes."""
    value = wcj.parse_strict(manifest_bytes)
    return wcj.sha256_digest(
        keyutil.MANIFEST_DIGEST_DOMAIN + wcj.canonicalize(value)
    )


# ---------------------------------------------------------------------------
# Container construction
# ---------------------------------------------------------------------------


def canonical_file(value: Any) -> bytes:
    """Canonical file bytes: WR-CJ bytes plus exactly one trailing LF."""
    return wcj.dump_canonical_file(value, trailing_lf=True)


def blob_digest(data: bytes) -> str:
    return wcj.sha256_digest(data)


def _record_entries(
    records: Sequence[dict[str, Any]],
    chain_indices: Sequence[int] | None,
) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, record in enumerate(records):
        digest = record_digest(record)
        if digest in seen:
            raise ValueError("duplicate record digest in manifest: %s" % digest)
        seen.add(digest)
        entry: dict[str, Any] = {
            "id": record["id"],
            "kind": record["kind"],
            "digest": digest,
        }
        if chain_indices is not None:
            entry["chain_index"] = chain_indices[index]
        entries.append(entry)
    entries.sort(key=lambda entry: entry["digest"])
    return entries


def default_chain_head(records: Sequence[dict[str, Any]]) -> str:
    """A deterministic internal-chain-head *claim* for L1/L2 containers.

    The head cannot be recomputed by an offline verifier (CONTRACT §11.2); any
    syntactically valid digest string works.  We derive one that changes with
    the record set so the vector reads naturally.
    """
    material = b"".join(
        record_digest(record).encode("ascii") + b"\n" for record in records
    )
    return wcj.sha256_digest(b"example/chain\n" + material)


def build_manifest(
    records: Sequence[dict[str, Any]],
    *,
    level: str = "L0",
    created_at: str = T0,
    origin_value: dict[str, Any] | None = None,
    previous_manifest: dict[str, Any] | None = None,
    chain: dict[str, Any] | None = None,
    chain_indices: Sequence[int] | None = None,
    blobs: Sequence[tuple[bytes, bytes]] | None = None,
) -> dict[str, Any]:
    """Build a manifest value (without digest, which lives in the sig file)."""
    if origin_value is None:
        origin_value = origin(kid("human-1"))
    manifest: dict[str, Any] = {
        "format": FORMAT,
        "manifest_version": 1,
        "origin": origin_value,
        "created_at": created_at,
        "level": level,
        "records": _record_entries(records, chain_indices),
        "previous_manifest": previous_manifest,
    }
    if chain is not None:
        manifest["chain"] = chain
    if blobs:
        entries = []
        for data, _size in blobs:
            entries.append({"digest": blob_digest(data), "size": len(data)})
        entries.sort(key=lambda entry: entry["digest"])
        if len({entry["digest"] for entry in entries}) != len(entries):
            raise ValueError("duplicate blob digest")
        manifest["blobs"] = entries
    return manifest


def manifest_sigfile(
    manifest_digest_value: str,
    signer_names: Sequence[str] = ("human-1",),
    timestamp_files: dict[str, bytes] | None = None,
) -> dict[str, Any]:
    """Build ``signatures/manifest.sig.json`` for a manifest digest."""
    entries = []
    for name in signer_names:
        material = key(name)
        signature = material.sign(sig_message_for_manifest(manifest_digest_value))
        entries.append(
            {
                "alg": "ed25519",
                "key": material.key_id,
                "value": keyutil.b64url_encode(signature),
            }
        )
    entries.sort(key=lambda entry: entry["key"])
    timestamps = []
    for path in sorted(timestamp_files or {}):
        timestamps.append(
            {"digest": wcj.sha256_digest(timestamp_files[path]), "path": path}
        )
    return {
        "digest": manifest_digest_value,
        "format": FORMAT,
        "signatures": entries,
        "timestamps": timestamps,
    }


def seal_container(
    files: dict[str, bytes],
    manifest_value: dict[str, Any],
    *,
    manifest_signers: Sequence[str] = ("human-1",),
    timestamp_files: dict[str, bytes] | None = None,
) -> dict[str, bytes]:
    """Write/replace ``manifest.json`` and ``signatures/manifest.sig.json``.

    ``timestamp_files`` maps relative paths (``signatures/timestamp-N.tsr``)
    to their exact bytes; those files are added to *files*.  Any previously
    present timestamp entries are removed.
    """
    manifest_bytes = canonical_file(manifest_value)
    files["manifest.json"] = manifest_bytes
    for path in [p for p in files if p.startswith("signatures/timestamp-")]:
        del files[path]
    for path, data in (timestamp_files or {}).items():
        files[path] = data
    digest = manifest_digest(manifest_bytes)
    sigfile = manifest_sigfile(digest, manifest_signers, timestamp_files)
    files["signatures/manifest.sig.json"] = canonical_file(sigfile)
    return files


def build_container(
    records: Sequence[dict[str, Any]],
    *,
    level: str = "L0",
    created_at: str = T0,
    manifest_signers: Sequence[str] = ("human-1",),
    origin_value: dict[str, Any] | None = None,
    previous_manifest_bytes: bytes | None = None,
    previous_manifest: dict[str, Any] | None = None,
    chain_head: str | None = None,
    chain_indices: Sequence[int] | None = None,
    blobs: Sequence[tuple[bytes, bytes]] | None = None,
    timestamp_files: dict[str, bytes] | None = None,
    extra_files: dict[str, bytes] | None = None,
) -> dict[str, bytes]:
    """Build the full relative-path -> bytes mapping of one container.

    ``previous_manifest`` is stored in ``manifest.previous_manifest``; when it
    is non-null the caller must also pass ``previous_manifest_bytes`` which is
    written to ``previous/manifest.json`` (and must hash to the digest).
    """
    files: dict[str, bytes] = {}
    for record in records:
        digest = record_digest(record)
        files["records/%s.json" % digest[len("sha256:") :]] = canonical_file(record)

    chain: dict[str, Any] | None = None
    if level in ("L1", "L2"):
        head = chain_head if chain_head is not None else default_chain_head(records)
        chain = {"algorithm": "sha256", "head": head}
        if chain_indices is None:
            chain_indices = list(range(len(records)))
    manifest = build_manifest(
        records,
        level=level,
        created_at=created_at,
        origin_value=origin_value,
        previous_manifest=previous_manifest,
        chain=chain,
        chain_indices=chain_indices,
        blobs=blobs,
    )
    if blobs:
        for data, _size in blobs:
            files["blobs/sha256/%s" % blob_digest(data)[len("sha256:") :]] = data
    if previous_manifest is not None:
        if previous_manifest_bytes is None:
            raise ValueError(
                "previous_manifest_bytes is required when previous_manifest is set"
            )
        files["previous/manifest.json"] = previous_manifest_bytes
    seal_container(
        files,
        manifest,
        manifest_signers=manifest_signers,
        timestamp_files=timestamp_files,
    )
    if extra_files:
        files.update(extra_files)
    return files


def previous_entry(previous_manifest_bytes: bytes) -> dict[str, Any]:
    """The ``previous_manifest`` member value for *previous_manifest_bytes*."""
    return {"digest": manifest_digest(previous_manifest_bytes)}


def replace_bytes(files: dict[str, bytes], path: str, data: bytes) -> None:
    files[path] = data


# ---------------------------------------------------------------------------
# Mutation helpers for negative container cases
# ---------------------------------------------------------------------------

ManifestMutator = Callable[[dict[str, Any]], dict[str, Any]]


def mutate_manifest(
    files: dict[str, bytes],
    mutator: ManifestMutator,
    *,
    resign_with: Sequence[str] | None = ("human-1",),
) -> dict[str, bytes]:
    """Apply *mutator* to the manifest, optionally re-sealing the sig file.

    With ``resign_with=None`` the original signature file is left untouched,
    which produces a manifest-digest mismatch (E_MANIFEST_DIGEST).
    """
    current = wcj.parse_strict(files["manifest.json"])
    mutated = mutator(current)
    manifest_bytes = canonical_file(mutated)
    files["manifest.json"] = manifest_bytes
    if resign_with is not None:
        timestamp_files = {
            path: files[path]
            for path in files
            if path.startswith("signatures/timestamp-")
        }
        seal_container(
            files,
            mutated,
            manifest_signers=resign_with,
            timestamp_files=timestamp_files,
        )
    return files


def mutate_sigfile(files: dict[str, bytes], mutator: Callable[[dict[str, Any]], dict[str, Any]]) -> None:
    current = wcj.parse_strict(files["signatures/manifest.sig.json"])
    files["signatures/manifest.sig.json"] = canonical_file(mutator(current))


# ---------------------------------------------------------------------------
# Key declaration records (used by tools/make_keys.py and lifecycle cases)
# ---------------------------------------------------------------------------


def key_declaration(
    name: str,
    *,
    record_id: str | None = None,
    recorded_at: str = T0,
    valid_from: str | None = None,
    valid_until: str | None = None,
    key_type: str | None = None,
    public_key_b64: str | None = None,
    declared_key_id: str | None = None,
    signed_by: str | None = None,
    note_text: str | None = None,
) -> dict[str, Any]:
    """Build a self-signed ``weave.key.declared`` record for a test key.

    ``public_key_b64``/``declared_key_id``/``key_type``/``signed_by`` may be
    overridden to build negative cases (a declaration whose key id does not
    match its public key, a non-self-signed declaration, ...).
    """
    material = key(name)
    public_b64 = public_key_b64 if public_key_b64 is not None else material.public_b64url()
    declared_id = declared_key_id if declared_key_id is not None else material.key_id
    declared_type = key_type if key_type is not None else material.key_type
    body: dict[str, Any] = {
        "algorithm": "ed25519",
        "key": declared_id,
        "key_type": declared_type,
        "public_key": public_b64,
    }
    if valid_from is not None:
        body["valid_from"] = valid_from
    if valid_until is not None:
        body["valid_until"] = valid_until
    if note_text is not None:
        body["note"] = note_text
    record = build_record(
        kind="weave.key.declared",
        id=record_id if record_id is not None else "key-declared-" + name,
        actor=actor(name, actor_type=declared_type),
        body=body,
        stage="accepted",
        recorded_at=recorded_at,
        origin_instance=declared_id,
    )
    # A declaration is signed by the key it declares (self-signature) and may
    # carry additional owner signatures.
    record = signed(record, signed_by if signed_by is not None else name)
    return record


def key_revocation(
    revoked_name: str,
    *,
    reason: str,
    effective_at: str,
    recorded_at: str | None = None,
    signer_name: str | None = None,
    record_id: str | None = None,
    declared_public_key_b64: str | None = None,
) -> dict[str, Any]:
    """Build a ``weave.key.revoked`` record signed by *signer_name*."""
    revoked_key = key(revoked_name)
    signer = signer_name if signer_name is not None else "human-1"
    body: dict[str, Any] = {
        "effective_at": effective_at,
        "key": revoked_key.key_id,
        "reason": reason,
    }
    record = build_record(
        kind="weave.key.revoked",
        id=record_id if record_id is not None else "key-revoked-%s-%s" % (revoked_name, reason),
        actor=actor(signer),
        body=body,
        stage="accepted",
        recorded_at=recorded_at if recorded_at is not None else effective_at,
        origin_instance=revoked_key.key_id,
    )
    return signed(record, signer)
