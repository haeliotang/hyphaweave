#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0

"""Generate the second half of the ``weave-record/1`` conformance vectors.

This generator owns the ``erasure``, ``grant``, ``key-lifecycle``, ``container``
and ``integrity-levels`` categories.  The first half (``jcs``, ``digest``,
``sig``, ``ref``, ``stage``, ``actor``, ``labels``) is produced by
``tools/gen_vectors.py``; both write the same case format and are catalogued by
``tools/gen_index.py``.

Design rules (`vectors/README.md`):

* Every case's expected verdict and error codes are **hand-authored** in the
  table below from the contract text.  The generator never imports, runs or
  otherwise consults the reference verifier; the files are built with the
  independent helpers in :mod:`wcj`, :mod:`keyutil` and :mod:`recordlib` (own
  WR-CJ, own digests, own Ed25519 signing through ``cryptography``).
* A case directory contains either ``record.json`` (record target), a
  ``container/`` tree (container target) or ``container.zip`` (zip container
  target), plus exactly one canonical ``expected.json``.
* Containers under ``integrity-levels/`` with a claimed L2 level carry a
  committed RFC 3161 ``.tsr`` reply generated once by the local OpenSSL 3.x test
  TSA (``vectors/keys/tsa/``).  Those bytes are fixtures: they are committed and
  reused on every regeneration, so a ``--check`` run is deterministic.  The
  exact regeneration procedure is documented in
  ``vectors/integrity-levels/README.md``.

Usage (from the repository root)::

    ./.venv/bin/python tools/gen_vectors_extra.py             # write cases
    ./.venv/bin/python tools/gen_vectors_extra.py --check     # verify on disk
    ./.venv/bin/python tools/gen_vectors_extra.py --only container
    ./.venv/bin/python tools/gen_vectors_extra.py --bootstrap # create missing TSR fixtures
    ./.venv/bin/python tools/gen_vectors_extra.py --freeze --frozen-source-commit <sha>
                                              # copy the gate-7 frozen set
"""

from __future__ import annotations

import argparse
import hashlib
import io
import os
import shutil
import subprocess
import sys
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Sequence

_TOOLS_DIR = Path(__file__).resolve().parent
if str(_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOLS_DIR))

import keyutil
import recordlib
import wcj

REPO_ROOT = _TOOLS_DIR.parent
VECTORS_DIR = REPO_ROOT / "vectors"
WORK_DIR = REPO_ROOT / ".tmp-work" / "gen-vectors-extra"
# OpenSSL 3.x with `openssl ts` is required only for --bootstrap (creating
# missing committed TSR fixtures). Override with OPENSSL=/path/to/openssl;
# the Homebrew path is the macOS development default and `openssl` on PATH is
# the portable fallback (its version must be 3.x with the ts command).
_DEFAULT_OPENSSL = "/opt/homebrew/opt/openssl@3/bin/openssl"
OPENSSL = os.environ.get("OPENSSL") or (
    _DEFAULT_OPENSSL if os.path.exists(_DEFAULT_OPENSSL) else shutil.which("openssl")
)
TSA_DIR = VECTORS_DIR / "keys" / "tsa"
TSA_CERT_NAME = "tsa.crt.pem"

FORMAT = recordlib.FORMAT
PROJECT = recordlib.PROJECT


# ---------------------------------------------------------------------------
# Case model
# ---------------------------------------------------------------------------


@dataclass
class Case:
    category: str
    name: str
    target: str
    input: str
    verdict: str
    build: Callable[[Path], dict[str, bytes]]
    errors: tuple[str, ...] = ()
    notices: tuple[str, ...] = ()
    args: tuple[str, ...] = ()
    notes: str = ""
    expected_digest: bool = False
    expected_resolution: tuple[str, ...] | None = None
    expected_container: dict[str, Any] | None = None
    records: tuple[dict[str, Any], ...] | None = None

    @property
    def id(self) -> str:
        return "%s/%s" % (self.category, self.name)

    @property
    def case_dir(self) -> Path:
        return VECTORS_DIR / self.category / self.name


CASES: list[Case] = []
_CURRENT_CONTEXT: dict[str, Any] = {}


def declare(
    category: str,
    name: str,
    target: str,
    input_value: str,
    verdict: str,
    *,
    build: Callable[[Path], dict[str, bytes]],
    **kwargs: Any,
) -> None:
    cases_append = Case(
        category=category,
        name=name,
        target=target,
        input=input_value,
        verdict=verdict,
        build=build,
        **kwargs,
    )
    CASES.append(cases_append)


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------


def canonical(value: Any) -> bytes:
    """Canonical file bytes of a value (WR-CJ bytes plus one trailing LF)."""
    return wcj.dump_canonical_file(value)


def parse(data: bytes) -> Any:
    return wcj.parse_strict(data)


def note(record_id: str, **kwargs: Any) -> dict[str, Any]:
    return recordlib.note(record_id, **kwargs)


def key(name: str) -> keyutil.KeyMaterial:
    return recordlib.key(name)


def kid(name: str) -> str:
    return recordlib.kid(name)


def ktype(name: str) -> str:
    return recordlib.ktype(name)


def digest_of(record: dict[str, Any]) -> str:
    return recordlib.record_digest(record)


def as_zip(files: dict[str, bytes]) -> bytes:
    """Deterministic STORED zip of a container file map."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as archive:
        for path in sorted(files):
            info = zipfile.ZipInfo(path, date_time=(2026, 11, 10, 0, 0, 0))
            info.external_attr = 0o644 << 16
            info.create_system = 3
            archive.writestr(info, files[path])
    return buffer.getvalue()


def wrap(files: dict[str, bytes]) -> dict[str, bytes]:
    """Wrap internal container paths under the case-relative ``container/`` dir."""
    return {"container/" + path: data for path, data in files.items()}


def zip_wrap(files: dict[str, bytes]) -> dict[str, bytes]:
    return {"container.zip": as_zip(files)}


def container(records: Sequence[dict[str, Any]], **kwargs: Any) -> dict[str, bytes]:
    """Build a container from records and wrap it under ``container/``."""
    return wrap(recordlib.build_container(records, **kwargs))


def mutate(
    files: dict[str, bytes],
    mutator: Callable[[dict[str, Any]], dict[str, Any]],
    *,
    resign_with: Sequence[str] | None = ("human-1",),
) -> dict[str, bytes]:
    """Apply *mutator* to the container's manifest (optionally re-sealing)."""
    working = dict(files)
    return recordlib.mutate_manifest(working, mutator, resign_with=resign_with)


def mutate_sigfile(
    files: dict[str, bytes], mutator: Callable[[dict[str, Any]], dict[str, Any]]
) -> dict[str, bytes]:
    working = dict(files)
    recordlib.mutate_sigfile(working, mutator)
    return working


def replace(files: dict[str, bytes], path: str, data: bytes) -> dict[str, bytes]:
    working = dict(files)
    working[path] = data
    return working


def drop(files: dict[str, bytes], path: str) -> dict[str, bytes]:
    working = dict(files)
    del working[path]
    return working


RECORD_FILES = "records/"


def record_path(files: dict[str, bytes]) -> str:
    for path in sorted(files):
        if path.startswith(RECORD_FILES) and path.endswith(".json"):
            return path
    raise SystemExit("container has no records/ file")


# ---------------------------------------------------------------------------
# Local RFC 3161 test TSA (vectors/keys/tsa + local OpenSSL 3.x)
# ---------------------------------------------------------------------------


def _tsa_workdir() -> Path:
    work = WORK_DIR / "tsa"
    work.mkdir(parents=True, exist_ok=True)
    for name in ("tsa.cnf", "tsa.crt.pem", "tsa.key.pem"):
        source = TSA_DIR / name
        if not source.is_file():
            raise SystemExit("missing local test TSA file: %s" % source)
        destination = work / name
        destination.write_bytes(source.read_bytes())
    # A fresh serial for each batch run; the TSR bytes are committed and reused.
    (work / "serial.txt").write_text("01\n", encoding="ascii")
    return work


def make_tsr(digest_hex: str) -> bytes:
    """Create one DER TimeStampResp for a raw 32-byte message imprint."""
    if len(digest_hex) != 64 or any(c not in "0123456789abcdef" for c in digest_hex):
        raise SystemExit("TSR imprint must be 32 bytes of lowercase hex")
    work = _tsa_workdir()
    query = work / "query.tsq"
    response = work / "response.tsr"
    if query.exists():
        query.unlink()
    if response.exists():
        response.unlink()
    subprocess.run(
        [
            OPENSSL,
            "ts",
            "-query",
            "-digest",
            digest_hex,
            "-sha256",
            "-cert",
            "-out",
            str(query),
        ],
        check=True,
        cwd=str(work),
    )
    subprocess.run(
        [
            OPENSSL,
            "ts",
            "-reply",
            "-config",
            "tsa.cnf",
            "-section",
            "tsa_config1",
            "-queryfile",
            str(query),
            "-out",
            str(response),
        ],
        check=True,
        cwd=str(work),
    )
    return response.read_bytes()


def tsr_fixture(case_dir: Path, relative: str, digest_hex: str) -> bytes:
    """Return the committed TSR bytes for one L2 case, creating them on bootstrap.

    The committed bytes are reused on every regeneration so that ``--check`` is
    byte-stable.  The file is written to disk by the case writer (it is part of
    the case directory); the first run creates it from the local test TSA.
    """
    path = case_dir / relative
    if path.is_file():
        return path.read_bytes()
    if not _CURRENT_CONTEXT.get("bootstrap"):
        raise SystemExit(
            "missing committed TSR fixture %s\n"
            "run: ./.venv/bin/python tools/gen_vectors_extra.py --bootstrap"
            % path.relative_to(VECTORS_DIR)
        )
    return make_tsr(digest_hex)


def l2_container(
    case_dir: Path,
    records: Sequence[dict[str, Any]],
    *,
    created_at: str = recordlib.T0,
    timestamp_rel: str = "signatures/timestamp-1.tsr",
) -> dict[str, bytes]:
    """Build an L2 container with exactly one committed RFC 3161 timestamp.

    Two-phase because the timestamp signs the manifest digest: build the
    manifest first (level/records only), derive the digest, obtain the TSR over
    that digest, then re-seal the signature file with the timestamp entry.
    """
    files = recordlib.build_container(
        records, level="L2", created_at=created_at, manifest_signers=("human-1",)
    )
    manifest_value = parse(files["manifest.json"])
    manifest_bytes = canonical(manifest_value)
    manifest_digest_value = recordlib.manifest_digest(manifest_bytes)
    imprint_hex = manifest_digest_value[len("sha256:") :]
    tsr_bytes = tsr_fixture(case_dir, "container/" + timestamp_rel, imprint_hex)
    recordlib.seal_container(
        files,
        manifest_value,
        manifest_signers=("human-1",),
        timestamp_files={timestamp_rel: tsr_bytes},
    )
    return files


def _tampered_signature_value(value: str) -> bytes:
    """Decode one 64-byte base64url signature and flip its first bit."""
    raw = keyutil.b64url_decode(value, expected_len=64)
    return bytes([raw[0] ^ 0x01]) + raw[1:]


def _zip_with_traversal(files: dict[str, bytes]) -> bytes:
    """Deterministic STORED zip that also contains one path-escaping entry."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as archive:
        for path in sorted(files):
            info = zipfile.ZipInfo(path, date_time=(2026, 11, 10, 0, 0, 0))
            info.external_attr = 0o644 << 16
            info.create_system = 3
            archive.writestr(info, files[path])
        info = zipfile.ZipInfo("../escape.json", date_time=(2026, 11, 10, 0, 0, 0))
        info.external_attr = 0o644 << 16
        info.create_system = 3
        archive.writestr(info, b"{}\n")
    return buffer.getvalue()


def _previous_manifest_bytes() -> bytes:
    """Manifest bytes of a tiny valid L0 container (used as previous/)."""
    return recordlib.build_container(
        [recordlib.key_declaration("human-2")],
        level="L0",
        created_at=recordlib.EARLY,
        manifest_signers=("human-2",),
    )["manifest.json"]


def _chain_previous_digest() -> str:
    return recordlib.manifest_digest(_previous_manifest_bytes())


def _chain_container(case_dir: Path, *, mismatch: bool) -> dict[str, bytes]:
    """Build container c2 that embeds the previous manifest bytes."""
    previous_bytes = _previous_manifest_bytes()
    previous_digest = recordlib.manifest_digest(previous_bytes)
    if mismatch:
        previous_digest = "sha256:" + "22" * 32
    files = recordlib.build_container(
        [recordlib.key_declaration("human-1")],
        level="L0",
        created_at=recordlib.T1,
        manifest_signers=("human-1",),
        previous_manifest={"digest": previous_digest},
        previous_manifest_bytes=previous_bytes,
    )
    return wrap(files)


# ---------------------------------------------------------------------------
# container cases: layout, manifest, records/ blobs/, chain
# ---------------------------------------------------------------------------

# A single valid self-signed key declaration is enough for the container-level
# cases: the manifest checks must fail before any record verdict is produced.
SIMPLE_RECORDS = lambda: [recordlib.key_declaration("human-1")]  # noqa: E731


def _two_records() -> list[dict[str, Any]]:
    return [
        recordlib.key_declaration("human-1"),
        recordlib.signed(note("container-note-2"), "human-1"),
    ]


declare(
    "container",
    "l0-minimal",
    "container",
    "container",
    "valid",
    build=lambda case_dir: container(SIMPLE_RECORDS()),
    expected_container={
        "level_claimed": "L0",
        "level_verified": "L0",
        "chain": {"status": "absent"},
        "previous_manifest_digest": None,
        "record_count": 1,
    },
    records=({"id": "key-declared-human-1", "verdict": "valid", "errors": []},),
    notes="SPECIAL CASE: the worked example of spec/offline-verification.md. One "
    "self-signed weave.key.declared record, an L0 manifest signed by that key, "
    "every byte canonical, nothing else; the manual sha256sum/openssl procedure "
    "must walk it end to end (valid, self-contained, no --keys needed).",
)

declare(
    "container",
    "manifest-unsigned",
    "container",
    "container",
    "invalid",
    errors=("E_MANIFEST_UNSIGNED",),
    build=lambda case_dir: mutate_sigfile(
        recordlib.build_container(SIMPLE_RECORDS()),
        lambda sigfile: {**sigfile, "signatures": []},
    ),
    notes="manifest attestation lists no signatures: a manifest MUST be signed "
    "(§11.3, I2); digest is correct and the container is otherwise sound.",
)

declare(
    "container",
    "manifest-sig-invalid",
    "container",
    "container",
    "invalid",
    errors=("E_MANIFEST_SIG_INVALID",),
    build=lambda case_dir: mutate_sigfile(
        recordlib.build_container(SIMPLE_RECORDS()),
        lambda sigfile: {
            **sigfile,
            "signatures": [
                {
                    **sigfile["signatures"][0],
                    "value": keyutil.b64url_encode(
                        _tampered_signature_value(sigfile["signatures"][0]["value"])
                    ),
                }
            ],
        },
    ),
    notes="A genuine manifest signature with one raw byte flipped must fail "
    "E_MANIFEST_SIG_INVALID (§3.3/§11.3).",
)

declare(
    "container",
    "manifest-digest-wrong",
    "container",
    "container",
    "invalid",
    errors=("E_MANIFEST_DIGEST",),
    build=lambda case_dir: mutate_sigfile(
        recordlib.build_container(SIMPLE_RECORDS()),
        lambda sigfile: {**sigfile, "digest": "sha256:" + "11" * 32},
    ),
    notes="signatures/manifest.sig.json.digest does not equal the §3.3 manifest "
    "digest; the digest check precedes signature verification (§14.6).",
)

declare(
    "container",
    "manifest-format-wrong",
    "container",
    "container",
    "invalid",
    errors=("E_MANIFEST_FORMAT",),
    build=lambda case_dir: mutate(
        recordlib.build_container(SIMPLE_RECORDS()),
        lambda manifest: {**manifest, "format": "weave-record/2"},
    ),
    notes="manifest.format is not weave-record/1; re-sealed so the digest and "
    "signature are internally consistent and only the format check fails.",
)

declare(
    "container",
    "manifest-version-unsupported",
    "container",
    "container",
    "invalid",
    errors=("E_MANIFEST_VERSION",),
    build=lambda case_dir: mutate(
        recordlib.build_container(SIMPLE_RECORDS()),
        lambda manifest: {**manifest, "manifest_version": 2},
    ),
    notes="H0 supports only manifest_version 1; an unknown integer version is "
    "unsupported (E_MANIFEST_VERSION), never silently accepted (K3).",
)

declare(
    "container",
    "record-extra",
    "container",
    "container",
    "invalid",
    errors=("E_MANIFEST_RECORD_EXTRA",),
    build=lambda case_dir: _record_extra_files(),
    notes="records/ contains a well-formed file that the manifest does not list "
    "(§11.5): every record file must be listed exactly once.",
)

declare(
    "container",
    "manifest-id-kind-mismatch",
    "container",
    "container",
    "invalid",
    errors=("E_MANIFEST_RECORDS",),
    build=lambda case_dir: _manifest_id_kind_mismatch_files(),
    notes="manifest.records[] entries claim the id and kind of the record they "
    "list; here the kind claim (weave.key.revoked) contradicts the envelope kind "
    "(weave.key.declared) inside records/<digest>.json while the digest is still "
    "correct. The manifest/records listing is inconsistent: E_MANIFEST_RECORDS "
    "(§11.2/§11.5). Re-sealed so only the cross-check fails.",
)

declare(
    "container",
    "record-missing",
    "container",
    "container",
    "invalid",
    errors=("E_MANIFEST_RECORD_MISSING",),
    build=lambda case_dir: drop(
        recordlib.build_container(SIMPLE_RECORDS()), record_path(
            recordlib.build_container(SIMPLE_RECORDS())
        )
    ),
    args=("--keys", "@keyset"),
    notes="A digest listed in manifest.records has no files/records/<hex>.json "
    "file (§11.5).",
)

declare(
    "container",
    "record-digest-mismatch",
    "container",
    "container",
    "invalid",
    errors=("E_MANIFEST_RECORD_DIGEST",),
    build=lambda case_dir: (
        lambda files: replace(
            files,
            record_path(files),
            canonical(note("container-tampered", body={"tampered": True})),
        )
    )(recordlib.build_container(SIMPLE_RECORDS())),
    args=("--keys", "@keyset"),
    notes="The records/ file content no longer hashes to its filename/manifest "
    "digest (§11.5).",
)

declare(
    "container",
    "manifest-records-unsorted",
    "container",
    "container",
    "invalid",
    errors=("E_MANIFEST_RECORDS",),
    build=lambda case_dir: mutate(
        recordlib.build_container(_two_records()),
        lambda manifest: {
            **manifest,
            "records": list(reversed(manifest["records"])),
        },
    ),
    notes="manifest.records must be sorted by digest ascending with unique "
    "digests (§11.2); two genuinely sorted entries are reversed here.",
)

declare(
    "container",
    "unknown-top-level-entry",
    "container",
    "container",
    "invalid",
    errors=("E_CONTAINER_ENTRY",),
    build=lambda case_dir: replace(
        recordlib.build_container(SIMPLE_RECORDS()), "notes.txt", b"not listed\n"
    ),
    notes="A file outside the closed container layout is E_CONTAINER_ENTRY "
    "(§11.1); the check runs during entry enumeration, before manifest checks.",
)

declare(
    "container",
    "zip-valid",
    "container",
    "container.zip",
    "valid",
    build=lambda case_dir: zip_wrap(recordlib.build_container(SIMPLE_RECORDS())),
    expected_container={"level_claimed": "L0", "level_verified": "L0"},
    notes="Positive zip form (§11.6): the same layout, STORED entries, POSIX "
    "relative paths; must verify like the directory form.",
)

declare(
    "container",
    "zip-traversal",
    "container",
    "container.zip",
    "invalid",
    errors=("E_CONTAINER_ENTRY",),
    build=lambda case_dir: {
        "container.zip": _zip_with_traversal(
            recordlib.build_container(SIMPLE_RECORDS())
        )
    },
    notes="A zip entry whose path escapes the container root must be rejected "
    "during safe entry enumeration (§11.1/§11.6), before any manifest parsing.",
)

declare(
    "container",
    "blobs-mismatch",
    "container",
    "container",
    "invalid",
    errors=("E_MANIFEST_BLOB",),
    build=lambda case_dir: _blobs_mismatch_files(),
    notes="blobs/sha256/<hex> content must hash to the manifest.blobs entry and "
    "match its size (§11.5); the bytes are altered after the manifest is sealed.",
)

declare(
    "container",
    "readable-ignored",
    "container",
    "container",
    "valid",
    build=lambda case_dir: replace(
        recordlib.build_container(SIMPLE_RECORDS()),
        "readable/notes.txt",
        b"human readable view, never hashed and never trusted\n",
    ),
    expected_container={"level_claimed": "L0", "level_verified": "L0"},
    notes="readable/ is an optional human view outside the digest (§11.5, I1): "
    "arbitrary bytes there must not change validity (N_READABLE_PRESENT is an "
    "optional notice, so it is not required here).",
)

declare(
    "container",
    "chain-valid",
    "container",
    "container",
    "valid",
    build=lambda case_dir: _chain_container(case_dir, mismatch=False),
    expected_container={
        "level_claimed": "L0",
        "level_verified": "L0",
        "previous_manifest_digest": _chain_previous_digest(),
    },
    notes="Container c2 embeds c1's manifest under previous/manifest.json and "
    "commits previous_manifest.digest == manifest-digest(c1 bytes) (§11.4, D1). "
    "The previous manifest's own signature is not re-verified (N_PREVIOUS_SIG_"
    "UNVERIFIED is optional, not required).",
)

declare(
    "container",
    "chain-digest-mismatch",
    "container",
    "container",
    "invalid",
    errors=("E_MANIFEST_CHAIN",),
    build=lambda case_dir: _chain_container(case_dir, mismatch=True),
    notes="previous_manifest.digest does not equal the digest of the embedded "
    "previous/manifest.json bytes (§11.4).",
)

declare(
    "container",
    "chain-missing",
    "container",
    "container",
    "invalid",
    errors=("E_MANIFEST_CHAIN_MISSING",),
    build=lambda case_dir: drop(
        _chain_container(case_dir, mismatch=False),
        "container/previous/manifest.json",
    ),
    notes="previous_manifest is non-null but previous/manifest.json is absent "
    "(§11.4, E_MANIFEST_CHAIN_MISSING).",
)

declare(
    "container",
    "chain-unexpected",
    "container",
    "container",
    "invalid",
    errors=("E_MANIFEST_CHAIN_UNEXPECTED",),
    build=lambda case_dir: replace(
        recordlib.build_container(SIMPLE_RECORDS()),
        "previous/manifest.json",
        _previous_manifest_bytes(),
    ),
    notes="previous_manifest is null but previous/ contains a manifest: an "
    "unexpected previous container is rejected (§11.4).",
)

declare(
    "container",
    "manifest-missing",
    "container",
    "container",
    "invalid",
    errors=("E_MANIFEST_MISSING",),
    build=lambda case_dir: drop(
        wrap(recordlib.build_container(SIMPLE_RECORDS())), "container/manifest.json"
    ),
    notes="A container directory without manifest.json is E_MANIFEST_MISSING "
    "(§11.2), not "
    "a generic parse error.",
)



# ---------------------------------------------------------------------------
# erasure cases (§7.7/§7.8, G3)
# ---------------------------------------------------------------------------


def erased_original(record_id: str = "erasure-original-1") -> dict[str, Any]:
    """The live record that is about to be erased (never exported)."""
    return note(record_id, body={"text": "sensitive original body"})


def erasure_record(
    original: dict[str, Any],
    *,
    record_id: str = "erasure-attestation-1",
    reason: str = "data-subject-request",
    signer: str = "human-1",
    actor_type: str | None = None,
    erased_digest: str | None = None,
    with_signature: bool = True,
) -> dict[str, Any]:
    original_digest = recordlib.record_digest(original)
    body = {
        "erased": recordlib.make_ref(
            original["origin"]["instance"],
            original["id"],
            erased_digest if erased_digest is not None else original_digest,
            kind=original["kind"],
        ),
        "reason": reason,
        "reason_note": None,
        "basis": None,
    }
    record = recordlib.build_record(
        kind="weave.erasure",
        id=record_id,
        actor=recordlib.actor(signer, actor_type=actor_type),
        body=body,
        stage="accepted",
        recorded_at=recordlib.T4,
        origin_instance=kid(signer),
    )
    return recordlib.signed(record, signer) if with_signature else record


def erased_placeholder(
    original: dict[str, Any],
    attestation: dict[str, Any],
    *,
    digest: str | None = None,
) -> dict[str, Any]:
    """The replacement object for an erased record (exact §7.8 shape)."""
    return {
        "format": FORMAT,
        "kind": "weave.erased",
        "origin": original["origin"],
        "id": original["id"],
        "digest": digest if digest is not None else recordlib.record_digest(original),
        "attestation": recordlib.make_ref(
            attestation["origin"]["instance"],
            attestation["id"],
            recordlib.record_digest(attestation),
            kind="weave.erasure",
        ),
    }


def _erasure_valid_files() -> dict[str, bytes]:
    original = erased_original()
    attestation = erasure_record(original)
    placeholder = erased_placeholder(original, attestation)
    return container([placeholder, attestation])


ERASURE_ARGS = ("--keys", "@keyset")

declare(
    "erasure",
    "valid-container",
    "container",
    "container",
    "valid",
    build=lambda case_dir: _erasure_valid_files(),
    args=ERASURE_ARGS,
    records=(
        {"id": "erasure-attestation-1", "verdict": "valid", "errors": []},
        {
            "id": "erasure-original-1",
            "verdict": "erased",
            "errors": [],
        },
    ),
    notes="Positive: the live record is replaced by a weaver.erased placeholder whose "
    "digest is the original record digest and whose attestation resolves to the "
    "signed weave.erasure record; the placeholder's own verdict is 'erased', the "
    "erasure record is valid, and both cross-checks hold (§7.7/§7.8, G3a/G3b).",
)

declare(
    "erasure",
    "unsigned",
    "record",
    "record.json",
    "invalid",
    errors=("E_SIG_REQUIRED",),
    build=lambda case_dir: {
        "record.json": canonical(
            erasure_record(
                erased_original(), record_id="erasure-unsigned-1", with_signature=False
            )
        )
    },
    args=ERASURE_ARGS,
    notes="A weave.erasure record MUST be per-record signed (§5.3); without sigs it "
    "is E_SIG_REQUIRED before any body/ref check.",
)

declare(
    "erasure",
    "reason-invalid",
    "record",
    "record.json",
    "invalid",
    errors=("E_KIND_BODY_SCHEMA",),
    build=lambda case_dir: {
        "record.json": canonical(
            erasure_record(erased_original(), reason="because-i-said-so")
        )
    },
    args=ERASURE_ARGS,
    notes="The erasure reason is a closed enum (§7.7); an unknown value is a kind "
    "body schema failure. Genuinely signed so the check is reached.",
)

declare(
    "erasure",
    "digest-mismatch",
    "container",
    "container",
    "invalid",
    errors=("E_ERASE_DIGEST_MISMATCH",),
    build=lambda case_dir: (
        lambda original, attestation: container(
            [
                erased_placeholder(
                    original,
                    attestation,
                    digest=recordlib.record_digest(original),
                ),
                attestation,
            ]
        )
    )(
        erased_original(),
        erasure_record(
            erased_original(), erased_digest="sha256:" + "33" * 32
        ),
    ),
    args=ERASURE_ARGS,
    notes="The erasure record's erased reference names a different digest than the "
    "placeholder it attests (§7.7): E_ERASE_DIGEST_MISMATCH.",
)

declare(
    "erasure",
    "attestation-missing",
    "container",
    "container",
    "invalid",
    errors=("E_ERASE_ATTESTATION",),
    build=lambda case_dir: container(
        [
            {
                "format": FORMAT,
                "kind": "weave.erased",
                "origin": recordlib.origin(kid("human-1")),
                "id": "erasure-orphan-1",
                "digest": "sha256:" + "44" * 32,
                "attestation": recordlib.make_ref(
                    kid("human-1"),
                    "no-such-erasure",
                    "sha256:" + "55" * 32,
                    kind="weave.erasure",
                ),
            }
        ]
    ),
    args=ERASURE_ARGS,
    notes="A placeholder whose attestation reference resolves to nothing is "
    "E_ERASE_ATTESTATION (§7.8): an erasure claim without its attestation is not "
    "acceptable evidence.",
)

declare(
    "erasure",
    "contradiction",
    "container",
    "container",
    "invalid",
    errors=("E_ERASE_CONTRADICTION",),
    build=lambda case_dir: (
        lambda original, attestation: container(
            [original, erased_placeholder(original, attestation), attestation]
        )
    )(erased_original(), erasure_record(erased_original())),
    args=ERASURE_ARGS,
    notes="The same origin+id appears both as the live record and as an erased "
    "placeholder: erasure must replace the record, never coexist with it (§7.7, "
    "G3e: withdrawn records are appended, only erasure replaces).",
)

declare(
    "erasure",
    "actor-not-human",
    "record",
    "record.json",
    "invalid",
    errors=("E_ERASE_ACTOR",),
    build=lambda case_dir: {
        "record.json": canonical(
            erasure_record(
                erased_original(),
                record_id="erasure-program-1",
                signer="program-1",
                actor_type="program",
            )
        )
    },
    args=ERASURE_ARGS,
    notes="Only a human may execute an erasure (§7.7, G3a): a program actor is "
    "E_ERASE_ACTOR invalid (the record is correctly signed by its own key, so the "
    "actor rule is the defect).",
)


# ---------------------------------------------------------------------------
# grant cases (§7.4, §8; principle "agents only propose unless granted")
# ---------------------------------------------------------------------------

GRANT_ARGS = ("--keys", "@keyset")
GRANT_ACTIONS = ["propose", "accept", "reject", "withdraw", "supersede", "erase", "grant"]


def parent_ref(grant: dict[str, Any]) -> dict[str, Any]:
    return recordlib.make_ref(
        grant["origin"]["instance"],
        grant["id"],
        recordlib.record_digest(grant),
        kind="weave.grant",
    )


def root_grant(
    *,
    record_id: str = "grant-root-1",
    granter: str = "human-1",
    grantee: str = "agent-1",
    kinds: Sequence[str] = ("example.note",),
    actions: Sequence[str] = ("propose", "accept"),
    scope: Sequence[str] = ("example",),
    valid_from: str = recordlib.T0,
    valid_until: str | None = recordlib.T9,
    transferable: bool = True,
) -> dict[str, Any]:
    """A root weave.grant issued by a human key (§7.4)."""
    body = {
        "action": "grant",
        "grant": {
            "grantee": {"key": kid(grantee)},
            "kinds": list(kinds),
            "actions": list(actions),
            "scope": list(scope),
            "valid_from": valid_from,
            "valid_until": valid_until,
            "transferable": transferable,
            "evidence": None,
            "remedy": None,
        },
    }
    record = recordlib.build_record(
        kind="weave.grant",
        id=record_id,
        actor=recordlib.actor(granter),
        body=body,
        stage="accepted",
        recorded_at=valid_from,
        origin_instance=kid(granter),
    )
    return recordlib.signed(record, granter)


def delegated_grant(
    parent: dict[str, Any],
    *,
    record_id: str = "grant-sub-1",
    sub_granter: str = "agent-1",
    grantee: str = "agent-2",
    kinds: Sequence[str] = ("example.note",),
    actions: Sequence[str] = ("propose",),
    scope: Sequence[str] = ("example",),
    valid_from: str = recordlib.T1,
    valid_until: str | None = recordlib.T8,
    transferable: bool = False,
) -> dict[str, Any]:
    """A delegated sub-grant signed by an agent under a parent grant."""
    body = {
        "action": "grant",
        "grant": {
            "grantee": {"key": kid(grantee)},
            "kinds": list(kinds),
            "actions": list(actions),
            "scope": list(scope),
            "valid_from": valid_from,
            "valid_until": valid_until,
            "transferable": transferable,
            "evidence": None,
            "remedy": None,
        },
    }
    actor = recordlib.actor(
        sub_granter,
        model="example/model@1.2.3",
        on_behalf_of=kid("human-1"),
        grant=parent_ref(parent),
        idempotency_key="idem-" + record_id,
    )
    record = recordlib.build_record(
        kind="weave.grant",
        id=record_id,
        actor=actor,
        body=body,
        stage="accepted",
        recorded_at=valid_from,
        origin_instance=kid(sub_granter),
    )
    return recordlib.signed(record, sub_granter)


def _agent_grant_without_parent() -> dict[str, Any]:
    """An agent-signed weave.grant whose actor.grant resolves to nothing."""
    body = {
        "action": "grant",
        "grant": {
            "grantee": {"key": kid("agent-2")},
            "kinds": ["example.note"],
            "actions": ["propose"],
            "scope": ["example"],
            "valid_from": recordlib.T1,
            "valid_until": recordlib.T8,
            "transferable": False,
            "evidence": None,
            "remedy": None,
        },
    }
    actor = recordlib.actor(
        "agent-1",
        model="example/model@1.2.3",
        on_behalf_of=kid("human-1"),
        grant=recordlib.make_ref(
            kid("human-1"), "no-such-parent-grant", "sha256:" + "77" * 32, kind="weave.grant"
        ),
        idempotency_key="idem-agent-grant-no-parent",
    )
    record = recordlib.build_record(
        kind="weave.grant",
        id="grant-agent-no-parent",
        actor=actor,
        body=body,
        stage="accepted",
        recorded_at=recordlib.T1,
        origin_instance=kid("agent-1"),
    )
    return recordlib.signed(record, "agent-1")


def grant_revocation(
    grant: dict[str, Any],
    *,
    record_id: str = "grant-revoke-1",
    signer: str = "human-1",
    effective_at: str = recordlib.T3,
    revokes_digest: str | None = None,
) -> dict[str, Any]:
    body = {
        "action": "revoke",
        "revoke": {
            "revokes": recordlib.make_ref(
                grant["origin"]["instance"],
                grant["id"],
                revokes_digest
                if revokes_digest is not None
                else recordlib.record_digest(grant),
                kind="weave.grant",
            ),
            "effective_at": effective_at,
            "reason": None,
        },
    }
    record = recordlib.build_record(
        kind="weave.grant",
        id=record_id,
        actor=recordlib.actor(signer),
        body=body,
        stage="accepted",
        recorded_at=effective_at,
        origin_instance=kid(signer),
    )
    return recordlib.signed(record, signer)


def agent_action(
    grant: dict[str, Any],
    *,
    record_id: str = "agent-action-1",
    key_name: str = "agent-1",
    kind: str = "example.note",
    stage: str = "accepted",
    recorded_at: str = recordlib.T2,
) -> dict[str, Any]:
    """A record authored by an agent citing the given grant (§8.3)."""
    actor = recordlib.actor(
        key_name,
        model="example/model@1.2.3",
        on_behalf_of=kid("human-1"),
        grant=parent_ref(grant),
        idempotency_key="idem-" + record_id,
    )
    record = recordlib.build_record(
        kind=kind,
        id=record_id,
        actor=actor,
        body={"text": "agent action"},
        stage=stage,
        recorded_at=recorded_at,
    )
    return recordlib.signed(record, key_name)


declare(
    "grant",
    "valid-root",
    "record",
    "record.json",
    "valid",
    build=lambda case_dir: {
        "record.json": canonical(
            root_grant(
                kinds=("example.note", "example.receipt"),
                actions=("propose", "accept"),
            )
        )
    },
    args=GRANT_ARGS,
    expected_digest=True,
    notes="Baseline root grant: a human key issues kind, action, scope, validity "
    "and transferability for one agent; signed by the granter's key (§7.4).",
)

declare(
    "grant",
    "agent-grant-without-parent",
    "record",
    "record.json",
    "unverifiable",
    errors=("E_GRANT_UNRESOLVED",),
    build=lambda case_dir: {
        "record.json": canonical(
            _agent_grant_without_parent()
        )
    },
    args=GRANT_ARGS,
    notes="An agent-signed weave.grant is a delegated sub-grant. Its actor.grant "
    "reference is absent from the verification context, so the delegation cannot "
    "be checked: unverifiable E_GRANT_UNRESOLVED (§7.4/§8, registry distinction: "
    "E_GRANT_GRANTER is only for a parent that is resolvable but does not permit "
    "issuing grants — see grant/parent-not-authorising).",
)

declare(
    "grant",
    "parent-not-authorising",
    "container",
    "container",
    "invalid",
    errors=("E_GRANT_GRANTER",),
    build=lambda case_dir: (
        lambda parent: container(
            [
                parent,
                delegated_grant(parent, record_id="grant-sub-parent-not-authorising"),
            ]
        )
    )(
        root_grant(
            record_id="grant-root-not-authorising",
            kinds=("example.note",),
            actions=("propose", "accept", "grant"),
            transferable=True,
        )
    ),
    args=GRANT_ARGS,
    records=(
        {"id": "grant-root-not-authorising", "verdict": "valid", "errors": []},
        {
            "id": "grant-sub-parent-not-authorising",
            "verdict": "invalid",
            "errors": ["E_GRANT_GRANTER"],
        },
    ),
    notes="The parent grant IS resolvable and transferable, but its kinds list does "
    "not contain weave.grant (it only allows example.note) and therefore does not "
    "authorise issuing further grants. A resolvable parent that does not permit "
    "granting is invalid E_GRANT_GRANTER (§7.4) — the companion case to "
    "agent-grant-without-parent (unresolvable => unverifiable).",
)

declare(
    "grant",
    "sub-grant-not-transferable",
    "container",
    "container",
    "invalid",
    errors=("E_GRANT_NOT_TRANSFERABLE",),
    build=lambda case_dir: (
        lambda parent: container(
            [parent, delegated_grant(parent, record_id="grant-sub-notransfer")]
        )
    )(
        root_grant(
            record_id="grant-root-notransfer",
            kinds=("weave.grant", "example.note"),
            actions=("grant", "propose", "accept"),
            transferable=False,
        )
    ),
    args=GRANT_ARGS,
    records=(
        {"id": "grant-root-notransfer", "verdict": "valid", "errors": []},
        {
            "id": "grant-sub-notransfer",
            "verdict": "invalid",
            "errors": ["E_GRANT_NOT_TRANSFERABLE"],
        },
    ),
    notes="A delegated sub-grant may only exist under a parent whose "
    "transferable=true (§7.4); a parent grant defaults to non-transferable in the "
    "decision draft, and delegation of a non-transferable grant is invalid.",
)

declare(
    "grant",
    "sub-grant-exceeds-parent",
    "container",
    "container",
    "invalid",
    errors=("E_GRANT_DELEGATION_EXCEEDS",),
    build=lambda case_dir: (
        lambda parent: container(
            [
                parent,
                delegated_grant(
                    parent,
                    record_id="grant-sub-exceeds",
                    kinds=("example.note", "example.receipt"),
                ),
            ]
        )
    )(
        root_grant(
            record_id="grant-root-exceeds",
            kinds=("weave.grant", "example.note"),
            actions=("grant", "propose", "accept"),
            transferable=True,
        )
    ),
    args=GRANT_ARGS,
    notes="A sub-grant's kinds must be a subset of its parent's kinds and its "
    "validity window must be inside the parent's (§7.4): granting example.receipt "
    "under a parent that only allows example.note exceeds the delegation.",
)

declare(
    "grant",
    "kind-not-covered",
    "container",
    "container",
    "invalid",
    errors=("E_GRANT_NOT_APPLICABLE",),
    build=lambda case_dir: (
        lambda grant: container(
            [grant, agent_action(grant, record_id="agent-kind-not-covered", kind="example.receipt")]
        )
    )(
        root_grant(
            record_id="grant-root-kind",
            kinds=("example.note",),
            actions=("propose", "accept"),
        )
    ),
    args=GRANT_ARGS,
    notes="An agent record whose kind is not listed in the cited grant is invalid "
    "(§8.3, E_GRANT_NOT_APPLICABLE): the authorization must cover the kind.",
)

declare(
    "grant",
    "grantee-mismatch",
    "container",
    "container",
    "invalid",
    errors=("E_GRANT_GRANTEE_MISMATCH",),
    build=lambda case_dir: (
        lambda grant: container(
            [grant, agent_action(grant, record_id="agent-grantee-mismatch")]
        )
    )(
        root_grant(
            record_id="grant-root-grantee",
            grantee="agent-2",
            kinds=("example.note",),
            actions=("propose", "accept"),
        )
    ),
    args=GRANT_ARGS,
    notes="The cited grant is issued to agent-2 but the record is authored by "
    "agent-1: agent.key must equal grantee.key (§8.3, E_GRANT_GRANTEE_MISMATCH).",
)

declare(
    "grant",
    "expired",
    "container",
    "container",
    "unverifiable",
    errors=("E_GRANT_EXPIRED",),
    build=lambda case_dir: (
        lambda grant: container([grant, agent_action(grant, record_id="agent-expired", recorded_at=recordlib.T2)])
    )(
        root_grant(
            record_id="grant-root-expired",
            valid_from=recordlib.T0,
            valid_until=recordlib.T1,
        )
    ),
    args=GRANT_ARGS,
    notes="The cited grant expired before the record's claimed recorded_at: the "
    "authorization cannot be checked, so the record and container are "
    "unverifiable, not invalid (§8.3, E_GRANT_EXPIRED).",
)

declare(
    "grant",
    "revoked",
    "container",
    "container",
    "unverifiable",
    errors=("E_GRANT_REVOKED",),
    build=lambda case_dir: (
        lambda grant, revocation: container(
            [
                grant,
                revocation,
                agent_action(grant, record_id="agent-revoked", recorded_at=recordlib.T4),
            ]
        )
    )(
        root_grant(record_id="grant-root-revoked"),
        grant_revocation(
            root_grant(record_id="grant-root-revoked"),
            record_id="grant-revoke-effective",
            effective_at=recordlib.T3,
        ),
    ),
    args=GRANT_ARGS,
    notes="A revocation record is effective at T3; the later agent record (T4) "
    "cites the revoked grant, so it is unverifiable E_GRANT_REVOKED (§8.5/§10.4), "
    "not invalid. Records at or before effective_at would be unaffected.",
)

declare(
    "grant",
    "revoke-bad-ref",
    "container",
    "container",
    "invalid",
    errors=("E_GRANT_REVOKE_REF",),
    build=lambda case_dir: (
        lambda grant: container(
            [
                grant,
                grant_revocation(
                    grant,
                    record_id="grant-revoke-bad-ref",
                    revokes_digest="sha256:" + "66" * 32,
                ),
            ]
        )
    )(
        root_grant(record_id="grant-root-revoke-ref")
    ),
    args=GRANT_ARGS,
    notes="A grant-revocation's revokes reference must resolve to the grant it "
    "names; a wrong digest makes the revocation invalid (E_GRANT_REVOKE_REF, §7.4).",
)

declare(
    "grant",
    "valid-revocation",
    "container",
    "container",
    "valid",
    build=lambda case_dir: (
        lambda grant: container([grant, grant_revocation(grant, record_id="grant-revoke-ok")])
    )(
        root_grant(record_id="grant-root-revoke-ok")
    ),
    args=GRANT_ARGS,
    records=(
        {"id": "grant-root-revoke-ok", "verdict": "valid", "errors": []},
        {"id": "grant-revoke-ok", "verdict": "valid", "errors": []},
    ),
    notes="Positive revocation: signed by the original granter, effective_at not "
    "after recorded_at, revokes reference resolves to a resolvable grant (§7.4).",
)

declare(
    "grant",
    "revoke-signer-not-qualified",
    "container",
    "container",
    "invalid",
    errors=("E_GRANT_REVOKE_SIGNER",),
    build=lambda case_dir: (
        lambda grant: container(
            [
                grant,
                grant_revocation(
                    grant, record_id="grant-revoke-program", signer="program-1"
                ),
            ]
        )
    )(
        root_grant(record_id="grant-root-revoke-signer")
    ),
    args=GRANT_ARGS,
    records=(
        {"id": "grant-root-revoke-signer", "verdict": "valid", "errors": []},
        {
            "id": "grant-revoke-program",
            "verdict": "invalid",
            "errors": ["E_GRANT_REVOKE_SIGNER"],
        },
    ),
    notes="A grant revocation must be signed by the original granter's key or by a "
    "declared human/organization key (§7.4). A program-key-signed revocation of a "
    "human-issued grant is E_GRANT_REVOKE_SIGNER invalid, even though the revokes "
    "reference itself resolves.",
)

declare(
    "grant",
    "agent-accepted-with-grant",
    "container",
    "container",
    "valid",
    build=lambda case_dir: (
        lambda grant: container(
            [grant, agent_action(grant, record_id="agent-covered-accepted")]
        )
    )(
        root_grant(
            record_id="grant-root-covered",
            kinds=("example.note",),
            actions=("propose", "accept"),
        )
    ),
    args=GRANT_ARGS,
    records=(
        {"id": "grant-root-covered", "verdict": "valid", "errors": []},
        {"id": "agent-covered-accepted", "verdict": "valid", "errors": []},
    ),
    notes="Positive agent authorization (§8.3): the grant lists example.note and "
    "the accept action, the grantee key equals actor.key, the record's recorded_at "
    "is inside the grant window and the grant is not revoked.",
)


# ---------------------------------------------------------------------------
# key-lifecycle cases (§7.1–§7.3, §10)
# ---------------------------------------------------------------------------


def record_signed_by(
    key_name: str,
    record_id: str,
    *,
    recorded_at: str = recordlib.T4,
    kind: str = "example.note",
    stage: str = "proposed",
) -> dict[str, Any]:
    record = recordlib.build_record(
        kind=kind,
        id=record_id,
        actor=recordlib.actor(key_name),
        body={"text": "signed after the key event"},
        stage=stage,
        recorded_at=recorded_at,
    )
    return recordlib.signed(record, key_name)


def key_rotation(
    *,
    record_id: str = "key-rotated-1",
    old_name: str = "key-old",
    new_name: str = "key-new",
    signers: Sequence[str] = ("key-old", "key-new"),
    recorded_at: str = recordlib.T2,
) -> dict[str, Any]:
    """A weave.key.rotated record signed by both the old and the new key (§7.2)."""
    body = {
        "new_key": kid(new_name),
        "new_public_key": key(new_name).public_b64url(),
        "old_key": kid(old_name),
        "old_public_key": key(old_name).public_b64url(),
        "reason": "scheduled rotation",
    }
    record = recordlib.build_record(
        kind="weave.key.rotated",
        id=record_id,
        actor=recordlib.actor(old_name),
        body=body,
        stage="accepted",
        recorded_at=recorded_at,
        origin_instance=kid(old_name),
    )
    return recordlib.signed(record, list(signers))


def undeclared_key_record() -> dict[str, Any]:
    """A record signed by a key that is deliberately not declared anywhere."""
    seed = hashlib.sha256(b"weave-record/1/test-key/undeclared-extra").digest()
    private = keyutil.private_from_seed(seed)
    public = keyutil.public_bytes(private)
    undeclared_id = keyutil.key_id(public)
    record = recordlib.build_record(
        kind="example.note",
        id="key-unknown-1",
        actor={"type": "human", "key": undeclared_id},
        body={"text": "whose key is this?"},
        stage="proposed",
        recorded_at=recordlib.T2,
        origin_instance=undeclared_id,
    )
    digest = recordlib.record_digest(record)
    signature = private.sign(keyutil.SIG_DOMAIN + digest.encode("ascii"))
    record["sigs"] = [
        {
            "alg": "ed25519",
            "key": undeclared_id,
            "value": keyutil.b64url_encode(signature),
        }
    ]
    return record


def declaration_with_mismatched_id() -> dict[str, Any]:
    """A declaration whose body.key contradicts its own public_key.

    The record is signed by the key whose raw bytes it publishes (human-1), so
    the signature verifies through the declaration's bootstrap key material and
    the first failing rule is the §3.4 derivation vs body.key (E_KEY_ID_-
    MISMATCH), not the signature.
    """
    body = {
        "algorithm": "ed25519",
        "key": kid("human-2"),
        "key_type": "human",
        "public_key": key("human-1").public_b64url(),
    }
    record = recordlib.build_record(
        kind="weave.key.declared",
        id="key-declared-id-mismatch",
        actor=recordlib.actor("human-2"),
        body=body,
        stage="accepted",
        recorded_at=recordlib.T0,
        origin_instance=kid("human-2"),
    )
    return recordlib.signed(record, "human-1")


def derived_key(name: str):
    """Deterministic synthetic key material not present in vectors/keys/."""
    seed = hashlib.sha256(b"weave-record/1/test-key/" + name.encode("ascii")).digest()
    private = keyutil.private_from_seed(seed)
    public = keyutil.public_bytes(private)
    return private, public, keyutil.key_id(public)


def _derived_signature(private, key_id: str, record: dict[str, Any]) -> dict[str, str]:
    digest = recordlib.record_digest(record)
    signature = private.sign(keyutil.SIG_DOMAIN + digest.encode("ascii"))
    return {
        "alg": "ed25519",
        "key": key_id,
        "value": keyutil.b64url_encode(signature),
    }


def declaration_with_validity(
    *, record_id: str, valid_until: str, valid_from: str = recordlib.T0
) -> dict[str, Any]:
    """A self-signed key declaration for a fresh key, with a validity window."""
    private, public, key_id = derived_key("expiring-key")
    body = {
        "algorithm": "ed25519",
        "key": key_id,
        "key_type": "human",
        "public_key": keyutil.b64url_encode(public),
        "valid_from": valid_from,
        "valid_until": valid_until,
    }
    record = recordlib.build_record(
        kind="weave.key.declared",
        id=record_id,
        actor={"type": "human", "key": key_id},
        body=body,
        stage="accepted",
        recorded_at=recordlib.T0,
        origin_instance=key_id,
    )
    record["sigs"] = [_derived_signature(private, key_id, record)]
    return record


def record_signed_by_derived(*, record_id: str, recorded_at: str) -> dict[str, Any]:
    private, _public, key_id = derived_key("expiring-key")
    record = recordlib.build_record(
        kind="example.note",
        id=record_id,
        actor={"type": "human", "key": key_id},
        body={"text": "signed with an expiring key"},
        stage="proposed",
        recorded_at=recorded_at,
        origin_instance=key_id,
    )
    record["sigs"] = [_derived_signature(private, key_id, record)]
    return record


LIFECYCLE_ARGS = ("--keys", "@keyset")

declare(
    "key-lifecycle",
    "declared-valid",
    "record",
    "record.json",
    "valid",
    build=lambda case_dir: {
        "record.json": canonical(recordlib.key_declaration("human-2"))
    },
    args=LIFECYCLE_ARGS,
    expected_digest=True,
    notes="Baseline weave.key.declared (§7.1): the key publishes its own raw public "
    "key, the key id is the §3.4 derivation, and the declaration is self-signed.",
)

declare(
    "key-lifecycle",
    "key-id-mismatch",
    "record",
    "record.json",
    "invalid",
    errors=("E_KEY_ID_MISMATCH",),
    build=lambda case_dir: {
        "record.json": canonical(declaration_with_mismatched_id())
    },
    args=LIFECYCLE_ARGS,
    notes="The declared key id is not the §3.4 derivation of the declared public "
    "key: key ids are claims until a declaration supplies the public key and the "
    "verifier recomputes the id (§3.4/§7.1, E_KEY_ID_MISMATCH). The record is "
    "signed by the key whose raw bytes it publishes, so the signature verifies "
    "and the key-id derivation is the first failing rule.",
)

declare(
    "key-lifecycle",
    "declared-not-self-signed",
    "record",
    "record.json",
    "invalid",
    errors=("E_KEY_DECLARED_NOT_SELF_SIGNED",),
    build=lambda case_dir: {
        "record.json": canonical(
            recordlib.key_declaration("human-1", signed_by="human-2")
        )
    },
    args=LIFECYCLE_ARGS,
    notes="A declaration MUST carry a signature by the declared key (§7.1). Here it "
    "carries only the owner's (human-2) signature over it: E_KEY_DECLARED_NOT_"
    "SELF_SIGNED. Note the generic §5.3 signature-presence rule is satisfied (the "
    "sigs array is non-empty and verifies), so this is the specific kind rule.",
)

declare(
    "key-lifecycle",
    "rotated-valid",
    "record",
    "record.json",
    "valid",
    build=lambda case_dir: {"record.json": canonical(key_rotation())},
    args=LIFECYCLE_ARGS,
    expected_digest=True,
    notes="Positive weave.key.rotated (§7.2): old and new public keys match their "
    "key ids, the actor is the old key, and the record is signed by both keys "
    "(rotation is a two-party statement).",
)

declare(
    "key-lifecycle",
    "rotation-missing-new-sig",
    "record",
    "record.json",
    "invalid",
    errors=("E_KEY_ROTATION_SIGS",),
    build=lambda case_dir: {
        "record.json": canonical(
            key_rotation(record_id="key-rotated-missing-new", signers=("key-old",))
        )
    },
    args=LIFECYCLE_ARGS,
    notes="A rotation is only valid when signed by BOTH the old and the new key "
    "(§7.2, E_KEY_ROTATION_SIGS); the old-key signature alone cannot authorize a "
    "new key.",
)

declare(
    "key-lifecycle",
    "retired-then-signed-after",
    "container",
    "container",
    "invalid",
    errors=("E_KEY_REVOKED",),
    build=lambda case_dir: container(
        [
            recordlib.key_revocation(
                "key-old",
                reason="retired",
                effective_at=recordlib.T3,
                recorded_at=recordlib.T3,
                signer_name="human-1",
                record_id="key-revoked-key-old-retired",
            ),
            record_signed_by(
                "key-old", "record-after-retirement", recorded_at=recordlib.T4
            ),
        ]
    ),
    args=LIFECYCLE_ARGS,
    notes="A 'retired' revocation is not retroactive (§10.3): a signature made "
    "after effective_at is E_KEY_REVOKED invalid. The revocation record is signed "
    "by a human key, which the retiral rule allows.",
)

declare(
    "key-lifecycle",
    "compromise-retroactive",
    "container",
    "container",
    "invalid",
    errors=("E_KEY_COMPROMISED",),
    build=lambda case_dir: container(
        [
            recordlib.key_revocation(
                "key-compromised",
                reason="key-compromise",
                effective_at=recordlib.T3,
                recorded_at=recordlib.T3,
                signer_name="human-1",
                record_id="key-revoked-key-compromised",
            ),
            record_signed_by(
                "key-compromised", "record-after-compromise", recorded_at=recordlib.T4
            ),
        ]
    ),
    args=LIFECYCLE_ARGS,
    notes="A key-compromise revocation is retroactive (§10.3): signatures after "
    "effective_at are E_KEY_COMPROMISED unless an earlier verified timestamp rescues "
    "them. Here there is no timestamp.",
)

declare(
    "key-lifecycle",
    "compromise-rescued-by-timestamp",
    "container",
    "container",
    "valid",
    build=lambda case_dir: _compromise_rescue_files(case_dir),
    args=("--keys", "@keyset", "--tsa-trust", TSA_CERT_NAME),
    expected_container={"level_claimed": "L2", "level_verified": "L2"},
    records=(
        {"id": "key-revoked-key-compromised", "verdict": "valid", "errors": []},
        {"id": "record-before-compromise", "verdict": "valid", "errors": []},
    ),
    notes="Positive retroactive-compromise rescue (§10.3, E5): the record claims a "
    "recorded_at after effective_at, but the container has a verified L2 RFC 3161 "
    "timestamp whose genTime is at/before effective_at, proving the record existed "
    "before the compromise; it stays valid. effective_at is chosen after the "
    "committed TSR generation time (see vectors/integrity-levels/README.md).",
)

declare(
    "key-lifecycle",
    "unknown-key",
    "record",
    "record.json",
    "unverifiable",
    errors=("E_KEY_UNKNOWN",),
    build=lambda case_dir: {"record.json": canonical(undeclared_key_record())},
    notes="A signature by a key with no declaration anywhere in the context cannot "
    "be checked: the record is unverifiable E_KEY_UNKNOWN, not invalid (§10.2); "
    "trust is TOFU but the key must be published first (§8.5).",
)


declare(
    "key-lifecycle",
    "key-expired",
    "container",
    "container",
    "invalid",
    errors=("E_KEY_EXPIRED",),
    build=lambda case_dir: container(
        [
            declaration_with_validity(
                record_id="key-declared-expiring", valid_until=recordlib.T2
            ),
            record_signed_by_derived(
                record_id="record-after-key-expiry", recorded_at=recordlib.T4
            ),
        ]
    ),
    args=LIFECYCLE_ARGS,
    records=(
        {"id": "key-declared-expiring", "verdict": "valid", "errors": []},
        {
            "id": "record-after-key-expiry",
            "verdict": "invalid",
            "errors": ["E_KEY_EXPIRED"],
        },
    ),
    notes="A declared key with valid_until T2 signs a record whose claimed "
    "recorded_at is T4 > valid_until: the signature is E_KEY_EXPIRED invalid "
    "(§10.1). The declaration itself is valid and is published in the container.",
)

declare(
    "key-lifecycle",
    "public-key-invalid",
    "record",
    "record.json",
    "invalid",
    errors=("E_KEY_PUBLIC_KEY",),
    build=lambda case_dir: {
        "record.json": canonical(
            recordlib.key_declaration(
                "human-1",
                public_key_b64=keyutil.b64url_encode(b"\x00" * 31),
                signed_by="human-2",
            )
        )
    },
    args=LIFECYCLE_ARGS,
    notes="A declaration whose public_key is not strict unpadded base64url of "
    "exactly 32 bytes (here 31 bytes) is E_KEY_PUBLIC_KEY invalid (§3.5/§7.1): a "
    "key declaration must publish a canonical 32-byte point. The record is signed "
    "by an owner key (human-2) rather than treated as its own bootstrap key, so the "
    "declaration body check is the first failing rule.",
)

declare(
    "key-lifecycle",
    "rotation-same-key",
    "record",
    "record.json",
    "invalid",
    errors=("E_KEY_ROTATION_KEYS",),
    build=lambda case_dir: {
        "record.json": canonical(
            key_rotation(
                record_id="key-rotated-same",
                old_name="key-old",
                new_name="key-old",
                signers=("key-old",),
            )
        )
    },
    args=LIFECYCLE_ARGS,
    notes="A rotation must actually change the key; old_key == new_key is "
    "E_KEY_ROTATION_KEYS invalid (§7.2).",
)


# ---------------------------------------------------------------------------
# integrity-levels cases (§11.2/§12, L0/L1/L2)
# ---------------------------------------------------------------------------

LEVEL_ARGS = ("--keys", "@keyset")
TSA_CERT = lambda: (TSA_DIR / TSA_CERT_NAME).read_bytes()  # noqa: E731


def _level_files_with_tsr(
    case_dir: Path,
    records: Sequence[dict[str, Any]],
    *,
    level: str,
    imprint_hex: str | None = None,
    timestamp_rel: str = "signatures/timestamp-1.tsr",
) -> dict[str, bytes]:
    """Internal container files of *level* with one committed TSR entry."""
    files = recordlib.build_container(
        records, level=level, created_at=recordlib.T0, manifest_signers=("human-1",)
    )
    manifest_value = parse(files["manifest.json"])
    manifest_bytes = canonical(manifest_value)
    manifest_digest_value = recordlib.manifest_digest(manifest_bytes)
    imprint = (
        imprint_hex
        if imprint_hex is not None
        else manifest_digest_value[len("sha256:") :]
    )
    tsr_bytes = tsr_fixture(case_dir, "container/" + timestamp_rel, imprint)
    recordlib.seal_container(
        files,
        manifest_value,
        manifest_signers=("human-1",),
        timestamp_files={timestamp_rel: tsr_bytes},
    )
    return files


def _l2_files(case_dir: Path, *, imprint_hex: str | None = None) -> dict[str, bytes]:
    """Case files of the L2 positive/trust cases (container + test TSA cert)."""
    internal = _level_files_with_tsr(case_dir, SIMPLE_RECORDS(), level="L2", imprint_hex=imprint_hex)
    return {**wrap(internal), TSA_CERT_NAME: TSA_CERT()}


def _compromise_rescue_files(case_dir: Path) -> dict[str, bytes]:
    """L2 container where a verified timestamp rescues a compromised-key signature."""
    effective_at = "2026-12-01T00:00:00.000Z"
    recorded_at = "2027-01-01T00:00:00.000Z"
    records = [
        recordlib.key_revocation(
            "key-compromised",
            reason="key-compromise",
            effective_at=effective_at,
            recorded_at=effective_at,
            signer_name="human-1",
            record_id="key-revoked-key-compromised",
        ),
        record_signed_by("key-compromised", "record-before-compromise", recorded_at=recorded_at),
    ]
    internal = _level_files_with_tsr(case_dir, records, level="L2")
    return {**wrap(internal), TSA_CERT_NAME: TSA_CERT()}


declare(
    "integrity-levels",
    "l0-valid",
    "container",
    "container",
    "valid",
    build=lambda case_dir: container(SIMPLE_RECORDS(), level="L0"),
    args=LEVEL_ARGS,
    expected_container={
        "level_claimed": "L0",
        "level_verified": "L0",
        "chain": {"status": "absent"},
    },
    notes="L0 positive: only the export-time container signature, no internal chain "
    "claim and no timestamp; level_verified is L0 and chain.status is 'absent'.",
)

declare(
    "integrity-levels",
    "l1-valid",
    "container",
    "container",
    "valid",
    build=lambda case_dir: container(SIMPLE_RECORDS(), level="L1"),
    args=LEVEL_ARGS,
    notices=("N_CHAIN_CLAIM_UNVERIFIED",),
    expected_container={
        "level_claimed": "L1",
        "level_verified": "L0",
        "chain": {"status": "unverified"},
    },
    notes="L1 positive: chain head plus chain_index on every record is structurally "
    "complete, but an offline verifier cannot recompute an exported internal chain, "
    "so it must report level_verified=L0 and the notice N_CHAIN_CLAIM_UNVERIFIED "
    "(§11.2, Q9) instead of claiming the chain was verified.",
)

declare(
    "integrity-levels",
    "l1-no-head",
    "container",
    "container",
    "invalid",
    errors=("E_MANIFEST_L1_NO_HEAD",),
    build=lambda case_dir: _l1_without_chain(),
    args=LEVEL_ARGS,
    notes="A manifest claiming L1 without manifest.chain is structurally incomplete "
    "(§11.2, E_MANIFEST_L1_NO_HEAD); the manifest digest and signature are valid.",
)

declare(
    "integrity-levels",
    "l1-no-position",
    "container",
    "container",
    "invalid",
    errors=("E_MANIFEST_L1_NO_POSITION",),
    build=lambda case_dir: _l1_without_position(),
    args=LEVEL_ARGS,
    notes="A manifest claiming L1 with chain present but a records[] entry lacking "
    "chain_index is incomplete (§11.2, E_MANIFEST_L1_NO_POSITION).",
)

declare(
    "integrity-levels",
    "l2-valid",
    "container",
    "container",
    "valid",
    build=lambda case_dir: _l2_files(case_dir),
    args=("--keys", "@keyset", "--tsa-trust", TSA_CERT_NAME),
    expected_container={"level_claimed": "L2", "level_verified": "L2"},
    records=({"id": "key-declared-human-1", "verdict": "valid", "errors": []},),
    notes="L2 positive (§12): one DER TimeStampResp whose messageImprint is "
    "{sha256, raw 32-byte manifest digest}, CMS signature verified against the "
    "committed test TSA certificate, genTime inside the certificate validity "
    "window; with --tsa-trust the container is L2-verified (valid).",
)

declare(
    "integrity-levels",
    "l2-no-timestamp",
    "container",
    "container",
    "invalid",
    errors=("E_MANIFEST_L2_NO_TIMESTAMP",),
    build=lambda case_dir: container(SIMPLE_RECORDS(), level="L2"),
    args=LEVEL_ARGS,
    notes="A manifest claiming L2 must list at least one RFC 3161 timestamp (§11.2, "
    "E_MANIFEST_L2_NO_TIMESTAMP); existing .tsr-like files are not allowed to be "
    "claimed implicitly.",
)

declare(
    "integrity-levels",
    "l2-without-trust",
    "container",
    "container",
    "unverifiable",
    errors=("E_TS_UNTRUSTED",),
    build=lambda case_dir: wrap(
        _level_files_with_tsr(case_dir, SIMPLE_RECORDS(), level="L2")
    ),
    args=LEVEL_ARGS,
    notes="Same L2 container without --tsa-trust: the timestamp is "
    "'present-unverified' and the container MUST be unverifiable E_TS_UNTRUSTED, "
    "never valid, even though the TSR file exists and parses (§12, §14.4).",
)

declare(
    "integrity-levels",
    "l2-imprint-mismatch",
    "container",
    "container",
    "invalid",
    errors=("E_TS_IMPRINT",),
    build=lambda case_dir: _l2_files(
        case_dir, imprint_hex=hashlib.sha256(b"wrong imprint").hexdigest()
    ),
    args=("--keys", "@keyset", "--tsa-trust", TSA_CERT_NAME),
    notes="The timestamp token's messageImprint.hashedMessage is not the raw 32-byte "
    "manifest digest (§12, E_TS_IMPRINT); a timestamp over some other document "
    "proves nothing about this manifest.",
)

declare(
    "integrity-levels",
    "l2-ts-file-digest",
    "container",
    "container",
    "invalid",
    errors=("E_TS_FILE",),
    build=lambda case_dir: _l2_bad_file_digest(case_dir),
    args=("--keys", "@keyset", "--tsa-trust", TSA_CERT_NAME),
    notes="The signature file lists a timestamp digest that the committed .tsr "
    "bytes do not hash to (§11.3, E_TS_FILE): the listed timestamp is not the file "
    "that is present.",
)

declare(
    "integrity-levels",
    "l0-with-timestamp",
    "container",
    "container",
    "invalid",
    errors=("E_MANIFEST_LEVEL",),
    build=lambda case_dir: wrap(_l0_with_timestamp(case_dir)),
    args=LEVEL_ARGS,
    notes="A container that carries a timestamp must claim L2; L0 with timestamps is "
    "a level/contents contradiction (§11.2/§12, E_MANIFEST_LEVEL).",
)


# === END CASE SECTIONS ===


# ---------------------------------------------------------------------------
# Case writing / checking
# ---------------------------------------------------------------------------


def _manifest_id_kind_mismatch_files() -> dict[str, bytes]:
    """A container whose manifest entry kind contradicts its record envelope."""
    built = recordlib.build_container(SIMPLE_RECORDS())

    def mutator(manifest: dict[str, Any]) -> dict[str, Any]:
        result = dict(manifest)
        entries = [dict(entry) for entry in result["records"]]
        entries[0]["kind"] = "weave.key.revoked"
        result["records"] = entries
        return result

    return recordlib.mutate_manifest(built, mutator, resign_with=("human-1",))


def _record_extra_files() -> dict[str, bytes]:
    """A container with one extra records/ file that the manifest does not list."""
    extra = note("container-extra")
    files = recordlib.build_container(SIMPLE_RECORDS())
    files["records/%s.json" % recordlib.record_digest(extra)[len("sha256:") :]] = canonical(
        extra
    )
    return files


def _blobs_mismatch_files() -> dict[str, bytes]:
    """A container whose blob bytes no longer match manifest.blobs."""
    files = recordlib.build_container(
        SIMPLE_RECORDS(), blobs=[(b"blob data\n", b"")]
    )
    blob_path = [path for path in files if path.startswith("blobs/sha256/")][0]
    files[blob_path] = b"tampered blob bytes\n"
    return files



def _l1_without_chain() -> dict[str, bytes]:
    """Internal container files of an L1 manifest that claims no chain at all."""
    records = SIMPLE_RECORDS()
    files: dict[str, bytes] = {}
    for record in records:
        digest_hex = recordlib.record_digest(record)[len("sha256:") :]
        files["records/%s.json" % digest_hex] = canonical(record)
    manifest_value = recordlib.build_manifest(
        records, level="L1", chain=None, chain_indices=[0]
    )
    recordlib.seal_container(files, manifest_value, manifest_signers=("human-1",))
    return files


def _l1_without_position() -> dict[str, bytes]:
    """Internal container files of an L1 manifest with one record missing chain_index."""
    built = recordlib.build_container(SIMPLE_RECORDS(), level="L1")

    def mutator(manifest: dict[str, Any]) -> dict[str, Any]:
        result = dict(manifest)
        entries = [dict(entry) for entry in result["records"]]
        entries[0].pop("chain_index", None)
        result["records"] = entries
        return result

    return recordlib.mutate_manifest(built, mutator, resign_with=("human-1",))


def _l2_bad_file_digest(case_dir: Path) -> dict[str, bytes]:
    """L2 case files whose sig file lists a timestamp digest the TSR does not have."""
    internal = _level_files_with_tsr(case_dir, SIMPLE_RECORDS(), level="L2")
    internal = mutate_sigfile(
        internal,
        lambda sigfile: {
            **sigfile,
            "timestamps": [
                {**entry, "digest": "sha256:" + "99" * 32}
                for entry in sigfile["timestamps"]
            ],
        },
    )
    return {**wrap(internal), TSA_CERT_NAME: TSA_CERT()}


def _l0_with_timestamp(case_dir: Path) -> dict[str, bytes]:
    """Internal container files of an L0 manifest that also carries a timestamp."""
    files = recordlib.build_container(SIMPLE_RECORDS(), level="L0")
    manifest_value = parse(files["manifest.json"])
    imprint = hashlib.sha256(b"l0-with-timestamp fixture").hexdigest()
    tsr_bytes = tsr_fixture(case_dir, "container/signatures/timestamp-1.tsr", imprint)
    recordlib.seal_container(
        files,
        manifest_value,
        manifest_signers=("human-1",),
        timestamp_files={"signatures/timestamp-1.tsr": tsr_bytes},
    )
    return files


def build_expected(case: Case, files: dict[str, bytes]) -> dict[str, Any]:
    expected: dict[str, Any] = {
        "id": case.id,
        "category": case.category,
        "target": case.target,
        "input": case.input,
        "verdict": case.verdict,
        "errors": list(case.errors),
    }
    if case.notices:
        expected["notices"] = list(case.notices)
    if case.args:
        expected["args"] = list(case.args)
    if case.expected_digest:
        if case.target != "record":
            raise SystemExit("%s: expected_digest is only for record targets" % case.id)
        record = parse(files[case.input])
        expected["expected_digest"] = recordlib.record_digest(record)
    if case.expected_resolution is not None:
        expected["expected_resolution"] = list(case.expected_resolution)
    if case.expected_container is not None:
        expected["expected_container"] = case.expected_container
    if case.records is not None:
        expected["records"] = list(case.records)
    if case.notes:
        expected["notes"] = case.notes
    return expected


def validate_case(case: Case, files: dict[str, bytes]) -> None:
    if case.verdict not in {"valid", "invalid", "unverifiable", "erased"}:
        raise SystemExit("%s: invalid verdict %r" % (case.id, case.verdict))
    if case.verdict == "invalid" and not case.errors:
        raise SystemExit("%s: invalid case must name expected error codes" % case.id)
    if case.verdict == "valid" and case.errors:
        raise SystemExit("%s: valid case may not expect error codes" % case.id)
    if case.target not in {"record", "container"}:
        raise SystemExit("%s: invalid target %r" % (case.id, case.target))
    if case.target == "record":
        if case.input not in files:
            raise SystemExit(
                "%s: input %r not among built files %s"
                % (case.id, case.input, sorted(files))
            )
    elif case.input == "container":
        if "container/manifest.json" not in files and "E_MANIFEST_MISSING" not in case.errors:
            raise SystemExit("%s: container case has no container/manifest.json" % case.id)
    elif case.input == "container.zip":
        if "container.zip" not in files:
            raise SystemExit("%s: zip case has no container.zip" % case.id)
    else:
        raise SystemExit("%s: container input must be container/container.zip" % case.id)
    for path in files:
        relative = Path(path)
        if relative.is_absolute() or ".." in relative.parts:
            raise SystemExit("%s: unsafe case file path %r" % (case.id, path))


def write_all(*, check: bool, only: str | None = None) -> list[str]:
    problems: list[str] = []
    selected = [case for case in CASES if only is None or case.category == only]
    seen: set[str] = set()
    for case in selected:
        if case.id in seen:
            raise SystemExit("duplicate case id %r" % case.id)
        seen.add(case.id)
        files = case.build(case.case_dir)
        # Builders may return internal container paths (manifest.json, records/...);
        # wrap those under the case-relative container/ dir that the runner reads.
        if (
            case.target == "container"
            and case.input == "container"
            and "manifest.json" in files
        ):
            files = wrap(files)
        validate_case(case, files)
        expected = build_expected(case, files)
        target_files = dict(files)
        target_files["expected.json"] = canonical(expected)
        case_dir = case.case_dir
        if check:
            if not case_dir.is_dir():
                problems.append("missing case dir %s" % case_dir)
                continue
            existing = {
                str(path.relative_to(case_dir)): path.read_bytes()
                for path in case_dir.rglob("*")
                if path.is_file()
            }
            for name, data in sorted(target_files.items()):
                if name not in existing:
                    problems.append("missing %s/%s" % (case_dir, name))
                elif existing[name] != data:
                    problems.append("content mismatch %s/%s" % (case_dir, name))
            for name in sorted(existing):
                if name not in target_files:
                    problems.append("unexpected file %s/%s" % (case_dir, name))
            continue
        if case_dir.exists():
            for path in sorted(case_dir.rglob("*"), reverse=True):
                if path.is_file() or path.is_symlink():
                    path.unlink()
                elif path.is_dir():
                    path.rmdir()
        case_dir.mkdir(parents=True, exist_ok=True)
        for name, data in target_files.items():
            destination = case_dir / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
    return problems



# ---------------------------------------------------------------------------
# Frozen regression set (`vectors/README.md`, gate 7)
# ---------------------------------------------------------------------------

FREEZE_VERSION = "v0.1"


def _all_case_expected() -> list[dict[str, Any]]:
    """Every generated case under vectors/<category>/<case-id>/ (frozen excluded)."""
    rows: list[dict[str, Any]] = []
    for expected_path in sorted(VECTORS_DIR.glob("*/*/expected.json")):
        if "frozen" in expected_path.parts:
            continue
        expected = wcj.parse_strict(expected_path.read_bytes())
        rows.append(
            {
                "id": expected["id"],
                "category": expected["category"],
                "case_dir": expected_path.parent,
                "expected": expected,
            }
        )
    return rows


def select_frozen_cases(rows: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    """All positive cases plus one deterministic negative per error code family."""
    selected: dict[str, dict[str, Any]] = {}
    for row in rows:
        if row["expected"]["verdict"] in ("valid", "erased"):
            selected[row["id"]] = row
    by_code: dict[str, dict[str, Any]] = {}
    for row in rows:
        for code in row["expected"].get("errors", []):
            by_code.setdefault(code, row)
    for code in sorted(by_code):
        selected.setdefault(by_code[code]["id"], by_code[code])
    return [selected[case_id] for case_id in sorted(selected)]


def freeze_cases(*, source_commit: str, freeze_date: str) -> int:
    """Copy the representative set verbatim into vectors/frozen/<version>/."""
    rows = _all_case_expected()
    selected = select_frozen_cases(rows)
    destination = VECTORS_DIR / "frozen" / FREEZE_VERSION
    if destination.exists():
        for path in sorted(destination.rglob("*"), reverse=True):
            if path.is_file() or path.is_symlink():
                path.unlink()
            elif path.is_dir():
                path.rmdir()
    destination.mkdir(parents=True, exist_ok=True)

    category_counts: dict[str, int] = {}
    verdict_counts: dict[str, int] = {}
    for row in selected:
        case_dir: Path = row["case_dir"]
        target = destination / row["category"] / case_dir.name
        target.mkdir(parents=True, exist_ok=True)
        for source in case_dir.rglob("*"):
            if not source.is_file():
                continue
            relative = source.relative_to(case_dir)
            destination_file = target / relative
            destination_file.parent.mkdir(parents=True, exist_ok=True)
            destination_file.write_bytes(source.read_bytes())
        category_counts[row["category"]] = category_counts.get(row["category"], 0) + 1
        verdict = row["expected"]["verdict"]
        verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1

    lines = [
        "<!-- SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com> -->",
        "<!-- SPDX-License-Identifier: Apache-2.0 -->",
        "",
        "# Frozen conformance vectors, %s" % FREEZE_VERSION,
        "",
        "> **The conclusions in this directory must never change** (`vectors/README.md`,",
        "> K3). A later implementation or profile change must add new vectors; these",
        "> cases are copied verbatim from a gated state of the repository and keep",
        "> their expected verdicts, error codes, notices, digests and container",
        "> bytes forever.",
        "",
        "- Freeze date: %s" % freeze_date,
        "- Source repository state: commit `%s`" % source_commit,
        "- Generated by: `tools/gen_vectors_extra.py --freeze` (only the copy step;",
        "  the cases themselves were generated by the independent generators).",
        "- Selection rule: **every positive case** (`valid`/`erased`) plus, for each",
        "  error code that appears in any case, the lexicographically first case that",
        "  expects it. This keeps at least one negative per registered error code",
        "  while remaining deterministic.",
        "",
        "| Category | Cases |",
        "|---|---:|",
    ]
    for category in sorted(category_counts):
        lines.append("| `%s` | %d |" % (category, category_counts[category]))
    lines.extend(
        [
            "| **total** | **%d** |" % len(selected),
            "",
            "Verdicts: "
            + ", ".join(
                "`%s` %d" % (verdict, verdict_counts[verdict])
                for verdict in sorted(verdict_counts)
            )
            + ".",
            "",
            "Run the frozen regression set with:",
            "",
            "```bash",
            "hyphaweave-verify vectors vectors/frozen/%s" % FREEZE_VERSION,
            "```",
            "",
            "`SHA256SUMS` lists the SHA-256 of every file in this directory (except",
            "itself); `--check`-style verification of the inputs against it proves the",
            "frozen bytes were not edited.",
            "",
        ]
    )
    (destination / "FROZEN.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    digest_lines = []
    for path in sorted(destination.rglob("*")):
        if not path.is_file() or path.name == "SHA256SUMS":
            continue
        digest_lines.append(
            "%s  %s" % (hashlib.sha256(path.read_bytes()).hexdigest(), path.relative_to(destination).as_posix())
        )
    (destination / "SHA256SUMS").write_text("\n".join(digest_lines) + "\n", encoding="utf-8")
    print(
        "wrote %d frozen case(s) under %s (%d categories)"
        % (len(selected), destination.relative_to(REPO_ROOT), len(category_counts))
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="compare regenerated output with the files on disk (exit 1 on drift)",
    )
    parser.add_argument(
        "--bootstrap",
        action="store_true",
        help="create missing committed RFC 3161 timestamp fixtures with openssl ts",
    )
    parser.add_argument(
        "--only",
        metavar="CATEGORY",
        help="regenerate one category only (erasure|grant|key-lifecycle|container|"
        "integrity-levels)",
    )
    parser.add_argument(
        "--freeze",
        action="store_true",
        help="copy the representative case set into vectors/frozen/v0.1 (gate 7)",
    )
    parser.add_argument(
        "--frozen-source-commit",
        metavar="SHA",
        help="source repository commit recorded in FROZEN.md (required with --freeze)",
    )
    parser.add_argument(
        "--freeze-date",
        metavar="YYYY-MM-DD",
        help="freeze date recorded in FROZEN.md (default: today, UTC)",
    )
    arguments = parser.parse_args(argv)
    if arguments.freeze:
        if not arguments.frozen_source_commit:
            print("--freeze requires --frozen-source-commit SHA", file=sys.stderr)
            return 2
        import datetime

        freeze_date = arguments.freeze_date or datetime.datetime.now(
            datetime.timezone.utc
        ).strftime("%Y-%m-%d")
        return freeze_cases(
            source_commit=arguments.frozen_source_commit, freeze_date=freeze_date
        )
    _CURRENT_CONTEXT["bootstrap"] = arguments.bootstrap
    problems = write_all(check=arguments.check, only=arguments.only)
    if "hyphaweave_verify" in sys.modules:
        raise SystemExit("vector generator imported the reference verifier")
    if problems:
        for problem in problems:
            print("FAIL: %s" % problem, file=sys.stderr)
        return 1
    count = len([case for case in CASES if arguments.only in (None, case.category)])
    if arguments.check:
        print("ok: %d extra vector case(s) match the generator" % count)
    else:
        print("wrote %d extra vector case(s) under vectors/" % count)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
