#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0
"""Offline self-check for the weave-record/1 JSON Schema set (CI gate "Schema self-check").

What it checks
--------------
1. Every ``schemas/**/*.json`` file is valid JSON without duplicate members, is a
   valid JSON Schema Draft 2020-12, and its ``$id`` is
   ``https://inceptless.com/hyphaweave/schemas/v1/<relative path>``.
2. A local, network-free resource registry is built from those files, so every
   relative cross-file ``$ref`` (``ref.json``, ``manifest.json#/$defs/origin``,
   ``../envelope.json``, ...) resolves against the checked-in schemas only.
3. Every *positive* vector input is validated against the appropriate schema:
   - target=record: the input file against its registered kind schema, against
     ``envelope.json`` for an opaque (unregistered) kind, or against
     ``kinds/weave.erased.json`` for the erased placeholder;
   - target=container: ``manifest.json``, ``signatures/manifest.sig.json`` and
     every ``records/*.json`` file.
4. Every vector whose ``expected.json`` lists a structural error code
   (``E_ENV_*``, ``E_KIND_BODY_SCHEMA``, ``E_MANIFEST_SCHEMA``,
   ``E_MANIFEST_RECORDS``) is rejected by the schema layer.
5. ``expected.json`` files and ``vectors/index.json`` match the case layout in `vectors/README.md`.

The "schema layer" is JSON Schema validation plus a small, documented set of
supplementary structural predicates for rules Draft 2020-12 cannot express:

- ``manifest.records`` sorted by digest ascending with unique digests;
- ``manifest.records[]`` ``id``/``kind`` equal to the record file they list;
- ``manifest.records[].chain_index`` unique for L1/L2;
- ``manifest.blobs`` sorted by digest ascending with unique digests;
- signature arrays sorted by key ascending with unique keys (record ``sigs`` and
  the manifest attestation ``signatures``);
- the signature geometry condition per entry (``alg=ed25519`` pairs with an
  ed25519 key id and a 64-byte value, other algorithm names with the generic key
  id and generic 1-2048-byte base64url value);
- ``weave.grant`` ``grant.revocation`` key lists with unique ed25519 key ids;
- manifest attestation ``timestamps`` sorted by path ascending with unique paths
  and one acyclic renewal chain (exactly one ``renews=null`` head, every
  ``renews`` path listed, no receipt renewed twice);
- semantically duplicate ``refs`` entries (same ``rel`` and target
  ``origin``/``id``/``digest`` even if the ``hints`` differ).

Every other rule JSON Schema cannot express (cross-field equalities, key-id
derivation, Ed25519 semantics, canonical bytes, ...) belongs to the verifier and
is listed in ``schemas/README.md``.

Usage
-----
::

    ./.venv/bin/python tools/check_schemas.py
    ./.venv/bin/python tools/check_schemas.py --vectors vectors --schemas schemas

Exit code 0 means every check passed; anything else prints the problems found.
No network access, no wall clock, deterministic output.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import zipfile
from dataclasses import dataclass
from importlib import metadata
from pathlib import Path
from typing import Any, Iterable, Iterator

try:
    from jsonschema import Draft202012Validator
    from referencing import Registry, Resource
    from referencing.jsonschema import DRAFT202012
except ImportError as exc:  # pragma: no cover - environment problem
    print(
        "schema-check: cannot import jsonschema/referencing (%s); "
        "run with ./.venv/bin/python tools/check_schemas.py" % (exc,),
        file=sys.stderr,
    )
    raise SystemExit(1)

SCHEMA_BASE = "https://inceptless.com/hyphaweave/schemas/v1/"
PINNED_JSONSCHEMA = "4.23.0"

ENVELOPE_REL = "envelope.json"
REF_REL = "ref.json"
MANIFEST_REL = "manifest.json"
ERASED_KIND = "weave.erased"
ERASED_SCHEMA_REL = "kinds/weave.erased.json"
KIND_SCHEMA_FILES: dict[str, str] = {
    "weave.key.declared": "kinds/weave.key.declared.json",
    "weave.key.rotated": "kinds/weave.key.rotated.json",
    "weave.key.revoked": "kinds/weave.key.revoked.json",
    "weave.grant": "kinds/weave.grant.json",
    "weave.consent.granted": "kinds/weave.consent.granted.json",
    "weave.consent.revoked": "kinds/weave.consent.revoked.json",
    "weave.erasure": "kinds/weave.erasure.json",
}
EXPECTED_SCHEMA_RELS = frozenset(
    {ENVELOPE_REL, REF_REL, MANIFEST_REL, ERASED_SCHEMA_REL,
     *KIND_SCHEMA_FILES.values()}
)

VECTOR_CATEGORIES = frozenset(
    {
        "jcs",
        "digest",
        "sig",
        "ref",
        "stage",
        "actor",
        "labels",
        "erasure",
        "grant",
        "key-lifecycle",
        "container",
        "integrity-levels",
    }
)
SKIPPED_VECTOR_DIRS = frozenset({"keys", "external", "frozen"})
TARGETS = ("record", "container")
VERDICTS = ("valid", "invalid", "unverifiable", "erased")
RESOLUTION_STATES = ("found", "moved", "missing", "erased", "unverifiable")

CODE_RE = re.compile(r"^[EN]_[A-Z0-9_]+$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
RECORD_MIRROR_FIELDS = ("id", "category", "target", "input", "verdict")

# Signature geometry (Q13 algorithm agility): the JSON Schema already encodes
# these conditions; the predicates below re-check them as structural fallbacks.
ED25519_KEY_RE = re.compile(r"^ed25519:[0-9a-f]{32}$")
ED25519_VALUE_RE = re.compile(r"^[A-Za-z0-9_-]{85}[AQgw]$")
GENERIC_KEY_RE = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*:[0-9a-f]{1,128}$")
GENERIC_VALUE_RES = (
    re.compile(r"^(?:[A-Za-z0-9_-]{4}){1,682}$"),
    re.compile(r"^(?:[A-Za-z0-9_-]{4}){0,682}[A-Za-z0-9_-][AQgw]$"),
    re.compile(r"^(?:[A-Za-z0-9_-]{4}){0,682}[A-Za-z0-9_-]{2}[AEIMQUYcgkosw048]$"),
)
TIMESTAMP_PATH_RE = re.compile(r"^signatures/timestamp-[1-9][0-9]*\.tsr$")


# --------------------------------------------------------------------------- #
# Problems and small helpers
# --------------------------------------------------------------------------- #


class InputProblem(Exception):
    """A file could not be read/parsed as expected."""


def load_json_strict(path: Path) -> Any:
    """Load a JSON file, rejecting duplicate member names and invalid UTF-8."""

    def no_duplicate_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        seen: set[str] = set()
        for key, _value in pairs:
            if key in seen:
                raise InputProblem(f"{path.name}: duplicate JSON member name {key!r}")
            seen.add(key)
        return dict(pairs)

    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise InputProblem(f"cannot read {path}: {exc}") from exc
    try:
        return json.loads(text, object_pairs_hook=no_duplicate_members)
    except InputProblem:
        raise
    except json.JSONDecodeError as exc:
        raise InputProblem(f"invalid JSON in {path}: {exc}") from exc


def _ordered_unique_problems(
    values: list[str], what: str, field: str
) -> list[str]:
    """Problems for an array that must be strictly ascending by ``field``."""

    problems: list[str] = []
    if values != sorted(values):
        problems.append(f"{what} are not sorted by {field} ascending")
    duplicates = sorted({value for value in values if values.count(value) > 1})
    if duplicates:
        problems.append(
            f"{what} contain duplicate {field} value(s): {', '.join(duplicates)}"
        )
    return problems


def _unique_problems(values: list[Any], what: str, field: str) -> list[str]:
    problems: list[str] = []
    seen: set[Any] = set()
    duplicates: set[Any] = set()
    for value in values:
        if value in seen:
            duplicates.add(value)
        seen.add(value)
    if duplicates:
        rendered = ", ".join(str(value) for value in sorted(duplicates, key=str))
        problems.append(f"{what} contain duplicate {field} value(s): {rendered}")
    return problems


def _walk_refs(node: Any) -> Iterator[str]:
    """Yield every "$ref" string found anywhere in a schema document."""

    if isinstance(node, dict):
        for key, value in node.items():
            if key == "$ref" and isinstance(value, str):
                yield value
            else:
                yield from _walk_refs(value)
    elif isinstance(node, list):
        for item in node:
            yield from _walk_refs(item)


def _contains_const(node: Any, expected: str) -> bool:
    """True when the schema document contains ``{"const": expected}`` anywhere."""

    if isinstance(node, dict):
        for key, value in node.items():
            if key == "const" and value == expected:
                return True
            if _contains_const(value, expected):
                return True
    elif isinstance(node, list):
        for item in node:
            if _contains_const(item, expected):
                return True
    return False


# --------------------------------------------------------------------------- #
# Schema set and local registry
# --------------------------------------------------------------------------- #


class SchemaSet:
    """The checked-in schema files plus the offline registry that resolves them."""

    def __init__(self, schemas_dir: Path) -> None:
        self.dir = schemas_dir
        self.docs: dict[str, dict[str, Any]] = {}
        self.registry: Registry = Registry()
        self.envelope: Draft202012Validator | None = None
        self.erased: Draft202012Validator | None = None
        self.manifest: Draft202012Validator | None = None
        self.attestation: Draft202012Validator | None = None
        self.kind_validators: dict[str, Draft202012Validator] = {}

    # -- loading ----------------------------------------------------------- #

    def load(self) -> list[str]:
        problems: list[str] = []
        if not self.dir.is_dir():
            return [f"schemas directory not found: {self.dir}"]
        paths = sorted(path for path in self.dir.rglob("*.json") if path.is_file())
        if not paths:
            return [f"no schema files found under {self.dir}"]

        seen_ids: dict[str, str] = {}
        resources: list[tuple[str, Resource[Any]]] = []
        for path in paths:
            rel = path.relative_to(self.dir).as_posix()
            if rel not in EXPECTED_SCHEMA_RELS:
                problems.append(
                    f"unexpected schema file {rel} under {self.dir}; registered "
                    f"files are: {', '.join(sorted(EXPECTED_SCHEMA_RELS))}"
                )
                continue
            try:
                schema = load_json_strict(path)
            except InputProblem as exc:
                problems.append(str(exc))
                continue
            if not isinstance(schema, dict):
                problems.append(f"{rel}: schema root must be a JSON object")
                continue
            expected_id = SCHEMA_BASE + rel
            schema_id = schema.get("$id")
            if schema_id != expected_id:
                problems.append(
                    f"{rel}: $id is {schema_id!r}, expected {expected_id!r}"
                )
            if isinstance(schema_id, str) and schema_id in seen_ids:
                problems.append(
                    f"{rel}: $id {schema_id!r} is already used by {seen_ids[schema_id]}"
                )
            if isinstance(schema_id, str):
                seen_ids[schema_id] = rel
            try:
                Draft202012Validator.check_schema(schema)
            except Exception as exc:  # jsonschema raises SchemaError
                problems.append(f"{rel}: not a valid Draft 2020-12 schema: {exc}")
            self.docs[rel] = schema
            if isinstance(schema_id, str):
                resources.append(
                    (
                        schema_id,
                        Resource.from_contents(
                            schema, default_specification=DRAFT202012
                        ),
                    )
                )

        missing = sorted(EXPECTED_SCHEMA_RELS.difference(self.docs))
        for rel in missing:
            problems.append(f"missing expected schema file {rel}")
        if problems:
            # A partial registry would make every later $ref unreliable.
            return problems

        self.registry = Registry().with_resources(resources)
        try:
            self.envelope = self._validator(self.docs[ENVELOPE_REL])
            self.erased = self._validator(self.docs[ERASED_SCHEMA_REL])
            self.manifest = self._validator(self.docs[MANIFEST_REL])
            self.attestation = Draft202012Validator(
                {
                    "$schema": "https://json-schema.org/draft/2020-12/schema",
                    "$ref": SCHEMA_BASE + MANIFEST_REL + "#/$defs/manifest_attestation",
                },
                registry=self.registry,
            )
            self.kind_validators = {
                kind: self._validator(self.docs[rel])
                for kind, rel in KIND_SCHEMA_FILES.items()
            }
        except Exception as exc:  # pragma: no cover - defensive
            problems.append(f"could not build validators: {exc}")
            return problems

        problems.extend(self._check_kind_linkage())
        return problems

    def _validator(self, schema: dict[str, Any]) -> Draft202012Validator:
        return Draft202012Validator(schema, registry=self.registry)

    def _check_kind_linkage(self) -> list[str]:
        problems: list[str] = []
        for kind, rel in KIND_SCHEMA_FILES.items():
            schema = self.docs[rel]
            if not _contains_const(schema, kind):
                problems.append(
                    f"{rel}: no {{'const': {kind!r}}} found; kind schema must pin its kind"
                )
            refs = list(_walk_refs(schema))
            if "../envelope.json" not in refs:
                problems.append(
                    f"{rel}: does not $ref ../envelope.json; registered kind "
                    "schemas must extend the record envelope"
                )
        erased_schema = self.docs[ERASED_SCHEMA_REL]
        if not _contains_const(erased_schema, ERASED_KIND):
            problems.append(
                f"{ERASED_SCHEMA_REL}: must pin a const of {ERASED_KIND!r}"
            )
        if any(ref == "../envelope.json" for ref in _walk_refs(erased_schema)):
            problems.append(
                f"{ERASED_SCHEMA_REL}: the erased placeholder is not "
                "a normal envelope and must not $ref ../envelope.json"
            )
        return problems

    # -- validation -------------------------------------------------------- #

    def violations(
        self, instance: Any, validator: Draft202012Validator, limit: int = 8
    ) -> list[str]:
        """Human-readable schema violations, deterministic and bounded."""

        try:
            errors = list(validator.iter_errors(instance))
        except Exception as exc:  # pragma: no cover - defensive
            return [f"validation raised {type(exc).__name__}: {exc}"]
        errors.sort(key=lambda error: [str(part) for part in error.absolute_path])
        messages: list[str] = []
        for error in errors[:limit]:
            location = "/".join(str(part) for part in error.absolute_path) or "<root>"
            messages.append(f"{location}: {error.message}")
        if len(errors) > limit:
            messages.append(f"... and {len(errors) - limit} more schema violation(s)")
        return messages


# --------------------------------------------------------------------------- #
# Supplementary structural predicates (rules JSON Schema cannot express)
# --------------------------------------------------------------------------- #


def _signature_geometry_problems(entries: list[Any], what: str) -> list[str]:
    """Re-check the per-entry signature geometry condition structurally.

    ``alg`` names the algorithm; ``alg == "ed25519"`` requires an ed25519 key id
    and a 64-byte value, every other algorithm token accepts the generic key id
    (algorithm token + 1-128 lowercase hex) and strict unpadded base64url of
    1-2048 bytes. Entries with unknown algorithms stay structurally valid and
    are ignored semantically by H0 verifiers.
    """

    problems: list[str] = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            continue
        alg = entry.get("alg")
        key = entry.get("key")
        value = entry.get("value")
        if not (
            isinstance(alg, str) and isinstance(key, str) and isinstance(value, str)
        ):
            continue
        if alg == "ed25519":
            if not ED25519_KEY_RE.match(key):
                problems.append(
                    f"{what}[{index}].key is not an ed25519 key id although "
                    "alg is ed25519"
                )
            if not ED25519_VALUE_RE.match(value):
                problems.append(
                    f"{what}[{index}].value is not a strict 64-byte unpadded "
                    "base64url value although alg is ed25519"
                )
        else:
            if not GENERIC_KEY_RE.match(key):
                problems.append(
                    f"{what}[{index}].key does not match the generic key id "
                    f"shape (algorithm token + 1-128 lowercase hex) for alg {alg!r}"
                )
            if not any(rx.match(value) for rx in GENERIC_VALUE_RES):
                problems.append(
                    f"{what}[{index}].value is not strict unpadded base64url of "
                    f"1-2048 bytes for alg {alg!r}"
                )
    return problems


def envelope_supplement(doc: Any) -> list[str]:
    problems: list[str] = []
    if not isinstance(doc, dict):
        return problems

    refs = doc.get("refs")
    if isinstance(refs, list):
        seen: dict[tuple[str, str, str, str, str], int] = {}
        for index, entry in enumerate(refs):
            if not isinstance(entry, dict):
                continue
            rel = entry.get("rel")
            ref = entry.get("ref")
            if not isinstance(rel, str) or not isinstance(ref, dict):
                continue
            origin = ref.get("origin")
            if not isinstance(origin, dict):
                continue
            project = origin.get("project")
            instance = origin.get("instance")
            ref_id = ref.get("id")
            digest = ref.get("digest")
            if not all(
                isinstance(value, str)
                for value in (project, instance, ref_id, digest)
            ):
                continue
            marker = (rel, project, instance, ref_id, digest)  # type: ignore[arg-type]
            if marker in seen:
                problems.append(
                    f"refs[{index}] duplicates refs[{seen[marker]}] "
                    "(same rel and target origin/id/digest)"
                )
            else:
                seen[marker] = index

    sigs = doc.get("sigs")
    if isinstance(sigs, list):
        keys = [entry.get("key") for entry in sigs if isinstance(entry, dict)]
        if len(keys) == len(sigs) and all(isinstance(key, str) for key in keys):
            problems.extend(
                _ordered_unique_problems(keys, "sigs", "key")  # type: ignore[arg-type]
            )
        problems.extend(_signature_geometry_problems(sigs, "sigs"))
    return problems


def manifest_supplement(doc: Any) -> list[str]:
    problems: list[str] = []
    if not isinstance(doc, dict):
        return problems

    records = doc.get("records")
    if isinstance(records, list) and all(isinstance(entry, dict) for entry in records):
        digests = [entry.get("digest") for entry in records]
        if all(isinstance(digest, str) for digest in digests):
            problems.extend(
                _ordered_unique_problems(
                    digests, "manifest.records", "digest"  # type: ignore[arg-type]
                )
            )
        if doc.get("level") in ("L1", "L2"):
            indexes = [
                entry.get("chain_index")
                for entry in records
                if "chain_index" in entry
            ]
            if indexes and all(
                isinstance(value, int) and not isinstance(value, bool)
                for value in indexes
            ):
                problems.extend(
                    _unique_problems(indexes, "manifest.records", "chain_index")
                )

    blobs = doc.get("blobs")
    if isinstance(blobs, list) and all(isinstance(entry, dict) for entry in blobs):
        digests = [entry.get("digest") for entry in blobs]
        if all(isinstance(digest, str) for digest in digests):
            problems.extend(
                _ordered_unique_problems(
                    digests, "manifest.blobs", "digest"  # type: ignore[arg-type]
                )
            )
    return problems


def _renewal_chain_problems(timestamps: list[Any]) -> list[str]:
    """Structural sanity of the timestamp re-stamping chain.

    Exactly one receipt is the chain head (``renews`` is null); every other
    ``renews`` value names a listed receipt, no receipt is renewed twice and the
    links are acyclic, so the listed receipts form one path ending at the head.
    The array order is the required path order; it is independent of the chain
    order, which is defined by the ``renews`` links. Imprint and CMS
    verification of the chain belong to the verifier.
    """

    problems: list[str] = []
    if not timestamps or not all(isinstance(entry, dict) for entry in timestamps):
        return problems
    if not all("renews" in entry for entry in timestamps):
        return problems
    paths = [entry.get("path") for entry in timestamps]
    if not all(isinstance(path, str) for path in paths):
        return problems
    listed = set(paths)
    renews = [entry.get("renews") for entry in timestamps]
    heads = [index for index, value in enumerate(renews) if value is None]
    if len(heads) != 1:
        problems.append(
            "manifest timestamps must contain exactly one chain head "
            f"(renews=null), found {len(heads)}"
        )
    targets: list[str] = []
    for index, renews_path in enumerate(renews):
        if renews_path is None:
            continue
        if not isinstance(renews_path, str):
            problems.append(
                f"manifest timestamps[{index}].renews must be a timestamp path or null"
            )
            continue
        targets.append(renews_path)
        if renews_path not in listed:
            problems.append(
                f"manifest timestamps[{index}].renews points to {renews_path!r} "
                "which is not listed"
            )
    branched = sorted({target for target in targets if targets.count(target) > 1})
    if branched:
        problems.append(
            "manifest timestamps renew the same receipt more than once "
            f"(the renewal chain must be single): {', '.join(branched)}"
        )
    # Acycle check: following renews links must terminate at the head.
    parents = {
        entry["path"]: entry.get("renews")
        for entry in timestamps
        if isinstance(entry.get("path"), str)
    }
    for start in parents:
        seen: list[str] = []
        current = parents[start]
        while isinstance(current, str):
            if current in seen or current == start:
                problems.append(
                    f"manifest timestamps renewal chain contains a cycle at {start!r}"
                )
                break
            seen.append(current)
            current = parents.get(current)
    return problems


def attestation_supplement(doc: Any) -> list[str]:
    problems: list[str] = []
    if not isinstance(doc, dict):
        return problems

    signatures = doc.get("signatures")
    if isinstance(signatures, list):
        keys = [entry.get("key") for entry in signatures if isinstance(entry, dict)]
        if len(keys) == len(signatures) and all(
            isinstance(key, str) for key in keys
        ):
            problems.extend(
                _ordered_unique_problems(
                    keys, "manifest signatures", "key"  # type: ignore[arg-type]
                )
            )
        problems.extend(
            _signature_geometry_problems(signatures, "manifest signatures")
        )

    timestamps = doc.get("timestamps")
    if isinstance(timestamps, list):
        paths = [entry.get("path") for entry in timestamps if isinstance(entry, dict)]
        if len(paths) == len(timestamps) and all(
            isinstance(path, str) for path in paths
        ):
            problems.extend(
                _ordered_unique_problems(
                    paths, "manifest timestamps", "path"  # type: ignore[arg-type]
                )
            )
            problems.extend(_renewal_chain_problems(timestamps))
    return problems


# --------------------------------------------------------------------------- #
# Containers (directory or zip), read-only
# --------------------------------------------------------------------------- #


class ContainerReader:
    """Read manifest/attestation/record files from a container directory or zip."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._directory: Path | None = None
        self._zip: zipfile.ZipFile | None = None

    def open(self) -> None:
        if self.path.is_dir():
            self._directory = self.path
            return
        if self.path.is_file() and zipfile.is_zipfile(self.path):
            self._zip = zipfile.ZipFile(self.path)
            return
        raise InputProblem(
            f"container input is neither a directory nor a zip archive: {self.path}"
        )

    def close(self) -> None:
        if self._zip is not None:
            self._zip.close()
            self._zip = None

    def read_text(self, name: str) -> str:
        if self._directory is not None:
            candidate = self._directory / name
            if not candidate.is_file():
                raise InputProblem(f"missing container file {name}")
            try:
                return candidate.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as exc:
                raise InputProblem(f"cannot read {name}: {exc}") from exc
        assert self._zip is not None
        try:
            raw = self._zip.read(name)
        except KeyError as exc:
            raise InputProblem(f"missing container file {name}") from exc
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise InputProblem(f"container file {name} is not UTF-8: {exc}") from exc

    def record_names(self) -> list[str]:
        if self._directory is not None:
            records_dir = self._directory / "records"
            if not records_dir.is_dir():
                return []
            names = {
                "records/" + child.name
                for child in records_dir.iterdir()
                if child.is_file() and child.name.endswith(".json")
            }
        else:
            assert self._zip is not None
            prefix = "records/"
            names = {
                name
                for name in self._zip.namelist()
                if name.startswith(prefix)
                and "/" not in name[len(prefix):]
                and name.endswith(".json")
            }
        return sorted(names)


def read_container_json(
    container: ContainerReader, name: str
) -> tuple[Any | None, list[str]]:
    """Read and parse one container JSON file; returns (document, problems)."""

    try:
        text = container.read_text(name)
    except InputProblem as exc:
        return None, [str(exc)]
    try:
        return json.loads(text), []
    except json.JSONDecodeError as exc:
        return None, [f"{name}: invalid JSON: {exc}"]


def manifest_record_identity_problems(
    container: ContainerReader, manifest: Any
) -> list[str]:
    """manifest.records[] id/kind against the record file they list.

    JSON Schema cannot compare a manifest entry with another file, so this
    supplementary predicate reads ``records/<digest>.json`` and reports an
    entry whose ``id`` or ``kind`` contradicts the record it lists. A missing or
    unreadable record file is not reported here: it belongs to the
    ``E_MANIFEST_RECORD_MISSING`` family, not to ``E_MANIFEST_RECORDS``.
    """

    problems: list[str] = []
    if not isinstance(manifest, dict):
        return problems
    records = manifest.get("records")
    if not isinstance(records, list):
        return problems
    for index, entry in enumerate(records):
        if not isinstance(entry, dict):
            continue
        digest = entry.get("digest")
        entry_id = entry.get("id")
        entry_kind = entry.get("kind")
        if not (
            isinstance(digest, str)
            and isinstance(entry_id, str)
            and isinstance(entry_kind, str)
        ):
            continue
        if not digest.startswith("sha256:") or len(digest) != len("sha256:") + 64:
            continue
        name = "records/" + digest[len("sha256:"):] + ".json"
        document, _read_problems = read_container_json(container, name)
        if not isinstance(document, dict):
            continue
        record_id = document.get("id")
        record_kind = document.get("kind")
        if record_id != entry_id:
            problems.append(
                f"manifest.records[{index}].id is {entry_id!r} but {name} "
                f"has id {record_id!r}"
            )
        if record_kind != entry_kind:
            problems.append(
                f"manifest.records[{index}].kind is {entry_kind!r} but {name} "
                f"has kind {record_kind!r}"
            )
    return problems


def kind_body_supplement(document: Any) -> list[str]:
    """Kind-specific structural fallbacks for rules JSON Schema cannot express."""

    problems: list[str] = []
    if not isinstance(document, dict) or document.get("kind") != "weave.grant":
        return problems
    body = document.get("body")
    if not isinstance(body, dict) or body.get("action") != "grant":
        return problems
    grant = body.get("grant")
    if not isinstance(grant, dict):
        return problems
    revocation = grant.get("revocation")
    if revocation is None:
        return problems
    if not isinstance(revocation, list):
        return problems
    keys = [key for key in revocation if isinstance(key, str)]
    if len(keys) != len(revocation):
        return problems
    problems.extend(
        _unique_problems(keys, "weave.grant.grant.revocation", "key")
    )
    for index, key in enumerate(keys):
        if not ED25519_KEY_RE.match(key):
            problems.append(
                f"weave.grant.grant.revocation[{index}] is not an ed25519 key id"
            )
    return problems


# --------------------------------------------------------------------------- #
# Vector cases
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Case:
    category: str
    case_id: str
    directory: Path

    @property
    def key(self) -> str:
        return f"{self.category}/{self.case_id}"


def structural_families(codes: Iterable[str]) -> set[str]:
    """Map expected structural error codes to the component they live on."""

    families: set[str] = set()
    for code in codes:
        if code.startswith("E_ENV_") or code == "E_KIND_BODY_SCHEMA":
            families.add("record")
        elif code in ("E_MANIFEST_SCHEMA", "E_MANIFEST_RECORDS"):
            families.add("manifest")
    return families


class VectorChecks:
    def __init__(self, vectors_dir: Path, schemas: SchemaSet) -> None:
        self.dir = vectors_dir
        self.schemas = schemas
        self.stats = {
            "cases": 0,
            "categories": 0,
            "positive": 0,
            "structural": 0,
            "indexed": 0,
        }

    # -- discovery --------------------------------------------------------- #

    def run(self) -> list[str]:
        problems: list[str] = []
        if not self.dir.is_dir():
            return [f"vectors directory not found: {self.dir}"]
        cases, discovery_problems = self.discover_cases()
        problems.extend(discovery_problems)
        self.stats["cases"] = len(cases)
        self.stats["categories"] = len({case.category for case in cases})
        if not cases:
            problems.append(f"no vector cases found under {self.dir}")
            return problems

        expectations: dict[str, dict[str, Any]] = {}
        for case in cases:
            case_problems, expected = self.check_expected(case)
            problems.extend(f"{case.key}: {problem}" for problem in case_problems)
            if expected is not None:
                expectations[case.key] = expected

        problems.extend(self.check_index(cases, expectations))

        for case in cases:
            expected = expectations.get(case.key)
            if expected is None:
                continue
            problems.extend(self.check_against_schemas(case, expected))
        return problems

    def discover_cases(self) -> tuple[list[Case], list[str]]:
        problems: list[str] = []
        cases: list[Case] = []
        for category_dir in sorted(self.dir.iterdir(), key=lambda path: path.name):
            if not category_dir.is_dir() or category_dir.name.startswith("."):
                continue
            if category_dir.name in SKIPPED_VECTOR_DIRS:
                continue
            if category_dir.name not in VECTOR_CATEGORIES:
                problems.append(
                    f"unexpected vector category directory {category_dir.name!r}; "
                    f"known categories are: {', '.join(sorted(VECTOR_CATEGORIES))}"
                )
                continue
            for case_dir in sorted(category_dir.iterdir(), key=lambda path: path.name):
                if not case_dir.is_dir() or case_dir.name.startswith("."):
                    continue
                if not (case_dir / "expected.json").is_file():
                    problems.append(
                        f"{category_dir.name}/{case_dir.name}: case directory has "
                        "no expected.json"
                    )
                    continue
                cases.append(Case(category_dir.name, case_dir.name, case_dir))
        return cases, problems

    # -- expected.json structure (the case layout in `vectors/README.md`) --------------------------- #

    def check_expected(
        self, case: Case
    ) -> tuple[list[str], dict[str, Any] | None]:
        problems: list[str] = []
        path = case.directory / "expected.json"
        try:
            expected = load_json_strict(path)
        except InputProblem as exc:
            return [str(exc)], None
        if not isinstance(expected, dict):
            return ["expected.json must be a JSON object"], None

        for field in ("id", "category", "target", "input", "verdict"):
            if field not in expected:
                problems.append(f"expected.json is missing required member {field!r}")
        if problems:
            return problems, None

        expected_id = expected.get("id")
        if not isinstance(expected_id, str):
            problems.append("expected.json member 'id' must be a string")
        elif expected_id != case.key:
            problems.append(
                f"expected.json 'id' is {expected_id!r}, expected {case.key!r}"
            )
        category = expected.get("category")
        if not isinstance(category, str):
            problems.append("expected.json member 'category' must be a string")
        elif category != case.category:
            problems.append(
                f"expected.json 'category' is {category!r}, expected {case.category!r}"
            )
        target = expected.get("target")
        if target not in TARGETS:
            problems.append(f"expected.json 'target' must be one of {TARGETS}")
        verdict = expected.get("verdict")
        if verdict not in VERDICTS:
            problems.append(f"expected.json 'verdict' must be one of {VERDICTS}")
        if target == "container" and verdict == "erased":
            problems.append(
                "a container target cannot have verdict 'erased'; erased is a "
                "per-record verdict and a container holding placeholders is 'valid'"
            )

        input_value = expected.get("input")
        input_path: Path | None = None
        if not isinstance(input_value, str) or not input_value:
            problems.append("expected.json member 'input' must be a non-empty string")
        else:
            relative = Path(input_value)
            if relative.is_absolute() or ".." in relative.parts:
                problems.append(
                    f"expected.json 'input' must be a relative path inside the case "
                    f"directory, got {input_value!r}"
                )
            else:
                input_path = case.directory / relative
                if not input_path.exists():
                    problems.append(
                        f"expected.json 'input' does not exist: {input_value!r}"
                    )
                elif target == "record" and not input_path.is_file():
                    problems.append(
                        f"record target 'input' must be a file, got {input_value!r}"
                    )
                elif target == "container" and not (
                    input_path.is_dir() or input_path.is_file()
                ):
                    problems.append(
                        f"container target 'input' must be a directory or zip file, "
                        f"got {input_value!r}"
                    )

        for field, prefix in (("errors", "E_"), ("notices", "N_")):
            values = expected.get(field)
            if values is None:
                continue
            if not isinstance(values, list):
                problems.append(f"expected.json member {field!r} must be an array")
                continue
            duplicates: list[str] = []
            seen: set[str] = set()
            for value in values:
                if not isinstance(value, str) or not CODE_RE.match(value):
                    problems.append(
                        f"expected.json {field!r} contains an invalid code {value!r}"
                    )
                    continue
                if not value.startswith(prefix):
                    problems.append(
                        f"expected.json {field!r} contains {value!r}, expected a "
                        f"{prefix}* code"
                    )
                if value in seen:
                    duplicates.append(value)
                seen.add(value)
            if duplicates:
                print(
                    f"[schema-check] note: {case.key}: duplicate code(s) in "
                    f"{field}: {', '.join(duplicates)}",
                    file=sys.stderr,
                )

        if verdict == "valid" and expected.get("errors"):
            problems.append(
                "expected.json verdict 'valid' contradicts a non-empty 'errors' array"
            )
        if verdict == "invalid":
            errors = expected.get("errors")
            if not isinstance(errors, list) or not errors:
                problems.append(
                    "an 'invalid' vector must list at least one expected error code"
                )

        args = expected.get("args")
        if args is not None and (
            not isinstance(args, list)
            or not all(isinstance(arg, str) for arg in args)
        ):
            problems.append("expected.json member 'args' must be an array of strings")

        expected_digest = expected.get("expected_digest")
        if expected_digest is not None and (
            not isinstance(expected_digest, str)
            or not DIGEST_RE.match(expected_digest)
        ):
            problems.append(
                "expected.json member 'expected_digest' must be a sha256:<64 hex> string"
            )

        expected_resolution = expected.get("expected_resolution")
        if expected_resolution is not None:
            if not isinstance(expected_resolution, list) or not all(
                isinstance(state, str) and state in RESOLUTION_STATES
                for state in expected_resolution
            ):
                problems.append(
                    "expected.json member 'expected_resolution' must be an array of "
                    f"states from {RESOLUTION_STATES}"
                )

        expected_container = expected.get("expected_container")
        if expected_container is not None and not isinstance(expected_container, dict):
            problems.append(
                "expected.json member 'expected_container' must be a JSON object"
            )

        records = expected.get("records")
        if records is not None:
            if not isinstance(records, list):
                problems.append(
                    "expected.json member 'records' must be an array of objects"
                )
            else:
                for index, record in enumerate(records):
                    if not isinstance(record, dict):
                        problems.append(
                            f"expected.json records[{index}] must be an object"
                        )
                        continue
                    if not isinstance(record.get("id"), str):
                        problems.append(
                            f"expected.json records[{index}].id must be a string"
                        )
                    # records[] entries are per-record report subsets: only the ids
                    # are required, and verdict/kind_known/errors are optional.
                    if "verdict" in record and record["verdict"] not in VERDICTS:
                        problems.append(
                            f"expected.json records[{index}].verdict must be one of "
                            f"{VERDICTS}"
                        )
                    if "kind_known" in record and not isinstance(
                        record["kind_known"], bool
                    ):
                        problems.append(
                            f"expected.json records[{index}].kind_known must be a "
                            "boolean"
                        )
                    record_errors = record.get("errors")
                    if record_errors is not None and (
                        not isinstance(record_errors, list)
                        or not all(
                            isinstance(code, str) and CODE_RE.match(code)
                            for code in record_errors
                        )
                    ):
                        problems.append(
                            f"expected.json records[{index}].errors must be an array "
                            "of E_*/N_* codes"
                        )

        notes = expected.get("notes")
        if notes is not None and not isinstance(notes, str):
            problems.append("expected.json member 'notes' must be a string")

        if verdict == "erased" and target == "record" and input_path is not None:
            try:
                document = load_json_strict(input_path)
            except InputProblem as exc:
                problems.append(f"verdict 'erased' but {exc}")
            else:
                if not (
                    isinstance(document, dict)
                    and document.get("kind") == ERASED_KIND
                ):
                    problems.append(
                        "expected.json verdict 'erased' requires a weave.erased "
                        "placeholder input"
                    )

        return problems, expected

    # -- vectors/index.json -------------------------------------------------- #

    def check_index(
        self,
        cases: list[Case],
        expectations: dict[str, dict[str, Any]],
    ) -> list[str]:
        problems: list[str] = []
        index_path = self.dir / "index.json"
        if not index_path.is_file():
            return [f"vectors index not found: {index_path}"]
        try:
            index = load_json_strict(index_path)
        except InputProblem as exc:
            return [str(exc)]
        if not isinstance(index, dict):
            return ["vectors/index.json must be a JSON object"]
        for field in ("format", "spec", "case_count", "cases"):
            if field not in index:
                problems.append(f"vectors/index.json is missing member {field!r}")
        if problems:
            return problems
        if index.get("format") != "weave-record-vectors/1":
            problems.append(
                "vectors/index.json 'format' must be 'weave-record-vectors/1'"
            )
        if index.get("spec") != "weave-record/1":
            problems.append("vectors/index.json 'spec' must be 'weave-record/1'")
        entries = index.get("cases")
        if not isinstance(entries, list):
            return problems + ["vectors/index.json member 'cases' must be an array"]
        case_count = index.get("case_count")
        if not isinstance(case_count, int) or isinstance(case_count, bool):
            problems.append("vectors/index.json 'case_count' must be an integer")
        elif case_count != len(entries):
            problems.append(
                f"vectors/index.json 'case_count' is {case_count}, but 'cases' has "
                f"{len(entries)} entries"
            )

        seen_ids: set[str] = set()
        listed_ids: list[str] = []
        for position, entry in enumerate(entries):
            if not isinstance(entry, dict):
                problems.append(
                    f"vectors/index.json cases[{position}] must be an object"
                )
                continue
            entry_id = entry.get("id")
            if not isinstance(entry_id, str):
                problems.append(
                    f"vectors/index.json cases[{position}].id must be a string"
                )
                continue
            listed_ids.append(entry_id)
            if entry_id in seen_ids:
                problems.append(
                    f"vectors/index.json contains duplicate case id {entry_id!r}"
                )
                continue
            seen_ids.add(entry_id)
            for field in ("category", "target", "input", "verdict"):
                if not isinstance(entry.get(field), str):
                    problems.append(
                        f"vectors/index.json case {entry_id!r}: {field!r} must be a string"
                    )
            expected = expectations.get(entry_id)
            if expected is None:
                problems.append(
                    f"vectors/index.json lists case {entry_id!r} that has no readable "
                    "expected.json under vectors/"
                )
                continue
            for field in RECORD_MIRROR_FIELDS:
                if entry.get(field) != expected.get(field):
                    problems.append(
                        f"vectors/index.json case {entry_id!r}: {field!r} is "
                        f"{entry.get(field)!r} but expected.json says "
                        f"{expected.get(field)!r}"
                    )
            for field in ("errors", "notices"):
                expected_values = expected.get(field) or []
                if field in entry:
                    entry_values = entry[field]
                    if not isinstance(entry_values, list):
                        problems.append(
                            f"vectors/index.json case {entry_id!r}: {field!r} must be "
                            "an array"
                        )
                    elif sorted(map(str, entry_values)) != sorted(
                        map(str, expected_values)
                    ):
                        problems.append(
                            f"vectors/index.json case {entry_id!r}: {field!r} differs "
                            "from expected.json"
                        )
                elif expected_values:
                    problems.append(
                        f"vectors/index.json case {entry_id!r}: expected.json has "
                        f"{field!r} but the index entry omits them"
                    )

        # the case layout does not require index ordering; gen_index.py emits
        # category order. Uniqueness and exact id coverage are checked above.
        self.stats["indexed"] = len(listed_ids)

        expected_ids = set(expectations)
        missing_ids = sorted(expected_ids.difference(seen_ids))
        if missing_ids:
            problems.append(
                "vectors/index.json does not list every case with an expected.json; "
                f"missing: {', '.join(missing_ids)}"
            )
        return problems

    # -- positive and structural-negative assertions ------------------------ #

    def check_against_schemas(
        self, case: Case, expected: dict[str, Any]
    ) -> list[str]:
        problems: list[str] = []
        verdict = expected.get("verdict")
        target = expected.get("target")
        positive = verdict == "valid" or (
            target == "record" and verdict == "erased"
        )
        if positive:
            self.stats["positive"] += 1
            problems.extend(self.check_positive(case, expected))
        families = structural_families(expected.get("errors") or [])
        if families:
            self.stats["structural"] += 1
            problems.extend(self.check_structural(case, expected, families))
        return problems

    # -- record helpers ------------------------------------------------------ #

    def record_violations(self, document: Any) -> list[str]:
        """Schema + supplementary violations for one record document."""

        if not isinstance(document, dict):
            return ["record is not a JSON object"]
        kind = document.get("kind")
        if kind == ERASED_KIND:
            return self.schemas.violations(document, self.schemas.erased)
        if isinstance(kind, str) and kind in self.schemas.kind_validators:
            problems = self.schemas.violations(
                document, self.schemas.kind_validators[kind]
            )
        else:
            problems = self.schemas.violations(document, self.schemas.envelope)
        problems.extend(envelope_supplement(document))
        problems.extend(kind_body_supplement(document))
        return problems

    def _report(self, problems: list[str], prefix: str) -> list[str]:
        return [f"{prefix}: {problem}" for problem in problems]

    # -- positive vectors ---------------------------------------------------- #

    def check_positive(
        self, case: Case, expected: dict[str, Any]
    ) -> list[str]:
        input_value = expected["input"]
        path = case.directory / input_value
        if expected["target"] == "record":
            if not path.is_file():
                return [f"positive record input is missing: {input_value!r}"]
            try:
                document = load_json_strict(path)
            except InputProblem as exc:
                return [f"positive record input is not valid JSON: {exc}"]
            problems = self.record_violations(document)
            return self._report(problems, "positive record")
        return self.check_positive_container(case, expected, path)

    def check_positive_container(
        self, case: Case, expected: dict[str, Any], path: Path
    ) -> list[str]:
        problems: list[str] = []
        container = ContainerReader(path)
        try:
            container.open()
        except InputProblem as exc:
            return [str(exc)]
        try:
            manifest, manifest_problems = read_container_json(container, "manifest.json")
            problems.extend(self._report(manifest_problems, "manifest.json"))
            if manifest is not None:
                problems.extend(
                    self._report(
                        self.schemas.violations(manifest, self.schemas.manifest)
                        + manifest_supplement(manifest)
                        + manifest_record_identity_problems(container, manifest),
                        "manifest.json",
                    )
                )
            attestation_name = "signatures/manifest.sig.json"
            attestation, attestation_problems = read_container_json(
                container, attestation_name
            )
            if attestation_problems:
                problems.extend(
                    self._report(attestation_problems, attestation_name)
                )
            elif attestation is not None:
                problems.extend(
                    self._report(
                        self.schemas.violations(
                            attestation, self.schemas.attestation
                        )
                        + attestation_supplement(attestation),
                        attestation_name,
                    )
                )
            record_names = container.record_names()
            if not record_names:
                problems.append("positive container has no records/*.json files")
            for name in record_names:
                document, record_problems = read_container_json(container, name)
                if record_problems:
                    problems.extend(self._report(record_problems, name))
                elif document is not None:
                    problems.extend(
                        self._report(self.record_violations(document), name)
                    )
        finally:
            container.close()
        return problems

    # -- structural-negative vectors ----------------------------------------- #

    def check_structural(
        self, case: Case, expected: dict[str, Any], families: set[str]
    ) -> list[str]:
        target = expected.get("target")
        input_value = expected["input"]
        path = case.directory / input_value
        codes = sorted(
            code
            for code in (expected.get("errors") or [])
            if structural_families([code])
        )
        if target == "record":
            if "manifest" in families:
                return [
                    "expected manifest-level structural error(s) "
                    f"{codes} but the case target is a single record"
                ]
            return self.check_structural_record(case, path, codes)
        return self.check_structural_container(path, families, codes)

    def check_structural_record(
        self, case: Case, path: Path, codes: list[str]
    ) -> list[str]:
        if not path.is_file():
            return [f"structural-negative record input is missing: {path.name!r}"]
        try:
            document = load_json_strict(path)
        except InputProblem:
            # The schema layer can never accept unparseable input; the expected
            # structural code family will be checked by the verifier.
            return []
        if self.record_violations(document):
            return []
        return [
            "expected structural error(s) "
            f"{codes} but the schema layer accepted the record; JSON Schema cannot "
            "express this rule, so either add a supplementary predicate in "
            "tools/check_schemas.py or fix the vector"
        ]

    def check_structural_container(
        self, path: Path, families: set[str], codes: list[str]
    ) -> list[str]:
        problems: list[str] = []
        if not path.exists():
            return [f"structural-negative container input is missing: {path.name!r}"]
        container = ContainerReader(path)
        try:
            container.open()
        except InputProblem as exc:
            return [str(exc)]
        try:
            if "manifest" in families:
                manifest, read_problems = read_container_json(
                    container, "manifest.json"
                )
                if manifest is None:
                    # A missing/unparseable manifest is itself a failure of the
                    # schema layer; the verifier must report the expected code.
                    pass
                else:
                    failures = (
                        self.schemas.violations(manifest, self.schemas.manifest)
                        + manifest_supplement(manifest)
                        + manifest_record_identity_problems(container, manifest)
                    )
                    if not failures:
                        problems.append(
                            "expected manifest structural error(s) "
                            f"{codes} but manifest.json satisfies the schema layer"
                        )
            if "record" in families:
                record_names = container.record_names()
                if not record_names:
                    problems.append(
                        "expected record-level structural error(s) "
                        f"{codes} but the container has no records/*.json files to "
                        "carry them"
                    )
                else:
                    any_failure = False
                    for name in record_names:
                        document, read_problems = read_container_json(
                            container, name
                        )
                        if document is None:
                            any_failure = True
                            continue
                        if self.record_violations(document):
                            any_failure = True
                            break
                    if not any_failure:
                        problems.append(
                            "expected record-level structural error(s) "
                            f"{codes} but every records/*.json file satisfies the "
                            "schema layer"
                        )
        finally:
            container.close()
        return problems


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #


def check_environment() -> tuple[list[str], tuple[str, str] | None]:
    problems: list[str] = []
    if sys.version_info < (3, 11):
        problems.append(
            f"Python >= 3.11 is required, found {sys.version.split()[0]}"
        )
    try:
        version = metadata.version("jsonschema")
    except metadata.PackageNotFoundError:
        problems.append(
            "jsonschema is not installed; run ./.venv/bin/python tools/check_schemas.py"
        )
        return problems, None
    if version != PINNED_JSONSCHEMA:
        problems.append(
            f"jsonschema {version} is installed but H0 pins {PINNED_JSONSCHEMA}; "
            "run ./.venv/bin/python tools/check_schemas.py"
        )
    referencing_version = metadata.version("referencing")
    if problems:
        return problems, None
    return problems, (version, referencing_version)


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    repo_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(
        description=(
            "Offline JSON Schema self-check for the weave-record/1 schema set "
            "(CI gate \"Schema self-check\")."
        )
    )
    parser.add_argument(
        "--schemas",
        type=Path,
        default=repo_root / "schemas",
        help="schema directory (default: <repo>/schemas)",
    )
    parser.add_argument(
        "--vectors",
        type=Path,
        default=repo_root / "vectors",
        help="vector directory (default: <repo>/vectors)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="print every schema file and every checked case",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    environment_problems, environment = check_environment()
    if environment_problems:
        for problem in environment_problems:
            print(f"schema-check: {problem}", file=sys.stderr)
        print("FAILED: environment check failed", file=sys.stderr)
        return 1
    assert environment is not None
    jsonschema_version, referencing_version = environment
    print(
        f"[schema-check] python {sys.version.split()[0]}, "
        f"jsonschema {jsonschema_version}, referencing {referencing_version}"
    )

    schema_set = SchemaSet(args.schemas)
    schema_problems = schema_set.load()
    if schema_problems:
        for problem in schema_problems:
            print(f"[schema-check] PROBLEM schemas: {problem}", file=sys.stderr)
        print(
            f"FAILED: {len(schema_problems)} schema problem(s)", file=sys.stderr
        )
        return 1
    print(
        f"[schema-check] schemas: {len(schema_set.docs)} files under "
        f"{len(EXPECTED_SCHEMA_RELS)} registered files, all valid Draft 2020-12, "
        f"$id base {SCHEMA_BASE}"
    )
    if args.verbose:
        for rel in sorted(schema_set.docs):
            print(f"[schema-check]   schema {rel}")

    vector_checks = VectorChecks(args.vectors, schema_set)
    vector_problems = vector_checks.run()
    stats = vector_checks.stats
    print(
        f"[schema-check] vectors: {stats['cases']} cases in "
        f"{stats['categories']} categories, index entries {stats['indexed']}"
    )
    print(
        f"[schema-check] positive vector inputs validated: {stats['positive']}; "
        f"structural negative assertions: {stats['structural']}"
    )
    if vector_problems:
        for problem in vector_problems:
            print(f"[schema-check] PROBLEM vectors: {problem}", file=sys.stderr)
        print(
            f"FAILED: {len(vector_problems)} vector/schema problem(s)",
            file=sys.stderr,
        )
        return 1
    print("OK: schema self-check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
