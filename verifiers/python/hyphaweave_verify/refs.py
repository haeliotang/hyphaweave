# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0

"""References, origins and five-state reference resolution (spec §6).

A reference is an object, never a URI: ``{origin, id, digest, kind?, hints?}``
(B2) and it always carries the digest of the referenced record (B4). Resolution
against a verification context yields exactly one of ``found``, ``moved``,
``missing``, ``erased`` or ``unverifiable`` (B5).

Resolution needs the target's own verdict, which can depend on other records.
The context object passed in by the verifier exposes
:meth:`ResolutionContext.find_records`; the verifier is responsible for
memoisation and for reporting a dependency cycle as ``unverifiable`` (spec §6.4).
This module never loops and never touches I/O.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from . import grammar
from .encoding import is_digest_string, is_key_id, is_supported_digest
from .errors import WeaveError
from .grammar import RELS  # re-exported for convenience


# ---------------------------------------------------------------------------
# Origin and reference objects
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Origin:
    """The ``{project, instance}`` pair naming a system and key instance."""

    project: str
    instance: str

    def to_json(self) -> dict[str, str]:
        return {"project": self.project, "instance": self.instance}

    def subject_key(self) -> tuple[str, str]:
        return (self.project, self.instance)


def validate_origin(origin: Any, code: str = "E_ENV_ORIGIN") -> Origin:
    """Validate a closed origin object."""
    if not isinstance(origin, dict):
        raise WeaveError(code, "origin must be an object")
    if "project" not in origin:
        raise WeaveError(code, "origin.project is required")
    project = origin["project"]
    if not grammar.is_valid_project_slug(project):
        raise WeaveError(code, "origin.project is not a valid project slug")
    if "instance" not in origin:
        raise WeaveError(code, "origin.instance is required")
    instance = origin["instance"]
    if not is_key_id(instance):
        raise WeaveError(code, "origin.instance is not a key id")
    for member in origin:
        if member not in ("project", "instance"):
            raise WeaveError("E_ENV_UNKNOWN_FIELD", "unknown member in origin object")
    return Origin(project=project, instance=instance)


@dataclass(frozen=True)
class Reference:
    """A reference object (spec §6.1)."""

    origin: Origin
    id: str
    digest: str
    kind: str | None = None
    hints: tuple[str, ...] = ()

    def subject_key(self) -> tuple[str, str, str]:
        return (self.origin.project, self.origin.instance, self.id)

    def to_json(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "origin": self.origin.to_json(),
            "id": self.id,
            "digest": self.digest,
        }
        if self.kind is not None:
            result["kind"] = self.kind
        if self.hints:
            result["hints"] = list(self.hints)
        return result


def validate_reference(value: Any) -> Reference:
    """Validate a reference object; structural problems are ``E_ENV_REFS``.

    ``E_ENV_REFS`` is the code the specification assigns to reference-object
    grammar violations (spec §6.1: unknown members, malformed origin, malformed
    digest/kind/hints).
    """
    if not isinstance(value, dict):
        raise WeaveError("E_ENV_REFS", "reference must be an object")
    for member in value:
        if member not in ("origin", "id", "digest", "kind", "hints"):
            raise WeaveError("E_ENV_REFS", "unknown member in reference object")
    if "origin" not in value:
        raise WeaveError("E_ENV_REFS", "reference.origin is required")
    try:
        origin = validate_origin(value["origin"])
    except WeaveError as error:
        raise WeaveError("E_ENV_REFS", "malformed reference origin") from error
    if "id" not in value:
        raise WeaveError("E_ENV_REFS", "reference.id is required")
    if not grammar.is_valid_id(value["id"]):
        raise WeaveError("E_ENV_REFS", "reference.id is not a valid id")
    if "digest" not in value:
        raise WeaveError("E_ENV_REFS", "reference.digest is required")
    digest = value["digest"]
    if not is_digest_string(digest):
        raise WeaveError("E_ENV_REFS", "reference.digest is not a digest string")
    claimed_kind = value.get("kind")
    if claimed_kind is not None:
        from . import kinds

        if not kinds.is_kind_syntax(claimed_kind):
            raise WeaveError("E_ENV_REFS", "reference.kind is not a kind name")
    hints_value = value.get("hints", [])
    if not isinstance(hints_value, list):
        raise WeaveError("E_ENV_REFS", "reference.hints must be an array")
    if len(hints_value) > grammar.MAX_HINTS:
        raise WeaveError("E_ENV_REFS", "reference.hints has too many entries")
    hints: list[str] = []
    for hint in hints_value:
        if not grammar.is_valid_hint(hint):
            raise WeaveError("E_ENV_REFS", "reference hint is not a URI reference")
        hints.append(hint)
    return Reference(
        origin=origin,
        id=value["id"],
        digest=digest,
        kind=claimed_kind,
        hints=tuple(hints),
    )


@dataclass(frozen=True)
class ReferenceEntry:
    """A ``refs[]`` entry: ``{"rel": ..., "ref": ...}``."""

    rel: str
    ref: Reference


def validate_reference_entry(value: Any) -> ReferenceEntry:
    """Validate one ``refs[]`` entry (exactly ``rel`` and ``ref``)."""
    if not isinstance(value, dict):
        raise WeaveError("E_ENV_REFS", "refs entry must be an object")
    for member in value:
        if member not in ("rel", "ref"):
            raise WeaveError("E_ENV_REFS", "refs entry has an unknown member")
    if "rel" not in value or "ref" not in value:
        raise WeaveError("E_ENV_REFS", "refs entry must contain rel and ref")
    rel = value["rel"]
    if not isinstance(rel, str) or rel not in RELS:
        raise WeaveError("E_ENV_REFS", "refs entry rel is not in the closed vocabulary")
    return ReferenceEntry(rel=rel, ref=validate_reference(value["ref"]))


def validate_reference_list(value: Any) -> tuple[ReferenceEntry, ...]:
    """Validate an envelope ``refs`` array (<=256 unique entries)."""
    if not isinstance(value, list):
        raise WeaveError("E_ENV_REFS", "refs must be an array")
    if len(value) > grammar.MAX_REFS:
        raise WeaveError("E_ENV_REFS", "refs has too many entries")
    entries: list[ReferenceEntry] = []
    seen: set[tuple[str, str, str, str, str]] = set()
    for raw_entry in value:
        entry = validate_reference_entry(raw_entry)
        identity = (entry.rel, *entry.ref.subject_key(), entry.ref.digest)
        if identity in seen:
            raise WeaveError("E_ENV_REFS", "duplicate refs entry")
        seen.add(identity)
        entries.append(entry)
    return tuple(entries)


# ---------------------------------------------------------------------------
# Five-state resolution
# ---------------------------------------------------------------------------

FOUND = "found"
MOVED = "moved"
MISSING = "missing"
ERASED = "erased"
UNVERIFIABLE = "unverifiable"

RESOLUTION_STATES = (FOUND, MOVED, MISSING, ERASED, UNVERIFIABLE)

NOTICE_BY_STATE = {
    MOVED: "N_REF_MOVED",
    MISSING: "N_REF_MISSING",
    UNVERIFIABLE: "N_REF_UNVERIFIABLE",
}

#: Verdicts a target may carry, as used by resolution.
_TARGET_VALID = "valid"
_TARGET_ERASED = "erased"


@dataclass(frozen=True)
class TargetView:
    """The verifier's view of one record that may satisfy a reference.

    ``computed_digest`` is the record's own digest (§2.2); for a ``weave.erased``
    placeholder that is the placeholder digest, while ``payload_digest`` is the
    original record digest carried in its ``digest`` member.
    """

    origin: Origin
    id: str
    kind: str | None
    verdict: str
    computed_digest: str | None
    payload_digest: str | None = None
    is_placeholder: bool = False
    #: The verifier's record view for the target (opaque to this module).
    record: object | None = None


class ResolutionContext(Protocol):
    """What reference resolution needs from the verifier's live context."""

    def find_records(self, origin: Origin, record_id: str) -> tuple[TargetView, ...]:
        """Return every context record with the given origin and id."""
        ...


@dataclass(frozen=True)
class Resolution:
    """The resolved state of one reference, plus the target when one matched."""

    state: str
    target: TargetView | None = None

    @property
    def notice(self) -> str | None:
        return NOTICE_BY_STATE.get(self.state)

    @property
    def resolved(self) -> bool:
        """Whether a target record was found in the context (any state but missing)."""
        return self.state != MISSING


def resolve_reference(reference: Reference, context: ResolutionContext) -> Resolution:
    """Resolve one reference against the verification context (spec §6.3)."""
    if not is_supported_digest(reference.digest):
        return Resolution(UNVERIFIABLE)
    candidates = context.find_records(reference.origin, reference.id)
    if not candidates:
        return Resolution(MISSING)
    live_exact = [
        candidate
        for candidate in candidates
        if not candidate.is_placeholder and candidate.computed_digest == reference.digest
    ]
    placeholder_exact = [
        candidate
        for candidate in candidates
        if candidate.is_placeholder and candidate.payload_digest == reference.digest
    ]
    for candidate in live_exact:
        if candidate.verdict == _TARGET_VALID:
            return Resolution(FOUND, candidate)
    for candidate in placeholder_exact:
        if candidate.verdict == _TARGET_ERASED:
            return Resolution(ERASED, candidate)
    # Present but not usable: an invalid/unverifiable copy, or only non-matching
    # versions (the record moved to a different digest).
    for candidate in live_exact:
        return Resolution(UNVERIFIABLE, candidate)
    for candidate in placeholder_exact:
        return Resolution(UNVERIFIABLE, candidate)
    # A record with the same origin+id but a different digest is NOT "moved" for
    # an offline verifier (M-1/B5): a digest mismatch means the target could not
    # be verified. ``moved`` means "found elsewhere via hints with a matching
    # digest", which requires network resolution and never happens offline.
    return Resolution(UNVERIFIABLE)


def kind_claim_mismatch(reference: Reference, resolution: Resolution) -> bool:
    """Whether a present ``kind`` claim contradicts the resolved target's kind.

    A resolved target has a known kind for ``found``/``moved`` and the
    placeholder kind ``weave.erased`` for ``erased``; for other states no kind
    claim can be checked (spec §6.3, `weave.erasure` page).
    """
    if reference.kind is None:
        return False
    if resolution.state in (MISSING, UNVERIFIABLE):
        return False
    assert resolution.target is not None
    target_kind = resolution.target.kind
    if resolution.state == ERASED:
        target_kind = "weave.erased"
    return target_kind is not None and target_kind != reference.kind
