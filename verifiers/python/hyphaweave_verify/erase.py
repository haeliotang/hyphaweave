# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0

"""Erasure: the ``weave.erased`` placeholder and container cross-checks (spec §10).

The placeholder is *not* a normal envelope; it is the closed six-member object
of spec §4.5. Its own record digest (file name / manifest entry) is computed
over the placeholder, while its ``digest`` member is the original record's
digest, which is what references resolve against.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from . import grammar
from .encoding import is_digest_string, is_supported_digest
from .errors import WeaveError
from .refs import Origin, Reference, validate_origin, validate_reference

PLACEHOLDER_MEMBERS = ("format", "kind", "origin", "id", "digest", "attestation")
REQUIRED_IN_ORDER = ("format", "kind", "origin", "id", "digest", "attestation")


@dataclass(frozen=True)
class Placeholder:
    """A structurally validated ``weave.erased`` placeholder."""

    raw: dict[str, Any]
    origin: Origin
    record_id: str
    digest: str
    attestation: Reference

    @property
    def kind(self) -> str:
        return "weave.erased"


def looks_like_placeholder(value: Any) -> bool:
    """Whether a parsed record is dispatched to the placeholder validator."""
    return isinstance(value, dict) and value.get("kind") == "weave.erased"


def validate_placeholder(record: Any) -> Placeholder:
    """Validate the special placeholder shape (spec §4.5).

    A malformed ``digest``/``attestation`` member maps to ``E_KIND_BODY_SCHEMA``
    per the placeholder kind page's PROVISIONAL gap-filling choice.
    """
    if not isinstance(record, dict):
        raise WeaveError("E_JSON_INVALID", "record must be a JSON object")
    for member in REQUIRED_IN_ORDER:
        if member not in record:
            raise WeaveError("E_ENV_MISSING_FIELD", "placeholder is missing a member")
    for member in record:
        if member not in PLACEHOLDER_MEMBERS:
            raise WeaveError("E_ENV_UNKNOWN_FIELD", "placeholder has an unknown member")
    if record["format"] != "weave-record/1":
        raise WeaveError("E_ENV_FORMAT", "placeholder format is not weave-record/1")
    if record["kind"] != "weave.erased":
        raise WeaveError("E_ENV_KIND_SYNTAX", "placeholder kind is not weave.erased")
    origin = validate_origin(record["origin"])
    if not grammar.is_valid_id(record["id"]):
        raise WeaveError("E_ENV_ID", "placeholder id violates the id grammar")
    digest = record["digest"]
    if not is_digest_string(digest):
        raise WeaveError(
            "E_KIND_BODY_SCHEMA", "placeholder digest is not a digest string"
        )
    try:
        attestation = validate_reference(record["attestation"])
    except WeaveError as error:
        raise WeaveError(
            "E_KIND_BODY_SCHEMA", "placeholder attestation is not a valid reference"
        ) from error
    return Placeholder(
        raw=record,
        origin=origin,
        record_id=record["id"],
        digest=digest,
        attestation=attestation,
    )


def placeholder_digest_matches(placeholder: Placeholder, reference: Reference) -> bool:
    """Whether ``reference`` names the erased record this placeholder replaces."""
    if not is_supported_digest(placeholder.digest):
        return False
    return (
        reference.origin == placeholder.origin
        and reference.id == placeholder.record_id
        and reference.digest == placeholder.digest
    )
