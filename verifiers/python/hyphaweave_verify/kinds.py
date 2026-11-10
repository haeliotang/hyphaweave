# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0

"""Kind registry and kind-body structural validation (spec §7, kind pages).

H0 registers exactly eight ``weave.*`` kinds. Seven are normal envelopes with a
``body`` validated here; ``weave.erased`` is the special placeholder shape and
is validated by :mod:`hyphaweave_verify.erase`.

Unknown but syntactically valid kinds are *opaque but not understood*: this
module reports them as unregistered and never validates their body (K3 forward
compatibility).

Semantic rules that need cross-record context (key ids, signers, grants,
consequential effects) live in the dedicated modules; this module only checks
the body's fixed grammar and returns the registry facts the verifier needs.
"""

from __future__ import annotations

import re
from typing import Any

from . import grammar
from .encoding import is_key_id
from .errors import WeaveError
from .refs import validate_reference
from .times import is_valid_timestamp

KIND_DECLARED = "weave.key.declared"
KIND_ROTATED = "weave.key.rotated"
KIND_REVOKED = "weave.key.revoked"
KIND_GRANT = "weave.grant"
KIND_CONSENT_GRANTED = "weave.consent.granted"
KIND_CONSENT_REVOKED = "weave.consent.revoked"
KIND_ERASURE = "weave.erasure"
KIND_ERASED = "weave.erased"

#: The eight kinds registered by H0.
REGISTERED_KINDS: frozenset[str] = frozenset(
    {
        KIND_DECLARED,
        KIND_ROTATED,
        KIND_REVOKED,
        KIND_GRANT,
        KIND_CONSENT_GRANTED,
        KIND_CONSENT_REVOKED,
        KIND_ERASURE,
        KIND_ERASED,
    }
)

#: Kinds whose per-record signature and ``accepted`` stage are mandatory (§4.4).
MUST_SIGN_KINDS: frozenset[str] = REGISTERED_KINDS - {KIND_ERASED}
ACCEPTED_REQUIRED_KINDS: frozenset[str] = MUST_SIGN_KINDS

#: Key-lifecycle kinds: ``actor.type`` names a key class, not a delegated actor
#: (spec §4.2 exception, PROVISIONAL Q28 / registry note). Their own signer-class
#: rules are authoritative instead of the generic human-key prohibition.
KEY_LIFECYCLE_KINDS: frozenset[str] = frozenset(
    {KIND_DECLARED, KIND_ROTATED, KIND_REVOKED}
)

KIND_NAME_PATTERN = re.compile(r"^[a-z][a-z0-9]*(?:[.-][a-z][a-z0-9]*)*$")
KIND_NAME_MAX_BYTES = 128

KEY_TYPES = ("human", "agent", "program", "device", "organization")
REVOCATION_REASONS = ("key-compromise", "retired", "other")
ERASURE_REASONS = (
    "data-subject-request",
    "legal",
    "safety",
    "mistaken-inclusion",
    "retention-expired",
    "other",
)
GRANT_ACTIONS = ("propose", "accept", "reject", "withdraw", "supersede", "erase", "grant")
GRANT_OBJECT_MEMBERS = (
    "grantee",
    "kinds",
    "actions",
    "scope",
    "valid_from",
    "valid_until",
    "transferable",
    "evidence",
    "remedy",
)
REVOKE_OBJECT_MEMBERS = ("revokes", "effective_at", "reason")


def is_kind_syntax(value: object) -> bool:
    """Kind name grammar: dotted lowercase name, at most 128 bytes.

    The specification reserves the ``weave.`` namespace and requires a project
    segment, so a name without a dot is syntactically invalid (spec §7.1).
    """
    if not isinstance(value, str):
        return False
    if len(value.encode("utf-8")) > KIND_NAME_MAX_BYTES:
        return False
    if "." not in value:
        return False
    return KIND_NAME_PATTERN.match(value) is not None


def is_registered(kind: object) -> bool:
    """Whether ``kind`` is one of the eight kinds registered by H0."""
    return isinstance(kind, str) and kind in REGISTERED_KINDS


def requires_accepted(kind: object) -> bool:
    """Whether the kind MUST use ``stage == "accepted"`` (spec §7.2)."""
    return isinstance(kind, str) and kind in ACCEPTED_REQUIRED_KINDS


def is_key_lifecycle(kind: object) -> bool:
    """Whether ``kind`` is one of the three key-lifecycle kinds."""
    return isinstance(kind, str) and kind in KEY_LIFECYCLE_KINDS


# ---------------------------------------------------------------------------
# Body schema helpers
# ---------------------------------------------------------------------------


def _body_error(code: str, detail: str) -> None:
    raise WeaveError(code, detail)


def _require_members(body: dict[str, Any], required: tuple[str, ...], code: str) -> None:
    for member in required:
        if member not in body:
            _body_error(code, "body is missing required member %r" % member)


def _closed_object(
    value: Any,
    members: tuple[str, ...],
    required: tuple[str, ...],
    code: str,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        _body_error(code, "expected a closed object")
    for member in value:
        if member not in members:
            _body_error(code, "unknown member in closed object")
    _require_members(value, required, code)
    return value


def _check_ts(value: Any, code: str, *, nullable: bool = False) -> None:
    if value is None and nullable:
        return
    if not is_valid_timestamp(value):
        _body_error(code, "not a TS literal")


def _check_reference(value: Any, code: str, *, nullable: bool = False) -> None:
    if value is None and nullable:
        return
    try:
        validate_reference(value)
    except WeaveError as error:
        raise WeaveError(code, "malformed reference object") from error


def _check_reference_or_null(value: Any, code: str) -> None:
    _check_reference(value, code, nullable=True)


def _check_string(value: Any, code: str, *, nullable: bool = False) -> None:
    if value is None and nullable:
        return
    if not isinstance(value, str):
        _body_error(code, "expected a string")


def _check_key_id(value: Any, code: str) -> None:
    if not is_key_id(value):
        _body_error(code, "not a key id")


def _check_unique_strings(
    value: Any,
    code: str,
    *,
    minimum: int,
    maximum: int,
) -> None:
    if not isinstance(value, list):
        _body_error(code, "expected an array")
    if not minimum <= len(value) <= maximum:
        _body_error(code, "array length out of range")
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, str):
            _body_error(code, "array item must be a string")
        if item in seen:
            _body_error(code, "array items must be unique")
        seen.add(item)


# ---------------------------------------------------------------------------
# Per-kind body validators
# ---------------------------------------------------------------------------


def _validate_declared(body: dict[str, Any]) -> None:
    code = "E_KIND_BODY_SCHEMA"
    _require_members(body, ("algorithm", "key", "key_type", "public_key"), code)
    if body["algorithm"] != "ed25519":
        _body_error(code, "algorithm must be ed25519")
    _check_key_id(body["key"], code)
    if body["key_type"] not in KEY_TYPES:
        _body_error(code, "key_type is not one of the closed values")
    if not isinstance(body["public_key"], str):
        _body_error(code, "public_key must be a base64url string")
    if "valid_from" in body:
        _check_ts(body["valid_from"], code)
    if "valid_until" in body:
        _check_ts(body["valid_until"], code)
    if "note" in body:
        _check_string(body["note"], code)


def _validate_rotated(body: dict[str, Any]) -> None:
    code = "E_KIND_BODY_SCHEMA"
    _require_members(body, ("new_key", "new_public_key", "old_key"), code)
    _check_key_id(body["new_key"], code)
    _check_key_id(body["old_key"], code)
    if not isinstance(body["new_public_key"], str):
        _body_error(code, "new_public_key must be a base64url string")
    if "old_public_key" in body and not isinstance(body["old_public_key"], str):
        _body_error(code, "old_public_key must be a base64url string")
    if "reason" in body:
        _check_string(body["reason"], code)


def _validate_revoked(body: dict[str, Any]) -> None:
    code = "E_KIND_BODY_SCHEMA"
    _require_members(body, ("effective_at", "key", "reason"), code)
    _check_ts(body["effective_at"], code)
    _check_key_id(body["key"], code)
    if body["reason"] not in REVOCATION_REASONS:
        _body_error(code, "reason is not one of the closed values")
    if "note" in body:
        _check_string(body["note"], code)


def _validate_grant_object(grant: Any) -> None:
    code = "E_GRANT_SCHEMA"
    grant = _closed_object(grant, GRANT_OBJECT_MEMBERS, GRANT_OBJECT_MEMBERS, code)
    grantee = grant["grantee"]
    if not isinstance(grantee, dict):
        _body_error(code, "grant.grantee must be an object")
    for member in grantee:
        if member != "key":
            _body_error(code, "grant.grantee is closed")
    if "key" not in grantee:
        _body_error(code, "grant.grantee.key is required")
    _check_key_id(grantee["key"], code)
    kinds_list = grant["kinds"]
    _check_unique_strings(kinds_list, code, minimum=1, maximum=64)
    for kind_name in kinds_list:
        if not is_kind_syntax(kind_name):
            _body_error(code, "grant.kinds contains a malformed kind name")
    actions = grant["actions"]
    _check_unique_strings(actions, code, minimum=1, maximum=len(GRANT_ACTIONS))
    for action in actions:
        if action not in GRANT_ACTIONS:
            _body_error(code, "grant.actions contains an unknown action")
    scope = grant["scope"]
    if not isinstance(scope, list) or not 1 <= len(scope) <= 32:
        _body_error(code, "grant.scope must contain 1-32 strings")
    for item in scope:
        if not grammar.is_valid_scope_string(item):
            _body_error(code, "grant.scope item is not a 1-256 character string")
    _check_ts(grant["valid_from"], code)
    _check_ts(grant["valid_until"], code, nullable=True)
    if not isinstance(grant["transferable"], bool):
        _body_error(code, "grant.transferable must be a boolean")
    _check_reference_or_null(grant["evidence"], code)
    _check_string(grant["remedy"], code, nullable=True)


def _validate_revoke_object(revoke: Any) -> None:
    code = "E_GRANT_SCHEMA"
    revoke = _closed_object(revoke, REVOKE_OBJECT_MEMBERS, REVOKE_OBJECT_MEMBERS, code)
    _check_reference(revoke["revokes"], code)
    _check_ts(revoke["effective_at"], code)
    _check_string(revoke["reason"], code, nullable=True)


def _validate_grant(body: dict[str, Any]) -> None:
    code = "E_GRANT_SCHEMA"
    _require_members(body, ("action",), code)
    action = body["action"]
    if action == "grant":
        if "grant" not in body:
            _body_error(code, "action grant requires the grant object")
        if "revoke" in body:
            _body_error(code, "action grant must not contain revoke")
        _validate_grant_object(body["grant"])
    elif action == "revoke":
        if "revoke" not in body:
            _body_error(code, "action revoke requires the revoke object")
        if "grant" in body:
            _body_error(code, "action revoke must not contain grant")
        _validate_revoke_object(body["revoke"])
    else:
        _body_error(code, "action is not one of the closed values")


def _validate_consent_granted(body: dict[str, Any]) -> None:
    code = "E_KIND_BODY_SCHEMA"
    _require_members(
        body,
        ("purpose", "scope", "valid_from", "valid_until", "data_subject", "terms"),
        code,
    )
    if not grammar.is_valid_text(body["purpose"], 1, 1024):
        _body_error(code, "purpose must be a 1-1024 character string")
    scope = body["scope"]
    if not isinstance(scope, list) or not 1 <= len(scope) <= 32:
        _body_error(code, "scope must contain 1-32 strings")
    for item in scope:
        if not grammar.is_valid_scope_string(item):
            _body_error(code, "scope item is not a 1-256 character string")
    _check_ts(body["valid_from"], code)
    _check_ts(body["valid_until"], code, nullable=True)
    _check_reference_or_null(body["data_subject"], code)
    _check_string(body["terms"], code, nullable=True)


def _validate_consent_revoked(body: dict[str, Any]) -> None:
    code = "E_KIND_BODY_SCHEMA"
    _require_members(body, ("revokes", "effective_at", "reason"), code)
    _check_reference(body["revokes"], code)
    _check_ts(body["effective_at"], code)
    _check_string(body["reason"], code, nullable=True)


def _validate_erasure(body: dict[str, Any]) -> None:
    code = "E_KIND_BODY_SCHEMA"
    _require_members(body, ("erased", "reason", "reason_note", "basis"), code)
    _check_reference(body["erased"], code)
    if body["reason"] not in ERASURE_REASONS:
        _body_error(code, "reason is not one of the closed values")
    _check_string(body["reason_note"], code, nullable=True)
    _check_reference_or_null(body["basis"], code)
    if "executed_at" in body:
        _check_ts(body["executed_at"], code)


_BODY_VALIDATORS = {
    KIND_DECLARED: _validate_declared,
    KIND_ROTATED: _validate_rotated,
    KIND_REVOKED: _validate_revoked,
    KIND_GRANT: _validate_grant,
    KIND_CONSENT_GRANTED: _validate_consent_granted,
    KIND_CONSENT_REVOKED: _validate_consent_revoked,
    KIND_ERASURE: _validate_erasure,
}


def validate_body_schema(kind: str, body: dict[str, Any]) -> None:
    """Validate the structural schema of a registered kind's body.

    Unregistered kinds are opaque: their body is never interpreted (K3).
    ``weave.erased`` is a placeholder, not a body-bearing kind.
    """
    validator = _BODY_VALIDATORS.get(kind)
    if validator is not None:
        validator(body)


#: Stage -> authorisation action mapping (spec §5.4).
STAGE_ACTION = {
    "proposed": "propose",
    "accepted": "accept",
    "rejected": "reject",
    "withdrawn": "withdraw",
    "superseded": "supersede",
}
