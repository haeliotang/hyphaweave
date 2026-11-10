# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0

"""Record envelope validation (spec §4, CONTRACT §5).

The whole envelope is validated structurally here, in the deterministic order of
CONTRACT §14.6: required members, closed-member check, then field grammars in
table order. A failure raises :class:`WeaveError` with the registry code from
``spec/error-codes.md``; the per-record pipeline stops at the first failure.

Nothing in this module touches the network, the clock, the environment or the
filesystem: it validates an already parsed JSON value.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from . import grammar, kinds
from .encoding import decode_base64url, is_key_id
from .errors import WeaveError
from .refs import (
    Origin,
    Reference,
    ReferenceEntry,
    validate_origin,
    validate_reference,
    validate_reference_list,
)
from .times import is_valid_timestamp

#: Format identifier of the H0 format.
FORMAT = "weave-record/1"

STAGES = ("proposed", "accepted", "rejected", "withdrawn", "superseded")
ACTOR_TYPES = ("human", "agent", "program", "device", "organization")
AGENT_ONLY_MEMBERS = ("model", "on_behalf_of", "grant", "idempotency_key")
SENSITIVITIES = ("public", "internal", "personal", "local-only")
SENSITIVITY_RANK = {"public": 0, "internal": 1, "personal": 2, "local-only": 3}

ENVELOPE_MEMBERS = (
    "format",
    "kind",
    "origin",
    "id",
    "stage",
    "actor",
    "recorded_at",
    "occurred_at",
    "refs",
    "labels",
    "salt",
    "body",
    "sigs",
)
REQUIRED_MEMBERS = ("format", "kind", "origin", "id", "stage", "actor", "recorded_at", "body")
ACTOR_MEMBERS = ("type", "key", "model", "on_behalf_of", "grant", "idempotency_key")
LABEL_MEMBERS = ("sensitivity", "licence", "consent")
SIG_MEMBERS = ("alg", "key", "value")


# ---------------------------------------------------------------------------
# Signature entries
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Signature:
    """A validated-shape ``sigs[]`` entry."""

    alg: str
    key: str
    value: str
    raw: bytes


def _validate_sigs(value: Any) -> tuple[Signature, ...]:
    if not isinstance(value, list):
        raise WeaveError("E_ENV_SIGS", "sigs must be an array")
    if not 1 <= len(value) <= grammar.MAX_SIGS:
        raise WeaveError("E_ENV_SIGS", "sigs must contain 1-16 entries")
    signatures: list[Signature] = []
    for entry in value:
        if not isinstance(entry, dict):
            raise WeaveError("E_ENV_SIGS", "signature entry must be an object")
        for member in entry:
            if member not in SIG_MEMBERS:
                raise WeaveError("E_ENV_SIGS", "unknown member in signature entry")
        for member in SIG_MEMBERS:
            if member not in entry:
                raise WeaveError("E_ENV_SIGS", "signature entry is missing a member")
        alg = entry["alg"]
        if alg != "ed25519":
            raise WeaveError("E_ENV_SIG_ALG", "signature algorithm must be ed25519")
        key = entry["key"]
        if not is_key_id(key):
            raise WeaveError("E_ENV_SIG_KEY", "signature key is not a key id")
        encoded = entry["value"]
        if not isinstance(encoded, str):
            raise WeaveError("E_ENV_SIG_VALUE", "signature value must be a base64url string")
        try:
            raw = decode_base64url(encoded, 64)
        except ValueError as error:
            raise WeaveError(
                "E_ENV_SIG_VALUE", "signature value is not 64 base64url bytes"
            ) from error
        signatures.append(Signature(alg=alg, key=key, value=encoded, raw=raw))
    for previous, current in zip(signatures, signatures[1:]):
        if not previous.key < current.key:
            raise WeaveError("E_ENV_SIGS", "sigs must be sorted by key and have unique keys")
    return tuple(signatures)


# ---------------------------------------------------------------------------
# Actor and labels objects
# ---------------------------------------------------------------------------


def _validate_actor(value: Any, *, kind: str) -> tuple[str, str, Reference | None]:
    if not isinstance(value, dict):
        raise WeaveError("E_ENV_ACTOR", "actor must be an object")
    for member in value:
        if member not in ACTOR_MEMBERS:
            raise WeaveError("E_ENV_UNKNOWN_FIELD", "unknown member in actor object")
    if "type" not in value:
        raise WeaveError("E_ENV_ACTOR", "actor.type is required")
    actor_type = value["type"]
    if actor_type not in ACTOR_TYPES:
        raise WeaveError("E_ENV_ACTOR_TYPE", "actor.type is not one of the closed values")
    if "key" not in value:
        raise WeaveError("E_ENV_ACTOR", "actor.key is required")
    actor_key = value["key"]
    if not is_key_id(actor_key):
        raise WeaveError("E_ENV_ACTOR_KEY", "actor.key is not a key id")

    grant_reference: Reference | None = None
    if actor_type == "agent":
        # Key-lifecycle records describe a key class; they are not delegated
        # actions, so the four agent-only members are not required there
        # (spec §4.2 exception, PROVISIONAL Q28).
        exempt = kinds.is_key_lifecycle(kind)
        if "model" not in value:
            if not exempt:
                raise WeaveError("E_ENV_ACTOR_MODEL_MISSING", "agent actor requires model")
        elif not grammar.is_valid_model(value["model"]):
            raise WeaveError(
                "E_ENV_ACTOR_MODEL", "actor.model does not match provider/model@version"
            )
        if "on_behalf_of" not in value:
            if not exempt:
                raise WeaveError(
                    "E_ENV_ACTOR_ON_BEHALF_MISSING", "agent actor requires on_behalf_of"
                )
        elif not is_key_id(value["on_behalf_of"]):
            raise WeaveError("E_ENV_ACTOR_ON_BEHALF", "actor.on_behalf_of is not a key id")
        if "grant" not in value:
            if not exempt:
                raise WeaveError("E_ENV_ACTOR_GRANT_MISSING", "agent actor requires grant")
        else:
            try:
                grant_reference = validate_reference(value["grant"])
            except WeaveError as error:
                raise WeaveError(
                    "E_ENV_ACTOR", "actor.grant is not a valid reference"
                ) from error
        if "idempotency_key" not in value:
            if not exempt:
                raise WeaveError(
                    "E_ENV_ACTOR_IDEMPOTENCY_MISSING",
                    "agent actor requires idempotency_key",
                )
        elif not grammar.is_valid_id(value["idempotency_key"]):
            raise WeaveError(
                "E_ENV_ACTOR_IDEMPOTENCY", "actor.idempotency_key is not a valid string"
            )
    else:
        for member in AGENT_ONLY_MEMBERS:
            if member in value:
                raise WeaveError(
                    "E_ENV_ACTOR", "agent-only member present on a non-agent actor"
                )
    return (actor_type, actor_key, grant_reference)


def _validate_labels(value: Any) -> tuple[str | None, str | None, Reference | None]:
    if not isinstance(value, dict):
        raise WeaveError("E_ENV_LABELS", "labels must be an object")
    for member in value:
        if member not in LABEL_MEMBERS:
            raise WeaveError("E_ENV_LABELS", "unknown member in labels object")
    sensitivity = value.get("sensitivity")
    if "sensitivity" in value and sensitivity not in SENSITIVITIES:
        raise WeaveError(
            "E_ENV_SENSITIVITY", "labels.sensitivity is not one of the closed values"
        )
    licence = value.get("licence")
    if "licence" in value and not grammar.is_valid_spdx_expression(licence):
        raise WeaveError(
            "E_ENV_LICENCE", "labels.licence is not a syntactically valid SPDX expression"
        )
    consent_reference: Reference | None = None
    if "consent" in value:
        try:
            consent_reference = validate_reference(value["consent"])
        except WeaveError as error:
            raise WeaveError(
                "E_ENV_LABELS", "labels.consent is not a valid reference"
            ) from error
    return (sensitivity, licence, consent_reference)


def _validate_salt(record: dict[str, Any]) -> str | None:
    """Validate the conditional salt; return the encoded salt or ``None``."""
    labels = record.get("labels")
    sensitivity = None
    if isinstance(labels, dict):
        sensitivity = labels.get("sensitivity")
    if sensitivity in ("personal", "local-only") and "salt" not in record:
        raise WeaveError("E_ENV_SALT_MISSING", "salt is required for this sensitivity")
    if "salt" not in record:
        return None
    salt = record["salt"]
    if not isinstance(salt, str):
        raise WeaveError("E_ENV_SALT", "salt must be a base64url string")
    try:
        decode_base64url(salt, grammar.MAX_SALT_BYTES)
    except ValueError as error:
        raise WeaveError("E_ENV_SALT", "salt is not 16 base64url bytes") from error
    return salt


# ---------------------------------------------------------------------------
# The envelope
# ---------------------------------------------------------------------------


@dataclass
class Envelope:
    """A structurally validated normal record envelope."""

    raw: dict[str, Any]
    format: str
    kind: str
    origin: Origin
    record_id: str
    stage: str
    actor_type: str
    actor_key: str
    actor_grant: Reference | None
    recorded_at: str
    occurred_at: str | None
    refs: tuple[ReferenceEntry, ...]
    labels: dict[str, Any] | None
    sensitivity: str | None
    licence: str | None
    consent: Reference | None
    salt: str | None
    body: dict[str, Any]
    sigs: tuple[Signature, ...]
    kind_known: bool = field(default=True)

    @property
    def sensitivity_rank(self) -> int:
        if self.sensitivity is None:
            return -1
        return SENSITIVITY_RANK[self.sensitivity]


def validate_envelope(record: Any) -> Envelope:
    """Validate a normal record envelope and return its parsed representation."""
    if not isinstance(record, dict):
        raise WeaveError("E_JSON_INVALID", "record must be a JSON object")
    for member in REQUIRED_MEMBERS:
        if member not in record:
            raise WeaveError("E_ENV_MISSING_FIELD", "missing required member %r" % member)
    for member in record:
        if member not in ENVELOPE_MEMBERS:
            raise WeaveError("E_ENV_UNKNOWN_FIELD", "unknown top-level member %r" % member)

    format_value = record["format"]
    if format_value != FORMAT:
        raise WeaveError("E_ENV_FORMAT", "format is not weave-record/1")

    kind = record["kind"]
    if not kinds.is_kind_syntax(kind):
        raise WeaveError("E_ENV_KIND_SYNTAX", "kind is not a well-formed kind name")

    origin = validate_origin(record["origin"])

    record_id = record["id"]
    if not grammar.is_valid_id(record_id):
        raise WeaveError("E_ENV_ID", "id violates the id grammar")

    stage = record["stage"]
    if stage not in STAGES:
        raise WeaveError("E_ENV_STAGE", "stage is not one of the closed values")
    if kinds.requires_accepted(kind) and stage != "accepted":
        raise WeaveError("E_ENV_STAGE", "this kind requires stage accepted")

    actor_type, actor_key, actor_grant = _validate_actor(record["actor"], kind=kind)

    recorded_at = record["recorded_at"]
    if not is_valid_timestamp(recorded_at):
        raise WeaveError("E_ENV_TIME", "recorded_at is not a TS literal")
    occurred_at = record.get("occurred_at")
    if "occurred_at" in record and not is_valid_timestamp(occurred_at):
        raise WeaveError("E_ENV_TIME", "occurred_at is not a TS literal")

    refs: tuple[ReferenceEntry, ...] = ()
    if "refs" in record:
        refs = validate_reference_list(record["refs"])

    labels = record.get("labels")
    sensitivity = licence = None
    consent = None
    if "labels" in record:
        sensitivity, licence, consent = _validate_labels(labels)

    salt = _validate_salt(record)

    body = record["body"]
    if not isinstance(body, dict):
        raise WeaveError("E_ENV_BODY", "body must be a JSON object")

    sigs: tuple[Signature, ...] = ()
    if "sigs" in record:
        sigs = _validate_sigs(record["sigs"])

    return Envelope(
        raw=record,
        format=format_value,
        kind=kind,
        origin=origin,
        record_id=record_id,
        stage=stage,
        actor_type=actor_type,
        actor_key=actor_key,
        actor_grant=actor_grant,
        recorded_at=recorded_at,
        occurred_at=occurred_at,
        refs=refs,
        labels=labels,
        sensitivity=sensitivity,
        licence=licence,
        consent=consent,
        salt=salt,
        body=body,
        sigs=sigs,
        kind_known=kinds.is_registered(kind),
    )


def signing_required(kind: str, stage: str) -> bool:
    """Whether the record MUST carry a per-record signature (spec §4.4)."""
    return stage == "accepted" or kind in kinds.MUST_SIGN_KINDS


def has_signature_by(sigs: tuple[Signature, ...], key: str) -> bool:
    """Whether ``sigs`` contains an entry whose key is exactly ``key``."""
    return any(signature.key == key for signature in sigs)
