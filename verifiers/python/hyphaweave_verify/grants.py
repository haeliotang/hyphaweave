# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0

"""Grants, delegated sub-grants and authorisation (spec §5.4-§5.6, §9.6).

A ``weave.grant`` record either grants authority (``action: "grant"``) or
revokes a previously granted authority (``action: "revoke"``). Root grants are
signed by human/organization actors; delegated sub-grants are signed by an
agent/program/device under a transferable parent grant and may not exceed it
[§8.2][Q10]. The body grammar itself is validated by :mod:`kinds`; this module
holds the cross-record semantics and the authorisation evaluation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from . import kinds, refs
from .envelope import Envelope
from .errors import WeaveError
from .refs import Reference, Resolution
from .keys import KeyState
from .times import timestamp_sort_key


# ---------------------------------------------------------------------------
# State derived from valid context records
# ---------------------------------------------------------------------------


@dataclass
class GrantRecord:
    """A valid ``weave.grant`` record with ``action == "grant"``."""

    digest: str
    actor_key: str
    actor_type: str
    recorded_at: str
    grantee_key: str
    kind_names: tuple[str, ...]
    actions: tuple[str, ...]
    valid_from: str
    valid_until: str | None
    transferable: bool
    envelope: Envelope


@dataclass
class GrantRevocationRecord:
    """A valid ``weave.grant`` record with ``action == "revoke"``."""

    digest: str
    actor_key: str
    effective_at: str
    target_digest: str
    envelope: Envelope


class GrantState:
    """Grants and grant revocations derived from valid context records."""

    def __init__(self) -> None:
        self.grants: dict[str, GrantRecord] = {}
        self.revocations: list[GrantRevocationRecord] = []

    def add(self, grant: GrantRecord) -> None:
        self.grants.setdefault(grant.digest, grant)

    def add_revocation(self, revocation: GrantRevocationRecord) -> None:
        self.revocations.append(revocation)

    def revocation_as_of(self, digest: str, recorded_at: str) -> GrantRevocationRecord | None:
        """Return a revocation that is effective at or before ``recorded_at``."""
        for revocation in sorted(
            self.revocations,
            key=lambda item: (timestamp_sort_key(item.effective_at), item.digest),
        ):
            if revocation.target_digest != digest:
                continue
            if timestamp_sort_key(revocation.effective_at) <= timestamp_sort_key(recorded_at):
                return revocation
        return None

    def extension_of(self, child: GrantRecord, parent: GrantRecord) -> None:
        """Check that a sub-grant does not exceed its parent's authority."""
        for kind_name in child.kind_names:
            if kind_name not in parent.kind_names:
                raise WeaveError(
                    "E_GRANT_DELEGATION_EXCEEDS", "sub-grant grants a kind outside the parent"
                )
        if timestamp_sort_key(child.valid_from) < timestamp_sort_key(parent.valid_from):
            raise WeaveError(
                "E_GRANT_DELEGATION_EXCEEDS", "sub-grant starts before the parent grant"
            )
        if parent.valid_until is None:
            return
        if child.valid_until is None or timestamp_sort_key(child.valid_until) > timestamp_sort_key(
            parent.valid_until
        ):
            raise WeaveError(
                "E_GRANT_DELEGATION_EXCEEDS", "sub-grant ends after the parent grant"
            )


def grant_record_from_envelope(envelope: Envelope, digest: str) -> GrantRecord:
    """Build the state view of a valid ``action: "grant"`` record."""
    body = envelope.body
    grant = body["grant"]
    return GrantRecord(
        digest=digest,
        actor_key=envelope.actor_key,
        actor_type=envelope.actor_type,
        recorded_at=envelope.recorded_at,
        grantee_key=grant["grantee"]["key"],
        kind_names=tuple(grant["kinds"]),
        actions=tuple(grant["actions"]),
        valid_from=grant["valid_from"],
        valid_until=grant["valid_until"],
        transferable=grant["transferable"],
        envelope=envelope,
    )


# ---------------------------------------------------------------------------
# Context protocol
# ---------------------------------------------------------------------------


class GrantContext(Protocol):
    """What grant evaluation needs from the verifier's live context."""

    @property
    def grant_state(self) -> GrantState:
        ...

    @property
    def key_state(self) -> "KeyState":
        ...

    def resolve(self, reference: Reference) -> Resolution:
        """Resolve a reference against the current verification context."""
        ...


# ---------------------------------------------------------------------------
# Kind semantics: weave.grant
# ---------------------------------------------------------------------------


def _resolve_parent_grant(
    reference: Reference | None, context: GrantContext
) -> GrantRecord:
    """Resolve the parent grant of a delegated sub-grant.

    An unresolvable parent makes the sub-grant ``unverifiable``
    (``E_GRANT_UNRESOLVED``); a parent that resolves but does not cover
    ``weave.grant``/``grant`` is ``E_GRANT_GRANTER`` (registry semantics).
    """
    if reference is None:
        raise WeaveError("E_GRANT_UNRESOLVED", "delegated grant has no parent reference")
    resolution = context.resolve(reference)
    if resolution.state != refs.FOUND or resolution.target is None:
        raise WeaveError("E_GRANT_UNRESOLVED", "parent grant cannot be resolved")
    target = resolution.target
    if target.kind != kinds.KIND_GRANT or target.record is None:
        raise WeaveError("E_GRANT_GRANTER", "parent reference does not resolve to a grant")
    parent_envelope = target.record.envelope  # type: ignore[attr-defined]
    if parent_envelope is None or parent_envelope.body.get("action") != "grant":
        raise WeaveError("E_GRANT_GRANTER", "parent grant is not an authorising grant")
    parent = grant_record_from_envelope(parent_envelope, target.computed_digest or "")
    if "weave.grant" not in parent.kind_names or "grant" not in parent.actions:
        raise WeaveError(
            "E_GRANT_GRANTER", "parent grant does not authorise granting weave.grant"
        )
    return parent


def check_grant_semantics(
    envelope: Envelope, digest: str, context: GrantContext
) -> GrantRecord | GrantRevocationRecord:
    """Cross-record semantic checks for a ``weave.grant`` record (spec §5.5).

    Called after the record's own signatures and body grammar were validated.
    Returns the state view the verifier records when the record is valid.
    """
    body = envelope.body
    action = body["action"]
    if action == "revoke":
        return _check_grant_revocation(envelope, digest, context)
    grant = grant_record_from_envelope(envelope, digest)
    valid_until = grant.valid_until
    if valid_until is not None and timestamp_sort_key(grant.valid_from) > timestamp_sort_key(
        valid_until
    ):
        raise WeaveError("E_KEY_VALIDITY", "grant valid_from is after valid_until")
    if envelope.actor_type in ("human", "organization"):
        return grant  # root grant
    # Delegated sub-grant.
    parent = _resolve_parent_grant(envelope.actor_grant, context)
    if not parent.transferable:
        raise WeaveError("E_GRANT_NOT_TRANSFERABLE", "parent grant is not transferable")
    if parent.grantee_key != envelope.actor_key:
        raise WeaveError(
            "E_GRANT_GRANTER", "parent grantee is not the sub-granting key"
        )
    if timestamp_sort_key(envelope.recorded_at) < timestamp_sort_key(parent.valid_from):
        raise WeaveError("E_GRANT_GRANTER", "parent grant is not yet valid")
    if parent.valid_until is not None and timestamp_sort_key(
        envelope.recorded_at
    ) > timestamp_sort_key(parent.valid_until):
        raise WeaveError("E_GRANT_GRANTER", "parent grant is expired")
    if context.grant_state.revocation_as_of(parent.digest, envelope.recorded_at) is not None:
        raise WeaveError("E_GRANT_GRANTER", "parent grant is revoked")
    context.grant_state.extension_of(grant, parent)
    return grant


def _check_grant_revocation(
    envelope: Envelope, digest: str, context: GrantContext
) -> GrantRevocationRecord:
    """Semantic checks for a grant-revocation record (spec §5.5)."""
    revoke = envelope.body["revoke"]
    reference = refs.validate_reference(revoke["revokes"])
    resolution = context.resolve(reference)
    if resolution.state != refs.FOUND or resolution.target is None:
        raise WeaveError("E_GRANT_REVOKE_REF", "revoked grant cannot be resolved")
    target = resolution.target
    if target.kind != kinds.KIND_GRANT:
        raise WeaveError("E_GRANT_REVOKE_REF", "revoked target is not a grant record")
    if target.record is None:
        raise WeaveError("E_GRANT_REVOKE_REF", "revoked target is not a grant record")
    target_envelope = target.record.envelope  # type: ignore[attr-defined]
    if target_envelope is None or target_envelope.body.get("action") != "grant":
        raise WeaveError("E_GRANT_REVOKE_REF", "revoked target is not an authorising grant")
    if refs.kind_claim_mismatch(reference, resolution):
        raise WeaveError("E_REF_KIND_MISMATCH", "revokes kind claim contradicts target kind")
    # Signer: the original granter's actor.key, or a declared human/organization key.
    signature_keys = frozenset(signature.key for signature in envelope.sigs)
    allowed = target_envelope.actor_key in signature_keys or any(
        context.key_state.key_type(key) in ("human", "organization") for key in signature_keys
    )
    if not allowed:
        raise WeaveError(
            "E_GRANT_REVOKE_SIGNER", "revocation lacks an acceptable signer"
        )
    return GrantRevocationRecord(
        digest=digest,
        actor_key=envelope.actor_key,
        effective_at=revoke["effective_at"],
        target_digest=target.computed_digest or "",
        envelope=envelope,
    )


# ---------------------------------------------------------------------------
# Authorisation of agent records by their cited grant
# ---------------------------------------------------------------------------


def _action_for_stage(stage: str) -> str:
    try:
        return kinds.STAGE_ACTION[stage]
    except KeyError as error:  # pragma: no cover - envelope validated the stage
        raise WeaveError("E_ENV_STAGE", "unknown stage") from error


def check_agent_authorization(envelope: Envelope, context: GrantContext) -> None:
    """Check that an agent-authored record is covered by its cited grant.

    Enforced for every agent record except key-lifecycle records (which are key
    classes, not delegated actions — spec §4.2 exception / Q28). A delegated
    ``weave.grant`` record is governed by the delegation rules instead of the
    generic stage/action mapping (spec §5.4, Q10), so it is skipped here.
    """
    if envelope.kind in kinds.KEY_LIFECYCLE_KINDS:
        return
    if envelope.kind == kinds.KIND_GRANT:
        return
    reference = envelope.actor_grant
    if reference is None:
        raise WeaveError(
            "E_ENV_ACTOR_GRANT_MISSING", "agent record cites no authorisation"
        )
    resolution = context.resolve(reference)
    if resolution.state != refs.FOUND or resolution.target is None:
        raise WeaveError("E_GRANT_UNRESOLVED", "cited authorisation cannot be resolved")
    target = resolution.target
    if target.kind != kinds.KIND_GRANT or target.record is None:
        raise WeaveError("E_GRANT_UNRESOLVED", "cited authorisation is not a grant")
    grant_envelope = target.record.envelope  # type: ignore[attr-defined]
    if grant_envelope is None or grant_envelope.body.get("action") != "grant":
        raise WeaveError("E_GRANT_UNRESOLVED", "cited grant is not an authorising grant")
    grant_digest = target.computed_digest or ""
    grant = grant_record_from_envelope(grant_envelope, grant_digest)
    if context.grant_state.revocation_as_of(grant_digest, envelope.recorded_at) is not None:
        raise WeaveError("E_GRANT_REVOKED", "cited grant has been revoked")
    recorded_at = envelope.recorded_at
    if timestamp_sort_key(recorded_at) < timestamp_sort_key(grant.valid_from) or (
        grant.valid_until is not None
        and timestamp_sort_key(recorded_at) > timestamp_sort_key(grant.valid_until)
    ):
        raise WeaveError("E_GRANT_EXPIRED", "cited grant is outside its validity window")
    if grant.grantee_key != envelope.actor_key:
        raise WeaveError(
            "E_GRANT_GRANTEE_MISMATCH", "record is not written by the grant's grantee"
        )
    if envelope.kind not in grant.kind_names:
        raise WeaveError(
            "E_GRANT_NOT_APPLICABLE", "grant does not cover the record's kind"
        )
    action = _action_for_stage(envelope.stage)
    if action not in grant.actions:
        raise WeaveError(
            "E_GRANT_NOT_APPLICABLE", "grant does not cover the record's action"
        )
