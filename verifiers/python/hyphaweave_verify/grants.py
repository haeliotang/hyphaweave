# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0

"""Grants, delegated sub-grants, revocations and authorisation (S3/Q10/Q11/M-3/M-5).

Revision-1 rules (decision #34):

* a delegated sub-grant must be a **subset** of its parent: kinds, actions and
  scope are subsets, the validity window lies inside the parent's, and ``grant``
  itself must be among the parent's actions to be re-delegated;
* the delegated-chain verdict order is fixed: unresolvable parent
  (``E_GRANT_UNRESOLVED``), parent is not an authorising grant
  (``E_GRANT_GRANTER``), non-transferable (``E_GRANT_NOT_TRANSFERABLE``), granter
  mismatch (``E_GRANT_GRANTER``), parent does not allow granting
  (``E_GRANT_GRANTER``), authority exceeded (``E_GRANT_DELEGATION_EXCEEDS``),
  parent revoked/expired (``E_GRANT_REVOKED``/``E_GRANT_EXPIRED``), chain depth /
  cycles (``E_GRANT_UNRESOLVED``);
* every stage of an agent record needs grant coverage (including ``propose``,
  ``reject``, ``withdraw``, ``supersede``);
* a grant may list the keys allowed to revoke it (``revocation``); the default is
  the granter's key plus its explicit rotation successors;
* revocation boundaries are inclusive: a grant revoked with
  ``effective_at <= recorded_at`` is revoked for that record.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from . import kinds, refs
from .envelope import Envelope
from .errors import WeaveError
from .refs import Reference, Resolution
from .times import timestamp_sort_key

MAX_CHAIN_DEPTH = 8


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
    scopes: tuple[str, ...]
    valid_from: str
    valid_until: str | None
    transferable: bool
    revocation_keys: tuple[str, ...] | None
    parent_reference: Reference | None
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


def grant_record_from_envelope(envelope: Envelope, digest: str) -> GrantRecord:
    """Build the state view of a valid ``action: "grant"`` record."""
    grant = envelope.body["grant"]
    revocation_value = grant.get("revocation")
    return GrantRecord(
        digest=digest,
        actor_key=envelope.actor_key,
        actor_type=envelope.actor_type,
        recorded_at=envelope.recorded_at,
        grantee_key=grant["grantee"]["key"],
        kind_names=tuple(grant["kinds"]),
        actions=tuple(grant["actions"]),
        scopes=tuple(grant["scope"]),
        valid_from=grant["valid_from"],
        valid_until=grant["valid_until"],
        transferable=grant["transferable"],
        revocation_keys=(
            None if revocation_value is None else tuple(revocation_value)
        ),
        parent_reference=envelope.actor_grant,
        envelope=envelope,
    )


class GrantContext(Protocol):
    """What grant evaluation needs from the verifier's live context."""

    @property
    def grant_state(self) -> GrantState:
        ...

    @property
    def key_state(self) -> "object":
        """A :class:`hyphaweave_verify.keys.KeyState` (rotation successors)."""

    def resolve(self, reference: Reference) -> Resolution:
        ...

    def is_declared_key(self, key_id: str) -> bool:
        """Whether the key id is declared anywhere in the context."""


# ---------------------------------------------------------------------------
# Chain validation
# ---------------------------------------------------------------------------


def _as_grant(envelope: Envelope, digest: str) -> GrantRecord:
    if envelope.kind != kinds.KIND_GRANT or envelope.body.get("action") != "grant":
        raise WeaveError("E_GRANT_GRANTER", "reference does not resolve to an authorising grant")
    return grant_record_from_envelope(envelope, digest)


def _resolve_grant(
    reference: Reference | None, context: GrantContext
) -> tuple[GrantRecord, str]:
    """Resolve a grant reference to a valid authorising grant record."""
    if reference is None:
        raise WeaveError("E_GRANT_UNRESOLVED", "no grant reference")
    resolution = context.resolve(reference)
    if resolution.state != refs.FOUND or resolution.target is None:
        raise WeaveError("E_GRANT_UNRESOLVED", "grant cannot be resolved")
    target = resolution.target
    digest = target.computed_digest or ""
    record = getattr(target.record, "envelope", None)
    if record is None or target.kind != kinds.KIND_GRANT:
        raise WeaveError("E_GRANT_GRANTER", "reference does not resolve to a grant record")
    return _as_grant(record, digest), digest


def _check_window(grant: GrantRecord, at_time: str) -> None:
    if timestamp_sort_key(at_time) < timestamp_sort_key(grant.valid_from) or (
        grant.valid_until is not None
        and timestamp_sort_key(at_time) > timestamp_sort_key(grant.valid_until)
    ):
        raise WeaveError("E_GRANT_EXPIRED", "grant is outside its validity window")


def _check_delegation(
    child: GrantRecord,
    parent: GrantRecord,
    context: GrantContext,
    at_time: str,
) -> None:
    """Steps 2-7 of the delegated sub-grant rules (fixed order)."""
    if "weave.grant" not in parent.kind_names or "grant" not in parent.actions:
        raise WeaveError(
            "E_GRANT_GRANTER", "parent grant does not authorise granting weave.grant"
        )
    if not parent.transferable:
        raise WeaveError("E_GRANT_NOT_TRANSFERABLE", "parent grant is not transferable")
    if parent.grantee_key != child.actor_key:
        raise WeaveError("E_GRANT_GRANTER", "parent grantee is not the sub-granting key")
    if not set(child.kind_names).issubset(set(parent.kind_names)):
        raise WeaveError(
            "E_GRANT_DELEGATION_EXCEEDS", "sub-grant grants kinds outside the parent"
        )
    if not set(child.actions).issubset(set(parent.actions)):
        raise WeaveError(
            "E_GRANT_DELEGATION_EXCEEDS", "sub-grant grants actions outside the parent"
        )
    if not set(child.scopes).issubset(set(parent.scopes)):
        raise WeaveError(
            "E_GRANT_DELEGATION_EXCEEDS", "sub-grant scope exceeds the parent"
        )
    if timestamp_sort_key(child.valid_from) < timestamp_sort_key(parent.valid_from):
        raise WeaveError(
            "E_GRANT_DELEGATION_EXCEEDS", "sub-grant starts before the parent grant"
        )
    if parent.valid_until is None:
        parent_until = None
    else:
        parent_until = timestamp_sort_key(parent.valid_until)
    if parent_until is not None and (
        child.valid_until is None
        or timestamp_sort_key(child.valid_until) > parent_until
    ):
        raise WeaveError(
            "E_GRANT_DELEGATION_EXCEEDS", "sub-grant ends after the parent grant"
        )
    # Step 7: parent revoked / outside its own window at the evaluation time.
    if context.grant_state.revocation_as_of(parent.digest, at_time) is not None:
        raise WeaveError("E_GRANT_REVOKED", "parent grant is revoked")
    if timestamp_sort_key(at_time) < timestamp_sort_key(parent.valid_from):
        raise WeaveError("E_GRANT_EXPIRED", "parent grant is not yet valid")
    if parent.valid_until is not None and timestamp_sort_key(at_time) > timestamp_sort_key(
        parent.valid_until
    ):
        raise WeaveError("E_GRANT_EXPIRED", "parent grant is expired")


def validate_grant_chain(
    grant: GrantRecord,
    context: GrantContext,
    at_time: str,
    *,
    depth: int = 0,
    seen: frozenset[str] = frozenset(),
) -> None:
    """Validate a grant and its ancestor chain at ``at_time`` (S3, fixed order)."""
    if depth > MAX_CHAIN_DEPTH or grant.digest in seen:
        raise WeaveError("E_GRANT_UNRESOLVED", "grant chain is too deep or cyclic")
    seen = seen | {grant.digest}
    _check_window(grant, at_time)
    if context.grant_state.revocation_as_of(grant.digest, at_time) is not None:
        raise WeaveError("E_GRANT_REVOKED", "grant is revoked")
    if grant.actor_type in ("human", "organization"):
        return  # root grant
    parent, _parent_digest = _resolve_grant(grant.parent_reference, context)
    # The whole authorisation chain, ancestors included, is evaluated at the
    # verified record's claimed time. This single assignment is the anti-
    # verification anchor for the old §5.5.2 step-6 reading: mutating it to the
    # grant's own time must make grant/ancestor-revoked-before-record fail.
    ancestor_time = at_time
    _check_delegation(grant, parent, context, ancestor_time)
    validate_grant_chain(parent, context, ancestor_time, depth=depth + 1, seen=seen)


def check_grant_semantics(
    envelope: Envelope,
    digest: str,
    context: GrantContext,
    verified_signature_keys: frozenset[str] = frozenset(),
) -> GrantRecord | GrantRevocationRecord:
    """Cross-record semantic checks for a ``weave.grant`` record."""
    body = envelope.body
    action = body["action"]
    if action == "revoke":
        return _check_grant_revocation(
            envelope, digest, context, verified_signature_keys
        )
    grant = grant_record_from_envelope(envelope, digest)
    valid_until = grant.valid_until
    if valid_until is not None and timestamp_sort_key(grant.valid_from) > timestamp_sort_key(
        valid_until
    ):
        raise WeaveError("E_KEY_VALIDITY", "grant valid_from is after valid_until")
    if envelope.actor_type in ("human", "organization"):
        return grant  # root grant
    # Delegated sub-grant: steps 1-8 at the sub-grant's recorded_at.
    parent, _ = _resolve_grant(envelope.actor_grant, context)
    _check_delegation(grant, parent, context, envelope.recorded_at)
    validate_grant_chain(parent, context, envelope.recorded_at, depth=1, seen=frozenset({digest}))
    return grant


def _check_grant_revocation(
    envelope: Envelope,
    digest: str,
    context: GrantContext,
    verified_signature_keys: frozenset[str],
) -> GrantRevocationRecord:
    """Semantic checks for a grant-revocation record."""
    revoke = envelope.body["revoke"]
    reference = refs.validate_reference(revoke["revokes"])
    resolution = context.resolve(reference)
    if resolution.state != refs.FOUND or resolution.target is None:
        raise WeaveError("E_GRANT_REVOKE_REF", "revoked grant cannot be resolved")
    target = resolution.target
    if target.kind != kinds.KIND_GRANT:
        raise WeaveError("E_GRANT_REVOKE_REF", "revoked target is not a grant record")
    target_envelope = getattr(target.record, "envelope", None)
    if target_envelope is None or target_envelope.body.get("action") != "grant":
        raise WeaveError("E_GRANT_REVOKE_REF", "revoked target is not an authorising grant")
    if refs.kind_claim_mismatch(reference, resolution):
        raise WeaveError("E_REF_KIND_MISMATCH", "revokes kind claim contradicts target kind")
    target_grant = grant_record_from_envelope(target_envelope, target.computed_digest or "")
    allowed = _allowed_revocation_keys(target_grant, context)
    signature_keys = frozenset(signature.key for signature in envelope.sigs)
    if not allowed & verified_signature_keys:
        candidate_unknown = any(
            key in allowed
            and any(
                entry.alg != "ed25519"
                for entry in envelope.sigs
                if entry.key == key
            )
            for key in signature_keys
        )
        if candidate_unknown:
            if any(context.is_declared_key(key) for key in allowed & signature_keys):
                raise WeaveError(
                    "E_SIG_UNVERIFIABLE",
                    "revocation signer only has unknown-algorithm entries",
                )
            raise WeaveError(
                "E_KEY_UNKNOWN", "revocation signer is not declared in the context"
            )
        raise WeaveError(
            "E_GRANT_REVOKE_SIGNER", "revocation lacks an authorised signer"
        )
    return GrantRevocationRecord(
        digest=digest,
        actor_key=envelope.actor_key,
        effective_at=revoke["effective_at"],
        target_digest=target_grant.digest,
        envelope=envelope,
    )


def _allowed_revocation_keys(grant: GrantRecord, context: GrantContext) -> frozenset[str]:
    if grant.revocation_keys is not None:
        return frozenset(grant.revocation_keys)
    key_state = context.key_state
    successors = getattr(key_state, "rotation_successors", lambda _key: frozenset())(
        grant.actor_key
    )
    return frozenset({grant.actor_key}) | frozenset(successors)


# ---------------------------------------------------------------------------
# Authorisation of records by their cited grant
# ---------------------------------------------------------------------------


def _action_for_stage(stage: str) -> str:
    try:
        return kinds.STAGE_ACTION[stage]
    except KeyError as error:  # pragma: no cover - envelope validated the stage
        raise WeaveError("E_ENV_STAGE", "unknown stage") from error


def check_agent_authorization(envelope: Envelope, context: GrantContext) -> None:
    """Check that a record's cited grant covers kind and stage action.

    Required for **every** stage of an agent record (M-3, decision #34), except
    key-lifecycle records (key classes, not delegated actions) and ``weave.grant``
    records (governed by the delegation rules).
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
    if target.kind != kinds.KIND_GRANT:
        raise WeaveError("E_GRANT_GRANTER", "cited authorisation is not a grant record")
    grant_envelope = getattr(target.record, "envelope", None)
    if grant_envelope is None or grant_envelope.body.get("action") != "grant":
        raise WeaveError("E_GRANT_GRANTER", "cited authorisation is not an authorising grant")
    grant = grant_record_from_envelope(grant_envelope, target.computed_digest or "")
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
    validate_grant_chain(
        grant, context, envelope.recorded_at, depth=0, seen=frozenset()
    )
