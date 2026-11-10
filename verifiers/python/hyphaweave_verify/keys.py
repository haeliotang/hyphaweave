# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0

"""Key lifecycle: declarations, rotations, revocations and their effects.

Implements the key-lifecycle rules (decisions #34 and #42):

* a declaration publishes the key structurally: the public key only has to be
  32 strict-base64url bytes and to derive the declared key id; point validity
  and subgroup membership are checked when a signature is verified (S1);
* a declaration must be self-signed, and additionally cosigned (S4/Q33): an
  agent/program/device key by its declared ``owner`` (a human/organization key),
  a human/organization key by a previously established human/organization key,
  except for the bootstrap root key which may be self-attested (notice
  ``N_SELF_ATTESTED_ROOT_KEY``);
* ``valid_until``/``valid_from`` bound the claimed signing time (Q20);
* ``retired``/``other`` revocations apply to signatures at or after
  ``effective_at``; a ``key-compromise`` revocation invalidates *every* signature
  of that key unless a verified external RFC 3161 timestamp with
  ``genTime_ms <= effective_at_ms`` covers the record (S2);
* the same key id declared more than once resolves to the earliest declaration
  by ``(recorded_at, digest)`` (Q12); signature key material is never inferred
  by following an ``old_key -> new_key`` rotation chain (M-12) — a rotation
  record may only be used where it explicitly lists the public key.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from . import encoding
from .errors import WeaveError
from .times import timestamp_sort_key


@dataclass(frozen=True)
class VerifiedTimestamp:
    """A verified L2 timestamp as far as compromise rescue is concerned.

    ``gen_time_us`` is genTime in integer microseconds and ``accuracy_us`` is
    the TSTInfo accuracy (seconds/millis/micros, absent fields = 0). S2/R3
    rescue requires ``gen_time_us + accuracy_us < effective_at_us`` (strictly
    earlier; equality does not rescue).
    """

    gen_time: str
    gen_time_ms: int
    gen_time_us: int = 0
    accuracy_us: int = 0

    @property
    def covered_until_us(self) -> int:
        """The last microsecond the receipt provably covers (exclusive bound +1)."""
        return self.gen_time_us + self.accuracy_us


@dataclass(frozen=True)
class KeyDeclaration:
    """A valid ``weave.key.declared`` record's facts."""

    key_id: str
    key_type: str
    public_key: bytes
    owner: str | None
    valid_from: str | None
    valid_until: str | None
    recorded_at: str
    record_digest: str


@dataclass(frozen=True)
class KeyRotation:
    """A valid ``weave.key.rotated`` record; explicitly lists extra public keys."""

    old_key: str
    new_key: str
    old_public_key: bytes | None
    new_public_key: bytes
    recorded_at: str
    record_digest: str


@dataclass(frozen=True)
class KeyRevocation:
    """A valid ``weave.key.revoked`` record."""

    key_id: str
    reason: str
    effective_at: str
    effective_at_ms: int
    recorded_at: str
    record_digest: str


def _declaration_order(declaration: KeyDeclaration) -> tuple[tuple[int, ...], str]:
    return (timestamp_sort_key(declaration.recorded_at), declaration.record_digest)


class KeyState:
    """Key material and lifecycle state derived from valid context records."""

    def __init__(self) -> None:
        self.declarations: dict[str, KeyDeclaration] = {}
        self.rotations: list[KeyRotation] = []
        self.revocations: dict[str, list[KeyRevocation]] = {}

    # -- construction -----------------------------------------------------

    def add_declaration(self, declaration: KeyDeclaration) -> None:
        """Record a declaration; the earliest ``(recorded_at, digest)`` wins (Q12)."""
        current = self.declarations.get(declaration.key_id)
        if current is None or _declaration_order(declaration) < _declaration_order(current):
            self.declarations[declaration.key_id] = declaration

    def add_rotation(self, rotation: KeyRotation) -> None:
        self.rotations.append(rotation)

    def add_revocation(self, revocation: KeyRevocation) -> None:
        self.revocations.setdefault(revocation.key_id, []).append(revocation)

    # -- queries ----------------------------------------------------------

    def public_key(self, key_id: str) -> bytes | None:
        """Resolve a key id to raw public-key bytes, or ``None`` if unknown.

        Only declarations and rotation records that explicitly list the public
        key are consulted; no ``old_key -> new_key`` inference is performed.
        """
        declaration = self.declarations.get(key_id)
        if declaration is not None:
            return declaration.public_key
        for rotation in self.rotations:
            if rotation.new_key == key_id:
                return rotation.new_public_key
            if rotation.old_key == key_id and rotation.old_public_key is not None:
                return rotation.old_public_key
        return None

    def key_type(self, key_id: str) -> str | None:
        declaration = self.declarations.get(key_id)
        return None if declaration is None else declaration.key_type

    def is_declared(self, key_id: str) -> bool:
        return self.public_key(key_id) is not None

    def rotation_successors(self, key_id: str, max_depth: int = 8) -> frozenset[str]:
        """Explicit ``old_key -> new_key`` successors of ``key_id`` (grant revocations).

        Only used for the *revocation authorisation* rule (Q10/M-5); signature key
        resolution never infers keys along this chain (M-12). Cycles are cut off.
        """
        result: set[str] = set()
        frontier = [key_id]
        for _ in range(max_depth):
            next_frontier: list[str] = []
            for current in frontier:
                for rotation in self.rotations:
                    if rotation.old_key != current:
                        continue
                    successor = rotation.new_key
                    if successor in result or successor == key_id:
                        continue
                    result.add(successor)
                    next_frontier.append(successor)
            if not next_frontier:
                break
            frontier = next_frontier
        return frozenset(result)

    # -- effects ----------------------------------------------------------

    def check_signature_effects(
        self,
        key_id: str,
        recorded_at: str,
        *,
        verified_timestamps: tuple[VerifiedTimestamp, ...] = (),
        timestamp_evidence_present: bool = False,
        skip_revocations: bool = False,
    ) -> None:
        """Apply declaration validity windows and revocation effects.

        ``skip_revocations`` is used for a ``weave.key.revoked`` record whose own
        signer is the revoked key: the revocation is the evidence and is not
        invalidated by itself.
        """
        declaration = self.declarations.get(key_id)
        if declaration is not None:
            if declaration.valid_from is not None and timestamp_sort_key(
                recorded_at
            ) < timestamp_sort_key(declaration.valid_from):
                raise WeaveError("E_KEY_EXPIRED", "signature made before valid_from")
            if declaration.valid_until is not None and timestamp_sort_key(
                recorded_at
            ) > timestamp_sort_key(declaration.valid_until):
                raise WeaveError("E_KEY_EXPIRED", "signature made after valid_until")
        if skip_revocations:
            return
        revocations = sorted(
            self.revocations.get(key_id, ()),
            key=lambda revocation: (revocation.effective_at_ms, revocation.record_digest),
        )
        for revocation in revocations:
            if revocation.reason == "key-compromise":
                # S2 + R3: the claimed recorded_at is not evidence. A verified
                # external timestamp rescues the signature only when
                # ``genTime + accuracy`` is strictly earlier than effective_at
                # (equality does not rescue; an absent accuracy counts as 0).
                effective_at_us = revocation.effective_at_ms * 1000
                rescued = any(
                    timestamp.covered_until_us < effective_at_us
                    for timestamp in verified_timestamps
                )
                if rescued:
                    continue
                if not verified_timestamps and timestamp_evidence_present:
                    # R4: receipts exist but no trust anchor was supplied: the
                    # missing information makes this unverifiable, not invalid.
                    raise WeaveError(
                        "E_TS_UNTRUSTED",
                        "timestamp receipts exist but no verified trust anchor is available",
                    )
                raise WeaveError(
                    "E_KEY_COMPROMISED",
                    "signature by a compromised key without an earlier verified timestamp",
                )
            if timestamp_sort_key(recorded_at) >= timestamp_sort_key(revocation.effective_at):
                raise WeaveError("E_KEY_REVOKED", "signature made at or after a retired revocation")


# ---------------------------------------------------------------------------
# Declaration / rotation / revocation semantics
# ---------------------------------------------------------------------------


class DeclarationContext(Protocol):
    """What the keyset-root trust rules need from the verification context."""

    def declaration_material(self, key_id: str) -> tuple[bytes, str] | None:
        """Public key and key class of any declared record, valid or not."""

    def trusted_human_org(self) -> frozenset[str]:
        """Human/organization key ids trusted via the keyset and its closure."""

    def is_declared_key(self, key_id: str) -> bool:
        """Whether the key id is declared anywhere in the context."""


def decode_public_key_material(value: object) -> bytes:
    """Decode declared key material: strict 32-byte base64url, no point checks.

    Point-canonicality and subgroup checks happen at signature verification
    (S1), so a declaration only fails here for structural encoding problems.
    """
    if not isinstance(value, str):
        raise WeaveError("E_KEY_PUBLIC_KEY", "public key must be a base64url string")
    try:
        return encoding.decode_base64url(value, 32)
    except ValueError as error:
        raise WeaveError(
            "E_KEY_PUBLIC_KEY", "public key is not 32 raw bytes in unpadded base64url"
        ) from error


def check_declared_semantics(
    *,
    body: dict,
    actor_key: str,
    actor_type: str,
    verified_signature_keys: frozenset[str],
    signature_entries_by_key: dict[str, frozenset[str]],
    recorded_at: str,
    record_digest: str,
    context: DeclarationContext,
    source: str,
) -> KeyDeclaration:
    """Semantic checks for ``weave.key.declared`` (S4-style cosign, R2/R5).

    Keyset-root trust model (decision #42): a human/organization key is trusted only via the verifier's
    local keyset (``source == "keyset"``); keyset declarations pass their own
    checks and need no cosignature. Container/target human/organization
    declarations become valid only when the key is already trusted or the
    declaration is cosigned by a trusted human/organization key; otherwise they
    are unverifiable with ``E_KEY_UNTRUSTED`` (plus
    ``N_SELF_ATTESTED_ROOT_KEY`` when a self-signature is their only signature)
    and never become trusted. Automated keys (agent/program/device) require an owner
    that is a human/organization declaration, cosigned and trusted (R5: a wrong
    owner class is ``E_KEY_OWNER_MISSING``).
    """
    declared_key = body["key"]
    if actor_key != declared_key:
        raise WeaveError("E_ENV_ACTOR_KEY", "actor.key must equal the declared key")
    key_type = body["key_type"]
    if actor_type != key_type:
        raise WeaveError(
            "E_ACTOR_KEY_TYPE_MISMATCH", "actor.type must equal body.key_type"
        )
    owner = body.get("owner")
    if key_type in ("agent", "program", "device") and owner is None:
        raise WeaveError(
            "E_KEY_OWNER_MISSING",
            "agent/program/device key declarations require body.owner",
        )
    public_key = decode_public_key_material(body["public_key"])
    derived = encoding.key_id_from_public_key(public_key)
    if derived != declared_key:
        raise WeaveError("E_KEY_ID_MISMATCH", "declared key id does not derive from public_key")
    valid_from = body.get("valid_from")
    valid_until = body.get("valid_until")
    if valid_from is not None and valid_until is not None:
        if timestamp_sort_key(valid_from) > timestamp_sort_key(valid_until):
            raise WeaveError("E_KEY_VALIDITY", "valid_from is after valid_until")
    if declared_key not in verified_signature_keys:
        # A missing self-signature is the kind's specific error; if the only
        # entry by that key used an unknown algorithm, the signature cannot be
        # checked at all (Q13).
        if signature_entries_by_key.get(declared_key):
            if context.is_declared_key(declared_key):
                raise WeaveError(
                    "E_SIG_UNVERIFIABLE",
                    "the declared key's signature entries use an unknown algorithm",
                )
            raise WeaveError(
                "E_KEY_UNKNOWN",
                "the declared key has no declaration that can be resolved",
            )
        raise WeaveError(
            "E_KEY_DECLARED_NOT_SELF_SIGNED",
            "no valid signature by the declared key",
        )

    if key_type in ("agent", "program", "device"):
        # R5: owner must be resolvable and be a human/organization declaration.
        if owner is None:  # pragma: no cover - checked above
            raise WeaveError("E_KEY_OWNER_MISSING", "missing owner")
        owner_material = context.declaration_material(owner)
        if owner_material is None:
            # Owner key is not declared anywhere in the context: unverifiable.
            raise WeaveError("E_KEY_UNKNOWN", "owner key is not declared in the context")
        if owner_material[1] not in ("human", "organization"):
            # A resolvable owner of the wrong class is an invalid declaration.
            raise WeaveError(
                "E_KEY_OWNER_MISSING",
                "owner declaration is not a human/organization key",
            )
        if owner not in verified_signature_keys:
            raise WeaveError(
                "E_KEY_DECLARED_NOT_COSIGNED",
                "agent/program/device key declaration lacks the owner's cosignature",
            )
        if owner not in context.trusted_human_org():
            raise WeaveError(
                "E_KEY_UNTRUSTED",
                "the owner key is not trusted through the local keyset",
            )
    else:
        if source == "keyset":
            # Keyset human/organization declarations are the local trust roots.
            pass
        else:
            trusted = context.trusted_human_org()
            if declared_key in trusted:
                pass  # duplicate declaration of an already trusted key
            elif (trusted & verified_signature_keys) - {declared_key}:
                pass  # cosigned by a trusted human/organization key
            else:
                self_signed_only = verified_signature_keys == {declared_key}
                raise WeaveError(
                    "E_KEY_UNTRUSTED",
                    "container declaration cannot be chained to a keyset trust root",
                    notice="N_SELF_ATTESTED_ROOT_KEY" if self_signed_only else None,
                )
    return KeyDeclaration(
        key_id=declared_key,
        key_type=key_type,
        public_key=public_key,
        owner=owner,
        valid_from=valid_from,
        valid_until=valid_until,
        recorded_at=recorded_at,
        record_digest=record_digest,
    )


def check_rotated_semantics(
    *,
    body: dict,
    actor_key: str,
    verified_signature_keys: frozenset[str],
    signature_entries_by_key: dict[str, frozenset[str]],
    recorded_at: str,
    record_digest: str,
) -> KeyRotation:
    """Semantic checks for ``weave.key.rotated`` (S4/Q33 note, M-11)."""
    old_key = body["old_key"]
    new_key = body["new_key"]
    if actor_key != old_key:
        raise WeaveError("E_ENV_ACTOR_KEY", "actor.key must equal body.old_key")
    if old_key == new_key:
        raise WeaveError("E_KEY_ROTATION_KEYS", "old_key and new_key are the same key")
    try:
        new_public_key = encoding.decode_base64url(body["new_public_key"], 32)
    except (ValueError, TypeError) as error:
        raise WeaveError(
            "E_KEY_ROTATION_KEYS", "new_public_key is not 32 raw base64url bytes"
        ) from error
    if encoding.key_id_from_public_key(new_public_key) != new_key:
        raise WeaveError("E_KEY_ROTATION_KEYS", "new_public_key contradicts its key id")
    old_public_key: bytes | None = None
    if body.get("old_public_key") is not None:
        try:
            old_public_key = encoding.decode_base64url(body["old_public_key"], 32)
        except (ValueError, TypeError) as error:
            raise WeaveError(
                "E_KEY_ROTATION_KEYS", "old_public_key is not 32 raw base64url bytes"
            ) from error
        if encoding.key_id_from_public_key(old_public_key) != old_key:
            raise WeaveError("E_KEY_ROTATION_KEYS", "old_public_key contradicts its key id")
    return KeyRotation(
        old_key=old_key,
        new_key=new_key,
        old_public_key=old_public_key,
        new_public_key=new_public_key,
        recorded_at=recorded_at,
        record_digest=record_digest,
    )


@dataclass(frozen=True)
class RevocationContext:
    """Adapter handed to :func:`check_revoked_semantics`."""

    signature_keys: frozenset[str]
    verified_signature_keys: frozenset[str]
    key_state: KeyState
    signature_entries_by_key: dict[str, frozenset[str]]

    def is_declared_key(self, key_id: str) -> bool:
        return self.key_state.is_declared(key_id)


def check_revoked_semantics(
    *,
    body: dict,
    recorded_at: str,
    record_digest: str,
    verification_context: RevocationContext,
) -> KeyRevocation:
    """Semantic checks for ``weave.key.revoked``."""
    effective_at = body["effective_at"]
    if timestamp_sort_key(effective_at) > timestamp_sort_key(recorded_at):
        raise WeaveError("E_KEY_REVOKE_EFFECTIVE", "effective_at is after recorded_at")
    revoked_key = body["key"]
    reason = body["reason"]

    signature_keys = verification_context.signature_keys
    verified_keys = verification_context.verified_signature_keys
    declared_human = frozenset(
        key
        for key in signature_keys
        if verification_context.key_state.key_type(key) in ("human", "organization")
    )
    allowed = set(declared_human)
    if reason != "key-compromise":
        allowed.add(revoked_key)
    if not (allowed & verified_keys):
        # Q13: when the only present entries by an allowed signer use unknown
        # algorithms, the signer cannot be checked at all.
        unverifiable_candidate = any(
            key in allowed and verification_context.signature_entries_by_key.get(key)
            for key in signature_keys
        )
        if unverifiable_candidate:
            if any(verification_context.is_declared_key(key) for key in allowed & signature_keys):
                raise WeaveError(
                    "E_SIG_UNVERIFIABLE",
                    "revocation signer only has unknown-algorithm entries",
                )
            raise WeaveError(
                "E_KEY_UNKNOWN", "revocation signer is not declared in the context"
            )
        raise WeaveError("E_KEY_REVOKE_SIGNER", "revocation lacks an acceptable signer")
    return KeyRevocation(
        key_id=revoked_key,
        reason=reason,
        effective_at=effective_at,
        effective_at_ms=_timestamp_ms(effective_at),
        recorded_at=recorded_at,
        record_digest=record_digest,
    )


def _timestamp_ms(value: str) -> int:
    """Convert a TS literal to integer milliseconds (S2 comparison unit)."""
    from datetime import datetime, timezone

    parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
        tzinfo=timezone.utc
    )
    return int(parsed.timestamp() * 1000)

