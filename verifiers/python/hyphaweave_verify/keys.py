# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0

"""Key lifecycle: declarations, rotations, revocations and their effects (spec §9).

State is built from records that verified in the verification context (a
container's records plus an externally supplied keyset). The trust model is
TOFU: a valid ``weave.key.declared`` record is enough to accept the key
[E4][Q12]; there is no CA and no network lookup.

Semantic checks for the three key-lifecycle kinds live here as well because
they are mostly local to the record's body. Revocation effects on *signatures*
are applied by the verifier through :meth:`KeyState.check_signature_effects`.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import encoding
from .ed25519 import is_canonical_point_encoding
from .errors import WeaveError
from .refs import Resolution
from .times import timestamp_sort_key


@dataclass(frozen=True)
class VerifiedTimestamp:
    """A verified L2 timestamp, as far as revocation rescue is concerned."""

    gen_time: str


@dataclass
class KeyDeclaration:
    """A valid ``weave.key.declared`` record's key facts."""

    key_id: str
    key_type: str
    public_key: bytes
    valid_from: str | None
    valid_until: str | None
    recorded_at: str
    record_digest: str


@dataclass
class KeyRotation:
    """A valid ``weave.key.rotated`` record; supplies extra public keys."""

    old_key: str
    new_key: str
    old_public_key: bytes | None
    new_public_key: bytes
    recorded_at: str
    record_digest: str


@dataclass
class KeyRevocation:
    """A valid ``weave.key.revoked`` record."""

    key_id: str
    reason: str
    effective_at: str
    recorded_at: str
    record_digest: str


class KeyState:
    """Key material and lifecycle state derived from valid context records."""

    def __init__(self) -> None:
        self.declarations: dict[str, KeyDeclaration] = {}
        self.rotations: list[KeyRotation] = []
        self.revocations: dict[str, list[KeyRevocation]] = {}

    # -- construction -----------------------------------------------------

    def add_declaration(self, declaration: KeyDeclaration) -> None:
        # Multiple declarations for the same key are permitted; the first one in
        # context order wins so the result does not depend on enumeration order
        # beyond the deterministic context order (limitation recorded in README).
        self.declarations.setdefault(declaration.key_id, declaration)

    def add_rotation(self, rotation: KeyRotation) -> None:
        self.rotations.append(rotation)

    def add_revocation(self, revocation: KeyRevocation) -> None:
        self.revocations.setdefault(revocation.key_id, []).append(revocation)

    # -- queries ----------------------------------------------------------

    def public_key(self, key_id: str) -> bytes | None:
        """Resolve a key id to raw public-key bytes, or ``None`` if unknown."""
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
        return key_id in self.declarations or self.public_key(key_id) is not None

    # -- effects ----------------------------------------------------------

    def check_signature_effects(
        self,
        key_id: str,
        recorded_at: str,
        *,
        verified_timestamps: tuple[VerifiedTimestamp, ...] = (),
        skip_revocations: bool = False,
    ) -> None:
        """Apply declaration validity and revocation effects to a signature.

        ``skip_revocations`` is used for a ``weave.key.revoked`` record whose own
        signer is the revoked key: the revocation is the evidence and is not
        invalidated by itself (spec §9.5).
        """
        declaration = self.declarations.get(key_id)
        if declaration is not None and declaration.valid_until is not None:
            if timestamp_sort_key(recorded_at) > timestamp_sort_key(declaration.valid_until):
                raise WeaveError("E_KEY_EXPIRED", "signature made after valid_until")
        if skip_revocations:
            return
        revocations = sorted(
            self.revocations.get(key_id, ()),
            key=lambda revocation: (
                timestamp_sort_key(revocation.effective_at),
                revocation.record_digest,
            ),
        )
        for revocation in revocations:
            if timestamp_sort_key(recorded_at) <= timestamp_sort_key(revocation.effective_at):
                continue
            if revocation.reason == "key-compromise":
                rescued = any(
                    timestamp_sort_key(timestamp.gen_time)
                    <= timestamp_sort_key(revocation.effective_at)
                    for timestamp in verified_timestamps
                )
                if rescued:
                    continue
                raise WeaveError(
                    "E_KEY_COMPROMISED",
                    "signature made after a key-compromise revocation",
                )
            raise WeaveError("E_KEY_REVOKED", "signature made after a retired revocation")


# ---------------------------------------------------------------------------
# Kind semantics for the key-lifecycle kinds
# ---------------------------------------------------------------------------


def decode_public_key_material(value: object) -> bytes:
    """Decode declared key material: strict 32-byte base64url, no point checks.

    Point-encoding checks are part of the strict Ed25519 profile and therefore
    surface as ``E_SIG_NONCANONICAL_A`` from signature verification (step 5),
    which runs before kind semantics (step 7).
    """
    if not isinstance(value, str):
        raise WeaveError("E_KEY_PUBLIC_KEY", "public key must be a base64url string")
    try:
        return encoding.decode_base64url(value, 32)
    except ValueError as error:
        raise WeaveError(
            "E_KEY_PUBLIC_KEY", "public key is not 32 raw bytes in unpadded base64url"
        ) from error


def _decode_public_key(value: object) -> bytes:
    """Decode a declared public key, including the canonical point-encoding check."""
    raw = decode_public_key_material(value)
    if not is_canonical_point_encoding(raw):
        raise WeaveError("E_KEY_PUBLIC_KEY", "public key is not a canonical point encoding")
    return raw


def decode_declared_public_key(value: object) -> bytes:
    """Public wrapper used by the verifier for bootstrap key resolution."""
    return _decode_public_key(value)


def check_declared_semantics(
    *,
    body: dict,
    actor_key: str,
    actor_type: str,
    verified_signature_keys: frozenset[str],
    recorded_at: str,
    record_digest: str,
) -> KeyDeclaration:
    """Semantic checks for ``weave.key.declared`` (spec §9.1)."""
    declared_key = body["key"]
    if actor_key != declared_key:
        raise WeaveError("E_ENV_ACTOR_KEY", "actor.key must equal the declared key")
    key_type = body["key_type"]
    if actor_type != key_type:
        raise WeaveError(
            "E_ACTOR_KEY_TYPE_MISMATCH", "actor.type must equal body.key_type"
        )
    public_key = _decode_public_key(body["public_key"])
    derived = encoding.key_id_from_public_key(public_key)
    if derived != declared_key:
        raise WeaveError("E_KEY_ID_MISMATCH", "declared key id does not derive from public_key")
    valid_from = body.get("valid_from")
    valid_until = body.get("valid_until")
    if valid_from is not None and valid_until is not None:
        if timestamp_sort_key(valid_from) > timestamp_sort_key(valid_until):
            raise WeaveError("E_KEY_VALIDITY", "valid_from is after valid_until")
    if declared_key not in verified_signature_keys:
        raise WeaveError(
            "E_KEY_DECLARED_NOT_SELF_SIGNED",
            "no valid signature by the declared key",
        )
    return KeyDeclaration(
        key_id=declared_key,
        key_type=key_type,
        public_key=public_key,
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
    recorded_at: str,
    record_digest: str,
) -> KeyRotation:
    """Semantic checks for ``weave.key.rotated`` (spec §9.2)."""
    old_key = body["old_key"]
    new_key = body["new_key"]
    if actor_key != old_key:
        raise WeaveError("E_ENV_ACTOR_KEY", "actor.key must equal body.old_key")
    if old_key == new_key:
        raise WeaveError("E_KEY_ROTATION_KEYS", "old_key and new_key are the same key")
    new_public_key = _decode_public_key(body["new_public_key"])
    derived_new = encoding.key_id_from_public_key(new_public_key)
    if derived_new != new_key:
        raise WeaveError(
            "E_KEY_ROTATION_KEYS", "new_public_key contradicts its key id"
        )
    old_public_key: bytes | None = None
    if body.get("old_public_key") is not None:
        old_public_key = _decode_public_key(body["old_public_key"])
        derived_old = encoding.key_id_from_public_key(old_public_key)
        if derived_old != old_key:
            raise WeaveError(
                "E_KEY_ROTATION_KEYS", "old_public_key contradicts its key id"
            )
    if old_key not in verified_signature_keys or new_key not in verified_signature_keys:
        raise WeaveError(
            "E_KEY_ROTATION_SIGS", "rotation requires valid signatures by old and new keys"
        )
    return KeyRotation(
        old_key=old_key,
        new_key=new_key,
        old_public_key=old_public_key,
        new_public_key=new_public_key,
        recorded_at=recorded_at,
        record_digest=record_digest,
    )


def check_revoked_semantics(
    *,
    body: dict,
    recorded_at: str,
    record_digest: str,
    verification_context: "RevocationContext",
) -> KeyRevocation:
    """Semantic checks for ``weave.key.revoked`` (spec §9.3)."""

    effective_at = body["effective_at"]
    if timestamp_sort_key(effective_at) > timestamp_sort_key(recorded_at):
        raise WeaveError("E_KEY_REVOKE_EFFECTIVE", "effective_at is after recorded_at")
    revoked_key = body["key"]
    reason = body["reason"]

    # Signer requirements: examine every verified signature key of the record.
    signature_keys = verification_context.signature_keys
    declared_human = frozenset(
        key
        for key in signature_keys
        if verification_context.key_state.key_type(key) in ("human", "organization")
    )
    allowed = False
    if reason == "key-compromise":
        allowed = bool(declared_human)
    else:
        allowed = revoked_key in signature_keys or bool(declared_human)
    if not allowed:
        raise WeaveError("E_KEY_REVOKE_SIGNER", "revocation lacks an acceptable signer")
    return KeyRevocation(
        key_id=revoked_key,
        reason=reason,
        effective_at=effective_at,
        recorded_at=recorded_at,
        record_digest=record_digest,
    )


class RevocationContext:
    """Adapter handed to :func:`check_revoked_semantics`.

    Read-only; supplied by the verifier so keys.py does not depend on the whole
    verification context object.
    """

    __slots__ = ("signature_keys", "key_state")

    def __init__(self, signature_keys: frozenset[str], key_state: KeyState) -> None:
        self.signature_keys = signature_keys
        self.key_state = key_state
