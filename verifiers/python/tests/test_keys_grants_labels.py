# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0

"""Revision-1 key lifecycle, grant authorisation and label/consent semantics."""

from __future__ import annotations

import pytest

from hyphaweave_verify import envelope, grants, keys, labels, refs
from hyphaweave_verify.errors import WeaveError

HUMAN_1 = "ed25519:333f90d1d9dfb653b78df977b9b13ff2"
HUMAN_2 = "ed25519:928a1e1dbe45a5d298ce5f6b5ce2eabe"
AGENT_1 = "ed25519:b6190071e4bbc7c82afc702fa9ffa6f5"
ORIGIN_JSON = {"project": "example", "instance": HUMAN_1}
T0 = "2026-11-01T00:00:00.000Z"
T1 = "2026-11-02T00:00:00.000Z"
T2 = "2026-11-03T00:00:00.000Z"


def require_code(callable_object, code: str) -> None:
    with pytest.raises(WeaveError) as raised:
        callable_object()
    assert raised.value.code == code


def _ms(ts: str) -> int:
    return keys._timestamp_ms(ts)


def _declaration(
    key_id: str = HUMAN_1,
    *,
    key_type: str = "human",
    valid_from: str | None = None,
    valid_until: str | None = None,
    recorded_at: str = T0,
    digest: str = "sha256:" + "00" * 32,
) -> keys.KeyDeclaration:
    return keys.KeyDeclaration(
        key_id=key_id,
        key_type=key_type,
        public_key=bytes(32),
        owner=None,
        valid_from=valid_from,
        valid_until=valid_until,
        recorded_at=recorded_at,
        record_digest=digest,
    )


# ---------------------------------------------------------------------------
# KeyState effects
# ---------------------------------------------------------------------------


def test_declared_key_validity_windows() -> None:
    state = keys.KeyState()
    state.add_declaration(_declaration(valid_from=T1, valid_until=T2))
    state.check_signature_effects(HUMAN_1, T1)  # at valid_from: allowed
    state.check_signature_effects(HUMAN_1, T2)  # at valid_until: allowed
    require_code(lambda: state.check_signature_effects(HUMAN_1, T0), "E_KEY_EXPIRED")
    require_code(lambda: state.check_signature_effects(HUMAN_1, "2026-11-04T00:00:00.000Z"), "E_KEY_EXPIRED")


def test_retired_revocation_boundary_is_inclusive() -> None:
    state = keys.KeyState()
    state.add_revocation(
        keys.KeyRevocation(
            key_id=HUMAN_1,
            reason="retired",
            effective_at=T1,
            effective_at_ms=_ms(T1),
            recorded_at=T1,
            record_digest="sha256:" + "01" * 32,
        )
    )
    state.check_signature_effects(HUMAN_1, T0)  # before effective_at: unaffected
    require_code(lambda: state.check_signature_effects(HUMAN_1, T1), "E_KEY_REVOKED")
    require_code(lambda: state.check_signature_effects(HUMAN_1, T2), "E_KEY_REVOKED")


def test_compromise_revocation_ignores_claimed_recorded_at() -> None:
    """S2: a backdated recorded_at does not rescue a compromised-key signature."""
    state = keys.KeyState()
    state.add_revocation(
        keys.KeyRevocation(
            key_id=HUMAN_1,
            reason="key-compromise",
            effective_at=T1,
            effective_at_ms=_ms(T1),
            recorded_at=T1,
            record_digest="sha256:" + "02" * 32,
        )
    )
    require_code(
        lambda: state.check_signature_effects(HUMAN_1, T0), "E_KEY_COMPROMISED"
    )
    # A verified external timestamp at or before the effective time rescues it.
    state.check_signature_effects(
        HUMAN_1,
        T0,
        verified_timestamps=(keys.VerifiedTimestamp(gen_time=T1, gen_time_ms=_ms(T1)),),
    )
    require_code(
        lambda: state.check_signature_effects(
            HUMAN_1,
            T0,
            verified_timestamps=(keys.VerifiedTimestamp(gen_time=T2, gen_time_ms=_ms(T2)),),
        ),
        "E_KEY_COMPROMISED",
    )


def test_self_evidencing_revocation_skips_effects() -> None:
    state = keys.KeyState()
    state.add_revocation(
        keys.KeyRevocation(
            key_id=HUMAN_1,
            reason="retired",
            effective_at=T1,
            effective_at_ms=_ms(T1),
            recorded_at=T1,
            record_digest="sha256:" + "03" * 32,
        )
    )
    state.check_signature_effects(HUMAN_1, T2, skip_revocations=True)


def test_earliest_declaration_wins() -> None:
    """Q12: the earliest (recorded_at, digest) declaration is authoritative."""
    state = keys.KeyState()
    later = _declaration(valid_until=T2, recorded_at=T2, digest="sha256:" + "b" * 64)
    earlier = _declaration(valid_until=T1, recorded_at=T1, digest="sha256:" + "a" * 64)
    state.add_declaration(later)
    state.add_declaration(earlier)
    assert state.declarations[HUMAN_1].record_digest == earlier.record_digest
    require_code(lambda: state.check_signature_effects(HUMAN_1, T2), "E_KEY_EXPIRED")


def test_rotation_supplies_only_explicit_material() -> None:
    state = keys.KeyState()
    new_key = "ed25519:" + "b" * 32
    state.add_rotation(
        keys.KeyRotation(
            old_key=HUMAN_1,
            new_key=new_key,
            old_public_key=bytes(32),
            new_public_key=bytes([1]) * 32,
            recorded_at=T0,
            record_digest="sha256:" + "04" * 32,
        )
    )
    assert state.public_key(new_key) == bytes([1]) * 32
    assert state.public_key("ed25519:" + "c" * 32) is None
    assert state.rotation_successors(HUMAN_1) == frozenset({new_key})


# ---------------------------------------------------------------------------
# Grant authorisation
# ---------------------------------------------------------------------------


def _grant_envelope(
    *,
    grantee: str = AGENT_1,
    kinds: tuple[str, ...] = ("example.note",),
    actions: tuple[str, ...] = ("accept", "propose"),
    scopes: tuple[str, ...] = ("test-scope",),
    transferable: bool = False,
    valid_from: str = T0,
    valid_until: str | None = T1,
    revocation: list[str] | None = None,
) -> envelope.Envelope:
    grant: dict = {
        "grantee": {"key": grantee},
        "kinds": list(kinds),
        "actions": list(actions),
        "scope": list(scopes),
        "valid_from": valid_from,
        "valid_until": valid_until,
        "transferable": transferable,
        "evidence": None,
        "remedy": None,
    }
    if revocation is not None:
        grant["revocation"] = revocation
    record = {
        "format": "weave-record/1",
        "kind": "weave.grant",
        "origin": ORIGIN_JSON,
        "id": "grant-1",
        "stage": "accepted",
        "actor": {"type": "human", "key": HUMAN_1},
        "recorded_at": T0,
        "body": {"action": "grant", "grant": grant},
        "sigs": [{"alg": "ed25519", "key": HUMAN_1, "value": "A" * 86}],
    }
    return envelope.validate_envelope(record)


class _FakeRecordView:
    def __init__(self, record_envelope: envelope.Envelope) -> None:
        self.envelope = record_envelope


class _GrantContext:
    def __init__(self, grant_envelope: envelope.Envelope | None, *, digest: str = "sha256:" + "aa" * 32) -> None:
        self.grant_state = grants.GrantState()
        self.key_state = keys.KeyState()
        self._grant_envelope = grant_envelope
        self._digest = digest
        if grant_envelope is not None:
            self.grant_state.add(grants.grant_record_from_envelope(grant_envelope, digest))

    def resolve(self, reference: refs.Reference) -> refs.Resolution:
        if self._grant_envelope is None:
            return refs.Resolution(refs.MISSING)
        return refs.Resolution(
            refs.FOUND,
            refs.TargetView(
                origin=self._grant_envelope.origin,
                id=self._grant_envelope.record_id,
                kind="weave.grant",
                verdict="valid",
                computed_digest=self._digest,
                record=_FakeRecordView(self._grant_envelope),
            ),
        )


def _agent_record(
    *, stage: str = "accepted", kind: str = "example.note", recorded_at: str = T0
) -> envelope.Envelope:
    record = {
        "format": "weave-record/1",
        "kind": kind,
        "origin": {"project": "example", "instance": AGENT_1},
        "id": "agent-record",
        "stage": stage,
        "actor": {
            "type": "agent",
            "key": AGENT_1,
            "model": "example/model@1.2.3",
            "on_behalf_of": HUMAN_1,
            "grant": {
                "origin": ORIGIN_JSON,
                "id": "grant-1",
                "digest": "sha256:" + "aa" * 32,
                "kind": "weave.grant",
            },
            "idempotency_key": "idem-1",
        },
        "recorded_at": recorded_at,
        "body": {"text": "x"},
        "sigs": [{"alg": "ed25519", "key": AGENT_1, "value": "A" * 86}],
    }
    return envelope.validate_envelope(record)


def test_agent_authorization_positive_for_all_stages() -> None:
    context = _GrantContext(_grant_envelope())
    for stage in ("proposed", "accepted"):
        grants.check_agent_authorization(_agent_record(stage=stage), context)


def test_agent_authorization_unresolved() -> None:
    require_code(
        lambda: grants.check_agent_authorization(_agent_record(), _GrantContext(None)),
        "E_GRANT_UNRESOLVED",
    )


def test_agent_authorization_codes() -> None:
    mismatched = _GrantContext(_grant_envelope(grantee="ed25519:" + "c" * 32))
    require_code(
        lambda: grants.check_agent_authorization(_agent_record(), mismatched),
        "E_GRANT_GRANTEE_MISMATCH",
    )
    wrong_kind = _GrantContext(_grant_envelope(kinds=("other.kind",)))
    require_code(
        lambda: grants.check_agent_authorization(_agent_record(), wrong_kind),
        "E_GRANT_NOT_APPLICABLE",
    )
    wrong_action = _GrantContext(_grant_envelope(actions=("propose",)))
    require_code(
        lambda: grants.check_agent_authorization(_agent_record(), wrong_action),
        "E_GRANT_NOT_APPLICABLE",
    )
    expired = _GrantContext(_grant_envelope(valid_until=T1))
    require_code(
        lambda: grants.check_agent_authorization(_agent_record(recorded_at=T2), expired),
        "E_GRANT_EXPIRED",
    )


def test_grant_revoked_boundary_is_inclusive() -> None:
    context = _GrantContext(_grant_envelope())
    context.grant_state.add_revocation(
        grants.GrantRevocationRecord(
            digest="sha256:" + "bb" * 32,
            actor_key=HUMAN_1,
            effective_at=T0,
            target_digest="sha256:" + "aa" * 32,
            envelope=_grant_envelope(),
        )
    )
    require_code(
        lambda: grants.check_agent_authorization(_agent_record(recorded_at=T0), context),
        "E_GRANT_REVOKED",
    )


def test_delegated_grant_chain_codes() -> None:
    """S3: delegation requires a transferable parent that is a subset superset."""
    parent_envelope = _grant_envelope(
        kinds=("weave.grant", "example.note"),
        actions=("grant", "accept", "propose"),
        transferable=True,
        valid_until=None,
    )
    parent = grants.grant_record_from_envelope(parent_envelope, "sha256:" + "aa" * 32)

    child_grant = {
        "grantee": {"key": "ed25519:" + "d" * 32},
        "kinds": ["example.note"],
        "actions": ["accept"],
        "scope": ["test-scope"],
        "valid_from": T0,
        "valid_until": None,
        "transferable": False,
        "evidence": None,
        "remedy": None,
    }

    def child_record(**overrides) -> envelope.Envelope:
        grant = dict(child_grant)
        grant.update(overrides.pop("grant", {}))
        body = {"action": "grant", "grant": grant}
        record = {
            "format": "weave-record/1",
            "kind": "weave.grant",
            "origin": {"project": "example", "instance": AGENT_1},
            "id": "sub-grant",
            "stage": "accepted",
            "actor": {
                "type": "agent",
                "key": AGENT_1,
                "model": "example/model@1.2.3",
                "on_behalf_of": HUMAN_1,
                "grant": {
                    "origin": ORIGIN_JSON,
                    "id": "grant-1",
                    "digest": "sha256:" + "aa" * 32,
                    "kind": "weave.grant",
                },
                "idempotency_key": "idem-sub",
            },
            "recorded_at": T0,
            "body": body,
            "sigs": [{"alg": "ed25519", "key": AGENT_1, "value": "A" * 86}],
        }
        record.update(overrides)
        return envelope.validate_envelope(record)

    context = _GrantContext(parent_envelope)
    grants.check_grant_semantics(child_record(), "sha256:" + "cc" * 32, context)  # ok

    require_code(
        lambda: grants.check_grant_semantics(
            child_record(grant={"actions": ["accept", "erase"]}),
            "sha256:" + "cc" * 32,
            context,
        ),
        "E_GRANT_DELEGATION_EXCEEDS",
    )
    require_code(
        lambda: grants.check_grant_semantics(
            child_record(grant={"kinds": ["example.note", "example.receipt"]}),
            "sha256:" + "cc" * 32,
            context,
        ),
        "E_GRANT_DELEGATION_EXCEEDS",
    )
    wrong_granter = _grant_envelope(
        kinds=("weave.grant", "example.note"),
        actions=("grant", "accept", "propose"),
        transferable=True,
        valid_until=None,
        grantee="ed25519:" + "e" * 32,
    )
    require_code(
        lambda: grants.check_grant_semantics(
            child_record(), "sha256:" + "cc" * 32, _GrantContext(wrong_granter)
        ),
        "E_GRANT_GRANTER",
    )
    not_transferable = _grant_envelope(
        kinds=("weave.grant", "example.note"),
        actions=("grant", "accept", "propose"),
        transferable=False,
        valid_until=None,
    )
    require_code(
        lambda: grants.check_grant_semantics(
            child_record(), "sha256:" + "cc" * 32, _GrantContext(not_transferable)
        ),
        "E_GRANT_NOT_TRANSFERABLE",
    )
    require_code(
        lambda: grants.check_grant_semantics(
            child_record(), "sha256:" + "cc" * 32, _GrantContext(None)
        ),
        "E_GRANT_UNRESOLVED",
    )


# ---------------------------------------------------------------------------
# Labels and consent
# ---------------------------------------------------------------------------


class _LabelContext:
    def __init__(
        self,
        target_envelope: envelope.Envelope | None,
        *,
        revoked_at: str | None = None,
    ) -> None:
        self.target_envelope = target_envelope
        self.revoked_at = revoked_at

    def resolve(self, reference: refs.Reference) -> refs.Resolution:
        if self.target_envelope is None:
            return refs.Resolution(refs.MISSING)
        return refs.Resolution(
            refs.FOUND,
            refs.TargetView(
                origin=self.target_envelope.origin,
                id=self.target_envelope.record_id,
                kind=self.target_envelope.kind,
                verdict="valid",
                computed_digest="sha256:" + "00" * 32,
                record=_FakeRecordView(self.target_envelope),
            ),
        )

    def consent_revoked_as_of(self, consent_digest: str, recorded_at: str):
        if self.revoked_at is None:
            return None
        from hyphaweave_verify.times import timestamp_sort_key

        if timestamp_sort_key(self.revoked_at) <= timestamp_sort_key(recorded_at):
            return object()
        return None


def _note(
    *,
    sensitivity: str | None,
    rel: str = "derived_from",
    consent_digest: str | None = None,
    recorded_at: str = T0,
) -> envelope.Envelope:
    reference = {
        "origin": ORIGIN_JSON,
        "id": "input-record",
        "digest": "sha256:" + "00" * 32,
    }
    record: dict = {
        "format": "weave-record/1",
        "kind": "example.note",
        "origin": {"project": "example", "instance": HUMAN_1},
        "id": "derived-record",
        "stage": "proposed",
        "actor": {"type": "human", "key": HUMAN_1},
        "recorded_at": recorded_at,
        "body": {},
    }
    if sensitivity is not None:
        record["labels"] = {"sensitivity": sensitivity}
        if sensitivity in ("personal", "local-only"):
            record["salt"] = "AAECAwQFBgcICQoLDA0ODw"
    if consent_digest is not None:
        record.setdefault("labels", {})["consent"] = {
            "origin": ORIGIN_JSON,
            "id": "consent-1",
            "digest": consent_digest,
            "kind": "weave.consent.granted",
        }
    record["refs"] = [{"rel": rel, "ref": reference}]
    return envelope.validate_envelope(record)


def test_label_propagation_all_derivation_relations() -> None:
    personal_input = _note(sensitivity="personal")
    for rel in ("derived_from", "reshaped_from", "migrated_from", "correction_of"):
        require_code(
            lambda: labels.check_label_propagation(
                _note(sensitivity="public", rel=rel), _LabelContext(personal_input)
            ),
            "E_LABEL_DOWNGRADE",
        )
    # A non-derivation relation does not propagate.
    assert (
        labels.check_label_propagation(
            _note(sensitivity="public", rel="supersedes"), _LabelContext(personal_input)
        )
        == []
    )


def test_label_propagation_unresolved_is_a_notice() -> None:
    notices = labels.check_label_propagation(_note(sensitivity="public"), _LabelContext(None))
    assert notices == ["N_LABEL_PROPAGATION_UNCHECKED"]


def _consent_granted() -> envelope.Envelope:
    record = {
        "format": "weave-record/1",
        "kind": "weave.consent.granted",
        "origin": ORIGIN_JSON,
        "id": "consent-1",
        "stage": "accepted",
        "actor": {"type": "human", "key": HUMAN_1},
        "recorded_at": T0,
        "body": {
            "purpose": "test",
            "scope": ["test"],
            "valid_from": T0,
            "valid_until": None,
            "data_subject": None,
            "terms": None,
        },
        "sigs": [{"alg": "ed25519", "key": HUMAN_1, "value": "A" * 86}],
    }
    return envelope.validate_envelope(record)


def test_consent_revoked_is_invalid_after_effective_time() -> None:
    granted = _consent_granted()
    consent_digest = "sha256:" + "00" * 32
    note = _note(sensitivity="internal", consent_digest=consent_digest, recorded_at=T1)
    # Before the withdrawal: still consistent.
    assert labels.check_consent_reference(note, _LabelContext(granted)) == []
    require_code(
        lambda: labels.check_consent_reference(
            note, _LabelContext(granted, revoked_at=T1)
        ),
        "E_CONSENT_REVOKED",
    )
    # A withdrawal after the record's recorded_at does not invalidate it.
    assert (
        labels.check_consent_reference(
            _note(
                sensitivity="internal",
                consent_digest=consent_digest,
                recorded_at=T0,
            ),
            _LabelContext(granted, revoked_at=T1),
        )
        == []
    )
    # Unresolvable consent is only a notice.
    assert labels.check_consent_reference(note, _LabelContext(None)) == [
        "N_CONSENT_UNRESOLVED"
    ]
