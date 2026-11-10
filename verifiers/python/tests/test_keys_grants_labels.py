# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0

"""Key lifecycle effects, grant authorisation and label propagation rules."""

from __future__ import annotations

import pytest

from hyphaweave_verify import envelope, grants, keys, labels, refs
from hyphaweave_verify.errors import WeaveError

HUMAN_1 = "ed25519:333f90d1d9dfb653b78df977b9b13ff2"
AGENT_1 = "ed25519:b6190071e4bbc7c82afc702fa9ffa6f5"
ORIGIN_JSON = {"project": "example", "instance": HUMAN_1}
T0 = "2026-11-01T00:00:00.000Z"
T1 = "2026-11-02T00:00:00.000Z"
T2 = "2026-11-03T00:00:00.000Z"


def require_code(callable_object, code: str) -> None:
    with pytest.raises(WeaveError) as raised:
        callable_object()
    assert raised.value.code == code


# ---------------------------------------------------------------------------
# KeyState effects
# ---------------------------------------------------------------------------


def _declaration(key_id: str = HUMAN_1, valid_until: str | None = None) -> keys.KeyDeclaration:
    return keys.KeyDeclaration(
        key_id=key_id,
        key_type="human",
        public_key=bytes(32),
        valid_from=None,
        valid_until=valid_until,
        recorded_at=T0,
        record_digest="sha256:" + "00" * 32,
    )


def test_declared_key_validity_window() -> None:
    state = keys.KeyState()
    state.add_declaration(_declaration(valid_until=T1))
    state.check_signature_effects(HUMAN_1, T0)  # inside the window
    state.check_signature_effects(HUMAN_1, T1)  # at the boundary is allowed
    require_code(
        lambda: state.check_signature_effects(HUMAN_1, T2), "E_KEY_EXPIRED"
    )


def test_retired_revocation_is_forward_only() -> None:
    state = keys.KeyState()
    state.add_revocation(
        keys.KeyRevocation(
            key_id=HUMAN_1,
            reason="retired",
            effective_at=T1,
            recorded_at=T1,
            record_digest="sha256:" + "01" * 32,
        )
    )
    state.check_signature_effects(HUMAN_1, T1)  # at effective_at: unaffected
    require_code(lambda: state.check_signature_effects(HUMAN_1, T2), "E_KEY_REVOKED")


def test_compromise_revocation_is_retroactive_and_rescuable() -> None:
    state = keys.KeyState()
    state.add_revocation(
        keys.KeyRevocation(
            key_id=HUMAN_1,
            reason="key-compromise",
            effective_at=T1,
            recorded_at=T1,
            record_digest="sha256:" + "02" * 32,
        )
    )
    require_code(
        lambda: state.check_signature_effects(HUMAN_1, T2), "E_KEY_COMPROMISED"
    )
    # A verified L2 timestamp with genTime <= effective_at rescues the signature.
    state.check_signature_effects(
        HUMAN_1, T2, verified_timestamps=(keys.VerifiedTimestamp(gen_time=T0),)
    )
    # A timestamp after the compromise does not rescue it.
    require_code(
        lambda: state.check_signature_effects(
            HUMAN_1, T2, verified_timestamps=(keys.VerifiedTimestamp(gen_time=T2),)
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
            recorded_at=T1,
            record_digest="sha256:" + "03" * 32,
        )
    )
    # The revocation record itself is signed by the revoked key; it stays valid.
    state.check_signature_effects(HUMAN_1, T2, skip_revocations=True)


def test_rotation_supplies_key_material() -> None:
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
    assert state.public_key(HUMAN_1) == bytes(32)
    assert state.public_key("ed25519:" + "c" * 32) is None


# ---------------------------------------------------------------------------
# Grant authorisation
# ---------------------------------------------------------------------------


def _grant_envelope(
    *,
    grantee: str = AGENT_1,
    kinds: tuple[str, ...] = ("example.note",),
    actions: tuple[str, ...] = ("accept", "propose"),
    transferable: bool = False,
    valid_from: str = T0,
    valid_until: str | None = T1,
) -> envelope.Envelope:
    record = {
        "format": "weave-record/1",
        "kind": "weave.grant",
        "origin": ORIGIN_JSON,
        "id": "grant-1",
        "stage": "accepted",
        "actor": {"type": "human", "key": HUMAN_1},
        "recorded_at": T0,
        "body": {
            "action": "grant",
            "grant": {
                "grantee": {"key": grantee},
                "kinds": list(kinds),
                "actions": list(actions),
                "scope": ["test"],
                "valid_from": valid_from,
                "valid_until": valid_until,
                "transferable": transferable,
                "evidence": None,
                "remedy": None,
            },
        },
        "sigs": [
            {
                "alg": "ed25519",
                "key": HUMAN_1,
                "value": "A" * 86,
            }
        ],
    }
    return envelope.validate_envelope(record)


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
        target = refs.TargetView(
            origin=self._grant_envelope.origin,
            id=self._grant_envelope.record_id,
            kind="weave.grant",
            verdict="valid",
            computed_digest=self._digest,
            record=_RecordView(self._grant_envelope),
        )
        return refs.Resolution(refs.FOUND, target)


class _RecordView:
    def __init__(self, record_envelope: envelope.Envelope) -> None:
        self.envelope = record_envelope


def _agent_record(*, stage: str = "accepted", kind: str = "example.note", recorded_at: str = T0) -> envelope.Envelope:
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


def test_agent_authorization_positive() -> None:
    context = _GrantContext(_grant_envelope())
    grants.check_agent_authorization(_agent_record(), context)


def test_agent_authorization_unresolved() -> None:
    require_code(
        lambda: grants.check_agent_authorization(
            _agent_record(), _GrantContext(None)
        ),
        "E_GRANT_UNRESOLVED",
    )


def test_agent_authorization_grantee_kind_and_action() -> None:
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


def test_agent_authorization_expiry_and_revocation() -> None:
    expired = _GrantContext(_grant_envelope(valid_until=T0))
    require_code(
        lambda: grants.check_agent_authorization(_agent_record(recorded_at=T1), expired),
        "E_GRANT_EXPIRED",
    )
    # Not-yet-valid grants are treated like expired grants.
    future = _GrantContext(_grant_envelope(valid_from=T2, valid_until=None))
    require_code(
        lambda: grants.check_agent_authorization(_agent_record(recorded_at=T1), future),
        "E_GRANT_EXPIRED",
    )
    revoked_context = _GrantContext(_grant_envelope())
    revoked_context.grant_state.add_revocation(
        grants.GrantRevocationRecord(
            digest="sha256:" + "bb" * 32,
            actor_key=HUMAN_1,
            effective_at=T0,
            target_digest="sha256:" + "aa" * 32,
            envelope=_grant_envelope(),
        )
    )
    require_code(
        lambda: grants.check_agent_authorization(_agent_record(recorded_at=T1), revoked_context),
        "E_GRANT_REVOKED",
    )


def test_key_lifecycle_agent_records_need_no_authorization() -> None:
    # An agent-class key declaration has no grant coverage requirement (Q28).
    record = {
        "format": "weave-record/1",
        "kind": "weave.key.declared",
        "origin": {"project": "example", "instance": AGENT_1},
        "id": "decl",
        "stage": "accepted",
        "actor": {"type": "agent", "key": AGENT_1},
        "recorded_at": T0,
        "body": {
            "algorithm": "ed25519",
            "key": AGENT_1,
            "key_type": "agent",
            "public_key": "A" * 43,
        },
        "sigs": [{"alg": "ed25519", "key": AGENT_1, "value": "A" * 86}],
    }
    parsed = envelope.validate_envelope(record)
    grants.check_agent_authorization(parsed, _GrantContext(None))  # no exception


# ---------------------------------------------------------------------------
# Labels
# ---------------------------------------------------------------------------


class _LabelContext:
    def __init__(self, target_envelope: envelope.Envelope | None) -> None:
        self.target_envelope = target_envelope

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
                record=_RecordView(self.target_envelope),
            ),
        )


def _note(*, sensitivity: str | None, derived_from: bool = True) -> envelope.Envelope:
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
        "recorded_at": T0,
        "body": {},
    }
    if sensitivity is not None:
        record["labels"] = {"sensitivity": sensitivity}
        if sensitivity in ("personal", "local-only"):
            record["salt"] = "AAECAwQFBgcICQoLDA0ODw"
    if derived_from:
        record["refs"] = [{"rel": "derived_from", "ref": reference}]
    return envelope.validate_envelope(record)


def test_label_propagation_strictest_wins() -> None:
    personal_input = _note(sensitivity="personal")
    labels.check_label_propagation(_note(sensitivity="personal"), _LabelContext(personal_input))
    labels.check_label_propagation(_note(sensitivity="local-only"), _LabelContext(personal_input))
    require_code(
        lambda: labels.check_label_propagation(
            _note(sensitivity="public"), _LabelContext(personal_input)
        ),
        "E_LABEL_DOWNGRADE",
    )
    require_code(
        lambda: labels.check_label_propagation(
            _note(sensitivity=None), _LabelContext(personal_input)
        ),
        "E_LABEL_DOWNGRADE",
    )
    # A missing label is fine when the input is public.
    public_input = _note(sensitivity="public")
    assert labels.check_label_propagation(
        _note(sensitivity=None), _LabelContext(public_input)
    ) == []


def test_label_propagation_unresolved_is_a_notice() -> None:
    notices = labels.check_label_propagation(_note(sensitivity="public"), _LabelContext(None))
    assert notices == ["N_LABEL_PROPAGATION_UNCHECKED"]


def test_consent_reference_rules() -> None:
    consent_record = {
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
    consent_envelope = envelope.validate_envelope(consent_record)
    other = _note(sensitivity="public")
    other_kind = envelope.validate_envelope(
        {
            **other.raw,
            "labels": {
                "consent": {
                    "origin": ORIGIN_JSON,
                    "id": "consent-1",
                    "digest": "sha256:" + "00" * 32,
                    "kind": "weave.consent.granted",
                }
            },
        }
    )
    assert labels.check_consent_reference(other_kind, _LabelContext(consent_envelope)) == []
    mismatched = _LabelContext(_note(sensitivity="public"))
    require_code(
        lambda: labels.check_consent_reference(other_kind, mismatched),
        "E_REF_KIND_MISMATCH",
    )
    assert labels.check_consent_reference(other_kind, _LabelContext(None)) == [
        "N_CONSENT_UNRESOLVED"
    ]
