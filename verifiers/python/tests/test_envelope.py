# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0

"""Record envelope structure: closed members, order, exemptions and grammars."""

from __future__ import annotations

import copy
import json
import pathlib

import pytest

from hyphaweave_verify import envelope, kinds
from hyphaweave_verify.errors import WeaveError

VECTORS = pathlib.Path(__file__).resolve().parents[3] / "vectors"
HUMAN_1 = "ed25519:333f90d1d9dfb653b78df977b9b13ff2"
AGENT_1 = "ed25519:b6190071e4bbc7c82afc702fa9ffa6f5"
T0 = "2026-11-01T00:00:00.000Z"


def base_record() -> dict:
    return {
        "format": "weave-record/1",
        "kind": "example.note",
        "origin": {"project": "example", "instance": HUMAN_1},
        "id": "record-1",
        "stage": "proposed",
        "actor": {"type": "human", "key": HUMAN_1},
        "recorded_at": T0,
        "body": {"text": "synthetic"},
    }


def changed(**overrides) -> dict:
    record = base_record()
    for key, value in overrides.items():
        if value is DELETE:
            record.pop(key, None)
        else:
            record[key] = value
    return record


DELETE = object()


def validate(record: dict) -> WeaveError:
    with pytest.raises(WeaveError) as raised:
        envelope.validate_envelope(record)
    return raised.value


def test_minimal_record_is_valid() -> None:
    parsed = envelope.validate_envelope(base_record())
    assert parsed.kind == "example.note"
    assert parsed.origin.project == "example"
    assert parsed.record_id == "record-1"
    assert not parsed.kind_known
    assert parsed.sensitivity is None


def test_roundtrip_of_a_vector_record() -> None:
    raw = (VECTORS / "stage" / "accepted-signed" / "record.json").read_bytes()
    from hyphaweave_verify import canonical

    parsed = envelope.validate_envelope(canonical.parse_file_bytes(raw))
    assert parsed.kind == "example.note"
    assert parsed.stage == "accepted"
    assert len(parsed.sigs) == 1


def test_missing_required_member() -> None:
    assert validate(changed(stage=DELETE)).code == "E_ENV_MISSING_FIELD"
    assert validate(changed(body=DELETE)).code == "E_ENV_MISSING_FIELD"


def test_unknown_member() -> None:
    record = base_record()
    record["extra"] = 1
    assert validate(record).code == "E_ENV_UNKNOWN_FIELD"


def test_format_kind_origin_id() -> None:
    assert validate(changed(format="weave-record/2")).code == "E_ENV_FORMAT"
    assert validate(changed(kind="nodot")).code == "E_ENV_KIND_SYNTAX"
    assert validate(changed(kind="Weave.grant")).code == "E_ENV_KIND_SYNTAX"
    assert validate(changed(origin={"project": "Example", "instance": HUMAN_1})).code == (
        "E_ENV_ORIGIN"
    )
    assert validate(
        changed(origin={"project": "example", "instance": HUMAN_1, "other": 1})
    ).code == "E_ENV_UNKNOWN_FIELD"
    assert validate(changed(id="")).code == "E_ENV_ID"
    assert validate(changed(id=" leading")).code == "E_ENV_ID"
    assert validate(changed(id="trailing ")).code == "E_ENV_ID"
    assert validate(changed(id="control\x01char")).code == "E_ENV_ID"
    assert validate(changed(id="x" * 257)).code == "E_ENV_ID"
    assert envelope.validate_envelope(changed(id="x" * 256)).record_id == "x" * 256


def test_stage_vocabulary_and_kind_constraints() -> None:
    assert validate(changed(stage="pending")).code == "E_ENV_STAGE"
    record = changed(kind="weave.grant", stage="proposed")
    assert validate(record).code == "E_ENV_STAGE"
    for kind in kinds.ACCEPTED_REQUIRED_KINDS:
        assert envelope.validate_envelope(
            changed(kind=kind, stage="accepted", body={})
        ).stage == "accepted"


def test_actor_rules() -> None:
    assert validate(changed(actor=[])).code == "E_ENV_ACTOR"
    assert validate(changed(actor={"key": HUMAN_1})).code == "E_ENV_ACTOR"
    assert validate(changed(actor={"type": "robot", "key": HUMAN_1})).code == (
        "E_ENV_ACTOR_TYPE"
    )
    assert validate(changed(actor={"type": "human"})).code == "E_ENV_ACTOR"
    assert validate(changed(actor={"type": "human", "key": "nope"})).code == (
        "E_ENV_ACTOR_KEY"
    )
    assert validate(
        changed(actor={"type": "human", "key": HUMAN_1, "model": "p/m@1"})
    ).code == "E_ENV_ACTOR"


def _agent_actor(**members: object) -> dict:
    actor = {
        "type": "agent",
        "key": AGENT_1,
        "model": "example/model@1.2.3",
        "on_behalf_of": HUMAN_1,
        "grant": {
            "origin": {"project": "example", "instance": HUMAN_1},
            "id": "grant-1",
            "digest": "sha256:" + "ab" * 32,
        },
        "idempotency_key": "idem-1",
    }
    for key, value in members.items():
        if value is DELETE:
            actor.pop(key, None)
        else:
            actor[key] = value
    return actor


def test_agent_actor_obligations() -> None:
    assert envelope.validate_envelope(changed(actor=_agent_actor())).actor_type == "agent"
    cases = {
        "model": "E_ENV_ACTOR_MODEL_MISSING",
        "on_behalf_of": "E_ENV_ACTOR_ON_BEHALF_MISSING",
        "grant": "E_ENV_ACTOR_GRANT_MISSING",
        "idempotency_key": "E_ENV_ACTOR_IDEMPOTENCY_MISSING",
    }
    for member, code in cases.items():
        assert validate(changed(actor=_agent_actor(**{member: DELETE}))).code == code
    assert validate(changed(actor=_agent_actor(model="bogus"))).code == "E_ENV_ACTOR_MODEL"
    assert validate(changed(actor=_agent_actor(on_behalf_of="bogus"))).code == (
        "E_ENV_ACTOR_ON_BEHALF"
    )
    assert validate(changed(actor=_agent_actor(idempotency_key="bad\x01"))).code == (
        "E_ENV_ACTOR_IDEMPOTENCY"
    )


def test_key_lifecycle_agent_exemption() -> None:
    """Agent-class key declarations need no model/grant/idempotency members (Q28)."""
    for kind in kinds.KEY_LIFECYCLE_KINDS:
        record = changed(
            kind=kind,
            stage="accepted",
            actor={"type": "agent", "key": AGENT_1},
        )
        parsed = envelope.validate_envelope(record)
        assert parsed.kind == kind
    # The exemption is limited to key-lifecycle kinds: an ordinary agent record
    # without the four members still fails.
    assert validate(
        changed(actor={"type": "agent", "key": AGENT_1})
    ).code == "E_ENV_ACTOR_MODEL_MISSING"


def test_timestamps() -> None:
    assert validate(changed(recorded_at="2026-11-01T00:00:00Z")).code == "E_ENV_TIME"
    assert validate(changed(recorded_at="2026-11-01T00:00:00.000+00:00")).code == (
        "E_ENV_TIME"
    )
    assert validate(changed(recorded_at="2026-02-30T00:00:00.000Z")).code == "E_ENV_TIME"
    assert validate(changed(recorded_at="2026-11-01T00:00:60.000Z")).code == "E_ENV_TIME"
    assert validate(changed(occurred_at="nope")).code == "E_ENV_TIME"
    assert envelope.validate_envelope(changed(occurred_at=T0)).occurred_at == T0


def test_refs_rules() -> None:
    reference = {
        "origin": {"project": "example", "instance": HUMAN_1},
        "id": "target",
        "digest": "sha256:" + "00" * 32,
    }
    valid = [{"rel": "derived_from", "ref": reference}]
    assert len(envelope.validate_envelope(changed(refs=valid)).refs) == 1
    assert validate(changed(refs={})).code == "E_ENV_REFS"
    assert validate(changed(refs=[{"rel": "unknown_rel", "ref": reference}])).code == (
        "E_ENV_REFS"
    )
    duplicate = valid + [{"rel": "derived_from", "ref": copy.deepcopy(reference)}]
    assert validate(changed(refs=duplicate)).code == "E_ENV_REFS"
    # Duplicates differ by digest only; same (rel, origin, id, digest) is the key.
    other = copy.deepcopy(reference)
    other["digest"] = "sha256:" + "11" * 32
    two = valid + [{"rel": "derived_from", "ref": other}]
    assert len(envelope.validate_envelope(changed(refs=two)).refs) == 2
    reference_with_extra = copy.deepcopy(reference)
    reference_with_extra["extra"] = 1
    assert validate(changed(refs=[{"rel": "derived_from", "ref": reference_with_extra}])).code == (
        "E_ENV_REFS"
    )


def test_labels_and_salt() -> None:
    assert validate(changed(labels={"sensitivity": "secret"})).code == "E_ENV_SENSITIVITY"
    assert validate(changed(labels={"extra": 1})).code == "E_ENV_LABELS"
    assert validate(changed(labels={"licence": "not a licence"})).code == "E_ENV_LICENCE"
    # A licence-only labels object is valid (Q16 ruling: sensitivity may be absent).
    parsed = envelope.validate_envelope(changed(labels={"licence": "MIT OR Apache-2.0"}))
    assert parsed.sensitivity is None
    # personal/local-only require a salt; others do not.
    assert validate(changed(labels={"sensitivity": "personal"})).code == "E_ENV_SALT_MISSING"
    assert validate(
        changed(labels={"sensitivity": "personal"}, salt="short")
    ).code == "E_ENV_SALT"
    valid_salt = "AAECAwQFBgcICQoLDA0ODw"
    parsed = envelope.validate_envelope(
        changed(labels={"sensitivity": "personal"}, salt=valid_salt)
    )
    assert parsed.salt == valid_salt
    assert envelope.validate_envelope(changed(labels={"sensitivity": "public"})).salt is None
    # A malformed salt is still an error when it is optional.
    assert validate(changed(salt="AAAAAAAAAAAAAAAAAAAAAA==")).code == "E_ENV_SALT"


def test_sigs_rules() -> None:
    valid_value = "A" * 86  # 64 zero bytes, unpadded base64url

    def sig(key: str = HUMAN_1, value: str = valid_value) -> dict:
        return {"alg": "ed25519", "key": key, "value": value}

    parsed = envelope.validate_envelope(changed(sigs=[sig()]))
    assert len(parsed.sigs) == 1 and parsed.sigs[0].raw == bytes(64)
    # Shape problems are E_ENV_SIGS.
    assert validate(changed(sigs=sig())).code == "E_ENV_SIGS"
    assert validate(changed(sigs=[])).code == "E_ENV_SIGS"
    without_value = sig()
    del without_value["value"]
    assert validate(changed(sigs=[without_value])).code == "E_ENV_SIGS"
    with_extra = sig()
    with_extra["extra"] = 1
    assert validate(changed(sigs=[with_extra])).code == "E_ENV_SIGS"
    # Member value errors.
    bad_alg = sig()
    bad_alg["alg"] = "rsa"
    assert validate(changed(sigs=[bad_alg])).code == "E_ENV_SIG_ALG"
    assert validate(changed(sigs=[sig("not-a-key")])).code == "E_ENV_SIG_KEY"
    assert validate(changed(sigs=[sig(value="A" * 85)])).code == "E_ENV_SIG_VALUE"
    assert validate(changed(sigs=[sig(value="A" * 86 + "=")])).code == "E_ENV_SIG_VALUE"
    # Ordering and uniqueness.
    unsorted = [sig("ed25519:" + "b" * 32), sig("ed25519:" + "a" * 32)]
    assert validate(changed(sigs=unsorted)).code == "E_ENV_SIGS"
    sorted_sigs = [sig("ed25519:" + "a" * 32), sig("ed25519:" + "b" * 32)]
    assert len(envelope.validate_envelope(changed(sigs=sorted_sigs)).sigs) == 2
    duplicated = [sig("ed25519:" + "a" * 32), sig("ed25519:" + "a" * 32)]
    assert validate(changed(sigs=duplicated)).code == "E_ENV_SIGS"


def test_signing_required_rules() -> None:
    assert envelope.signing_required("example.note", "proposed") is False
    assert envelope.signing_required("example.note", "accepted") is True
    for kind in kinds.MUST_SIGN_KINDS:
        assert envelope.signing_required(kind, "accepted") is True


def test_envelope_of_vector_key_declaration_is_valid() -> None:
    from hyphaweave_verify import canonical

    raw = (VECTORS / "key-lifecycle" / "declared-valid" / "record.json").read_bytes()
    parsed = envelope.validate_envelope(canonical.parse_file_bytes(raw))
    assert parsed.kind == "weave.key.declared"
    assert parsed.kind_known


def test_kind_names_require_a_project_segment() -> None:
    assert kinds.is_kind_syntax("example.note")
    assert kinds.is_kind_syntax("weave.key.declared")
    assert kinds.is_kind_syntax("a.b-c.d0")
    assert not kinds.is_kind_syntax("plain")
    assert not kinds.is_kind_syntax("Upper.case")
    assert not kinds.is_kind_syntax("a.b" * 100)
