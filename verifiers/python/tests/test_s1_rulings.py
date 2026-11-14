# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0

"""Focused unit tests for the S1 revision rulings (S1, S2, S9, S10, S11, S12,
S13, S14 and the F-finding behaviours that are not vector-pinned)."""

from __future__ import annotations

import json
from pathlib import Path
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hyphaweave_verify import encoding, keys, timestamps
from hyphaweave_verify.errors import UsageError, WeaveError
from hyphaweave_verify import verifier

from conftest import KEYSET, VECTORS, run_cli


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _public_key(byte: int) -> tuple[bytes, str]:
    private = Ed25519PrivateKey.from_private_bytes(bytes([byte]) * 32)
    raw = private.public_key().public_bytes_raw()
    return raw, encoding.key_id_from_public_key(raw)


def _declaration(byte: int, key_type: str, recorded_at: str, window=("2026-01-01T00:00:00.000Z", None), source="context"):
    _raw, key_id = _public_key(byte)
    return keys.KeyDeclaration(
        key_id=key_id,
        key_type=key_type,
        public_key=_raw,
        owner=None,
        valid_from=window[0],
        valid_until=window[1],
        recorded_at=recorded_at,
        record_digest="sha256:" + ("%02x" % byte) * 32,
        source=source,
    )


def _revocation(key_id: str, effective_at: str, reason: str = "retired") -> keys.KeyRevocation:
    return keys.KeyRevocation(
        key_id=key_id,
        reason=reason,
        effective_at=effective_at,
        effective_at_ms=keys._timestamp_ms(effective_at),
        recorded_at="2026-01-01T00:00:00.000Z",
        record_digest="sha256:" + "aa" * 32,
    )


class _DeclaredContext:
    """Minimal DeclarationContext for check_declared_semantics tests."""

    def __init__(self, governing: str | None = None, material=None, trusted=frozenset()):
        self._governing = governing
        self._material = material
        self._trusted = frozenset(trusted)

    def declaration_material(self, key_id: str):
        return self._material

    def trusted_human_org(self) -> frozenset[str]:
        return self._trusted

    def is_declared_key(self, key_id: str) -> bool:
        return self._material is not None

    def governing_class(self, key_id: str, exclude_digest: str) -> str | None:
        return self._governing


def _declared_body(byte: int, key_type: str) -> dict:
    raw, key_id = _public_key(byte)
    return {
        "key": key_id,
        "key_type": key_type,
        "algorithm": "ed25519",
        "public_key": encoding.encode_base64url(raw),
    }


# ---------------------------------------------------------------------------
# S1 - keyset declaration governs class and window
# ---------------------------------------------------------------------------


def test_keyset_declaration_governs_window_and_class() -> None:
    raw, key_id = _public_key(1)
    keyset = keys.KeyDeclaration(
        key_id=key_id,
        key_type="human",
        public_key=raw,
        owner=None,
        valid_from="2026-01-01T00:00:00.000Z",
        valid_until="2026-02-01T00:00:00.000Z",
        recorded_at="2026-01-01T00:00:00.000Z",
        record_digest="sha256:" + "01" * 32,
        source="keyset",
    )
    # A backdated in-context re-declaration widens the window and reclassifies.
    attack = keys.KeyDeclaration(
        key_id=key_id,
        key_type="agent",
        public_key=raw,
        owner=None,
        valid_from="2025-01-01T00:00:00.000Z",
        valid_until="2027-01-01T00:00:00.000Z",
        recorded_at="2025-01-01T00:00:00.000Z",
        record_digest="sha256:" + "02" * 32,
        source="context",
    )
    state = keys.KeyState()
    state.add_declaration(attack)
    state.add_declaration(keyset)
    assert state.key_type(key_id) == "human"
    assert state.declarations[key_id].valid_until == "2026-02-01T00:00:00.000Z"
    with pytest.raises(WeaveError) as raised:
        state.check_signature_effects(key_id, "2026-03-01T00:00:00.000Z")
    assert raised.value.code == "E_KEY_EXPIRED"


def test_class_conflict_is_invalid_with_dedicated_code() -> None:
    body = _declared_body(3, "human")
    context = _DeclaredContext(governing="agent")
    with pytest.raises(WeaveError) as raised:
        keys.check_declared_semantics(
            body=body,
            actor_key=body["key"],
            actor_type="human",
            verified_signature_keys=frozenset({body["key"]}),
            signature_entries_by_key={},
            recorded_at="2026-01-02T00:00:00.000Z",
            record_digest="sha256:" + "03" * 32,
            context=context,
            source="container",
        )
    assert raised.value.code == "E_KEY_CLASS_CONFLICT"


def test_same_class_redeclaration_does_not_override_governed_window() -> None:
    body = _declared_body(4, "human")
    context = _DeclaredContext(governing="human", trusted=frozenset({body["key"]}))
    declaration = keys.check_declared_semantics(
        body=body,
        actor_key=body["key"],
        actor_type="human",
        verified_signature_keys=frozenset({body["key"]}),
        signature_entries_by_key={},
        recorded_at="2026-01-02T00:00:00.000Z",
        record_digest="sha256:" + "04" * 32,
        context=context,
        source="container",
    )
    # Valid, but the keyset's window still governs (KeyState keeps the keyset
    # declaration; see the window test above).
    assert declaration.key_type == "human"


# ---------------------------------------------------------------------------
# S2 - revocation effects are order independent
# ---------------------------------------------------------------------------


def _revoked_state() -> tuple[keys.KeyState, str]:
    raw, key_id = _public_key(5)
    state = keys.KeyState()
    state.add_declaration(
        keys.KeyDeclaration(
            key_id=key_id,
            key_type="human",
            public_key=raw,
            owner=None,
            valid_from="2026-01-01T00:00:00.000Z",
            valid_until=None,
            recorded_at="2026-01-01T00:00:00.000Z",
            record_digest="sha256:" + "05" * 32,
            source="keyset",
        )
    )
    return state, key_id


def test_retired_revocation_merge_is_order_independent() -> None:
    for order in (
        ("2026-02-01T00:00:00.000Z", "2026-04-01T00:00:00.000Z"),
        ("2026-04-01T00:00:00.000Z", "2026-02-01T00:00:00.000Z"),
    ):
        state, key_id = _revoked_state()
        for effective_at in order:
            state.add_revocation(_revocation(key_id, effective_at))
        with pytest.raises(WeaveError) as raised:
            state.check_signature_effects(key_id, "2026-03-01T00:00:00.000Z")
        assert raised.value.code == "E_KEY_REVOKED"


def test_compromise_uses_the_earliest_revocation_for_rescue() -> None:
    for order in ((1, 2), (2, 1)):
        state, key_id = _revoked_state()
        bounds = {
            1: _revocation(key_id, "2026-03-01T00:00:00.000Z", reason="key-compromise"),
            2: _revocation(key_id, "2026-05-01T00:00:00.000Z", reason="key-compromise"),
        }
        for index in order:
            state.add_revocation(bounds[index])
        # A receipt covering until a time between the two T values rescues only
        # the later compromise, never the earlier one (most conservative).
        covered_until_us = keys._timestamp_ms("2026-04-01T00:00:00.000Z") * 1000
        timestamp = keys.VerifiedTimestamp(
            gen_time="2026-04-01T00:00:00.000Z",
            gen_time_ms=keys._timestamp_ms("2026-04-01T00:00:00.000Z"),
            gen_time_us=covered_until_us,
            accuracy_us=0,
        )
        with pytest.raises(WeaveError) as raised:
            state.check_signature_effects(
                key_id,
                "2026-06-01T00:00:00.000Z",
                verified_timestamps=(timestamp,),
                timestamp_evidence_present=True,
            )
        assert raised.value.code == "E_KEY_COMPROMISED"


# ---------------------------------------------------------------------------
# S10 - a grant revocation takes effect only when the revocation is valid
# ---------------------------------------------------------------------------


def test_invalid_grant_revocation_does_not_apply() -> None:
    from hyphaweave_verify import grants

    target = "sha256:" + "bb" * 32
    revocation = grants.GrantRevocationRecord(
        digest="sha256:" + "aa" * 32,
        actor_key="ed25519:" + "ab" * 32,
        effective_at="2026-02-01T00:00:00.000Z",
        target_digest=target,
        envelope=None,  # type: ignore[arg-type]
    )
    valid_view = verifier.RecordView(
        loaded=verifier.LoadedRecord(raw=b"", value=None, digest=None, source="container")
    )
    valid_view.verdict = "valid"
    valid_view.grant_revocation = revocation
    invalid_view = verifier.RecordView(
        loaded=verifier.LoadedRecord(raw=b"", value=None, digest=None, source="container")
    )
    invalid_view.verdict = "invalid"
    invalid_view.grant_revocation = revocation
    context = verifier.Context()
    context.register(valid_view)
    context.register(invalid_view)
    context.rebuild()
    # Only the valid revocation record takes effect (S10(a)); the invalid copy is
    # the same record here, so the state must contain exactly one revocation.
    assert context.grant_state.revocation_as_of(
        target, "2026-03-01T00:00:00.000Z"
    ) is not None
    only_invalid = verifier.Context()
    invalid_alone = verifier.RecordView(
        loaded=verifier.LoadedRecord(raw=b"", value=None, digest=None, source="container")
    )
    invalid_alone.verdict = "invalid"
    invalid_alone.grant_revocation = revocation
    only_invalid.register(invalid_alone)
    only_invalid.rebuild()
    assert (
        only_invalid.grant_state.revocation_as_of(target, "2026-03-01T00:00:00.000Z")
        is None
    )


# ---------------------------------------------------------------------------
# S11 - timestamp accuracy bound and checked arithmetic
# ---------------------------------------------------------------------------


class _AccuracyValue:
    def __init__(self, value):
        self.native = value


class _TstInfo:
    def __init__(self, accuracy):
        self._accuracy = accuracy

    def __getitem__(self, member):
        if member == "accuracy":
            return _AccuracyValue(self._accuracy)
        raise KeyError(member)


def test_accuracy_conversion_is_checked_and_bounded() -> None:
    # Absent fields are exact (0); a present accuracy is converted.
    assert timestamps._accuracy_to_us(_TstInfo(None)) == 0
    assert timestamps._accuracy_to_us(_TstInfo({"seconds": 1})) == 1_000_000
    assert timestamps._accuracy_to_us(_TstInfo({"millis": 500})) == 500_000
    assert timestamps._accuracy_to_us(_TstInfo({"micros": 500})) == 500
    assert timestamps._accuracy_to_us(
        _TstInfo({"seconds": timestamps.MAX_TS_ACCURACY_SECONDS})
    ) == timestamps.MAX_TS_ACCURACY_US
    # T3(1): millis/micros outside 1-999 (including an explicit 0) and negative
    # or non-integer values are format errors (invalid receipt).
    for accuracy in (
        {"millis": 1000},
        {"micros": 5000},
        {"millis": 0},
        {"micros": 0},
        {"millis": -1},
        {"seconds": -1},
        {"seconds": "1"},
    ):
        with pytest.raises(WeaveError) as raised:
            timestamps._accuracy_to_us(_TstInfo(accuracy))
        assert raised.value.code == "E_TS_SCHEMA"
    # T3(2): above MAX_TS_ACCURACY or overflowing is *unusable evidence*, not a
    # format error: None means present-unverified (E_TS_UNTRUSTED, never rescue).
    for accuracy in (
        {"seconds": timestamps.MAX_TS_ACCURACY_SECONDS + 1},
        {"seconds": 10**12},
        {"seconds": 9_223_372_036_854, "millis": 999, "micros": 999},
    ):
        assert timestamps._accuracy_to_us(_TstInfo(accuracy)) is None


# ---------------------------------------------------------------------------
# S12 - limitations are closed identifiers
# ---------------------------------------------------------------------------


def _report(*arguments: str):
    result = run_cli(*arguments)
    return result, json.loads(result.stdout.decode("utf-8"))


def test_record_limitations_are_sorted_identifiers() -> None:
    _result, report = _report(
        "record",
        str(VECTORS / "grant" / "valid-root" / "record.json"),
        "--keys",
        str(VECTORS / "keys" / "keyset"),
    )
    assert report["limitations"] == ["L_OFFLINE_CONTEXT"]
    from hyphaweave_verify.report import LIMITATION_IDENTIFIERS

    assert set(report["limitations"]) <= LIMITATION_IDENTIFIERS


def test_standalone_placeholder_has_both_erasure_limitations() -> None:
    _result, report = _report(
        "record",
        str(VECTORS / "digest" / "record-erased-placeholder" / "record.json"),
        "--keys",
        str(VECTORS / "keys" / "keyset"),
    )
    assert report["verdict"] == "erased"
    assert report["limitations"] == [
        "L_ERASED_PLACEHOLDER",
        "L_ERASED_STANDALONE",
        "L_OFFLINE_CONTEXT",
    ]


def test_unknown_kind_limitation_only_for_a_valid_record() -> None:
    _result, valid = _report(
        "record",
        str(VECTORS / "stage" / "unknown-kind-opaque" / "record.json"),
        "--keys",
        str(VECTORS / "keys" / "keyset"),
    )
    assert valid["verdict"] == "valid"
    assert "L_UNKNOWN_KIND_OPAQUE" in valid["limitations"]
    # An invalid unknown-kind record reports kind_known=false without the
    # limitation (F12.3).
    _result, invalid = _report(
        "record",
        str(VECTORS / "jcs" / "depth-limit-plus-one" / "record.json"),
    )
    assert "L_UNKNOWN_KIND_OPAQUE" not in invalid["limitations"]


# ---------------------------------------------------------------------------
# S14 - container input identity is null when the manifest is absent
# ---------------------------------------------------------------------------


def test_missing_manifest_has_null_input_identity() -> None:
    result, report = _report(
        "container", str(VECTORS / "container" / "manifest-missing" / "container")
    )
    assert result.returncode == 1
    assert report["container"]["errors"] == ["E_MANIFEST_MISSING"]
    assert report["input"] == {"sha256": None, "size": None}


# ---------------------------------------------------------------------------
# F6 - no human-signature notice on an unverifiable signature outcome
# ---------------------------------------------------------------------------


def test_no_human_signature_notice_is_not_reported_for_unverifiable() -> None:
    _result, report = _report(
        "record",
        str(VECTORS / "sig" / "unknown-alg" / "record.json"),
        "--keys",
        str(VECTORS / "keys" / "keyset"),
    )
    assert report["verdict"] == "unverifiable"
    assert "N_NO_HUMAN_SIGNATURE" not in report["records"][0]["notices"]


# ---------------------------------------------------------------------------
# F10 / S8.9 - keyset structural versus semantic boundary
# ---------------------------------------------------------------------------


def _copy_keyset_file(tmp_path: Path) -> Path:
    keyset = tmp_path / "keyset"
    keyset.mkdir()
    for source in sorted(KEYSET.iterdir()):
        if source.is_file() and source.suffix == ".json":
            (keyset / source.name).write_bytes(source.read_bytes())
    return keyset


def test_keyset_body_schema_failure_is_a_usage_error(tmp_path) -> None:
    keyset = _copy_keyset_file(tmp_path)
    # Structurally an envelope, but violates the weave.key.declared body schema
    # (public_key is missing): the S8.9 structural side is a usage error.
    body = json.dumps(
        {
            "format": "weave-record/1",
            "kind": "weave.key.declared",
            "origin": {
                "project": "example",
                "instance": "ed25519:" + "33" * 16,
            },
            "id": "bad-declaration",
            "stage": "accepted",
            "actor": {"type": "human", "key": "ed25519:" + "33" * 16},
            "recorded_at": "2026-11-01T00:00:00.000Z",
            "body": {"key": "ed25519:" + "33" * 16, "key_type": "human", "algorithm": "ed25519"},
        },
        separators=(",", ":"),
        sort_keys=True,
    )
    (keyset / "zz-bad.json").write_text(body + "\n")
    with pytest.raises(UsageError):
        verifier.load_keyset_directory(keyset)


def test_keyset_semantic_failure_is_not_a_usage_error(tmp_path) -> None:
    keyset = _copy_keyset_file(tmp_path)
    # Structurally valid but semantically wrong (effective_at after recorded_at):
    # it establishes no trust but is not a usage error (S8.9).
    bad = json.dumps(
        {
            "actor": {"key": "ed25519:" + "33" * 16, "type": "human"},
            "body": {
                "effective_at": "2026-12-01T00:00:00.000Z",
                "key": "ed25519:" + "44" * 16,
                "reason": "retired",
            },
            "format": "weave-record/1",
            "id": "bad-revocation",
            "kind": "weave.key.revoked",
            "origin": {"instance": "ed25519:" + "33" * 16, "project": "example"},
            "recorded_at": "2026-11-01T00:00:00.000Z",
            "stage": "accepted",
        },
        separators=(",", ":"),
        sort_keys=True,
    )
    (keyset / "zz-semantic.json").write_text(bad + "\n")
    loaded = verifier.load_keyset_directory(keyset)
    assert any(record.value is not None for record in loaded)
