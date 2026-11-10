# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0

"""Integrated semantics: keyset trust roots, Q13, consent, compromise timing.

These tests build their own canonical records and sign them with the published
synthetic test keys, so they pin behaviour independently of the conformance
vector suite. Trust roots come only from the local ``--keys`` keyset (decision
2026-11-10 #42); those fixtures are marked with ``source="keyset"``.
"""

from __future__ import annotations

import json
import pathlib

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hyphaweave_verify import (
    canonical,
    container as container_module,
    encoding,
    envelope,
    keys as keys_module,
    verifier,
)
from hyphaweave_verify.errors import WeaveError

VECTORS = pathlib.Path(__file__).resolve().parents[3] / "vectors"
KEYS = VECTORS / "keys"
KEYSET = KEYS / "keyset"
T0 = "2026-11-01T00:00:00.000Z"
T1 = "2026-11-02T00:00:00.000Z"
T2 = "2026-11-03T00:00:00.000Z"


# ---------------------------------------------------------------------------
# Fixture builders
# ---------------------------------------------------------------------------


def load_key(name: str) -> tuple[str, Ed25519PrivateKey]:
    info = json.loads((KEYS / (name + ".json")).read_text(encoding="utf-8"))
    seed = bytes.fromhex((KEYS / info["seed_file"]).read_text(encoding="utf-8").strip())
    return info["key_id"], Ed25519PrivateKey.from_private_bytes(seed)


def sign_record(record: dict, signer_names: list[str]) -> dict:
    digest = encoding.record_digest(record)
    message = encoding.record_sig_message(digest)
    signatures = []
    for name in signer_names:
        key_id, private_key = load_key(name)
        signatures.append(
            {
                "alg": "ed25519",
                "key": key_id,
                "value": encoding.encode_base64url(private_key.sign(message)),
            }
        )
    signatures.sort(key=lambda entry: entry["key"])
    record["sigs"] = signatures
    return record


def canonical_bytes(value: dict) -> bytes:
    return canonical.canonicalize(value) + b"\n"


def declared(
    name: str,
    *,
    key_type: str = "human",
    owner: str | None = None,
    recorded_at: str = T0,
    valid_from: str | None = None,
    valid_until: str | None = None,
    cosigners: list[str] | None = None,
) -> dict:
    key_id, _private = load_key(name)
    body: dict = {
        "algorithm": "ed25519",
        "key": key_id,
        "key_type": key_type,
        "public_key": encoding.encode_base64url((KEYS / (name + ".pub.bin")).read_bytes()),
    }
    if owner is not None:
        body["owner"] = owner
    if valid_from is not None:
        body["valid_from"] = valid_from
    if valid_until is not None:
        body["valid_until"] = valid_until
    record = {
        "format": "weave-record/1",
        "kind": "weave.key.declared",
        "origin": {"project": "example", "instance": key_id},
        "id": "declare-" + name,
        "stage": "accepted",
        "actor": {"type": key_type, "key": key_id},
        "recorded_at": recorded_at,
        "body": body,
    }
    return sign_record(record, [name] + (cosigners or []))


def note(*, signer: str = "human-1", recorded_at: str = T0, stage: str = "proposed", **body_extra) -> dict:
    key_id, _private = load_key(signer)
    record = {
        "format": "weave-record/1",
        "kind": "example.note",
        "origin": {"project": "example", "instance": key_id},
        "id": "note-1",
        "stage": stage,
        "actor": {"type": "human", "key": key_id},
        "recorded_at": recorded_at,
        "body": {"text": "synthetic", **body_extra},
    }
    return sign_record(record, [signer])


def _loaded(records: list[dict], source: str) -> list[verifier.LoadedRecord]:
    return [
        verifier.LoadedRecord(
            raw=canonical_bytes(record),
            value=record,
            digest=encoding.record_digest(record),
            source=source,
        )
        for record in records
    ]


def verify_set(
    records: list[dict],
    *,
    keyset_records: int = 0,
    timestamp_evidence_present: bool = False,
) -> list[verifier.RecordView]:
    """Verify records, optionally treating the first ``keyset_records`` as --keys."""
    keyset_records_list = records[:keyset_records]
    container_records_list = records[keyset_records:]
    keyset_views: list[verifier.RecordView] = []
    if keyset_records_list:
        keyset_views = verifier.verify_record_set(_loaded(keyset_records_list, "keyset"))
    container_views = verifier.verify_record_set(
        _loaded(container_records_list, "container"),
        context_views=keyset_views,
        timestamp_evidence_present=timestamp_evidence_present,
    )
    return keyset_views + container_views


def by_id(views: list[verifier.RecordView]) -> dict[str, verifier.RecordView]:
    return {(view.envelope.record_id if view.envelope else "?"): view for view in views}


# ---------------------------------------------------------------------------
# Roots come only from the local keyset (decision #42)
# ---------------------------------------------------------------------------


def test_keyset_human_root_is_trusted_without_notice() -> None:
    views = verify_set([declared("human-1")], keyset_records=1)
    record = by_id(views)["declare-human-1"]
    assert record.verdict == "valid"
    assert "N_SELF_ATTESTED_ROOT_KEY" not in record.notices


def test_duplicate_declaration_of_keyset_root_in_container_is_valid() -> None:
    views = verify_set([declared("human-1"), declared("human-1")], keyset_records=1)
    container_record = views[-1]
    assert container_record.verdict == "valid"
    assert container_record.errors == []


def test_container_human_cosigned_by_keyset_root_is_valid() -> None:
    views = verify_set(
        [
            declared("human-1"),
            declared("human-2", recorded_at=T1, cosigners=["human-1"]),
        ],
        keyset_records=1,
    )
    record = by_id(views)["declare-human-2"]
    assert record.verdict == "valid"
    assert record.errors == []


def test_container_human_cosign_chain_closes_iteratively() -> None:
    """key-old (cosigned by the keyset root) becomes trusted for key-new."""
    views = verify_set(
        [
            declared("human-1"),
            declared("key-old", recorded_at=T1, cosigners=["human-1"]),
            declared("key-new", recorded_at=T2, cosigners=["key-old"]),
        ],
        keyset_records=1,
    )
    records = by_id(views)
    assert records["declare-key-old"].verdict == "valid"
    assert records["declare-key-new"].verdict == "valid"


def test_container_self_attested_human_is_untrusted_with_notice() -> None:
    """Backdating the claimed recorded_at no longer elects a root (decision #42)."""
    attacker = declared("human-2", recorded_at="2020-01-01T00:00:00.000Z")
    views = verify_set([declared("human-1"), attacker], keyset_records=1)
    record = by_id(views)["declare-human-2"]
    assert record.verdict == "unverifiable"
    assert record.errors == ["E_KEY_UNTRUSTED"]
    assert "N_SELF_ATTESTED_ROOT_KEY" in record.notices


def test_untrusted_container_root_does_not_invalidate_keyset_root() -> None:
    attacker = declared("human-2", recorded_at="2020-01-01T00:00:00.000Z")
    legitimate_note = note(signer="human-1")
    views = verify_set(
        [declared("human-1"), attacker, legitimate_note], keyset_records=1
    )
    records = by_id(views)
    assert records["declare-human-2"].verdict == "unverifiable"
    assert records["note-1"].verdict == "valid"


def test_agent_declaration_requires_owner() -> None:
    views = verify_set([declared("agent-1", key_type="agent")])
    assert views[0].verdict == "invalid"
    assert views[0].errors == ["E_KEY_OWNER_MISSING"]


def test_agent_declaration_requires_owner_cosignature() -> None:
    human_id = load_key("human-1")[0]
    views = verify_set(
        [
            declared("human-1"),
            declared("agent-1", key_type="agent", owner=human_id, recorded_at=T1),
        ],
        keyset_records=1,
    )
    record = by_id(views)["declare-agent-1"]
    assert record.verdict == "invalid"
    assert record.errors == ["E_KEY_DECLARED_NOT_COSIGNED"]


def test_agent_declaration_with_trusted_owner_cosignature_is_valid() -> None:
    human_id = load_key("human-1")[0]
    views = verify_set(
        [
            declared("human-1"),
            declared(
                "agent-1",
                key_type="agent",
                owner=human_id,
                recorded_at=T1,
                cosigners=["human-1"],
            ),
        ],
        keyset_records=1,
    )
    assert by_id(views)["declare-agent-1"].verdict == "valid"


def test_owner_wrong_class_is_invalid_owner_missing() -> None:
    """R5: a resolvable owner of the wrong class is E_KEY_OWNER_MISSING."""
    agent_id = load_key("agent-1")[0]
    # Owner is this very agent declaration: its single self-signature also serves
    # as the owner cosignature, and the owner material's class is agent.
    views = verify_set(
        [declared("agent-1", key_type="agent", owner=agent_id)]
    )
    record = views[0]
    assert record.verdict == "invalid"
    assert record.errors == ["E_KEY_OWNER_MISSING"]


def test_untrusted_owner_leaves_agent_declaration_unverifiable() -> None:
    container_owner = declared("human-2", recorded_at=T1)
    owner_id = load_key("human-2")[0]
    agent = declared(
        "agent-1",
        key_type="agent",
        owner=owner_id,
        recorded_at=T2,
        cosigners=["human-2"],
    )
    views = verify_set([declared("human-1"), container_owner, agent], keyset_records=1)
    records = by_id(views)
    assert records["declare-human-2"].errors == ["E_KEY_UNTRUSTED"]
    assert records["declare-agent-1"].verdict == "unverifiable"
    assert records["declare-agent-1"].errors == ["E_KEY_UNTRUSTED"]


def test_no_keyset_means_no_trust_roots() -> None:
    result = container_module.verify_container(
        VECTORS / "container" / "self-attested-root-untrusted" / "container"
    )
    report = result.report
    assert report["verdict"] == "unverifiable"
    entry = report["records"][0]
    assert entry["errors"] == ["E_KEY_UNTRUSTED"]
    assert "N_SELF_ATTESTED_ROOT_KEY" in entry["notices"]


def test_keyset_makes_the_same_container_valid() -> None:
    keyset = verifier.load_keyset_directory(KEYSET)
    keyset_views = verifier.verify_record_set(keyset)
    result = container_module.verify_container(
        VECTORS / "container" / "l0-minimal" / "container",
        keyset_records=keyset,
        keyset_views=keyset_views,
    )
    assert result.report["verdict"] == "valid"


# ---------------------------------------------------------------------------
# Compromise revocation: timestamp accuracy and evidence split
# ---------------------------------------------------------------------------


def _compromise_state() -> tuple[keys_module.KeyState, str]:
    effective = T1
    state = keys_module.KeyState()
    state.add_revocation(
        keys_module.KeyRevocation(
            key_id=load_key("key-compromised")[0],
            reason="key-compromise",
            effective_at=effective,
            effective_at_ms=keys_module._timestamp_ms(effective),
            recorded_at=T1,
            record_digest="sha256:" + "02" * 32,
        )
    )
    return state, effective


def _verified(gen_time: str, accuracy_us: int = 0) -> keys_module.VerifiedTimestamp:
    gen_time_ms = keys_module._timestamp_ms(gen_time)
    return keys_module.VerifiedTimestamp(
        gen_time=gen_time,
        gen_time_ms=gen_time_ms,
        gen_time_us=gen_time_ms * 1000,
        accuracy_us=accuracy_us,
    )


def test_r4_no_timestamp_evidence_is_invalid() -> None:
    state, effective = _compromise_state()
    key_id = load_key("key-compromised")[0]
    with pytest.raises(WeaveError) as raised:
        state.check_signature_effects(key_id, T0)
    assert raised.value.code == "E_KEY_COMPROMISED"


def test_r4_untrusted_receipts_make_it_unverifiable() -> None:
    state, effective = _compromise_state()
    key_id = load_key("key-compromised")[0]
    with pytest.raises(WeaveError) as raised:
        state.check_signature_effects(
            key_id, T0, timestamp_evidence_present=True
        )
    assert raised.value.code == "E_TS_UNTRUSTED"
    assert raised.value.effect == "unverifiable"


def test_r3_rescue_requires_strictly_earlier_gen_time() -> None:
    state, effective = _compromise_state()
    key_id = load_key("key-compromised")[0]
    # genTime == T: equality does not rescue.
    with pytest.raises(WeaveError) as raised:
        state.check_signature_effects(
            key_id, T0, verified_timestamps=(_verified(effective),)
        )
    assert raised.value.code == "E_KEY_COMPROMISED"
    # genTime earlier than T: rescued.
    earlier = "2026-10-31T00:00:00.000Z"
    state.check_signature_effects(key_id, T0, verified_timestamps=(_verified(earlier),))


def test_r3_accuracy_is_added_to_gen_time() -> None:
    state, effective = _compromise_state()
    key_id = load_key("key-compromised")[0]
    # genTime 500ms before T + 1s accuracy crosses T: not provably earlier.
    gen_time = "2026-12-31T00:00:00.000Z"
    state = keys_module.KeyState()
    state.add_revocation(
        keys_module.KeyRevocation(
            key_id=key_id,
            reason="key-compromise",
            effective_at=gen_time,
            effective_at_ms=keys_module._timestamp_ms(gen_time),
            recorded_at=T1,
            record_digest="sha256:" + "03" * 32,
        )
    )
    half_before = "2026-12-30T23:59:59.500Z"
    with pytest.raises(WeaveError) as raised:
        state.check_signature_effects(
            key_id,
            T0,
            verified_timestamps=(_verified(half_before, accuracy_us=1_000_000),),
        )
    assert raised.value.code == "E_KEY_COMPROMISED"


# ---------------------------------------------------------------------------
# Q13: unknown signature algorithms are ignored
# ---------------------------------------------------------------------------


def _with_unknown_alg(record: dict, *, keep_known: bool) -> dict:
    record = json.loads(json.dumps(record))
    known = record.get("sigs", [])
    unknown = {
        "alg": "ml-dsa-65",
        "key": "ml-dsa-65:" + "ab" * 32,
        "value": encoding.encode_base64url(b"\x01\x02\x03"),
    }
    record["sigs"] = sorted(
        ([*known, unknown] if keep_known else [unknown]), key=lambda entry: entry["key"]
    )
    return record


def test_unknown_algorithm_optional_record_is_valid() -> None:
    record = _with_unknown_alg(note(signer="human-1"), keep_known=False)
    views = verify_set([declared("human-1"), record], keyset_records=1)
    record_view = views[-1]
    assert record_view.verdict == "valid"
    assert record_view.sigs[0]["state"] == "ignored"


def test_unknown_algorithm_ignored_when_a_known_signature_is_valid() -> None:
    record = _with_unknown_alg(note(signer="human-1"), keep_known=True)
    views = verify_set([declared("human-1"), record], keyset_records=1)
    record_view = views[-1]
    assert record_view.verdict == "valid"
    states = {entry["key"]: entry["state"] for entry in record_view.sigs}
    assert "ignored" in states.values()
    assert "valid" in states.values()


# ---------------------------------------------------------------------------
# Manifest Q13 symmetry
# ---------------------------------------------------------------------------


def _minimal_container(tmp_path: pathlib.Path, attestation_signatures: list[dict]) -> pathlib.Path:
    human_id, _private = load_key("human-1")
    record = declared("human-1")
    record_bytes = canonical_bytes(record)
    digest = encoding.record_digest(record)
    manifest = {
        "created_at": T0,
        "format": "weave-record/1",
        "level": "L0",
        "manifest_version": 1,
        "origin": {"instance": human_id, "project": "example"},
        "previous_manifest": None,
        "records": [{"digest": digest, "id": "declare-human-1", "kind": "weave.key.declared"}],
    }
    manifest_bytes = canonical_bytes(manifest)
    manifest_digest = encoding.manifest_digest(canonical.canonicalize(manifest))
    container = tmp_path / "container"
    (container / "records").mkdir(parents=True)
    (container / "signatures").mkdir()
    (container / "manifest.json").write_bytes(manifest_bytes)
    (container / "records" / (digest.partition(":")[2] + ".json")).write_bytes(record_bytes)
    attestation = {
        "digest": manifest_digest,
        "format": "weave-record/1",
        "signatures": sorted(attestation_signatures, key=lambda entry: entry["key"]),
        "timestamps": [],
    }
    (container / "signatures" / "manifest.sig.json").write_bytes(canonical_bytes(attestation))
    return container


def _keyset_for_container():
    keyset = verifier.load_keyset_directory(KEYSET)
    keyset_views = verifier.verify_record_set(keyset)
    return keyset, keyset_views


def test_manifest_unknown_algorithm_only_is_unverifiable(tmp_path) -> None:
    unknown = {"alg": "ml-dsa-65", "key": "ml-dsa-65:" + "ab" * 32, "value": "AAAA"}
    container = _minimal_container(tmp_path, [unknown])
    keyset, keyset_views = _keyset_for_container()
    result = container_module.verify_container(
        container, keyset_records=keyset, keyset_views=keyset_views
    )
    assert result.report["verdict"] == "unverifiable"
    assert "E_SIG_UNVERIFIABLE" in result.report["container"]["errors"]


def test_manifest_unknown_algorithm_ignored_with_known_signature(tmp_path) -> None:
    human_id, private = load_key("human-1")
    container = _minimal_container(tmp_path, [])
    manifest_bytes = (container / "manifest.json").read_bytes()
    manifest_value = canonical.parse_file_bytes(manifest_bytes)
    manifest_digest = encoding.manifest_digest(canonical.canonicalize(manifest_value))
    known = {
        "alg": "ed25519",
        "key": human_id,
        "value": encoding.encode_base64url(
            private.sign(encoding.manifest_sig_message(manifest_digest))
        ),
    }
    unknown = {"alg": "ml-dsa-65", "key": "ml-dsa-65:" + "ab" * 32, "value": "AAAA"}
    (container / "signatures" / "manifest.sig.json").write_bytes(
        canonical_bytes(
            {
                "digest": manifest_digest,
                "format": "weave-record/1",
                "signatures": sorted([known, unknown], key=lambda entry: entry["key"]),
                "timestamps": [],
            }
        )
    )
    keyset, keyset_views = _keyset_for_container()
    result = container_module.verify_container(
        container, keyset_records=keyset, keyset_views=keyset_views
    )
    assert result.report["verdict"] == "valid", result.report["container"]["errors"]


# ---------------------------------------------------------------------------
# Consent withdrawal (M-7) under the keyset trust model
# ---------------------------------------------------------------------------


def _consent_granted() -> dict:
    human_id = load_key("human-1")[0]
    record = {
        "format": "weave-record/1",
        "kind": "weave.consent.granted",
        "origin": {"project": "example", "instance": human_id},
        "id": "consent-1",
        "stage": "accepted",
        "actor": {"type": "human", "key": human_id},
        "recorded_at": T0,
        "body": {
            "purpose": "test",
            "scope": ["test"],
            "valid_from": T0,
            "valid_until": None,
            "data_subject": None,
            "terms": None,
        },
    }
    return sign_record(record, ["human-1"])


def test_record_citing_withdrawn_consent_is_invalid() -> None:
    consent = _consent_granted()
    human_id = load_key("human-1")[0]
    withdrawal = {
        "format": "weave-record/1",
        "kind": "weave.consent.revoked",
        "origin": {"project": "example", "instance": human_id},
        "id": "consent-revoke-1",
        "stage": "accepted",
        "actor": {"type": "human", "key": human_id},
        "recorded_at": T1,
        "body": {
            "revokes": {
                "origin": consent["origin"],
                "id": consent["id"],
                "digest": encoding.record_digest(consent),
                "kind": "weave.consent.granted",
            },
            "effective_at": T1,
            "reason": "withdrawn",
        },
    }
    sign_record(withdrawal, ["human-1"])
    citing = {
        "format": "weave-record/1",
        "kind": "example.note",
        "origin": {"project": "example", "instance": human_id},
        "id": "citing-note",
        "stage": "proposed",
        "actor": {"type": "human", "key": human_id},
        "recorded_at": T1,
        "labels": {
            "sensitivity": "internal",
            "consent": {
                "origin": consent["origin"],
                "id": consent["id"],
                "digest": encoding.record_digest(consent),
                "kind": "weave.consent.granted",
            },
        },
        "body": {"text": "uses personal data"},
    }
    sign_record(citing, ["human-1"])
    views = verify_set(
        [declared("human-1"), consent, withdrawal, citing], keyset_records=1
    )
    records = by_id(views)
    assert records["consent-1"].verdict == "valid"
    assert records["consent-revoke-1"].verdict == "valid"
    assert records["citing-note"].errors == ["E_CONSENT_REVOKED"]
