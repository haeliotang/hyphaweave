# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0

"""Revision-1 integrated semantics: declarations, Q13, consent withdrawal, S2.

These tests build their own canonical records and sign them with the published
synthetic test keys, so they pin behaviour independently of the conformance
vector suite.
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
    kinds,
    verifier,
)
from hyphaweave_verify.errors import WeaveError

VECTORS = pathlib.Path(__file__).resolve().parents[3] / "vectors"
KEYS = VECTORS / "keys"
T0 = "2026-11-01T00:00:00.000Z"
T1 = "2026-11-02T00:00:00.000Z"


def load_key(name: str) -> tuple[str, Ed25519PrivateKey]:
    info = json.loads((KEYS / (name + ".json")).read_text(encoding="utf-8"))
    seed = bytes.fromhex((KEYS / info["seed_file"]).read_text(encoding="utf-8").strip())
    return info["key_id"], Ed25519PrivateKey.from_private_bytes(seed)


def sign_record(record: dict, signer_names: list[str]) -> dict:
    """Compute the record digest and attach signatures by the given test keys."""
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


def revoked(name: str, *, signer: str, effective_at: str = T1, reason: str = "retired") -> dict:
    key_id, _private = load_key(name)
    signer_id, _signer_private = load_key(signer)
    record = {
        "format": "weave-record/1",
        "kind": "weave.key.revoked",
        "origin": {"project": "example", "instance": signer_id},
        "id": f"revoke-{name}-{reason}",
        "stage": "accepted",
        "actor": {"type": "human", "key": signer_id},
        "recorded_at": T1,
        "body": {"effective_at": effective_at, "key": key_id, "reason": reason},
    }
    return sign_record(record, [signer])


def note(*, signer: str = "human-1", recorded_at: str = T0, **body_extra) -> dict:
    key_id, _private = load_key(signer)
    record = {
        "format": "weave-record/1",
        "kind": "example.note",
        "origin": {"project": "example", "instance": key_id},
        "id": "note-1",
        "stage": "proposed",
        "actor": {"type": "human", "key": key_id},
        "recorded_at": recorded_at,
        "body": {"text": "synthetic", **body_extra},
    }
    return sign_record(record, [signer])


def verify_set(records: list[dict]) -> list[verifier.RecordView]:
    loaded = [
        verifier.LoadedRecord(
            raw=canonical_bytes(record),
            value=record,
            digest=encoding.record_digest(record),
            source="container",
        )
        for record in records
    ]
    return verifier.verify_record_set(loaded)


def _errors(views: list[verifier.RecordView]) -> dict[str, list[str]]:
    return {
        (view.envelope.record_id if view.envelope else "?"): view.errors for view in views
    }


# ---------------------------------------------------------------------------
# Key declarations: owner / cosignature / Q33 root bootstrap
# ---------------------------------------------------------------------------


def test_agent_declaration_requires_owner() -> None:
    record = declared("agent-1", key_type="agent")
    views = verify_set([record])
    assert views[0].verdict == "invalid"
    assert views[0].errors == ["E_KEY_OWNER_MISSING"]


def test_agent_declaration_requires_owner_cosignature() -> None:
    human_root = declared("human-1")
    agent = declared("agent-1", key_type="agent", owner=load_key("human-1")[0])
    views = verify_set([human_root, agent])
    by_id = {(view.envelope.record_id if view.envelope else ""): view for view in views}
    assert by_id["declare-human-1"].verdict == "valid"
    assert by_id["declare-agent-1"].errors == ["E_KEY_DECLARED_NOT_COSIGNED"]


def test_agent_declaration_with_owner_cosignature_is_valid() -> None:
    human_1 = load_key("human-1")[0]
    records = [
        declared("human-1"),
        declared("agent-1", key_type="agent", owner=human_1, cosigners=["human-1"]),
    ]
    views = verify_set(records)
    by_id = {(view.envelope.record_id if view.envelope else ""): view for view in views}
    assert by_id["declare-agent-1"].verdict == "valid"
    # The root human key is self-attested and must say so.
    assert "N_SELF_ATTESTED_ROOT_KEY" in by_id["declare-human-1"].notices


def test_later_self_attested_human_key_is_not_cosigned() -> None:
    root = declared("human-1")
    later = declared("human-2", recorded_at=T1)
    views = verify_set([root, later])
    by_id = {(view.envelope.record_id if view.envelope else ""): view for view in views}
    assert by_id["declare-human-1"].verdict == "valid"
    assert by_id["declare-human-2"].errors == ["E_KEY_DECLARED_NOT_COSIGNED"]


def test_human_key_with_root_cosignature_is_valid() -> None:
    records = [
        declared("human-1"),
        declared("human-2", recorded_at=T1, cosigners=["human-1"]),
    ]
    views = verify_set(records)
    by_id = {(view.envelope.record_id if view.envelope else ""): view for view in views}
    assert by_id["declare-human-2"].verdict == "valid"


# ---------------------------------------------------------------------------
# S2 key-compromise (no recorded_at evidence)
# ---------------------------------------------------------------------------


def test_compromise_revocation_invalidates_backdated_signature() -> None:
    records = [
        declared("human-1"),
        declared("key-compromised", recorded_at=T1, cosigners=["human-1"]),
        revoked("key-compromised", signer="human-1", effective_at=T1, reason="key-compromise"),
        # A forged record signed by the compromised key, backdated before T.
        note(signer="key-compromised", recorded_at=T0),
    ]
    views = verify_set(records)
    by_id = {(view.envelope.record_id if view.envelope else ""): view for view in views}
    assert by_id["note-1"].verdict == "invalid"
    assert "E_KEY_COMPROMISED" in by_id["note-1"].errors


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


def test_unknown_algorithm_only_required_record_is_unverifiable() -> None:
    record = _with_unknown_alg(note(signer="human-1"), keep_known=False)
    record["stage"] = "accepted"  # accepted records require per-record signing
    # Recompute nothing: the record digest covered the pre-Q13 object only when
    # signed; here we only test the required-signer rule, so an undeclared
    # actor key keeps the failure unverifiable as well.
    views = verify_set([record])
    assert views[0].verdict == "unverifiable"
    assert views[0].errors == ["E_KEY_UNKNOWN"]
    assert any(entry["state"] == "ignored" for entry in views[0].sigs)


def test_unknown_algorithm_only_with_declared_key_is_unverifiable() -> None:
    record = note(signer="human-1")
    record = _with_unknown_alg(record, keep_known=False)
    record["stage"] = "accepted"
    # The actor key is declared in the context, but no known-algorithm signature
    # can be verified: E_SIG_UNVERIFIABLE (unverifiable), not invalid.
    views = verify_set([declared("human-1"), record])
    by_id = {(view.envelope.record_id if view.envelope else ""): view for view in views}
    note_view = by_id["note-1"]
    assert note_view.errors == ["E_SIG_UNVERIFIABLE"]
    assert note_view.verdict == "unverifiable"


def test_unknown_algorithm_ignored_when_a_known_signature_is_valid() -> None:
    record = note(signer="human-1")
    record = _with_unknown_alg(record, keep_known=True)
    views = verify_set([declared("human-1"), record])
    by_id = {(view.envelope.record_id if view.envelope else ""): view for view in views}
    assert by_id["note-1"].verdict == "valid"
    states = {entry["key"]: entry["state"] for entry in by_id["note-1"].sigs}
    assert "ignored" in states.values()
    assert "valid" in states.values()


def test_unknown_algorithm_optional_record_is_valid() -> None:
    record = _with_unknown_alg(note(signer="human-1"), keep_known=False)
    views = verify_set([record])
    assert views[0].verdict == "valid"
    assert views[0].sigs[0]["state"] == "ignored"


# ---------------------------------------------------------------------------
# Consent withdrawal (M-7)
# ---------------------------------------------------------------------------


def _consent_granted_record() -> dict:
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


def _consent_revoked_record(consent: dict) -> dict:
    human_id = load_key("human-1")[0]
    digest = encoding.record_digest(consent)
    record = {
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
                "digest": digest,
                "kind": "weave.consent.granted",
            },
            "effective_at": T1,
            "reason": "withdrawn",
        },
    }
    return sign_record(record, ["human-1"])


def test_record_citing_withdrawn_consent_is_invalid() -> None:
    consent = _consent_granted_record()
    withdrawal = _consent_revoked_record(consent)
    human_id = load_key("human-1")[0]
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
    views = verify_set([declared("human-1"), consent, withdrawal, citing])
    by_id = {(view.envelope.record_id if view.envelope else ""): view for view in views}
    assert by_id["consent-1"].verdict == "valid"
    assert by_id["consent-revoke-1"].verdict == "valid"
    assert by_id["citing-note"].errors == ["E_CONSENT_REVOKED"]


# ---------------------------------------------------------------------------
# Manifest Q13 symmetry
# ---------------------------------------------------------------------------


def _minimal_container(tmp_path: pathlib.Path, attestation_signatures: list[dict]) -> pathlib.Path:
    human_id, _private = load_key("human-1")
    record = {
        "format": "weave-record/1",
        "kind": "weave.key.declared",
        "origin": {"project": "example", "instance": human_id},
        "id": "decl",
        "stage": "accepted",
        "actor": {"type": "human", "key": human_id},
        "recorded_at": T0,
        "body": {
            "algorithm": "ed25519",
            "key": human_id,
            "key_type": "human",
            "public_key": encoding.encode_base64url((KEYS / "human-1.pub.bin").read_bytes()),
        },
    }
    sign_record(record, ["human-1"])
    record_bytes = canonical_bytes(record)
    digest = encoding.record_digest(record)
    manifest = {
        "created_at": T0,
        "format": "weave-record/1",
        "level": "L0",
        "manifest_version": 1,
        "origin": {"instance": human_id, "project": "example"},
        "previous_manifest": None,
        "records": [{"digest": digest, "id": "decl", "kind": "weave.key.declared"}],
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


def test_manifest_unknown_algorithm_only_is_unverifiable(tmp_path) -> None:
    unknown = {"alg": "ml-dsa-65", "key": "ml-dsa-65:" + "ab" * 32, "value": "AAAA"}
    container = _minimal_container(tmp_path, [unknown])
    result = container_module.verify_container(container)
    assert result.report["verdict"] == "unverifiable"
    assert "E_SIG_UNVERIFIABLE" in result.report["container"]["errors"]


def test_manifest_unknown_algorithm_ignored_with_known_signature(tmp_path) -> None:
    human_id, private = load_key("human-1")
    record = verifier.load_keyset_directory(KEYS / "keyset")
    # Build the known signature over the manifest digest used by the fixture.
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
    keyset = verifier.load_keyset_directory(KEYS / "keyset")
    result = container_module.verify_container(container, keyset_records=keyset)
    assert result.report["verdict"] == "valid", result.report["container"]["errors"]
