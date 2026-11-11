# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0

"""Focused tests for the S1-FIX3 rulings (V1/V2/V3/V5/V6/V7).

The committed vectors already pin most behaviours end-to-end; these tests cover
the mechanisms that a vector cannot express (usage errors, boundary counts,
direct helper contracts) and the ablation reasons recorded in the mutation
catalogue.
"""

from __future__ import annotations

import json
import shutil

import pytest
from conftest import KEYSET, VECTORS, run_cli

from hyphaweave_verify import container as container_module
from hyphaweave_verify import timestamps, verifier, zipread
from hyphaweave_verify.errors import UsageError, WeaveError


def _cli_json(*arguments: str) -> dict:
    result = run_cli(*arguments)
    return json.loads(result.stdout.decode("utf-8"))


def _case_arguments(case_dir) -> list[str]:
    expected = json.loads((case_dir / "expected.json").read_text(encoding="utf-8"))
    resolved: list[str] = []
    for token in expected.get("args") or ():
        if token in ("--keys", "--previous", "--tsa-trust"):
            resolved.append(token)
        elif token == "@keyset":
            for parent in (case_dir, *case_dir.parents):
                candidate = parent / "keys" / "keyset"
                if candidate.is_dir():
                    resolved.append(str(candidate))
                    break
            else:  # pragma: no cover - the suite always ships keys/keyset
                raise AssertionError("vector suite has no keys/keyset directory")
        else:
            resolved.append(str(case_dir / token))
    return resolved


def _run_case(case_id: str) -> dict:
    case_dir = VECTORS / case_id
    expected = json.loads((case_dir / "expected.json").read_text(encoding="utf-8"))
    return _cli_json(
        expected["target"], str(case_dir / expected["input"]), *_case_arguments(case_dir)
    )


# ---------------------------------------------------------------------------
# V1: decompression failures are zip-structure failures, never crashes
# ---------------------------------------------------------------------------


def test_corrupt_deflate_previous_is_manifest_chain_without_crash() -> None:
    report = _run_case("container/previous-zip-deflate-corrupt")
    assert report["verdict"] == "invalid"
    assert report["container"]["errors"] == ["E_MANIFEST_CHAIN"]


def test_decompress_errors_map_to_zip_structure_error() -> None:
    """Direct helper contract: a corrupt deflate member raises ZipStructureError."""
    case_dir = VECTORS / "container" / "previous-zip-deflate-corrupt"
    archive_path = case_dir / "previous-container.zip"
    with archive_path.open("rb") as handle:
        archive = zipread.parse_zip(handle)
        manifest = next(entry for entry in archive.entries if entry.name == "manifest.json")
        with pytest.raises(zipread.ZipStructureError):
            zipread.read_entry_data(handle, manifest)


# ---------------------------------------------------------------------------
# V2: strict DER and the per-receipt parsing boundary
# ---------------------------------------------------------------------------


def _valid_tsr() -> bytes:
    return (
        VECTORS
        / "integrity-levels"
        / "l2-valid"
        / "container"
        / "signatures"
        / "timestamp-1.tsr"
    ).read_bytes()


def test_strict_der_scan_accepts_valid_receipts() -> None:
    timestamps._validate_strict_der(_valid_tsr())


def test_strict_der_scan_rejects_nonminimal_length() -> None:
    raw = bytearray(_valid_tsr())
    # Rewrite the outer SEQUENCE length from 0x82 0xNN 0xNN to a non-minimal
    # 0x83 0x00 0xNN 0xNN form.
    raw[0:4] = bytes([0x30, 0x83, 0x00]) + bytes([raw[2]])
    with pytest.raises(WeaveError) as raised:
        timestamps._validate_strict_der(bytes(raw))
    assert raised.value.code == "E_TS_SCHEMA"


def test_strict_der_scan_rejects_ber_indefinite() -> None:
    raw = _valid_tsr()
    with pytest.raises(WeaveError) as raised:
        timestamps._validate_strict_der(b"\x30\x80" + raw[2:] + b"\x00\x00")
    assert raised.value.code == "E_TS_SCHEMA"


def test_receipt_boundary_turns_lazy_parse_errors_into_schema() -> None:
    """A huge inner DER length (the recheck2 crash shape) is E_TS_SCHEMA, never
    an exception escaping the per-receipt boundary."""
    raw = bytearray(_valid_tsr())
    # Rewrite the length octets of the last inner TLV to a huge value; the outer
    # structure then fails strict-DER/parse checks inside the receipt boundary.
    position = raw.rfind(b"\x30\x82")
    raw[position + 1 : position + 4] = b"\x84\xff\xff\xff\xf0"
    result = timestamps.verify_timestamp_token(
        tsr_bytes=bytes(raw),
        expected_imprint=b"\x00" * 32,
        listed_digest="sha256:" + "0" * 64,
        path="signatures/timestamp-1.tsr",
        trust_anchor_fingerprints=None,
    )
    assert result.state == timestamps.STATE_INVALID
    assert result.error == "E_TS_SCHEMA"


def test_bad_der_vectors_are_schema_errors() -> None:
    for case in (
        "integrity-levels/l2-ts-der-nonminimal-length",
        "integrity-levels/l2-ts-der-version-invalid",
        "integrity-levels/l2-ts-der-truncated-with-digest",
    ):
        report = _run_case(case)
        aggregate = set(report["container"]["errors"])
        for entry in report["records"]:
            aggregate.update(entry["errors"])
        assert "E_TS_SCHEMA" in aggregate, case


# ---------------------------------------------------------------------------
# V3: narrowed previous reading, signature verification and the new limitation
# ---------------------------------------------------------------------------


def test_supplied_verified_previous_reports_the_content_limitation() -> None:
    report = _run_case("container/previous-zip-valid")
    assert report["verdict"] == "valid"
    assert "L_PREVIOUS_CONTENT_UNVERIFIED" in report["limitations"]
    assert "N_PREVIOUS_SIG_UNVERIFIED" not in report["container"]["notices"]
    assert "L_PREVIOUS_SIG_UNVERIFIED" not in report["limitations"]


def test_previous_content_is_ignored() -> None:
    report = _run_case("container/previous-ignores-record-corruption")
    assert report["verdict"] == "valid"
    assert "L_PREVIOUS_CONTENT_UNVERIFIED" in report["limitations"]


def test_previous_duplicate_manifest_and_bad_attestation_are_chain_errors() -> None:
    for case in (
        "container/previous-ignores-duplicate-manifest",
        "container/previous-ignores-bad-attestation",
    ):
        report = _run_case(case)
        assert report["verdict"] == "invalid", case
        assert report["container"]["errors"] == ["E_MANIFEST_CHAIN"], case


def _previous_identity_fixture(tmp_path):
    """Materialise the chain-valid previous manifest + attestation into a dir."""
    parent = VECTORS / "container" / "previous-zip-valid"
    previous_zip = parent / "previous-container.zip"
    directory = tmp_path / "previous"
    (directory / "signatures").mkdir(parents=True)
    with previous_zip.open("rb") as handle:
        archive = zipread.parse_zip(handle)
        for name, target in (
            ("manifest.json", directory / "manifest.json"),
            ("signatures/manifest.sig.json", directory / "signatures" / "manifest.sig.json"),
        ):
            entry = next(item for item in archive.entries if item.name == name)
            target.write_bytes(zipread.read_entry_data(handle, entry))
    return directory


def test_previous_manifest_signature_is_verified(tmp_path) -> None:
    directory = _previous_identity_fixture(tmp_path)
    attestation_path = directory / "signatures" / "manifest.sig.json"
    attestation = json.loads(attestation_path.read_bytes())
    attestation["signatures"][0]["value"] = "A" * 86
    from hyphaweave_verify import canonical

    attestation_path.write_bytes(canonical.canonicalize(attestation))
    with pytest.raises(WeaveError) as raised:
        container_module._read_previous_identity(directory, [])
    assert raised.value.code == "E_MANIFEST_CHAIN"


def test_previous_attestation_digest_mismatch_is_manifest_chain(tmp_path) -> None:
    directory = _previous_identity_fixture(tmp_path)
    attestation_path = directory / "signatures" / "manifest.sig.json"
    attestation = json.loads(attestation_path.read_bytes())
    attestation["digest"] = "sha256:" + "0" * 64
    from hyphaweave_verify import canonical

    attestation_path.write_bytes(canonical.canonicalize(attestation))
    with pytest.raises(WeaveError) as raised:
        container_module._read_previous_identity(directory, [])
    assert raised.value.code == "E_MANIFEST_CHAIN"


def test_previous_symlinked_manifest_is_chain_error(tmp_path) -> None:
    directory = _previous_identity_fixture(tmp_path)
    manifest = directory / "manifest.json"
    manifest.rename(directory / "real-manifest.json")
    manifest.symlink_to(directory / "real-manifest.json")
    with pytest.raises(WeaveError) as raised:
        container_module._read_previous_identity(directory, [])
    assert raised.value.code == "E_MANIFEST_CHAIN"


# ---------------------------------------------------------------------------
# V5: public_key is a structural property
# ---------------------------------------------------------------------------


def test_bad_public_key_does_not_govern_class() -> None:
    report = _run_case("key-lifecycle/bad-public-key-does-not-govern")
    verdicts = {entry["id"]: entry["verdict"] for entry in report["records"]}
    assert verdicts["org1-org-T1"] == "valid"
    aggregate = set(report["container"]["errors"])
    for entry in report["records"]:
        aggregate.update(entry["errors"])
    assert "E_KEY_CLASS_CONFLICT" not in aggregate
    assert "E_KEY_PUBLIC_KEY" in aggregate


def test_keyset_bad_public_key_is_usage_error(tmp_path) -> None:
    from hyphaweave_verify import canonical

    keyset = tmp_path / "keyset"
    shutil.copytree(KEYSET, keyset)
    declaration = json.loads(
        (keyset / "key-declared-human-1.json").read_bytes()
    )
    declaration["body"]["public_key"] = "AAAA"
    (keyset / "zz-bad.json").write_bytes(canonical.canonicalize(declaration))
    with pytest.raises(UsageError):
        verifier.load_keyset_directory(keyset)


# ---------------------------------------------------------------------------
# V6/V7: zip fields, limits order, record_count and boundary counts
# ---------------------------------------------------------------------------


def test_zip_version_needed_and_entry_disk_start_are_container_zip() -> None:
    for case in (
        "container/zip-version-needed-too-high",
        "container/zip-entry-disk-start-nonzero",
    ):
        report = _run_case(case)
        assert report["verdict"] == "invalid", case
        assert report["container"]["errors"] == ["E_CONTAINER_ZIP"], case


def test_limits_are_checked_before_the_remaining_structural_rules() -> None:
    report = _run_case("container/zip-over-limit-and-structure-violation")
    assert report["verdict"] == "invalid"
    assert report["container"]["errors"] == ["E_CONTAINER_SIZE"]


def test_record_count_is_kept_after_the_manifest_structure_stage() -> None:
    report = _run_case("container/manifest-record-extra-and-missing")
    assert report["verdict"] == "invalid"
    assert report["container"]["record_count"] == 1


def test_directory_entry_count_includes_manifest(monkeypatch) -> None:
    """L6: the preloaded manifest.json counts; with a limit of 2 a container that
    holds manifest + attestation + one record is over the limit."""
    monkeypatch.setattr(container_module, "MAX_CONTAINER_ENTRIES", 2)
    case_dir = VECTORS / "container" / "l0-minimal"
    result = container_module.verify_container(case_dir / "container")
    assert result.report["verdict"] == "invalid"
    assert "E_CONTAINER_SIZE" in result.report["container"]["errors"]


# ---------------------------------------------------------------------------
# V8: the committed crash corpus is complete and replayable
# ---------------------------------------------------------------------------


def test_crash_corpus_index_is_complete() -> None:
    corpus = VECTORS.parent / "tools" / "crash_corpus"
    index = json.loads((corpus / "index.json").read_text(encoding="utf-8"))
    assert index["seed"] == 20261111
    assert index["case_count"] == 145
    for case in index["cases"]:
        assert case["category"] in ("previous", "tsa")
        assert case["base_case"]
        for relative in case["overlay"]:
            assert (corpus / case["file_id"] / relative).is_file(), case["file_id"]


def test_signer_info_version_profile() -> None:
    """V2/M3: signerInfo.version must be 1 (issuerAndSerialNumber) or 3 (SKI)."""
    from asn1crypto import tsp

    raw = _valid_tsr()
    response = tsp.TimeStampResp.load(raw)
    signed_data = response["time_stamp_token"]["content"]
    signed_data["signer_infos"][0]["version"] = 2
    tst_info = signed_data["encap_content_info"]["content"].parsed
    imprint = tst_info["message_imprint"]["hashed_message"].native
    mutated = response.dump(force=True)
    result = timestamps.verify_timestamp_token(
        tsr_bytes=mutated,
        expected_imprint=imprint,
        listed_digest="sha256:" + "0" * 64,
        path="signatures/timestamp-1.tsr",
        trust_anchor_fingerprints=None,
    )
    assert result.state == timestamps.STATE_INVALID
    assert result.error == "E_TS_SCHEMA"
