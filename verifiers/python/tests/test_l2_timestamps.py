# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0

"""L2 external anchors: the RFC 3161 archive profile against committed fixtures."""

from __future__ import annotations

import hashlib
import json
import re

import pytest

from hyphaweave_verify import canonical, encoding, timestamps
from hyphaweave_verify.errors import WeaveError

from conftest import VECTORS

LEVELS = VECTORS / "integrity-levels"


def _case(name: str):
    return LEVELS / name


def _manifest_digest(case) -> str:
    manifest_raw = (case / "container" / "manifest.json").read_bytes()
    value = canonical.parse_file_bytes(manifest_raw)
    return encoding.manifest_digest(canonical.canonicalize(value))


def _listed(case) -> list[dict]:
    attestation = json.loads(
        (case / "container" / "signatures" / "manifest.sig.json").read_text(encoding="utf-8")
    )
    return attestation["timestamps"]


def _files(case) -> dict[str, bytes]:
    signatures = case / "container" / "signatures"
    return {
        path.name: path.read_bytes()
        for path in sorted(signatures.iterdir())
        if path.suffix == ".tsr"
    }


def _files_by_relative_path(case) -> dict[str, bytes]:
    base = case / "container"
    result: dict[str, bytes] = {}
    for entry in _listed(case):
        result[entry["path"]] = (base / entry["path"]).read_bytes()
    return result


def _anchors(case) -> frozenset[bytes]:
    return timestamps.parse_trust_anchors((case / "tsa.crt.pem").read_bytes())


def _verify(case, *, trust=True, digest=None):
    return timestamps.verify_timestamp_archive(
        listed=_listed(case),
        files=_files_by_relative_path(case),
        manifest_digest=digest if digest is not None else _manifest_digest(case),
        trust_anchor_fingerprints=_anchors(case) if trust else None,
    )


@pytest.mark.skipif(not (LEVELS / "l2-valid").is_dir(), reason="L2 fixtures absent")
def test_committed_tsr_verifies_with_anchor() -> None:
    archive = _verify(_case("l2-valid"))
    assert archive.anchor_verified is True
    assert archive.errors == []
    assert len(archive.results) == 1
    result = archive.results[0]
    assert result.state == timestamps.STATE_VERIFIED
    assert result.error is None
    assert result.gen_time is not None
    assert re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$", result.gen_time)
    assert result.gen_time_ms is not None and isinstance(result.gen_time_ms, int)
    assert result.to_report(0)["path"] == "signatures/timestamp-1.tsr"


@pytest.mark.skipif(not (LEVELS / "l2-valid").is_dir(), reason="L2 fixtures absent")
def test_tsr_without_anchor_is_present_unverified() -> None:
    archive = _verify(_case("l2-valid"), trust=False)
    assert archive.anchor_verified is False
    assert archive.errors == ["E_TS_UNTRUSTED"]
    assert archive.results[0].state == timestamps.STATE_PRESENT_UNVERIFIED


@pytest.mark.skipif(not (LEVELS / "l2-valid").is_dir(), reason="L2 fixtures absent")
def test_tsr_with_wrong_anchor_is_present_unverified() -> None:
    archive = timestamps.verify_timestamp_archive(
        listed=_listed(_case("l2-valid")),
        files=_files_by_relative_path(_case("l2-valid")),
        manifest_digest=_manifest_digest(_case("l2-valid")),
        trust_anchor_fingerprints=frozenset({b"\x00" * 32}),
    )
    assert archive.results[0].state == timestamps.STATE_PRESENT_UNVERIFIED
    assert "E_TS_UNTRUSTED" in archive.errors


@pytest.mark.skipif(not (LEVELS / "l2-valid").is_dir(), reason="L2 fixtures absent")
def test_tsr_imprint_must_match_manifest_digest() -> None:
    archive = _verify(_case("l2-valid"), digest="sha256:" + "11" * 32)
    assert archive.results[0].state == timestamps.STATE_INVALID
    assert archive.results[0].error == "E_TS_IMPRINT"


@pytest.mark.skipif(not (LEVELS / "l2-valid").is_dir(), reason="L2 fixtures absent")
def test_tsr_file_digest_must_match_listing() -> None:
    case = _case("l2-valid")
    listed = _listed(case)
    files = _files_by_relative_path(case)
    listed[0]["digest"] = "sha256:" + "22" * 32
    archive = timestamps.verify_timestamp_archive(
        listed=listed,
        files=files,
        manifest_digest=_manifest_digest(case),
        trust_anchor_fingerprints=_anchors(case),
    )
    assert archive.results[0].state == timestamps.STATE_INVALID
    assert archive.results[0].error == "E_TS_FILE"


@pytest.mark.skipif(not (LEVELS / "l2-valid").is_dir(), reason="L2 fixtures absent")
def test_garbage_tsr_is_schema_error() -> None:
    case = _case("l2-valid")
    listed = _listed(case)
    files = _files_by_relative_path(case)
    files["signatures/timestamp-1.tsr"] = b"not a timestamp response"
    listed[0]["digest"] = "sha256:" + hashlib.sha256(
        files["signatures/timestamp-1.tsr"]
    ).hexdigest()
    archive = timestamps.verify_timestamp_archive(
        listed=listed,
        files=files,
        manifest_digest=_manifest_digest(case),
        trust_anchor_fingerprints=_anchors(case),
    )
    assert archive.results[0].state == timestamps.STATE_INVALID
    assert archive.results[0].error == "E_TS_SCHEMA"


@pytest.mark.skipif(not (LEVELS / "l2-valid").is_dir(), reason="L2 fixtures absent")
def test_tampered_tsr_is_rejected() -> None:
    case = _case("l2-valid")
    listed = _listed(case)
    files = _files_by_relative_path(case)
    data = bytearray(files["signatures/timestamp-1.tsr"])
    data[-1] ^= 0x01
    files["signatures/timestamp-1.tsr"] = bytes(data)
    listed[0]["digest"] = "sha256:" + hashlib.sha256(bytes(data)).hexdigest()
    archive = timestamps.verify_timestamp_archive(
        listed=listed,
        files=files,
        manifest_digest=_manifest_digest(case),
        trust_anchor_fingerprints=_anchors(case),
    )
    assert archive.results[0].state == timestamps.STATE_INVALID
    assert archive.results[0].error in ("E_TS_SCHEMA", "E_TS_CMS")


@pytest.mark.skipif(not (LEVELS / "l2-renewal-chain-valid").is_dir(), reason="renewal fixtures absent")
def test_renewal_chain_valid() -> None:
    archive = _verify(_case("l2-renewal-chain-valid"))
    assert archive.anchor_verified is True
    assert archive.errors == []
    assert archive.chain_paths == (
        "signatures/timestamp-1.tsr",
        "signatures/timestamp-2.tsr",
    )
    assert [result.state for result in archive.results] == [
        timestamps.STATE_VERIFIED,
        timestamps.STATE_VERIFIED,
    ]
    # Rescue evidence uses the earliest verified genTime of the chain.
    assert archive.earliest_verified_gen_time_ms == min(
        result.gen_time_ms for result in archive.results
    )


@pytest.mark.skipif(not (LEVELS / "l2-renewal-broken").is_dir(), reason="renewal fixtures absent")
def test_renewal_chain_broken() -> None:
    archive = _verify(_case("l2-renewal-broken"))
    assert archive.errors == ["E_TS_RENEWAL"]


@pytest.mark.skipif(not (LEVELS / "l2-valid").is_dir(), reason="L2 fixtures absent")
def test_trust_anchor_parsing() -> None:
    anchors = _anchors(_case("l2-valid"))
    assert len(anchors) == 1
    with pytest.raises(WeaveError) as raised:
        timestamps.parse_trust_anchors(b"not a pem bundle")
    assert raised.value.code == "E_TS_UNTRUSTED"


@pytest.mark.skipif(not (LEVELS / "l2-valid").is_dir(), reason="L2 fixtures absent")
def test_gen_time_is_normalised_to_milliseconds() -> None:
    archive = _verify(_case("l2-valid"))
    result = archive.results[0]
    assert result.gen_time_ms is not None
    assert result.to_report(0)["gen_time"] == result.gen_time
