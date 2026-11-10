# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0

"""L2 external anchors: RFC 3161 TSR verification against committed fixtures."""

from __future__ import annotations

import json
import pathlib
import re

import pytest

from hyphaweave_verify import canonical, encoding, timestamps
from hyphaweave_verify.errors import WeaveError

from conftest import VECTORS

CASE = VECTORS / "integrity-levels" / "l2-valid"
TSR_PATH = CASE / "container" / "signatures" / "timestamp-1.tsr"
TRUST_PATH = CASE / "tsa.crt.pem"


def _manifest_digest() -> str:
    manifest_raw = (CASE / "container" / "manifest.json").read_bytes()
    value = canonical.parse_file_bytes(manifest_raw)
    return encoding.manifest_digest(canonical.canonicalize(value))


def _anchors() -> frozenset[bytes]:
    return timestamps.parse_trust_anchors(TRUST_PATH.read_bytes())


def _verify(**overrides):
    arguments = {
        "tsr_bytes": TSR_PATH.read_bytes(),
        "listed_digest": "sha256:" + "00" * 32,
        "path": "signatures/timestamp-1.tsr",
        "manifest_digest": _manifest_digest(),
        "trust_anchor_fingerprints": _anchors(),
    }
    arguments.update(overrides)
    return timestamps.verify_timestamp_file(**arguments)


@pytest.mark.skipif(not TSR_PATH.exists(), reason="committed TSR fixture is absent")
def test_committed_tsr_verifies_with_anchor() -> None:
    result = _verify()
    assert result.state == timestamps.STATE_VERIFIED
    assert result.error is None
    assert result.gen_time is not None
    assert re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$", result.gen_time)


@pytest.mark.skipif(not TSR_PATH.exists(), reason="committed TSR fixture is absent")
def test_tsr_without_anchor_is_present_unverified() -> None:
    result = _verify(trust_anchor_fingerprints=None)
    assert result.state == timestamps.STATE_PRESENT_UNVERIFIED
    assert result.error == "E_TS_UNTRUSTED"
    assert result.gen_time is not None


@pytest.mark.skipif(not TSR_PATH.exists(), reason="committed TSR fixture is absent")
def test_tsr_with_wrong_anchor_is_present_unverified() -> None:
    result = _verify(trust_anchor_fingerprints=frozenset({b"\x00" * 32}))
    assert result.state == timestamps.STATE_PRESENT_UNVERIFIED
    assert result.error == "E_TS_UNTRUSTED"


@pytest.mark.skipif(not TSR_PATH.exists(), reason="committed TSR fixture is absent")
def test_tsr_imprint_must_match_manifest_digest() -> None:
    result = _verify(manifest_digest="sha256:" + "11" * 32)
    assert result.state == timestamps.STATE_INVALID
    assert result.error == "E_TS_IMPRINT"


@pytest.mark.skipif(not TSR_PATH.exists(), reason="committed TSR fixture is absent")
def test_garbage_tsr_is_schema_error() -> None:
    result = _verify(tsr_bytes=b"not a timestamp response")
    assert result.state == timestamps.STATE_INVALID
    assert result.error == "E_TS_SCHEMA"


@pytest.mark.skipif(not TSR_PATH.exists(), reason="committed TSR fixture is absent")
def test_tampered_tsr_is_rejected() -> None:
    data = bytearray(TSR_PATH.read_bytes())
    data[-1] ^= 0x01
    result = _verify(tsr_bytes=bytes(data))
    assert result.state == timestamps.STATE_INVALID
    assert result.error in ("E_TS_SCHEMA", "E_TS_CMS")


@pytest.mark.skipif(not TRUST_PATH.exists(), reason="committed TSA certificate is absent")
def test_trust_anchor_parsing() -> None:
    anchors = timestamps.parse_trust_anchors(TRUST_PATH.read_bytes())
    assert len(anchors) == 1
    with pytest.raises(WeaveError) as raised:
        timestamps.parse_trust_anchors(b"not a pem bundle")
    assert raised.value.code == "E_TS_UNTRUSTED"


@pytest.mark.skipif(not TSR_PATH.exists(), reason="committed TSR fixture is absent")
def test_gen_time_matches_attestation_case() -> None:
    result = _verify()
    # The committed case's README states the TSR genTime; it must be inside the
    # test TSA certificate validity window (2026-01-01 .. 2126-01-01).
    assert result.gen_time == "2026-11-10T09:52:40.000Z"
