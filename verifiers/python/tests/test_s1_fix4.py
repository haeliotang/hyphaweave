# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0

"""S1-FIX4 (Inceptless decision 2026-11-11 #16, W1-W11) unit tests.

The conformance vectors pin every rule that a report can express; these tests
pin what the vector format cannot (usage errors, exit 2) and check the DER
re-encoding of check 1c against an independent encoder.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from asn1crypto import tsp

from hyphaweave_verify import timestamps, verifier
from hyphaweave_verify.errors import UsageError, WeaveError

from conftest import VECTORS

KEYSET = VECTORS / "keys" / "keyset"
L2_VALID = VECTORS / "integrity-levels" / "l2-valid"
CLI = [sys.executable, "-m", "hyphaweave_verify.cli"]


def _run(argv: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(CLI + argv, capture_output=True, text=True)


def _invalid_version_pem(tmp_path: Path) -> Path:
    """The test TSA certificate with its TBSCertificate version set to 74."""
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding
    import base64

    certificate = x509.load_pem_x509_certificate((L2_VALID / "tsa.crt.pem").read_bytes())
    der = bytearray(certificate.public_bytes(Encoding.DER))
    marker = bytes([0xA0, 0x03, 0x02, 0x01, 0x02])
    position = der.index(marker)
    der[position + 4] = 0x4A
    body = base64.encodebytes(bytes(der)).decode("ascii")
    path = tmp_path / "invalid-version.pem"
    path.write_text("-----BEGIN CERTIFICATE-----\n" + body + "-----END CERTIFICATE-----\n")
    return path


# ---------------------------------------------------------------------------
# W4: operator inputs are usage errors (exit 2), naming the file
# ---------------------------------------------------------------------------


def test_tsa_trust_malformed_is_usage_error(tmp_path) -> None:
    bad = tmp_path / "not-a-pem.pem"
    bad.write_bytes(b"this is not a PEM bundle\n")
    completed = _run(
        ["container", str(L2_VALID / "container"), "--keys", str(KEYSET), "--tsa-trust", str(bad)]
    )
    assert completed.returncode == 2
    assert completed.stdout == ""
    assert str(bad) in completed.stderr
    assert "Traceback" not in completed.stderr


def test_tsa_trust_invalid_version_is_usage_error(tmp_path) -> None:
    """recheck3 H4: cryptography's InvalidVersion is not a ValueError."""
    pem = _invalid_version_pem(tmp_path)
    with pytest.raises(UsageError):
        timestamps.parse_trust_anchors(pem.read_bytes())
    completed = _run(
        ["container", str(L2_VALID / "container"), "--keys", str(KEYSET), "--tsa-trust", str(pem)]
    )
    assert completed.returncode == 2
    assert completed.stdout == ""
    assert str(pem) in completed.stderr
    assert "Traceback" not in completed.stderr


def test_tsa_trust_checked_before_an_early_container_failure(tmp_path) -> None:
    """The anchors are operator input: validated before any container stage."""
    bad = tmp_path / "empty.pem"
    bad.write_bytes(b"")
    missing_manifest = tmp_path / "empty-container"
    missing_manifest.mkdir()
    completed = _run(["container", str(missing_manifest), "--tsa-trust", str(bad)])
    assert completed.returncode == 2
    assert completed.stdout == ""


def test_previous_path_missing_is_usage_error(tmp_path) -> None:
    completed = _run(
        [
            "container",
            str(VECTORS / "container" / "previous-zip-valid" / "container"),
            "--keys",
            str(KEYSET),
            "--previous",
            str(tmp_path / "does-not-exist"),
        ]
    )
    assert completed.returncode == 2
    assert completed.stdout == ""
    assert "--previous" in completed.stderr


# ---------------------------------------------------------------------------
# W10/L6: keyset directory entries
# ---------------------------------------------------------------------------


def test_keyset_non_regular_json_entry_is_usage_error(tmp_path) -> None:
    keyset = tmp_path / "keyset"
    shutil.copytree(KEYSET, keyset)
    (keyset / "directory.json").mkdir()
    with pytest.raises(UsageError):
        verifier.load_keyset_directory(keyset)


def test_keyset_dangling_json_symlink_is_usage_error(tmp_path) -> None:
    keyset = tmp_path / "keyset"
    shutil.copytree(KEYSET, keyset)
    os.symlink(tmp_path / "nowhere.json", keyset / "dangling.json")
    with pytest.raises(UsageError):
        verifier.load_keyset_directory(keyset)


def test_keyset_hidden_json_file_is_read(tmp_path) -> None:
    keyset = tmp_path / "keyset"
    shutil.copytree(KEYSET, keyset)
    (keyset / ".hidden.json").write_bytes(b"not a record\n")
    with pytest.raises(UsageError):
        verifier.load_keyset_directory(keyset)


def test_keyset_other_names_are_ignored(tmp_path) -> None:
    keyset = tmp_path / "keyset"
    shutil.copytree(KEYSET, keyset)
    (keyset / "README.txt").write_bytes(b"ignored\n")
    (keyset / "notes.json.bak").write_bytes(b"ignored\n")
    assert len(verifier.load_keyset_directory(keyset)) == len(
        verifier.load_keyset_directory(KEYSET)
    )


# ---------------------------------------------------------------------------
# W3: the check-1c re-encoding agrees with an independent full re-encoder
# ---------------------------------------------------------------------------


def _committed_receipts() -> list[Path]:
    return sorted(
        path
        for path in VECTORS.rglob("*.tsr")
        if "previous-container" not in path.parts and path.stat().st_size > 64
    )


def _outcome(encode, data: bytes) -> str:
    try:
        return "equal" if encode(tsp.TimeStampResp.load(data, strict=True)) == data else "differs"
    except (ValueError, TypeError, KeyError, IndexError, timestamps._DerViolation):
        return "undecodable"


#: Receipts on which asn1crypto's whole-tree re-encoding is *expected* to
#: disagree with check 1c, and why. asn1crypto re-decodes OCTET STRING contents
#: (the TSTInfo eContent, certificate extension values), which check 1c
#: re-emits as decoded because check 2 (TSTInfo) and 1e (extension values) judge
#: them on their own; and it cannot re-encode a universal SET inside a value of
#: unknown type at all, so it rejects even the sorted control receipt.
EXPECTED_DIVERGENCE = {
    "l2-ts-der-boolean-not-ff": "TSTInfo defect: rejected by check 2",
    "l2-ts-der-default-encoded": "TSTInfo defect: rejected by check 2",
    "l2-ts-der-implicit-integer-nonminimal": "TSTInfo defect: rejected by check 2",
    "l2-ts-der-integer-nonminimal": "TSTInfo defect: rejected by check 2",
    "l2-ts-der-tstinfo-opaque-unsorted": "TSTInfo defect: rejected by check 2",
    "l2-ts-der-extension-value-nonminimal": "extension-value defect: rejected by check 1e",
    "l2-ts-der-setof-opaque-unsorted": "open-type SET: rejected by check 1a",
    "l2-ts-der-setof-sorted-control": "open-type SET in order: valid DER that asn1crypto cannot re-encode",
}


@pytest.mark.parametrize("receipt", _committed_receipts(), ids=lambda path: str(path.relative_to(VECTORS)))
def test_reencode_agrees_with_asn1crypto_force_dump(receipt: Path) -> None:
    """On the committed receipts, check 1c agrees with an independent re-encoder.

    asn1crypto's ``dump(force=True)`` re-encodes the whole parsed tree (about
    100 ms per receipt, too slow for the byte-flip gate). The linear re-encoding
    of check 1c must reach the same verdict on every committed receipt except
    the documented ones in ``EXPECTED_DIVERGENCE``; for those, the whole check
    1/2 pipeline must still reach the vector's conclusion (control accepted,
    every other one rejected with E_TS_SCHEMA).
    """
    data = receipt.read_bytes()
    case = receipt.parts[receipt.parts.index("container") - 1]
    ours = _outcome(timestamps._der_reencode, data)
    theirs = _outcome(lambda value: value.dump(force=True), data)
    if case not in EXPECTED_DIVERGENCE:
        assert ours == theirs
        return
    assert ours == "equal"
    assert theirs != "equal"
    if case.endswith("sorted-control"):
        timestamps._parse_tst_info(data)
    else:
        with pytest.raises(WeaveError) as raised:
            timestamps._parse_tst_info(data)
        assert raised.value.code == "E_TS_SCHEMA"


def test_sorted_open_type_set_is_not_rejected() -> None:
    """A universal SET of unknown type in ascending order passes check 1."""
    raw = (L2_VALID / "container" / "signatures" / "timestamp-1.tsr").read_bytes()
    response = tsp.TimeStampResp.load(raw, strict=True)
    assert timestamps._der_reencode(response) == raw
    timestamps._validate_strict_der(bytes.fromhex("3106020101020102"))
    with pytest.raises(Exception):
        timestamps._validate_strict_der(bytes.fromhex("3106020102020101"))
