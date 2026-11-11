# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0

"""S1-FIX4 (Inceptless decision 2026-11-11 #16, W1-W11) unit tests.

The conformance vectors pin every rule that a report can express; these tests
pin what the vector format cannot (usage errors, exit 2).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from hyphaweave_verify import der_schema, timestamps, verifier
from hyphaweave_verify.errors import UsageError

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
# W3: check 1a/1c on a sorted open-type SET (S1-FIX5 X1 replaced the former
# comparison with asn1crypto's own re-encoder: a parsing library's behaviour is
# not a criterion; see test_s1_fix5.py)
# ---------------------------------------------------------------------------


def test_sorted_open_type_set_is_not_rejected() -> None:
    """A universal SET of unknown type in ascending order passes check 1."""
    raw = (L2_VALID / "container" / "signatures" / "timestamp-1.tsr").read_bytes()
    assert der_schema.reencode(der_schema.TIME_STAMP_RESP, raw)[0] == raw
    timestamps._validate_strict_der(bytes.fromhex("3106020101020102"))
    with pytest.raises(Exception):
        timestamps._validate_strict_der(bytes.fromhex("3106020102020101"))
