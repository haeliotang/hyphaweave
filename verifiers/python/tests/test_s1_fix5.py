# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0

"""S1-FIX5 (Inceptless decision 2026-11-12 #1, X1-X3) unit tests.

X1: the DER judgement of §12.2 check 1 comes from X.690 and the ASN.1 module
definitions only. The expectations below are written from those texts (the
DEFAULT encodings are assembled here octet by octet from the module
definitions), never from a parsing library's output.

X3: every operator path is examined with ``lstat`` before it is opened; a FIFO,
device or socket is a usage error (exit 2) and the process never blocks. Each
subprocess runs under a timeout; a timeout fails the test.
"""

from __future__ import annotations

import ast
import os
import shutil
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from hyphaweave_verify import der_schema, timestamps
from hyphaweave_verify.errors import WeaveError

from conftest import PACKAGE_ROOT, VECTORS

KEYSET = VECTORS / "keys" / "keyset"
L2_VALID = VECTORS / "integrity-levels" / "l2-valid"
CLI = [sys.executable, "-m", "hyphaweave_verify.cli"]
#: Seconds before a CLI run counts as hung (a blocked FIFO open never returns).
HANG_TIMEOUT = 30


def _run(argv: list[str], *, cwd: Path | None = None) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            CLI + argv, capture_output=True, text=True, timeout=HANG_TIMEOUT, cwd=cwd
        )
    except subprocess.TimeoutExpired:  # subprocess.run kills its own child
        pytest.fail("the verifier blocked on an operator input: %r" % (argv,))


def _container_argv(*extra: str) -> list[str]:
    return ["container", str(L2_VALID / "container"), "--keys", str(KEYSET), *extra]


def _assert_usage_error(completed: subprocess.CompletedProcess, option: str) -> None:
    assert completed.returncode == 2, completed.stderr
    assert completed.stdout == ""
    assert option in completed.stderr
    assert "Traceback" not in completed.stderr


# ---------------------------------------------------------------------------
# X1: DEFAULT values are the module definitions' values
# ---------------------------------------------------------------------------


def _tlv(identifier: int, content: bytes) -> bytes:
    assert len(content) < 0x80
    return bytes([identifier, len(content)]) + content


#: id-sha256 = 2.16.840.1.101.3.4.2.1 (RFC 5754), content octets by hand:
#: 2*40+16 = 96 (0x60), 840 = 0x86 0x48, 1, 101 (0x65), 3, 4, 2, 1.
ID_SHA256 = bytes([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01])


def test_defaults_are_the_module_definition_values() -> None:
    # RFC 5035: hashAlgorithm AlgorithmIdentifier DEFAULT {algorithm id-sha256}
    # -- the parameters component is absent.
    assert der_schema.DEFAULTS["ESSCertIDv2.hashAlgorithm"] == _tlv(0x30, _tlv(0x06, ID_SHA256))
    # RFC 5280: version [0] EXPLICIT Version DEFAULT v1 (v1 = 0).
    assert der_schema.DEFAULTS["TBSCertificate.version"] == _tlv(0xA0, _tlv(0x02, b"\x00"))
    # RFC 5280 Extension.critical / RFC 3161 TSTInfo.ordering: BOOLEAN DEFAULT FALSE.
    assert der_schema.DEFAULTS["Extension.critical"] == _tlv(0x01, b"\x00")
    assert der_schema.DEFAULTS["TSTInfo.ordering"] == _tlv(0x01, b"\x00")
    assert set(der_schema.DEFAULTS) == {
        "ESSCertIDv2.hashAlgorithm",
        "TBSCertificate.version",
        "Extension.critical",
        "TSTInfo.ordering",
    }


def _ess_cert_id(hash_algorithm: bytes | None) -> bytes:
    body = (hash_algorithm or b"") + _tlv(0x04, b"\x11" * 32)
    return _tlv(0x30, body)


def test_ess_hash_algorithm_default_is_judged_by_value() -> None:
    schema = der_schema._ESS_CERT_ID_V2
    absent = _ess_cert_id(None)
    assert der_schema.reencode(schema, absent)[0] == absent
    with_null = _ess_cert_id(_tlv(0x30, _tlv(0x06, ID_SHA256) + b"\x05\x00"))
    assert der_schema.reencode(schema, with_null)[0] == with_null
    explicit_default = _ess_cert_id(_tlv(0x30, _tlv(0x06, ID_SHA256)))
    with pytest.raises(der_schema.DerViolation):
        der_schema.reencode(schema, explicit_default)


def test_generalized_time_is_compared_as_raw_content() -> None:
    schema = der_schema.GENERALIZED_TIME
    for text in (b"20261101000000Z", b"20261101000000.1234567Z", b"20261101000000.000000001Z"):
        encoded = _tlv(0x18, text)
        assert der_schema.reencode(schema, encoded)[0] == encoded
    for text in (b"20261101000000.10Z", b"20261101000000.Z", b"20261101000000+0000", b"202611010000Z"):
        with pytest.raises(der_schema.DerViolation):
            der_schema.reencode(schema, _tlv(0x18, text))


def test_open_type_values_are_never_type_decoded() -> None:
    schema = der_schema._ATTRIBUTE
    oid = _tlv(0x06, bytes([0x2A, 0x03, 0x04, 0x08, 0x05]))  # 1.2.3.4.8.5
    for value in (b"\x80\x01\x01", b"\x5f\x81\x48\x01\x01", b"\x5f\x81\x80\x00\x01\x01"):
        attribute = _tlv(0x30, oid + _tlv(0x31, value))
        assert der_schema.reencode(schema, attribute)[0] == attribute
        timestamps._validate_strict_der(attribute)


def test_high_tag_number_form_follows_x690_8_1_2_4() -> None:
    timestamps._validate_strict_der(bytes.fromhex("5f8180000101"))
    timestamps._validate_strict_der(bytes.fromhex("9f8180800001ff"))
    timestamps._validate_strict_der(bytes.fromhex("5f81480101"))
    # a long but minimal form: not limited by an implementation octet count
    timestamps._validate_strict_der(bytes.fromhex("5f8180808080800001ff"))
    for bad in ("5f8081480101", "5f050101", "5f1e0101"):
        with pytest.raises(WeaveError):
            timestamps._validate_strict_der(bytes.fromhex(bad))


def test_named_bit_list_drops_trailing_zero_bits() -> None:
    schema = der_schema.NAMED_BIT_STRING
    assert der_schema.reencode(schema, bytes.fromhex("03020780"))[0] == bytes.fromhex("03020780")
    # bit 0 set, encoded with 0 unused bits: DER requires 7 unused bits (X.690 §11.2.2)
    assert der_schema.reencode(schema, bytes.fromhex("03020080"))[0] != bytes.fromhex("03020080")
    assert der_schema.reencode(schema, bytes.fromhex("030100"))[0] == bytes.fromhex("030100")


def test_check_1c_does_not_consult_asn1crypto(monkeypatch) -> None:
    """The DER judgement module imports no parsing library and works without one."""
    source = (PACKAGE_ROOT / "hyphaweave_verify" / "der_schema.py").read_text()
    imported = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add((node.module or "").split(".")[0])
    assert imported <= {"__future__", "re", "typing"}, imported

    import asn1crypto.core

    def refuse(*_arguments, **_keywords):
        raise AssertionError("asn1crypto was consulted by check 1c")

    monkeypatch.setattr(asn1crypto.core.Asn1Value, "dump", refuse)
    monkeypatch.setattr(asn1crypto.core.Asn1Value, "load", classmethod(refuse))
    for case in sorted((VECTORS / "integrity-levels").glob("l2-ts-der-*")):
        for receipt in sorted((case / "container" / "signatures").glob("*.tsr")):
            data = receipt.read_bytes()
            try:
                timestamps._validate_strict_der(data)
                der_schema.reencode(der_schema.TIME_STAMP_RESP, data)
            except (WeaveError, der_schema.DerViolation):
                pass


# ---------------------------------------------------------------------------
# X3: operator paths are examined before they are opened
# ---------------------------------------------------------------------------


@pytest.fixture
def fifo(tmp_path) -> Path:
    path = tmp_path / "operator.fifo"
    os.mkfifo(path)
    return path


def test_tsa_trust_fifo_is_usage_error_without_blocking(fifo) -> None:
    _assert_usage_error(_run(_container_argv("--tsa-trust", str(fifo))), "--tsa-trust")


def test_previous_fifo_is_usage_error_without_blocking(fifo) -> None:
    _assert_usage_error(_run(_container_argv("--previous", str(fifo))), "--previous")


def test_keys_fifo_is_usage_error_without_blocking(fifo) -> None:
    completed = _run(["container", str(L2_VALID / "container"), "--keys", str(fifo)])
    _assert_usage_error(completed, "--keys")


def test_keyset_fifo_entry_is_usage_error_without_blocking(tmp_path) -> None:
    keyset = tmp_path / "keyset"
    shutil.copytree(KEYSET, keyset)
    os.mkfifo(keyset / "pipe.json")
    completed = _run(["container", str(L2_VALID / "container"), "--keys", str(keyset)])
    _assert_usage_error(completed, "--keys")
    assert "pipe.json" in completed.stderr


def test_tsa_trust_symlink_to_fifo_is_usage_error(fifo, tmp_path) -> None:
    link = tmp_path / "anchor.pem"
    os.symlink(fifo, link)
    _assert_usage_error(_run(_container_argv("--tsa-trust", str(link))), "--tsa-trust")


@pytest.mark.parametrize("option", ["--tsa-trust", "--previous", "--keys"])
def test_device_file_is_usage_error(option) -> None:
    if not os.path.exists(os.devnull):  # pragma: no cover - POSIX only
        pytest.skip("no device file")
    if option == "--keys":
        argv = ["container", str(L2_VALID / "container"), "--keys", os.devnull]
    else:
        argv = _container_argv(option, os.devnull)
    _assert_usage_error(_run(argv), option)


@pytest.mark.parametrize("option", ["--tsa-trust", "--previous"])
def test_socket_is_usage_error(option, tmp_path) -> None:
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    previous_directory = os.getcwd()
    try:
        os.chdir(tmp_path)  # a short relative name keeps under the sun_path limit
        listener.bind("s")
    finally:
        os.chdir(previous_directory)
    try:
        _assert_usage_error(_run(_container_argv(option, str(tmp_path / "s"))), option)
    finally:
        listener.close()


def test_tsa_trust_above_the_read_bound_is_usage_error(tmp_path) -> None:
    pem = (L2_VALID / "tsa.crt.pem").read_bytes()
    oversize = tmp_path / "big.pem"
    oversize.write_bytes(pem + b"\n" * (timestamps.MAX_TIMESTAMP_BYTES + 1 - len(pem)))
    completed = _run(_container_argv("--tsa-trust", str(oversize)))
    _assert_usage_error(completed, "--tsa-trust")
    assert str(timestamps.MAX_TIMESTAMP_BYTES) in completed.stderr


def test_tsa_trust_at_the_read_bound_is_read(tmp_path) -> None:
    pem = (L2_VALID / "tsa.crt.pem").read_bytes()
    at_limit = tmp_path / "limit.pem"
    at_limit.write_bytes(pem + b"\n" * (timestamps.MAX_TIMESTAMP_BYTES - len(pem)))
    assert len(timestamps.load_trust_anchor_file(at_limit)) == timestamps.MAX_TIMESTAMP_BYTES
