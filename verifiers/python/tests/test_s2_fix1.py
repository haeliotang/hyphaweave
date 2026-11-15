# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0
"""S2-FIX1 (decision 2026-11-15 #13): rules that a conformance vector cannot express.

Usage errors (exit 2, no report) have no place in the vector expectation schema, so
the S2-FIX1 shapes that end in a usage error are pinned here.
"""

from __future__ import annotations

import json
import shutil

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from conftest import VECTORS, run_cli
from hyphaweave_verify import timestamps
from hyphaweave_verify.errors import WeaveError

KEYSET = VECTORS / "keys" / "keyset"
TARGET = VECTORS / "stage" / "accepted-signed" / "record.json"


def _canonical_file(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n"
    ).encode("utf-8")


@pytest.mark.parametrize(
    "name", ["key-declared-human-2.json", "key-declared-key-new.json", "key-declared-human-1.json"]
)
def test_keyset_declaration_with_empty_sigs_is_a_usage_error(tmp_path, name) -> None:
    """T5 (§14.1): `sigs: []` on a keyset record that must be signed is exit 2.

    §14.1 lists "sigs presence and format (§4.3, including a record that requires
    per-record signatures but has sigs absent or empty)" in the structural group whose
    failure in a keyset file is a usage error. Review A's differential fuzz found the
    reference verifier accepting such a keyset (mutants keyset-00013, keyset-00217).
    """
    keyset = tmp_path / "keyset"
    shutil.copytree(KEYSET, keyset)
    path = keyset / name
    record = json.loads(path.read_bytes())
    record["sigs"] = []
    path.write_bytes(_canonical_file(record))
    result = run_cli("record", str(TARGET), "--keys", str(keyset))
    assert result.returncode == 2, result.stdout
    assert result.stdout == b""
    assert b"E_SIG_REQUIRED" in result.stderr


def test_keyset_declaration_without_sigs_member_is_a_usage_error(tmp_path) -> None:
    """T5: an absent `sigs` on a keyset declaration is the same usage error."""
    keyset = tmp_path / "keyset"
    shutil.copytree(KEYSET, keyset)
    path = keyset / "key-declared-human-2.json"
    record = json.loads(path.read_bytes())
    del record["sigs"]
    path.write_bytes(_canonical_file(record))
    result = run_cli("record", str(TARGET), "--keys", str(keyset))
    assert result.returncode == 2, result.stdout
    assert result.stdout == b""


def test_unmodified_keyset_still_verifies() -> None:
    """Control for T5: the committed keyset is accepted."""
    result = run_cli("record", str(TARGET), "--keys", str(KEYSET))
    assert result.returncode in (0, 1)
    assert json.loads(result.stdout)["verdict"] == "valid"


# ---------------------------------------------------------------------------
# Q4 (§12.2 check 10): the bounds at their edges, where no committed receipt sits.
# ---------------------------------------------------------------------------

def _rsa_public(bits: int, exponent: int) -> rsa.RSAPublicKey:
    modulus = (1 << (bits - 1)) | 0xC5  # an odd number of exactly `bits` bits
    return rsa.RSAPublicNumbers(exponent, modulus).public_key()


@pytest.mark.parametrize(
    "bits, exponent, accepted",
    [
        (2048, 65537, True),
        (8192, 65537, True),
        (2047, 65537, False),
        (8193, 65537, False),
        (2048, 65535, False),
        (2048, (1 << 256) - 1, True),
        (2048, 1 << 256 | 1, False),
    ],
)
def test_rsa_key_bounds(bits: int, exponent: int, accepted: bool) -> None:
    key = _rsa_public(bits, exponent)
    if accepted:
        timestamps._check_rsa_key_bounds(key)
    else:
        with pytest.raises(WeaveError) as raised:
            timestamps._check_rsa_key_bounds(key)
        assert raised.value.code == "E_TS_CMS"


def test_rsa_even_exponent_is_rejected() -> None:
    try:
        key = _rsa_public(2048, 65538)
    except ValueError:
        pytest.skip("the key loader itself refuses an even exponent")
    with pytest.raises(WeaveError):
        timestamps._check_rsa_key_bounds(key)


_P256 = ec.generate_private_key(ec.SECP256R1()).public_key()
_N256 = timestamps._EC_ORDERS["secp256r1"]


def _sig(*components: bytes, trailing: bytes = b"") -> bytes:
    body = b"".join(b"\x02" + bytes([len(c)]) + c for c in components)
    return b"\x30" + bytes([len(body)]) + body + trailing


def _int(value: int) -> bytes:
    return value.to_bytes(value.bit_length() // 8 + 1, "big")


@pytest.mark.parametrize(
    "signature, accepted",
    [
        (_sig(_int(1), _int(1)), True),
        (_sig(_int(_N256 - 1), _int(5)), True),
        (_sig(_int(0), _int(1)), False),
        (_sig(_int(_N256), _int(1)), False),
        (_sig(b"\xff", _int(1)), False),
        (_sig(b"\x00\x01", _int(1)), False),
        (_sig(_int(1)), False),
        (_sig(_int(1), _int(1), _int(1)), False),
        (_sig(_int(1), _int(1), trailing=b"\x00"), False),
        (b"\x30\x81\x06" + _sig(_int(1), _int(1))[2:], False),
    ],
)
def test_ecdsa_signature_encoding(signature: bytes, accepted: bool) -> None:
    if accepted:
        timestamps._check_ecdsa_signature_encoding(signature, _P256)
    else:
        with pytest.raises(WeaveError) as raised:
            timestamps._check_ecdsa_signature_encoding(signature, _P256)
        assert raised.value.code == "E_TS_CMS"
