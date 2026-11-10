# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0

"""Strict base64url, key ids, digest strings and the domain-separated digests."""

from __future__ import annotations

import json
import pathlib

import pytest

from hyphaweave_verify import encoding
from hyphaweave_verify.errors import WeaveError

VECTORS = pathlib.Path(__file__).resolve().parents[3] / "vectors"


def test_base64url_roundtrip_lengths() -> None:
    for length in (0, 1, 2, 3, 16, 31, 32, 64):
        data = bytes((index * 37 + 11) % 256 for index in range(length))
        encoded = encoding.encode_base64url(data)
        assert "=" not in encoded
        assert encoding.decode_base64url(encoded) == data
    assert encoding.encode_base64url(bytes(range(16))) == "AAECAwQFBgcICQoLDA0ODw"


def test_expected_character_counts() -> None:
    assert len(encoding.encode_base64url(bytes(16))) == 22
    assert len(encoding.encode_base64url(bytes(32))) == 43
    assert len(encoding.encode_base64url(bytes(64))) == 86


@pytest.mark.parametrize(
    "value",
    [
        "AAAAAAAAAAAAAAAAAAAAAA==",  # padded
        "AAAAAAAAAAAAAAAAAAAAA",  # 21 chars: wrong length for 16 bytes
        "AA AAAAAAAAAAAAAAAAAAAA",  # whitespace
        "++++++++++++++++++++++",  # standard base64 alphabet
        "//////////////////////",
        "AAAAAAAAAAAAAAAAAAAAA\u00e9",  # non-ASCII
    ],
)
def test_decode_rejects_non_strict_alphabet_or_padding(value: str) -> None:
    with pytest.raises(encoding.EncodingError):
        encoding.decode_base64url(value, 16)


def test_decode_rejects_non_zero_unused_trailing_bits() -> None:
    # 22 characters for 16 bytes: the final character carries four unused bits.
    canonical_salt = encoding.encode_base64url(bytes(16))
    assert canonical_salt[-1] in "AQgw"
    mutated = canonical_salt[:-1] + "B"  # B has a non-zero unused low bit
    with pytest.raises(encoding.EncodingError):
        encoding.decode_base64url(mutated, 16)


def test_decode_rejects_wrong_byte_length() -> None:
    with pytest.raises(encoding.EncodingError):
        encoding.decode_base64url(encoding.encode_base64url(bytes(31)), 32)


def test_key_ids_match_published_test_keys() -> None:
    for metadata_path in sorted((VECTORS / "keys").glob("*.json")):
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        public_key = (VECTORS / "keys" / metadata["pub_bin_file"]).read_bytes()
        derived = encoding.key_id_from_public_key(public_key)
        assert derived == metadata["key_id"]
        assert encoding.is_key_id(derived)


@pytest.mark.parametrize(
    "value",
    [
        "ed25519:",
        "ed25519:1234",
        "ed25519:" + "A" * 32,  # uppercase hex
        "ED25519:" + "a" * 32,
        "rsa256:" + "a" * 32,
        "ed25519:" + "a" * 33,
        None,
        123,
    ],
)
def test_invalid_key_ids(value: object) -> None:
    assert not encoding.is_key_id(value)


def test_key_id_hashes_raw_bytes_not_hex_text() -> None:
    # Correction v0.1.1: SHA-256 over the raw 32-byte public key.
    raw = bytes(range(32))
    import hashlib

    expected = "ed25519:" + hashlib.sha256(raw).hexdigest()[:32]
    assert encoding.key_id_from_public_key(raw) == expected
    hex_text_hash = "ed25519:" + hashlib.sha256(raw.hex().encode()).hexdigest()[:32]
    assert expected != hex_text_hash


def test_digest_string_rules() -> None:
    valid = "sha256:" + "ab" * 32
    assert encoding.is_digest_string(valid)
    assert encoding.is_supported_digest(valid)
    assert encoding.digest_bytes(valid) == bytes.fromhex("ab" * 32)
    # Unknown algorithms are structurally valid but unsupported.
    unknown = "sha3-256:" + "0f" * 32
    assert encoding.is_digest_string(unknown)
    assert not encoding.is_supported_digest(unknown)
    for malformed in ("sha256", "sha256:", ":abc", "sha256:" + "AB" * 32, ""):
        assert not encoding.is_digest_string(malformed)


def test_record_digest_excludes_sigs() -> None:
    unsigned = {
        "format": "weave-record/1",
        "id": "example",
        "kind": "example.note",
        "stage": "proposed",
        "body": {"text": "x"},
    }
    signed = dict(unsigned)
    signed["sigs"] = [
        {
            "alg": "ed25519",
            "key": "ed25519:" + "0" * 32,
            "value": encoding.encode_base64url(bytes(64)),
        }
    ]
    assert encoding.record_digest(unsigned) == encoding.record_digest(signed)


def test_digest_domain_prefixes() -> None:
    assert encoding.DIGEST_DOMAIN == b"weave-record/1/digest\n"
    assert encoding.SIG_DOMAIN == b"weave-record/1/sig\n"
    assert encoding.MANIFEST_DIGEST_DOMAIN == b"weave-record/1/manifest-digest\n"
    assert encoding.MANIFEST_SIG_DOMAIN == b"weave-record/1/manifest\n"
    message = encoding.record_sig_message("sha256:" + "0" * 64)
    assert message == b"weave-record/1/sig\nsha256:" + b"0" * 64


def test_manifest_digest_over_supplied_bytes() -> None:
    canonical_manifest = b'{"format":"weave-record/1"}'
    assert encoding.manifest_digest(canonical_manifest) == "sha256:" + (
        __import__("hashlib").sha256(b"weave-record/1/manifest-digest\n" + canonical_manifest).hexdigest()
    )


def test_fixed_record_digest_from_vectors() -> None:
    """A published vector's expected digest must be reproduced exactly."""
    expected = json.loads(
        (
            VECTORS / "key-lifecycle" / "declared-valid" / "expected.json"
        ).read_text(encoding="utf-8")
    )
    from hyphaweave_verify import canonical

    raw = (VECTORS / "key-lifecycle" / "declared-valid" / "record.json").read_bytes()
    value = canonical.parse_file_bytes(raw)
    assert encoding.record_digest(value) == expected["expected_digest"]
