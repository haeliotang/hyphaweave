# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0

"""Byte constructions and strict encodings for ``weave-record/1``.

Implements CONTRACT §3: domain-separated hashing, unpadded base64url with
strict decoding (no padding, no whitespace, canonical trailing bits), key ids
(``ed25519:`` + first 32 lowercase hex of SHA-256 over the **raw 32-byte public
key**, correction v0.1.1) and digest strings (``<alg>:<lowercase hex>``).

Every helper is pure: no clock, no environment, no I/O.
"""

from __future__ import annotations

import hashlib
from typing import Any

from . import canonical
from .errors import WeaveError

#: Domain-separation prefixes (ASCII, each ends with one LF, CONTRACT §3).
DIGEST_DOMAIN = b"weave-record/1/digest\n"
SIG_DOMAIN = b"weave-record/1/sig\n"
MANIFEST_DIGEST_DOMAIN = b"weave-record/1/manifest-digest\n"
MANIFEST_SIG_DOMAIN = b"weave-record/1/manifest\n"

#: SHA-256 digest string length after the ``sha256:`` prefix.
SHA256_HEX_LENGTH = 64

#: Expected canonical base64url character lengths (CONTRACT §3.5).
B64URL_LENGTHS = {16: 22, 32: 43, 64: 86}

_B64URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
_B64URL_INDEX = {character: index for index, character in enumerate(_B64URL_ALPHABET)}


class EncodingError(ValueError):
    """A value is not a strict encoding of the required shape."""


# ---------------------------------------------------------------------------
# base64url (unpadded, RFC 4648 §5, canonical trailing bits)
# ---------------------------------------------------------------------------


def encode_base64url(data: bytes) -> str:
    """Encode bytes as unpadded base64url."""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("encode_base64url expects bytes")
    return _b64url_encode(bytes(data))


def _b64url_encode(data: bytes) -> str:
    chunks: list[str] = []
    index = 0
    length = len(data)
    while index + 2 < length:
        chunk = (data[index] << 16) | (data[index + 1] << 8) | data[index + 2]
        chunks.append(
            _B64URL_ALPHABET[(chunk >> 18) & 0x3F]
            + _B64URL_ALPHABET[(chunk >> 12) & 0x3F]
            + _B64URL_ALPHABET[(chunk >> 6) & 0x3F]
            + _B64URL_ALPHABET[chunk & 0x3F]
        )
        index += 3
    remaining = length - index
    if remaining == 1:
        chunk = data[index] << 16
        chunks.append(
            _B64URL_ALPHABET[(chunk >> 18) & 0x3F]
            + _B64URL_ALPHABET[(chunk >> 12) & 0x3F]
        )
    elif remaining == 2:
        chunk = (data[index] << 16) | (data[index + 1] << 8)
        chunks.append(
            _B64URL_ALPHABET[(chunk >> 18) & 0x3F]
            + _B64URL_ALPHABET[(chunk >> 12) & 0x3F]
            + _B64URL_ALPHABET[(chunk >> 6) & 0x3F]
        )
    return "".join(chunks)


def decode_base64url(value: str, expected_length: int | None = None) -> bytes:
    """Strictly decode unpadded base64url.

    Rejects padding, whitespace, ``+``/``/``, non-ASCII characters, computed
    lengths other than ``ceil(8 * expected_length / 6)`` and any non-zero
    unused trailing bits. With ``expected_length`` the decoded byte length and
    the canonical character count are enforced, which is what the format's
    fixed-size fields (16/32/64 bytes) require.
    """
    if not isinstance(value, str):
        raise EncodingError("base64url value must be a string")
    for character in value:
        if character not in _B64URL_INDEX:
            raise EncodingError("invalid base64url character %r" % character)
    accumulator = 0
    bits = 0
    decoded = bytearray()
    for character in value:
        accumulator = (accumulator << 6) | _B64URL_INDEX[character]
        bits += 6
        if bits >= 8:
            bits -= 8
            decoded.append((accumulator >> bits) & 0xFF)
    if bits and (accumulator & ((1 << bits) - 1)):
        raise EncodingError("non-zero unused trailing bits")
    data = bytes(decoded)
    if expected_length is not None:
        if len(data) != expected_length:
            raise EncodingError(
                "expected %d bytes, decoded %d" % (expected_length, len(data))
            )
        expected_characters = (expected_length * 8 + 5) // 6
        if len(value) != expected_characters:
            raise EncodingError(
                "expected %d base64url characters, found %d"
                % (expected_characters, len(value))
            )
    return data


# ---------------------------------------------------------------------------
# SHA-256 and digest strings
# ---------------------------------------------------------------------------


def sha256_hex(data: bytes) -> str:
    """Return lowercase hex SHA-256 of ``data``."""
    return hashlib.sha256(data).hexdigest()


def sha256_digest(data: bytes) -> str:
    """Return ``sha256:<64 lowercase hex>`` for ``data``."""
    return "sha256:" + sha256_hex(data)


def is_digest_string(value: Any) -> bool:
    """Structural digest-string check (unknown algorithms are structurally valid).

    The profile grammar is ``<alg>:<lowercase hex>``. For H0 the only
    *supported* algorithm is ``sha256`` with 64 hex digits; callers that need
    support decide via :func:`digest_algorithm`.
    """
    if not isinstance(value, str):
        return False
    if ":" not in value:
        return False
    algorithm, _, hex_digits = value.partition(":")
    if not algorithm or not hex_digits:
        return False
    for character in algorithm:
        if not ("a" <= character <= "z" or "0" <= character <= "9" or character == "-"):
            return False
    for character in hex_digits:
        if not ("0" <= character <= "9" or "a" <= character <= "f"):
            return False
    return True


def digest_algorithm(value: str) -> str:
    """Return the algorithm name of a structurally valid digest string."""
    if not is_digest_string(value):
        raise EncodingError("not a digest string: %r" % (value,))
    return value.partition(":")[0]


def is_supported_digest(value: Any) -> bool:
    """Whether ``value`` is a digest string this implementation can compute."""
    return (
        is_digest_string(value)
        and value.partition(":")[0] == "sha256"
        and len(value.partition(":")[2]) == SHA256_HEX_LENGTH
    )


def digest_bytes(value: str) -> bytes:
    """Return the raw digest bytes of a supported digest string."""
    if not is_supported_digest(value):
        raise EncodingError("unsupported digest string: %r" % (value,))
    return bytes.fromhex(value.partition(":")[2])


# ---------------------------------------------------------------------------
# Key ids (CONTRACT §3.4 + correction v0.1.1)
# ---------------------------------------------------------------------------

KEY_ID_PREFIX = "ed25519:"
KEY_ID_HEX_LENGTH = 32


def key_id_from_public_key(public_key: bytes) -> str:
    """Derive a key id from a raw 32-byte Ed25519 public key.

    ``ed25519:`` + first 32 lowercase hex characters of
    SHA-256(**raw public-key bytes**). Never hash the hex text (that is the
    Inceptless ``humanFingerprint`` bug fixed by correction v0.1.1).
    """
    if not isinstance(public_key, (bytes, bytearray)) or len(public_key) != 32:
        raise EncodingError("Ed25519 public keys are exactly 32 bytes")
    return KEY_ID_PREFIX + sha256_hex(bytes(public_key))[:KEY_ID_HEX_LENGTH]


def is_key_id(value: Any) -> bool:
    """Whether ``value`` is a structurally valid ``ed25519:<32 lowercase hex>`` id."""
    if not isinstance(value, str) or not value.startswith(KEY_ID_PREFIX):
        return False
    hex_digits = value[len(KEY_ID_PREFIX) :]
    if len(hex_digits) != KEY_ID_HEX_LENGTH:
        return False
    return all("0" <= character <= "9" or "a" <= character <= "f" for character in hex_digits)


def require_key_id(value: Any, code: str) -> str:
    """Return ``value`` if it is a key id, else raise ``WeaveError(code)``."""
    if not is_key_id(value):
        raise WeaveError(code, "not a valid key id")
    return value


# ---------------------------------------------------------------------------
# Record and manifest digests / signature messages
# ---------------------------------------------------------------------------


def record_digest(record: dict[str, Any]) -> str:
    """Compute the record digest per CONTRACT §3.1.

    The digest covers the canonical serialization of the record with the
    top-level ``sigs`` member removed (if present).
    """
    if not isinstance(record, dict):
        raise WeaveError("E_JSON_INVALID", "record must be a JSON object")
    payload = {key: value for key, value in record.items() if key != "sigs"}
    return "sha256:" + sha256_hex(DIGEST_DOMAIN + canonical.canonicalize(payload))


def manifest_digest(canonical_manifest_bytes: bytes) -> str:
    """Compute the manifest digest per CONTRACT §3.3 over canonical bytes."""
    if not isinstance(canonical_manifest_bytes, (bytes, bytearray)):
        raise TypeError("manifest bytes must be bytes")
    return "sha256:" + sha256_hex(MANIFEST_DIGEST_DOMAIN + bytes(canonical_manifest_bytes))


def record_sig_message(record_digest_string: str) -> bytes:
    """Return ``weave-record/1/sig\\n`` + digest string (ASCII) per CONTRACT §3.2."""
    try:
        digest_ascii = record_digest_string.encode("ascii")
    except UnicodeEncodeError as exc:  # pragma: no cover - defensive
        raise WeaveError("E_JSON_INVALID", "digest string must be ASCII") from exc
    return SIG_DOMAIN + digest_ascii


def manifest_sig_message(manifest_digest_string: str) -> bytes:
    """Return ``weave-record/1/manifest\\n`` + digest string (ASCII) per CONTRACT §3.3."""
    try:
        digest_ascii = manifest_digest_string.encode("ascii")
    except UnicodeEncodeError as exc:  # pragma: no cover - defensive
        raise WeaveError("E_JSON_INVALID", "digest string must be ASCII") from exc
    return MANIFEST_SIG_DOMAIN + digest_ascii
