#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0

"""Encoding, key-id and Ed25519 helpers for the vector generators.

Independent of ``hyphaweave_verify`` (the verifier must not be imported by
vector generation).  The Ed25519 signature verification here is a plain
``cryptography`` call used only to keep generated positive vectors honest; it
does not implement the strict WR-SIG profile of the reference verifier (the
profile itself is exercised through hand-authored negative vectors).
"""

from __future__ import annotations

import base64
import hashlib
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

__all__ = [
    "b64url_decode",
    "b64url_encode",
    "key_id",
    "load_key",
    "load_public_bin",
    "private_from_seed",
    "public_bytes",
    "sign",
    "spki_pem",
    "verify",
]

_B64URL_ALPHABET = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)

# Domain-separation prefixes, CONTRACT §3 (ASCII, each ends with one LF).
DIGEST_DOMAIN = b"weave-record/1/digest\n"
SIG_DOMAIN = b"weave-record/1/sig\n"
MANIFEST_DIGEST_DOMAIN = b"weave-record/1/manifest-digest\n"
MANIFEST_DOMAIN = b"weave-record/1/manifest\n"


def b64url_encode(data: bytes) -> str:
    """Unpadded base64url (RFC 4648 §5) of *data*."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str, *, expected_len: int | None = None) -> bytes:
    """Strict unpadded base64url decode.

    Rejects padding, whitespace, ``+``/``/``, impossible lengths and non-zero
    unused trailing bits, as required by CONTRACT §3.5.
    """
    if not isinstance(text, str):
        raise ValueError("base64url input must be a string")
    if text == "":
        raise ValueError("base64url input is empty")
    allowed = _B64URL_ALPHABET
    for index, character in enumerate(text):
        if character not in allowed:
            raise ValueError(
                "base64url character %r at %d is not allowed" % (character, index)
            )
    if len(text) % 4 == 1:
        raise ValueError("impossible base64url length %d" % len(text))
    padded = text + "=" * (-len(text) % 4)
    raw = base64.urlsafe_b64decode(padded.encode("ascii"))
    # Non-zero unused trailing bits are not canonical: re-encoding must match.
    if b64url_encode(raw) != text:
        raise ValueError("base64url input has non-zero unused trailing bits")
    if expected_len is not None and len(raw) != expected_len:
        raise ValueError(
            "base64url input decodes to %d bytes, expected %d"
            % (len(raw), expected_len)
        )
    return raw


def key_id(public_bytes_: bytes) -> str:
    """Return ``ed25519:<first 32 lowercase hex of sha256(raw public key)>``."""
    if len(public_bytes_) != 32:
        raise ValueError("Ed25519 public key must be 32 bytes")
    return "ed25519:" + hashlib.sha256(public_bytes_).hexdigest()[:32]


def private_from_seed(seed: bytes) -> ed25519.Ed25519PrivateKey:
    if len(seed) != 32:
        raise ValueError("Ed25519 seed must be 32 bytes")
    return ed25519.Ed25519PrivateKey.from_private_bytes(seed)


def public_bytes(private_key: ed25519.Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def spki_pem(private_key: ed25519.Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def sign(private_key: ed25519.Ed25519PrivateKey, message: bytes) -> bytes:
    return private_key.sign(message)


def verify(public_key_raw: bytes, message: bytes, signature: bytes) -> bool:
    try:
        key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_raw)
        key.verify(signature, message)
        return True
    except (InvalidSignature, ValueError):
        return False


class KeyMaterial:
    """One synthetic test key loaded from ``vectors/keys``."""

    def __init__(self, keys_dir: Path, name: str) -> None:
        self.keys_dir = Path(keys_dir)
        self.name = name
        meta_path = self.keys_dir / (name + ".json")
        if not meta_path.is_file():
            raise FileNotFoundError("missing test key metadata: %s" % meta_path)
        import json

        self.meta: dict[str, Any] = json.loads(meta_path.read_text(encoding="utf-8"))
        self.seed = bytes.fromhex((self.keys_dir / (name + ".seed")).read_text().strip())
        self.private_key = private_from_seed(self.seed)
        self.public_raw = public_bytes(self.private_key)
        expected = key_id(self.public_raw)
        if expected != self.meta.get("key_id"):
            raise ValueError(
                "test key %r: metadata key id %r does not match derived %r"
                % (name, self.meta.get("key_id"), expected)
            )
        if self.meta.get("key_type") not in {
            "human",
            "agent",
            "program",
            "device",
            "organization",
        }:
            raise ValueError("test key %r has invalid key_type" % name)

    @property
    def key_id(self) -> str:
        return self.meta["key_id"]

    @property
    def key_type(self) -> str:
        return self.meta["key_type"]

    def sign(self, message: bytes) -> bytes:
        return sign(self.private_key, message)

    def public_b64url(self) -> str:
        return b64url_encode(self.public_raw)


def load_key(keys_dir: Path, name: str) -> KeyMaterial:
    return KeyMaterial(Path(keys_dir), name)


def load_public_bin(keys_dir: Path, name: str) -> bytes:
    data = (Path(keys_dir) / (name + ".pub.bin")).read_bytes()
    if len(data) != 32:
        raise ValueError("test key %r public key is not 32 bytes" % name)
    return data
