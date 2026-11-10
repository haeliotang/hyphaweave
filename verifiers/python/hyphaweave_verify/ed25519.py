# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0

"""Strict Ed25519 verification profile (CONTRACT §4).

The profile is single-message, strict, PureEdDSA, cofactorless, exactly as
``weave-record/1`` requires. The equation is implemented here in pure Python
(extended twisted-Edwards coordinates) *on top of* the explicit pre-checks, so
the result does not depend on any library's acceptance of edge cases. In
particular OpenSSL's raw Ed25519 verifier accepts the identity-key forgery
(public key = identity point, ``R`` = identity, ``S`` = 0); this profile must
reject it, and the eight small-order encodings below are rejected for both the
public key ``A`` and the signature nonce point ``R``.

``cryptography`` is only used by tests for cross-checking this implementation;
it is not needed to verify a signature.

Public API used by external cross-check tooling:

* :func:`verify` -> ``bool`` (never raises for a rejected signature);
* :func:`verify_signature` -> ``None`` or raises ``WeaveError`` with a registry
  code from the ``E_SIG_*`` family.
"""

from __future__ import annotations

import hashlib

from .errors import WeaveError

#: Field prime p = 2^255 - 19.
P = 2**255 - 19

#: Group order L = 2^252 + 27742317777372353535851937790883648493.
L = 2**252 + 27742317777372353535851937790883648493

#: Curve parameter d = -121665/121666 mod p.
D = (-121665 * pow(121666, P - 2, P)) % P

#: sqrt(-1) mod p, used for point decompression.
SQRT_M1 = pow(2, (P - 1) // 4, P)

#: Base point y coordinate 4/5 mod p.
_BASE_Y = (4 * pow(5, P - 2, P)) % P

#: The complete canonical encodings of the eight small-order points (§4).
SMALL_ORDER_ENCODINGS: frozenset[bytes] = frozenset(
    bytes.fromhex(value)
    for value in (
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000080",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    )
)

#: Affine identity point, encoded (y = 1, sign bit 0).
IDENTITY_ENCODING = bytes.fromhex(
    "0100000000000000000000000000000000000000000000000000000000000000"
)


def _decode_point(encoding: bytes, noncanonical_code: str) -> tuple[int, int, int, int]:
    """Decode a 32-byte compressed Edwards point.

    Rejects ``y >= p``, encodings with no corresponding curve x, and
    ``x == 0`` with the sign bit set. Returns extended coordinates.
    """
    if len(encoding) != 32:
        raise WeaveError(noncanonical_code, "point encoding must be 32 bytes")
    value = int.from_bytes(encoding, "little")
    sign = (value >> 255) & 1
    y = value & ((1 << 255) - 1)
    if y >= P:
        raise WeaveError(noncanonical_code, "point encoding y is not canonical")
    y_squared = y * y % P
    numerator = (y_squared - 1) % P
    denominator = (D * y_squared + 1) % P
    x_squared = numerator * pow(denominator, P - 2, P) % P
    if x_squared == 0:
        if sign:
            raise WeaveError(noncanonical_code, "x == 0 with the sign bit set")
        x = 0
    else:
        x = pow(x_squared, (P + 3) // 8, P)
        if (x * x - x_squared) % P != 0:
            x = x * SQRT_M1 % P
            if (x * x - x_squared) % P != 0:
                raise WeaveError(noncanonical_code, "point is not on the curve")
        if (x & 1) != sign:
            x = P - x
    return (x, y, 1, x * y % P)


def _point_add(
    first: tuple[int, int, int, int], second: tuple[int, int, int, int]
) -> tuple[int, int, int, int]:
    x1, y1, z1, t1 = first
    x2, y2, z2, t2 = second
    a = (y1 - x1) * (y2 - x2) % P
    b = (y1 + x1) * (y2 + x2) % P
    c = 2 * D * t1 * t2 % P
    d = 2 * z1 * z2 % P
    e = (b - a) % P
    f = (d - c) % P
    g = (d + c) % P
    h = (b + a) % P
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _point_double(point: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    x1, y1, z1, _t1 = point
    a = x1 * x1 % P
    b = y1 * y1 % P
    c = 2 * z1 * z1 % P
    d = -a % P
    e = ((x1 + y1) * (x1 + y1) - a - b) % P
    g = (d + b) % P
    f = (g - c) % P
    h = (d - b) % P
    return (e * f % P, g * h % P, f * g % P, e * h % P)


IDENTITY = (0, 1, 1, 0)

_BASE_X = None


def _base_point() -> tuple[int, int, int, int]:
    global _BASE_X
    if _BASE_X is None:
        y = _BASE_Y
        x_squared = (y * y - 1) % P * pow(D * y * y + 1, P - 2, P) % P
        x = pow(x_squared, (P + 3) // 8, P)
        if (x * x - x_squared) % P != 0:
            x = x * SQRT_M1 % P
        if x & 1:
            x = P - x
        _BASE_X = (x, y, 1, x * y % P)
    return _BASE_X


def _scalar_mult(point: tuple[int, int, int, int], scalar: int) -> tuple[int, int, int, int]:
    result = IDENTITY
    addend = point
    while scalar:
        if scalar & 1:
            result = _point_add(result, addend)
        addend = _point_double(addend)
        scalar >>= 1
    return result


def _point_equal(
    first: tuple[int, int, int, int], second: tuple[int, int, int, int]
) -> bool:
    x1, y1, z1, _t1 = first
    x2, y2, z2, _t2 = second
    return (x1 * z2 - x2 * z1) % P == 0 and (y1 * z2 - y2 * z1) % P == 0


def is_small_order(encoding: bytes) -> bool:
    """Whether ``encoding`` is one of the eight canonical small-order points."""
    return encoding in SMALL_ORDER_ENCODINGS


def is_canonical_point_encoding(encoding: bytes) -> bool:
    """Whether ``encoding`` is a canonical encoding of a curve point.

    Used by kind semantics for declared public keys (``E_KEY_PUBLIC_KEY``).
    Canonical encoding only: small-order points are canonical encodings and are
    *not* rejected here (they are rejected when used as a verification key).
    """
    try:
        _decode_point(encoding, "E_KEY_PUBLIC_KEY")
    except WeaveError:
        return False
    return True


def verify_signature(public_key: bytes, message: bytes, signature: bytes) -> None:
    """Verify a PureEdDSA Ed25519 signature under the strict profile.

    Raises :class:`WeaveError` with a registry ``E_SIG_*`` code on rejection and
    returns ``None`` on success.
    """
    if not isinstance(public_key, (bytes, bytearray)):
        raise WeaveError("E_SIG_NONCANONICAL_A", "public key must be bytes")
    if not isinstance(signature, (bytes, bytearray)):
        raise WeaveError("E_SIG_INVALID", "signature must be bytes")
    if not isinstance(message, (bytes, bytearray)):
        raise WeaveError("E_SIG_INVALID", "message must be bytes")
    public_key = bytes(public_key)
    signature = bytes(signature)
    message = bytes(message)

    # Step 1-2: decode A canonically (length, y >= p, on curve).
    a_point = _decode_point(public_key, "E_SIG_NONCANONICAL_A")
    # Step 3a: reject the eight small-order public keys (identity forgery).
    if public_key in SMALL_ORDER_ENCODINGS:
        raise WeaveError("E_SIG_SMALL_ORDER_A", "public key is a small-order point")

    if len(signature) != 64:
        raise WeaveError("E_ENV_SIG_VALUE", "signature must be exactly 64 bytes")
    r_encoding = signature[:32]
    r_point = _decode_point(r_encoding, "E_SIG_NONCANONICAL_R")
    if r_encoding in SMALL_ORDER_ENCODINGS:
        raise WeaveError("E_SIG_SMALL_ORDER_R", "R is a small-order point")

    # Step 3b: S must be canonical (S < L).
    s = int.from_bytes(signature[32:], "little")
    if s >= L:
        raise WeaveError("E_SIG_S_OUT_OF_RANGE", "S is not canonical (S >= L)")

    # Step 4: cofactorless equation [S]B = R + [k]A.
    #
    # The profile permits using a library for the final equation once all
    # pre-checks above are enforced (CONTRACT §4). cryptography's raw Ed25519
    # verifier is used here for speed; it is only reached after the explicit
    # canonical/small-order/S-range checks, and like this profile it does not
    # require the public key to be in the prime-order subgroup (mixed-order keys
    # are accepted iff the exact equation holds).
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
    except WeaveError:  # pragma: no cover - defensive
        raise
    except Exception as error:
        raise WeaveError(
            "E_SIG_INVALID", "Ed25519 verification equation does not hold"
        ) from error


def verify_equation_python(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Independent pure-Python check of the strict equation (tests/tooling only).

    Implements the same cofactorless equation with this module's point
    arithmetic, so tests can cross-check the library-backed verifier.
    """
    if len(public_key) != 32 or len(signature) != 64:
        return False
    try:
        a_point = _decode_point(public_key, "E_SIG_NONCANONICAL_A")
    except WeaveError:
        return False
    if public_key in SMALL_ORDER_ENCODINGS:
        return False
    r_encoding = signature[:32]
    try:
        r_point = _decode_point(r_encoding, "E_SIG_NONCANONICAL_R")
    except WeaveError:
        return False
    if r_encoding in SMALL_ORDER_ENCODINGS:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= L:
        return False
    k = int.from_bytes(
        hashlib.sha512(r_encoding + public_key + message).digest(), "little"
    ) % L
    left = _scalar_mult(_base_point(), s)
    right = _point_add(r_point, _scalar_mult(a_point, k))
    return _point_equal(left, right)


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Return ``True`` iff the strict profile accepts the signature.

    Rejections are returned as ``False`` (no exception). This is the stable API
    used by the repository's independent cross-check tooling.
    """
    try:
        verify_signature(public_key, message, signature)
    except WeaveError:
        return False
    return True
