# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0

"""Strict Ed25519 verification profile (spec §3, decision #34 / S1 + Q1).

The verification steps are fixed and ordered; the first failing step decides the
registry error code:

1. signature length (``E_ENV_SIG_VALUE``) and public-key length
   (``E_SIG_NONCANONICAL_A``);
2. ``S < L`` (``E_SIG_S_OUT_OF_RANGE``);
3. full RFC 8032 §5.1.3 decoding of ``A`` including "``x = 0`` with the sign bit
   set is a decoding failure" (``E_SIG_NONCANONICAL_A``);
4. ``[8]A == identity`` — the eight small-order points, detected from the
   decoded point rather than from an encoding list (``E_SIG_SMALL_ORDER_A``);
5. ``[L]A != identity`` — mixed-order public keys are rejected (Q1;
   ``E_SIG_MIXED_ORDER_A``);
6. full decoding of ``R`` (``E_SIG_NONCANONICAL_R``);
7. ``[8]R == identity`` (``E_SIG_SMALL_ORDER_R``);
8. cofactorless equation ``[S]B == R + [k]A`` with
   ``k = SHA-512(R || A || M) mod L`` (``E_SIG_INVALID``).

The explicit pre-checks are implemented here; once they pass, the final equation
is delegated to ``cryptography`` (OpenSSL) for speed, which implements the same
cofactorless equation. A pure-Python implementation of the equation is kept for
test cross-checking. The identity-key forgery and the non-canonical
``x = 0`` encodings are rejected by the pre-checks, not by the library.

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

#: The eight canonical encodings of the small-order points (for documentation and
#: tests; detection itself is point-based via ``[8]P == identity``).
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

#: Non-canonical identity-point encodings (x = 0 with the sign bit set); RFC 8032
#: requires these to be rejected at decoding. Kept for tests.
NONCANONICAL_IDENTITY_ENCODINGS: tuple[bytes, ...] = (
    bytes.fromhex("0100000000000000000000000000000000000000000000000000000000000080"),
    bytes.fromhex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
)

#: Cache of decoded public keys: bytes -> (error_code, point, order_class).
#: Mixed-order detection needs one scalar multiplication, so caching keeps the
#: verifier fast for suites that reuse a small set of published keys.
_PUBLIC_KEY_CACHE: dict[bytes, tuple[str | None, tuple[int, int, int, int] | None, str | None]] = {}
_CACHE_LIMIT = 4096


def _decode_point(encoding: bytes, noncanonical_code: str) -> tuple[int, int, int, int]:
    """Decode a 32-byte compressed Edwards point (RFC 8032 §5.1.3, full steps)."""
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
            # RFC 8032 §5.1.3 step 4: x = 0 with the sign bit set fails to decode.
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


def _point_negate(point: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    x, y, z, t = point
    return (-x % P, y, z, -t % P)


IDENTITY = (0, 1, 1, 0)

_BASE_X: int | None = None


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
        _BASE_X = x
    y = _BASE_Y
    x = _BASE_X
    return (x, y, 1, x * y % P)


def _scalar_mult_naf(
    point: tuple[int, int, int, int], scalar: int
) -> tuple[int, int, int, int]:
    """Non-adjacent-form scalar multiplication (fewer additions than double-add)."""
    naf: list[int] = []
    while scalar:
        if scalar & 1:
            digit = 2 - (scalar % 4)
            naf.append(digit)
            scalar -= digit
        else:
            naf.append(0)
        scalar >>= 1
    result = IDENTITY
    negative_point = _point_negate(point)
    for digit in reversed(naf):
        result = _point_double(result)
        if digit == 1:
            result = _point_add(result, point)
        elif digit == -1:
            result = _point_add(result, negative_point)
    return result


def _scalar_mult(point: tuple[int, int, int, int], scalar: int) -> tuple[int, int, int, int]:
    return _scalar_mult_naf(point, scalar)


def _point_equal(
    first: tuple[int, int, int, int], second: tuple[int, int, int, int]
) -> bool:
    x1, y1, z1, _t1 = first
    x2, y2, z2, _t2 = second
    return (x1 * z2 - x2 * z1) % P == 0 and (y1 * z2 - y2 * z1) % P == 0


def _is_small_order(point: tuple[int, int, int, int]) -> bool:
    """Whether ``[8]P == identity`` (the eight-point torsion subgroup)."""
    doubled = _point_double(_point_double(_point_double(point)))
    return _point_equal(doubled, IDENTITY)


def _is_prime_order(point: tuple[int, int, int, int]) -> bool:
    """Whether ``[L]P == identity`` (P is in the prime-order subgroup)."""
    return _point_equal(_scalar_mult(point, L), IDENTITY)


def _classify_public_key(
    public_key: bytes,
) -> tuple[str | None, tuple[int, int, int, int] | None, str | None]:
    """Decode and classify A once, caching the result.

    Returns ``(error_code, point, order_class)`` where ``order_class`` is
    ``"small"``, ``"mixed"`` or ``"prime"`` (only when no error).
    """
    cached = _PUBLIC_KEY_CACHE.get(public_key)
    if cached is not None:
        return cached
    try:
        point = _decode_point(public_key, "E_SIG_NONCANONICAL_A")
    except WeaveError as error:
        result = (error.code, None, None)
    else:
        if _is_small_order(point):
            result = (None, point, "small")
        elif _is_prime_order(point):
            result = (None, point, "prime")
        else:
            result = (None, point, "mixed")
    if len(_PUBLIC_KEY_CACHE) >= _CACHE_LIMIT:
        _PUBLIC_KEY_CACHE.clear()
    _PUBLIC_KEY_CACHE[public_key] = result
    return result


def is_small_order(encoding: bytes) -> bool:
    """Whether ``encoding`` decodes to a small-order point (``[8]P == identity``)."""
    try:
        return _is_small_order(_decode_point(encoding, "E_SIG_NONCANONICAL_A"))
    except WeaveError:
        return False


def is_canonical_point_encoding(encoding: bytes) -> bool:
    """Whether ``encoding`` is a canonical decoding of a curve point."""
    try:
        _decode_point(encoding, "E_KEY_PUBLIC_KEY")
    except WeaveError:
        return False
    return True


def verify_signature(public_key: bytes, message: bytes, signature: bytes) -> None:
    """Verify a PureEdDSA Ed25519 signature under the strict profile."""
    if not isinstance(public_key, (bytes, bytearray)):
        raise WeaveError("E_SIG_NONCANONICAL_A", "public key must be bytes")
    if not isinstance(signature, (bytes, bytearray)):
        raise WeaveError("E_ENV_SIG_VALUE", "signature must be bytes")
    if not isinstance(message, (bytes, bytearray)):
        raise WeaveError("E_SIG_INVALID", "message must be bytes")
    public_key = bytes(public_key)
    signature = bytes(signature)
    message = bytes(message)

    # Step 1: length checks.
    if len(public_key) != 32:
        raise WeaveError("E_SIG_NONCANONICAL_A", "public key must be 32 bytes")
    if len(signature) != 64:
        raise WeaveError("E_ENV_SIG_VALUE", "signature must be exactly 64 bytes")

    # Step 2: S < L.
    s = int.from_bytes(signature[32:], "little")
    if s >= L:
        raise WeaveError("E_SIG_S_OUT_OF_RANGE", "S is not canonical (S >= L)")

    # Steps 3-5: decode A, reject small-order A, reject mixed-order A.
    error_code, a_point, order_class = _classify_public_key(public_key)
    if error_code is not None:
        raise WeaveError(error_code, "public key is not a canonical curve point")
    if order_class == "small":
        raise WeaveError("E_SIG_SMALL_ORDER_A", "public key is a small-order point")
    if order_class == "mixed":
        raise WeaveError(
            "E_SIG_MIXED_ORDER_A", "public key is not in the prime-order subgroup"
        )

    # Steps 6-7: decode R and reject small-order R.
    r_encoding = signature[:32]
    r_point = _decode_point(r_encoding, "E_SIG_NONCANONICAL_R")
    if _is_small_order(r_point):
        raise WeaveError("E_SIG_SMALL_ORDER_R", "R is a small-order point")

    # Step 8: cofactorless equation, delegated to the library after the pre-checks.
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
    except Exception as error:
        raise WeaveError(
            "E_SIG_INVALID", "Ed25519 verification equation does not hold"
        ) from error


def verify_equation_python(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Independent pure-Python check of the equation (tests/tooling only).

    Unlike :func:`verify_signature` this does **not** reject mixed-order public
    keys: it tests the cofactorless equation itself, which is useful for
    constructing and cross-checking boundary vectors. It does reject
    non-canonical encodings and small-order A/R.
    """
    if len(public_key) != 32 or len(signature) != 64:
        return False
    try:
        a_point = _decode_point(public_key, "E_SIG_NONCANONICAL_A")
        r_point = _decode_point(signature[:32], "E_SIG_NONCANONICAL_R")
    except WeaveError:
        return False
    if _is_small_order(a_point) or _is_small_order(r_point):
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= L:
        return False
    k = int.from_bytes(
        hashlib.sha512(signature[:32] + public_key + message).digest(), "little"
    ) % L
    left = _scalar_mult(_base_point(), s)
    right = _point_add(r_point, _scalar_mult(a_point, k))
    return _point_equal(left, right)


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Return ``True`` iff the strict profile accepts the signature."""
    try:
        verify_signature(public_key, message, signature)
    except WeaveError:
        return False
    return True
