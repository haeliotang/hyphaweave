#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0

"""Independent, deterministic Edwards25519 crafting helpers for H0 revision 1.

This module is part of the *independent* tooling used to author test vectors.
It never imports the reference verifier (``hyphaweave_verify``): the curve
arithmetic, RFC 8032 point decoding and the verification order decided in
`spec/weave-record-1.md` §3.4 are implemented here in plain Python with ``hashlib``
only.  It is intentionally redundant with the verifier so that crafted edge
cases are not derived from the implementation under test.

Verification order implemented by :func:`verify_structural` (spec §3.4, decided):

1. ``len(signature) != 64`` -> ``E_ENV_SIG_VALUE``;
   ``len(public_key) != 32`` -> ``E_SIG_NONCANONICAL_A``.
2. ``S >= L`` -> ``E_SIG_S_OUT_OF_RANGE``.
3. A decode (RFC 8032 §5.1.3: length, ``y < p``, on curve, and the
   ``x == 0 and sign bit == 1`` failure) -> ``E_SIG_NONCANONICAL_A``.
4. ``[8]A == identity`` -> ``E_SIG_SMALL_ORDER_A``.
5. ``[L]A != identity`` (mixed order, new in revision 1) -> ``E_SIG_MIXED_ORDER_A``.
6. R decode (same steps) -> ``E_SIG_NONCANONICAL_R``.
7. ``[8]R == identity`` -> ``E_SIG_SMALL_ORDER_R``.
8. Cofactorless equation ``[S]B == R + [k]A`` else -> ``E_SIG_INVALID``.

``checks=`` keyword overrides on :func:`verify_structural` omit individual
steps; that is how :func:`selftest` proves "removing exactly this check would
accept the crafted signature", which is the independence evidence for the
gate-3 source-ablation mutations.

Crafted-signature helpers for the revision-1 vectors (all deterministic):

* :func:`identity_forgery` -- ``R = [r]B, S = r`` for an A that lenient
  decoders see as the identity (also the ``x = 0`` sign-bit-forgery shape).
* :func:`small_order_signature` -- small-order A; grind ``r`` until
  ``k = H(R || A || M) mod L`` satisfies ``k % 8 == 0`` so ``[k]A`` is the
  identity and the equation ``[S]B == R + [k]A`` holds.  Valid only when the
  small-order (and mixed-order) checks are removed.
* :func:`mixed_order_key_and_signature` -- mixed-order A = ``[a]B + T``
  (T a torsion point) and a cofactorless-valid signature obtained by grinding
  ``r`` with ``k % 8 == 0``, so dropping the mixed-order check yields valid.
* :func:`x0_sign_bit_r_signature` -- ``R`` is the ``x = 0, sign = 1`` identity
  encoding; the equation holds for decoders that omit the RFC 8032 step-4 rule.
* :func:`identity_r_signature`, :func:`small_order_r_signature` -- small-order R.
* :func:`noncanonical_a_forgery`, :func:`noncanonical_r_signature` -- encodings
  with ``y >= p``.
* :func:`s_out_of_range_signature` -- ``S = L`` / ``S = L + 1``.

Run ``python tools/edcraft.py --selftest`` for the self-proof (RFC 8032 test
vectors, group/torsion checks, every crafted shape accepted with exactly its
target check omitted and rejected by the full profile, determinism).
"""

from __future__ import annotations

import hashlib
import json
import sys

__all__ = [
    "BASE",
    "D",
    "EXPECTED_SMALL_ORDER_ENCODINGS",
    "L",
    "P",
    "DecodeError",
    "challenge",
    "decode_point",
    "decode_point_lenient",
    "ed25519_key_id",
    "encode_point",
    "identity",
    "identity_encoding",
    "identity_forgery",
    "identity_r_signature",
    "is_prime_order",
    "is_small_order",
    "mixed_order_key_and_signature",
    "mixed_order_public",
    "noncanonical_a_forgery",
    "noncanonical_encoding",
    "noncanonical_r_signature",
    "order2_encoding",
    "point_add",
    "point_equal",
    "point_mul",
    "point_neg",
    "private_scalar",
    "public_from_seed",
    "s_l",
    "s_l_plus_one",
    "selftest",
    "sign_seed",
    "signature_with_r_encoding",
    "small_order_r_signature",
    "small_order_signature",
    "torsion_encodings",
    "torsion_points",
    "verify_equation_only",
    "verify_structural",
    "x0_sign_one_identity_encoding",
    "x0_sign_one_order2_encoding",
    "x0_sign_bit_a_forgery",
    "x0_sign_bit_r_signature",
]

# ---------------------------------------------------------------------------
# Curve constants (RFC 8032 §5.1)
# ---------------------------------------------------------------------------

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)

# The eight canonical small-order point encodings (spec §3.3).
# Used only as a self-check oracle; the set itself is derived from the curve.
EXPECTED_SMALL_ORDER_ENCODINGS = [
    bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000"),
    bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000080"),
    bytes.fromhex("0100000000000000000000000000000000000000000000000000000000000000"),
    bytes.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),
    bytes.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85"),
    bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
    bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"),
    bytes.fromhex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
]

# One generator of the order-8 torsion subgroup (canonical encoding above).
_TORSION_GENERATOR_ENCODING = bytes.fromhex(
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"
)

_IDENTITY = (0, 1, 1, 0)  # extended coordinates (X, Y, Z, T), x = X/Z, y = Y/Z


class DecodeError(ValueError):
    """RFC 8032 point decoding failure with a machine-readable reason.

    ``reason`` is one of ``length``, ``y_ge_p``, ``not_on_curve`` or
    ``x0_sign``; callers map it to the role-specific error code.
    """

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


# ---------------------------------------------------------------------------
# Point arithmetic (extended coordinates, RFC 8032 §5.1.4)
# ---------------------------------------------------------------------------


def _add(first: tuple[int, int, int, int], second: tuple[int, int, int, int]):
    x1, y1, z1, t1 = first
    x2, y2, z2, t2 = second
    a = (y1 - x1) * (y2 - x2) % P
    b = (y1 + x1) * (y2 + x2) % P
    c = 2 * D * t1 * t2 % P
    dd = 2 * z1 * z2 % P
    e = b - a
    f = dd - c
    g = dd + c
    h = b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _double(point: tuple[int, int, int, int]):
    x1, y1, z1, _ = point
    a = x1 * x1 % P
    b = y1 * y1 % P
    c = 2 * z1 * z1 % P
    dd = -a % P
    e = ((x1 + y1) * (x1 + y1) - a - b) % P
    g = dd + b
    f = g - c
    h = dd - b
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def point_add(first, second):
    """Add two points (extended coordinate tuples)."""
    return _add(first, second)


def point_neg(point):
    """Negate a point."""
    x, y, z, t = point
    return ((-x) % P, y, (-t) % P, z)


def point_mul(scalar: int, point):
    """Scalar multiplication ``[scalar]point`` (double-and-add)."""
    if scalar < 0:
        return point_mul(-scalar, point_neg(point))
    result = _IDENTITY
    addend = point
    while scalar:
        if scalar & 1:
            result = _add(result, addend)
        addend = _double(addend)
        scalar >>= 1
    return result


def point_equal(first, second) -> bool:
    """Projective equality of two extended points."""
    x1, y1, z1, _ = first
    x2, y2, z2, _ = second
    return (
        (x1 * z2 - x2 * z1) % P == 0
        and (y1 * z2 - y2 * z1) % P == 0
        and (z1 * z2) % P != 0
        or (z1 == 0 and z2 == 0)
    ) and (x1 * z2 - x2 * z1) % P == 0 and (y1 * z2 - y2 * z1) % P == 0


def identity():
    """The neutral element."""
    return _IDENTITY


def _affine(point) -> tuple[int, int]:
    x, y, z, _ = point
    if z == 0:
        raise ValueError("point at infinity has no affine form")
    inverse = pow(z, P - 2, P)
    return (x * inverse % P, y * inverse % P)


def _encode_affine(x: int, y: int) -> bytes:
    value = y | ((x & 1) << 255)
    return value.to_bytes(32, "little")


def encode_point(point) -> bytes:
    """Canonical RFC 8032 encoding of *point* (``y`` little-endian, sign bit)."""
    return _encode_affine(*_affine(point))


def _decode_affine(
    encoding: bytes,
    *,
    reject_y_ge_p: bool = True,
    reject_x0_sign: bool = True,
) -> tuple[int, int]:
    if len(encoding) != 32:
        raise DecodeError("length")
    value = int.from_bytes(encoding, "little")
    sign_bit = value >> 255
    y = value & ((1 << 255) - 1)
    if y >= P:
        if reject_y_ge_p:
            raise DecodeError("y_ge_p")
        y %= P
    # x^2 = (y^2 - 1) / (d y^2 + 1); p = 5 (mod 8), so the square root is
    # computed with the (p+3)/8 exponent plus one multiplication by sqrt(-1).
    numerator = (y * y - 1) % P
    denominator = (D * y * y + 1) % P
    ratio = numerator * pow(denominator, P - 2, P) % P
    x = pow(ratio, (P + 3) // 8, P)
    if (x * x - ratio) % P != 0:
        x = x * SQRT_M1 % P
    if (x * x - ratio) % P != 0:
        raise DecodeError("not_on_curve")
    if x == 0 and sign_bit == 1:
        if reject_x0_sign:
            raise DecodeError("x0_sign")
        # Lenient reading for ablation demos: ignore the sign bit when x == 0.
        return (0, y)
    if (x & 1) != sign_bit:
        x = P - x
    return (x, y)


def decode_point(encoding: bytes):
    """Strict RFC 8032 §5.1.3 decoding; raises :class:`DecodeError`."""
    x, y = _decode_affine(encoding)
    return (x, y, 1, x * y % P)


def decode_point_lenient(
    encoding: bytes,
    *,
    reject_y_ge_p: bool = True,
    reject_x0_sign: bool = False,
):
    """Decoding with individual RFC 8032 rules optionally disabled.

    Only used to demonstrate what a verifier that omits one check would do.
    """
    x, y = _decode_affine(
        encoding, reject_y_ge_p=reject_y_ge_p, reject_x0_sign=reject_x0_sign
    )
    return (x, y, 1, x * y % P)


def _is_identity(point) -> bool:
    return point_equal(point, _IDENTITY)


def is_small_order(point) -> bool:
    """``[8]P == identity`` (spec §3.4 steps 4/7; a *point* test, not a list)."""
    return _is_identity(point_mul(8, point))


def is_prime_order(point) -> bool:
    """True iff the point is in the prime-order subgroup (``[L]P == identity``)."""
    return _is_identity(point_mul(L, point))


# Base point B: y = 4/5, x even (sign bit 0), per RFC 8032 §5.1.
_BASE_Y = 4 * pow(5, P - 2, P) % P
_BASE_X, _BASE_Y = _decode_affine(_encode_affine(0, _BASE_Y))
BASE = (_BASE_X, _BASE_Y, 1, _BASE_X * _BASE_Y % P)


# ---------------------------------------------------------------------------
# Torsion subgroup (all eight points, derived from the curve)
# ---------------------------------------------------------------------------


def _derive_torsion() -> list[tuple[int, int, int, int]]:
    generator = decode_point(_TORSION_GENERATOR_ENCODING)
    if not is_small_order(generator):
        raise AssertionError("torsion generator encoding is not small order")
    if _is_identity(point_mul(4, generator)):
        raise AssertionError("torsion generator does not have order 8")
    points = [point_mul(index, generator) for index in range(8)]
    points.sort(key=encode_point)
    return points


_TORSION_POINTS = _derive_torsion()
_TORSION_GENERATOR = _TORSION_POINTS[0]
# Re-derive a generator of order 8 from the sorted list (position independent).
for _candidate in _TORSION_POINTS:
    if not _is_identity(point_mul(4, _candidate)):
        _TORSION_GENERATOR = _candidate
        break


def torsion_points() -> list[tuple[int, int, int, int]]:
    """All eight points with ``[8]P == identity``, sorted by encoding."""
    return list(_TORSION_POINTS)


def torsion_encodings() -> list[bytes]:
    """The eight canonical small-order encodings, lexicographically sorted."""
    return [encode_point(point) for point in _TORSION_POINTS]


def identity_encoding() -> bytes:
    return encode_point(_IDENTITY)


def order2_encoding() -> bytes:
    """Canonical encoding of the unique order-2 point ``(0, -1)``."""
    return encode_point((0, P - 1, 1, 0))


def x0_sign_one_identity_encoding() -> bytes:
    """``y = 1`` with sign bit 1: the identity would be ``01..00``; RFC 8032
    decoding must fail because ``x == 0`` and the sign bit is 1."""
    return bytes([0x01] + [0x00] * 30 + [0x80])


def x0_sign_one_order2_encoding() -> bytes:
    """``y = p - 1`` with sign bit 1: also ``x == 0`` and sign bit 1."""
    value = (P - 1) | (1 << 255)
    return value.to_bytes(32, "little")


def noncanonical_encoding(index: int = 0, sign_bit: int = 0) -> bytes:
    """A 32-byte encoding with ``y = p + index`` (``y >= p``), 0 <= index <= 18."""
    if not 0 <= index <= 18:
        raise ValueError("only y in [p, 2^255-1] is expressible in 32 bytes")
    if sign_bit not in (0, 1):
        raise ValueError("sign_bit must be 0 or 1")
    value = (P + index) | (sign_bit << 255)
    if value >= (1 << 255):
        raise ValueError("encoding exceeds 32 bytes after sign bit")
    return value.to_bytes(32, "little")


# ---------------------------------------------------------------------------
# Keys, scalars and plain RFC 8032 signing
# ---------------------------------------------------------------------------


def private_scalar(seed: bytes) -> int:
    """RFC 8032 private scalar derived from a 32-byte seed."""
    if len(seed) != 32:
        raise ValueError("Ed25519 seed must be 32 bytes")
    digest = hashlib.sha512(seed).digest()
    scalar = int.from_bytes(digest[:32], "little")
    scalar &= (1 << 254) - 8
    scalar |= 1 << 254
    return scalar


def public_from_seed(seed: bytes) -> bytes:
    """32-byte public key for *seed*."""
    return encode_point(point_mul(private_scalar(seed), BASE))


def ed25519_key_id(public: bytes) -> str:
    """``ed25519:<first 32 lowercase hex of sha256(raw public key)>``.

    Included for independent recomputation; vector generators should normally
    use :mod:`tools.keyutil` for key ids.
    """
    if len(public) != 32:
        raise ValueError("Ed25519 public key must be 32 bytes")
    return "ed25519:" + hashlib.sha256(public).hexdigest()[:32]


def challenge(r_encoding: bytes, a_encoding: bytes, message: bytes) -> int:
    """``k = SHA-512(R || A || M) mod L`` over the raw supplied encodings."""
    digest = hashlib.sha512(r_encoding + a_encoding + message).digest()
    return int.from_bytes(digest, "little") % L


def sign_seed(seed: bytes, message: bytes) -> tuple[bytes, bytes]:
    """Plain RFC 8032 Ed25519 sign (pure Python); returns (public, signature)."""
    digest = hashlib.sha512(seed).digest()
    scalar = int.from_bytes(digest[:32], "little")
    scalar &= (1 << 254) - 8
    scalar |= 1 << 254
    prefix = digest[32:]
    public = encode_point(point_mul(scalar, BASE))
    nonce = int.from_bytes(hashlib.sha512(prefix + message).digest(), "little") % L
    r_encoding = encode_point(point_mul(nonce, BASE))
    k = challenge(r_encoding, public, message)
    s = (nonce + k * scalar) % L
    return public, r_encoding + s.to_bytes(32, "little")


def s_l() -> bytes:
    """The 32-byte little-endian encoding of ``S = L``."""
    return L.to_bytes(32, "little")


def s_l_plus_one() -> bytes:
    """The 32-byte little-endian encoding of ``S = L + 1``."""
    return (L + 1).to_bytes(32, "little")


# ---------------------------------------------------------------------------
# Crafted signatures
# ---------------------------------------------------------------------------


def identity_forgery(a_encoding: bytes, message: bytes, *, r: int = 1) -> bytes:
    """Signature ``(R = [r]B, S = r)`` for an A seen as the identity.

    Works for the canonical identity encoding ``01..00`` and for the ``x = 0``
    sign-bit encoding ``01..80`` (decoders that omit the RFC 8032 step-4 rule
    read it as the identity).  The equation holds for *any* message because
    ``[k]A`` vanishes.  The full revision-1 profile rejects the key first
    (``E_SIG_SMALL_ORDER_A`` or ``E_SIG_NONCANONICAL_A``).
    """
    if r <= 0:
        raise ValueError("r must be positive")
    point = decode_point_lenient(a_encoding, reject_x0_sign=False)
    if not _is_identity(point):
        raise ValueError(
            "identity_forgery needs A that lenient decoders read as the identity; "
            "use small_order_signature() for other small-order points"
        )
    del message  # the equation holds independently of k for identity A
    r_encoding = encode_point(point_mul(r, BASE))
    return r_encoding + r.to_bytes(32, "little")


def x0_sign_bit_a_forgery(message: bytes, *, r: int = 1) -> bytes:
    """Identity forgery against the ``x = 0, sign = 1`` public-key encoding."""
    return identity_forgery(x0_sign_one_identity_encoding(), message, r=r)


def small_order_signature(
    point_encoding: bytes, message: bytes, *, max_tries: int = 4096
) -> bytes:
    """Signature valid for a small-order A iff the small-order check is removed.

    ``R = [r]B, S = r`` with ``r`` ground so that ``k = H(R || A || M) mod L``
    is a multiple of 8; then ``[k]A == identity`` for every point whose order
    divides 8, and the cofactorless equation holds.  The full profile rejects
    the key with ``E_SIG_SMALL_ORDER_A`` before the equation is reached.
    """
    a_point = decode_point(point_encoding)
    if not is_small_order(a_point):
        raise ValueError("small_order_signature needs a small-order point encoding")
    for r in range(1, max_tries + 1):
        r_encoding = encode_point(point_mul(r, BASE))
        k = challenge(r_encoding, point_encoding, message)
        if k % 8 == 0:
            return r_encoding + r.to_bytes(32, "little")
    raise RuntimeError("failed to grind k %% 8 == 0 within %d tries" % max_tries)


def _seed_scalar(seed: bytes) -> int:
    return private_scalar(seed)


def x0_sign_bit_r_signature(seed: bytes, message: bytes) -> bytes:
    """Signature whose R is ``01..80`` and whose equation holds for decoders
    that omit the RFC 8032 ``x == 0, sign = 1`` rule.

    Naive reading: R = identity, so the equation reduces to
    ``[S]B == [k]A``; with ``A = [a]B`` choose ``S = k * a mod L``.
    Full profile: ``E_SIG_NONCANONICAL_R`` (step 6).
    """
    public = public_from_seed(seed)
    scalar = _seed_scalar(seed)
    r_encoding = x0_sign_one_identity_encoding()
    k = challenge(r_encoding, public, message)
    s = k * scalar % L
    return r_encoding + s.to_bytes(32, "little")


def signature_with_r_encoding(
    seed: bytes, message: bytes, r_encoding: bytes, *, s: int | None = None
) -> bytes:
    """Build a signature with an arbitrary supplied R encoding.

    ``A`` is the public key of *seed*; ``S = s`` when given, otherwise
    ``S = k * a mod L`` (the value that makes the equation hold if the reader
    decodes R as the identity).  This is the generic shape used for all 8
    small-order-R encodings.
    """
    if len(r_encoding) != 32:
        raise ValueError("R encoding must be 32 bytes")
    public = public_from_seed(seed)
    if s is None:
        s = challenge(r_encoding, public, message) * _seed_scalar(seed) % L
    if not 0 <= s < L:
        raise ValueError("S must be in [0, L)")
    return r_encoding + s.to_bytes(32, "little")


def identity_r_signature(seed: bytes, message: bytes) -> bytes:
    """Signature with R = canonical identity; valid iff the R small-order check
    is removed (T = identity has order 1, so the equation holds)."""
    return signature_with_r_encoding(seed, message, identity_encoding())


def small_order_r_signature(seed: bytes, message: bytes, r_encoding: bytes) -> bytes:
    """Signature with a supplied small-order R encoding.

    For the identity encoding the equation also holds, so removing the R
    small-order check yields ``valid``; for the other torsion encodings the
    equation does not hold (no solution exists with a prime-order A) and the
    full profile rejects with ``E_SIG_SMALL_ORDER_R``.
    """
    point = decode_point(r_encoding)
    if not is_small_order(point):
        raise ValueError("small_order_r_signature needs a small-order R encoding")
    return signature_with_r_encoding(seed, message, r_encoding)


def noncanonical_a_forgery(*, index: int = 0, sign_bit: int = 0) -> bytes:
    """A 64-byte signature shaped for a declaration whose ``public_key`` has
    ``y >= p``.  The A decode step rejects before any equation work, so the
    bytes can be arbitrary; zeros are deterministic and keep the case minimal.
    Callers must place :func:`noncanonical_encoding` bytes in ``body.public_key``.
    """
    del index, sign_bit
    return bytes(64)


def noncanonical_r_signature(
    seed: bytes, message: bytes, *, index: int = 0, sign_bit: int = 0
) -> bytes:
    """Signature whose R has ``y >= p``; there is no valid point encoding, so
    the R bytes are supplied verbatim and S is the naive-equation value."""
    return signature_with_r_encoding(
        seed, message, noncanonical_encoding(index=index, sign_bit=sign_bit)
    )


def s_out_of_range_signature(
    seed: bytes, message: bytes, *, value: int | None = None
) -> bytes:
    """A structurally valid signature whose S is out of range (default ``S = L``).

    Uses a real key/signature so that only the S range check can reject it;
    the full profile reports ``E_SIG_S_OUT_OF_RANGE`` at step 2.
    """
    s_value = L if value is None else value
    public, signature = sign_seed(seed, message)
    del public
    if not 0 <= s_value < (1 << 256):
        raise ValueError("S must fit in 32 bytes")
    return signature[:32] + s_value.to_bytes(32, "little")


def mixed_order_public(seed: bytes, *, torsion_index: int = 1) -> bytes:
    """Mixed-order public key ``A = [a]B + T`` for ``a = private_scalar(seed)``.

    ``T`` is a torsion point of order 8 (default: the first non-identity
    torsion point).  ``[8]A != identity`` and ``[L]A != identity``, so the
    revision-1 mixed-order check rejects it; a cofactorless-valid signature can
    still be crafted because ``k = 0 (mod 8)`` kills the torsion component.
    """
    torsion = torsion_points()[torsion_index % 8]
    point = point_add(point_mul(private_scalar(seed), BASE), torsion)
    return encode_point(point)


def mixed_order_key_and_signature(
    seed: bytes, message: bytes, *, torsion_index: int = 1, max_tries: int = 4096
) -> tuple[bytes, bytes]:
    """Return ``(A_encoding, signature)`` for the mixed-order-A vector.

    ``A = [a]B + T`` is mixed order.  Grind ``r`` until
    ``k = H([r]B || A || M) mod L`` satisfies ``k % 8 == 0``; then
    ``[k]A = [k*a]B`` and ``S = (r + k*a) mod L`` makes the cofactorless
    equation hold.  Removing only the mixed-order check therefore yields a
    ``valid`` record; the full profile reports ``E_SIG_MIXED_ORDER_A``.
    """
    torsion = torsion_points()[torsion_index % 8]
    scale = private_scalar(seed)
    mixed = point_add(point_mul(scale, BASE), torsion)
    a_encoding = encode_point(mixed)
    # Sanity: mixed order, not small order.
    if is_small_order(mixed) or is_prime_order(mixed):
        raise AssertionError("constructed key is not mixed order")
    for r in range(1, max_tries + 1):
        r_encoding = encode_point(point_mul(r, BASE))
        k = challenge(r_encoding, a_encoding, message)
        if k % 8 == 0:
            s = (r + k * scale) % L
            return a_encoding, r_encoding + s.to_bytes(32, "little")
    raise RuntimeError("failed to grind mixed-order k %% 8 == 0")


# ---------------------------------------------------------------------------
# Independent reference verification with per-check ablation
# ---------------------------------------------------------------------------

_CHECKS = {
    "sig_length": True,  # len(sig) == 64 -> E_ENV_SIG_VALUE
    "s_range": True,  # S < L -> E_SIG_S_OUT_OF_RANGE
    "a_length": True,  # len(public) == 32 -> E_SIG_NONCANONICAL_A
    "a_y_ge_p": True,  # y < p
    "a_x0_sign": True,  # x == 0 and sign bit 1
    "a_small_order": True,  # [8]A == identity
    "a_mixed_order": True,  # [L]A != identity
    "r_y_ge_p": True,
    "r_x0_sign": True,
    "r_small_order": True,
    "equation": True,
}


def verify_structural(
    public: bytes, message: bytes, signature: bytes, *, checks: dict | None = None
) -> str | None:
    """Reference verification in the spec §3.4 order; returns error code or None.

    ``checks`` overrides individual rules (True = keep the check); omitting a
    check models a verifier with that rule removed and is used only to prove
    what the crafted vectors would accept (gate-3 ablation evidence).
    """
    active = dict(_CHECKS)
    if checks:
        unknown = set(checks) - set(active)
        if unknown:
            raise KeyError("unknown check name(s): %s" % sorted(unknown))
        active.update(checks)

    if active["sig_length"] and len(signature) != 64:
        return "E_ENV_SIG_VALUE"
    if active["a_length"] and len(public) != 32:
        return "E_SIG_NONCANONICAL_A"
    if len(signature) != 64:
        return "E_ENV_SIG_VALUE"
    s = int.from_bytes(signature[32:], "little")
    r_encoding = signature[:32]
    if active["s_range"] and s >= L:
        return "E_SIG_S_OUT_OF_RANGE"

    try:
        a_point = decode_point_lenient(
            public,
            reject_y_ge_p=active["a_y_ge_p"],
            reject_x0_sign=active["a_x0_sign"],
        )
    except DecodeError:
        return "E_SIG_NONCANONICAL_A"
    if len(public) != 32:
        return "E_SIG_NONCANONICAL_A"
    if active["a_small_order"] and is_small_order(a_point):
        return "E_SIG_SMALL_ORDER_A"
    if active["a_mixed_order"] and not is_prime_order(a_point):
        return "E_SIG_MIXED_ORDER_A"

    try:
        r_point = decode_point_lenient(
            r_encoding,
            reject_y_ge_p=active["r_y_ge_p"],
            reject_x0_sign=active["r_x0_sign"],
        )
    except DecodeError:
        return "E_SIG_NONCANONICAL_R"
    if active["r_small_order"] and is_small_order(r_point):
        return "E_SIG_SMALL_ORDER_R"

    if active["equation"]:
        k = challenge(r_encoding, public, message)
        left = point_mul(s, BASE)
        right = point_add(r_point, point_mul(k, a_point))
        if not point_equal(left, right):
            return "E_SIG_INVALID"
    return None


def verify_equation_only(public: bytes, message: bytes, signature: bytes) -> bool:
    """Raw cofactorless equation check, with no RFC 8032 pre-checks at all.

    This is the "naive decoder" oracle: it proves a crafted signature would be
    accepted by an implementation that only evaluates the equation.
    """
    if len(public) != 32 or len(signature) != 64:
        return False
    try:
        a_point = decode_point_lenient(public)
        r_point = decode_point_lenient(signature[:32])
    except DecodeError:
        return False
    s = int.from_bytes(signature[32:], "little")
    k = challenge(signature[:32], public, message)
    return point_equal(
        point_mul(s, BASE), point_add(r_point, point_mul(k, a_point))
    )


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

# RFC 8032 §7.1 test vectors (TEST 1 and TEST 2).
_RFC8032_TESTS = [
    (
        "test1",
        bytes.fromhex(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
        ),
        bytes.fromhex(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        ),
        b"",
        bytes.fromhex(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555f"
            "b8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        ),
    ),
    (
        "test2",
        bytes.fromhex(
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
        ),
        bytes.fromhex(
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
        ),
        bytes.fromhex("72"),
        bytes.fromhex(
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
            "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
        ),
    ),
]


def _expect(condition: bool, label: str, failures: list[str]) -> None:
    if not condition:
        failures.append(label)


def selftest() -> dict:
    """Run the module self-proof; returns a deterministic JSON-able report."""
    failures: list[str] = []
    crafted: dict[str, str] = {}
    report: dict = {"ok": False, "checks": {}, "failures": failures}

    # --- RFC 8032 known-answer tests (arithmetic + encoding + challenge) ---
    for name, seed, public, message, signature in _RFC8032_TESTS:
        derived_public, derived_signature = sign_seed(seed, message)
        code = verify_structural(derived_public, message, derived_signature)
        ok = (
            derived_public == public
            and derived_signature == signature
            and code is None
        )
        report["checks"]["rfc8032_" + name] = ok
        _expect(ok, "rfc8032_" + name, failures)

    # --- Group / torsion sanity ---
    # Twisted Edwards equation: -x^2 + y^2 = 1 + d x^2 y^2.
    report["checks"]["base_on_curve"] = (
        (_BASE_Y * _BASE_Y - _BASE_X * _BASE_X - 1
         - D * _BASE_X * _BASE_X * _BASE_Y * _BASE_Y)
        % P
        == 0
    )
    _expect(report["checks"]["base_on_curve"], "base_on_curve", failures)
    report["checks"]["base_encoding"] = encode_point(BASE) == bytes.fromhex(
        "5866666666666666666666666666666666666666666666666666666666666666"
    )
    _expect(report["checks"]["base_encoding"], "base_encoding", failures)
    report["checks"]["L_base_identity"] = _is_identity(point_mul(L, BASE))
    _expect(report["checks"]["L_base_identity"], "L_base_identity", failures)
    encodings = [encode_point(point) for point in torsion_points()]
    report["checks"]["torsion_count"] = len(encodings) == 8
    _expect(report["checks"]["torsion_count"], "torsion_count", failures)
    report["checks"]["torsion_encodings"] = encodings == EXPECTED_SMALL_ORDER_ENCODINGS
    _expect(report["checks"]["torsion_encodings"], "torsion_encodings", failures)
    report["checks"]["torsion_small_order"] = all(
        is_small_order(point) for point in torsion_points()
    )
    _expect(report["checks"]["torsion_small_order"], "torsion_small_order", failures)
    report["checks"]["torsion_generator_order8"] = (
        not _is_identity(point_mul(4, _TORSION_GENERATOR))
        and _is_identity(point_mul(8, _TORSION_GENERATOR))
    )
    _expect(
        report["checks"]["torsion_generator_order8"],
        "torsion_generator_order8",
        failures,
    )

    # --- RFC 8032 decoding failures (incl. x = 0 sign rule) ---
    decode_reasons = {}
    for label, encoding in [
        ("y_ge_p", noncanonical_encoding()),
        ("x0_identity", x0_sign_one_identity_encoding()),
        ("x0_order2", x0_sign_one_order2_encoding()),
        ("all_ones", b"\xff" * 32),
    ]:
        try:
            decode_point(encoding)
            reason = None
        except DecodeError as error:
            reason = error.reason
        decode_reasons[label] = reason
    report["checks"]["decode_rejections"] = (
        decode_reasons["y_ge_p"] == "y_ge_p"
        and decode_reasons["x0_identity"] == "x0_sign"
        and decode_reasons["x0_order2"] == "x0_sign"
        and decode_reasons["all_ones"] == "y_ge_p"
    )
    _expect(
        report["checks"]["decode_rejections"], "decode_rejections", failures
    )
    # A deterministic y with no x is rejected as not_on_curve.
    off_curve = None
    for y in range(2, 64):
        try:
            _decode_affine(y.to_bytes(32, "little"))
        except DecodeError:
            off_curve = y
            break
    report["checks"]["decode_off_curve"] = off_curve is not None
    _expect(report["checks"]["decode_off_curve"], "decode_off_curve", failures)

    seed = hashlib.sha256(b"edcraft/selftest/seed").digest()
    message = b"weave-record/1/sig\nsha256:" + b"00" * 32
    other_message = b"weave-record/1/sig\nsha256:" + b"11" * 32
    public = public_from_seed(seed)

    def record(name: str, signature: bytes, expected: str, ablation: dict,
               *, public_override: bytes | None = None,
               expect_ablation: str | None = None,
               use_other_message: bool = False) -> None:
        chosen_message = other_message if use_other_message else message
        chosen_public = public if public_override is None else public_override
        full = verify_structural(chosen_public, chosen_message, signature)
        crafted[name + ":full"] = str(full)
        _expect(full == expected, name + " full profile %r != %r" % (full, expected), failures)
        ablated = verify_structural(
            chosen_public, chosen_message, signature, checks=ablation
        )
        crafted[name + ":ablated"] = str(ablated)
        wanted = expect_ablation
        _expect(
            ablated == wanted,
            name + " ablation %r != %r" % (ablated, wanted),
            failures,
        )

    # Identity forgery (canonical identity A): removing the small-order check
    # (identity is not mixed order: [L]I == I) accepts for any message.
    record(
        "identity_forgery",
        identity_forgery(identity_encoding(), message),
        "E_SIG_SMALL_ORDER_A",
        {"a_small_order": False},
        public_override=identity_encoding(),
        use_other_message=True,
    )

    # x = 0 sign-bit A: lenient decoders see the identity.  The full profile
    # rejects at decode; without the x=0 rule the point-based small-order check
    # still fires, and only with both rules removed is the forgery accepted.
    x0_sig = identity_forgery(x0_sign_one_identity_encoding(), message)
    record(
        "x0_sign_bit_a",
        x0_sig,
        "E_SIG_NONCANONICAL_A",
        {"a_x0_sign": False},
        public_override=x0_sign_one_identity_encoding(),
        expect_ablation="E_SIG_SMALL_ORDER_A",
    )
    crafted["x0_sign_bit_a:naive_accepts"] = str(
        verify_structural(
            x0_sign_one_identity_encoding(),
            message,
            x0_sig,
            checks={"a_x0_sign": False, "a_small_order": False, "a_mixed_order": False},
        )
    )
    _expect(
        crafted["x0_sign_bit_a:naive_accepts"] == "None",
        "x0_sign_bit_a naive decode must accept",
        failures,
    )
    # Equation-only oracle accepts the canonical-identity forgery as well.
    _expect(
        verify_equation_only(identity_encoding(), message, identity_forgery(identity_encoding(), message)),
        "identity forgery equation-only oracle must accept",
        failures,
    )

    # All eight small-order A encodings: full profile E_SIG_SMALL_ORDER_A;
    # removing both the small-order and mixed-order checks accepts (k % 8 == 0).
    small_ok = True
    for index, encoding in enumerate(torsion_encodings()):
        signature = small_order_signature(encoding, message)
        full = verify_structural(encoding, message, signature)
        ablated = verify_structural(
            encoding,
            message,
            signature,
            checks={"a_small_order": False, "a_mixed_order": False},
        )
        crafted["small_order_a[%d]" % index] = str(full)
        if full != "E_SIG_SMALL_ORDER_A" or ablated is not None:
            small_ok = False
    report["checks"]["small_order_a_all_eight"] = small_ok
    _expect(report["checks"]["small_order_a_all_eight"], "small_order_a_all_eight", failures)

    # x = 0 sign-bit R: equation holds for decoders that read R as identity.
    x0_r_sig = x0_sign_bit_r_signature(seed, message)
    record(
        "x0_sign_bit_r",
        x0_r_sig,
        "E_SIG_NONCANONICAL_R",
        {"r_x0_sign": False},
        expect_ablation="E_SIG_SMALL_ORDER_R",
    )
    _expect(
        verify_equation_only(public, message, x0_r_sig),
        "x0 R equation-only oracle must accept",
        failures,
    )

    # Small-order R encodings: full profile E_SIG_SMALL_ORDER_R; the identity
    # encoding additionally satisfies the equation when that check is removed.
    small_r_ok = True
    for index, encoding in enumerate(torsion_encodings()):
        signature = small_order_r_signature(seed, message, encoding)
        full = verify_structural(public, message, signature)
        crafted["small_order_r[%d]" % index] = str(full)
        if full != "E_SIG_SMALL_ORDER_R":
            small_r_ok = False
    report["checks"]["small_order_r_all_eight"] = small_r_ok
    _expect(report["checks"]["small_order_r_all_eight"], "small_order_r_all_eight", failures)
    identity_r_sig = identity_r_signature(seed, message)
    _expect(
        verify_structural(public, message, identity_r_sig) == "E_SIG_SMALL_ORDER_R"
        and verify_structural(public, message, identity_r_sig, checks={"r_small_order": False})
        is None,
        "identity R must be accepted iff the R small-order check is removed",
        failures,
    )

    # Mixed-order A with a cofactorless-valid signature: only the mixed-order
    # check rejects it.
    mixed_public, mixed_sig = mixed_order_key_and_signature(seed, message)
    mixed_point = decode_point(mixed_public)
    report["checks"]["mixed_order_shape"] = (
        not is_small_order(mixed_point)
        and not is_prime_order(mixed_point)
        and not _is_identity(point_mul(8, mixed_point))
    )
    _expect(report["checks"]["mixed_order_shape"], "mixed_order_shape", failures)
    crafted["mixed_order:full"] = str(
        verify_structural(mixed_public, message, mixed_sig)
    )
    crafted["mixed_order:ablated"] = str(
        verify_structural(mixed_public, message, mixed_sig, checks={"a_mixed_order": False})
    )
    _expect(
        crafted["mixed_order:full"] == "E_SIG_MIXED_ORDER_A"
        and crafted["mixed_order:ablated"] == "None",
        "mixed-order vector must be valid only without the mixed-order check",
        failures,
    )

    # Non-canonical A (y >= p) and non-canonical R (y >= p).
    crafted["noncanonical_a:full"] = str(
        verify_structural(noncanonical_encoding(), message, noncanonical_a_forgery())
    )
    crafted["noncanonical_a:ablated"] = str(
        verify_structural(
            noncanonical_encoding(),
            message,
            noncanonical_a_forgery(),
            checks={"a_y_ge_p": False},
        )
    )
    _expect(
        crafted["noncanonical_a:full"] == "E_SIG_NONCANONICAL_A"
        and crafted["noncanonical_a:ablated"] == "E_SIG_SMALL_ORDER_A",
        "non-canonical A must become small-order when the y >= p rule is removed",
        failures,
    )
    noncanonical_r_sig = noncanonical_r_signature(seed, message)
    crafted["noncanonical_r:full"] = str(
        verify_structural(public, message, noncanonical_r_sig)
    )
    crafted["noncanonical_r:ablated"] = str(
        verify_structural(
            public, message, noncanonical_r_sig, checks={"r_y_ge_p": False}
        )
    )
    _expect(
        crafted["noncanonical_r:full"] == "E_SIG_NONCANONICAL_R"
        and crafted["noncanonical_r:ablated"] == "E_SIG_SMALL_ORDER_R",
        "non-canonical R must become small-order when the y >= p rule is removed",
        failures,
    )

    # S = L and S = L + 1: rejected before the equation.
    for label, value in (("s_equals_l", L), ("s_l_plus_one", L + 1)):
        signature = s_out_of_range_signature(seed, message, value=value)
        crafted[label + ":full"] = str(
            verify_structural(public, message, signature)
        )
        crafted[label + ":ablated"] = str(
            verify_structural(public, message, signature, checks={"s_range": False})
        )
        _expect(
            crafted[label + ":full"] == "E_SIG_S_OUT_OF_RANGE"
            and crafted[label + ":ablated"] == "E_SIG_INVALID",
            label + ": full profile must reject at the S range, remove it and the equation fails",
            failures,
        )

    # Check-order precedence: S range before A/R decode, A small order before R.
    precedence_ok = True
    signature = x0_sign_bit_r_signature(seed, message)
    bad_s = signature[:32] + L.to_bytes(32, "little")
    if verify_structural(public, message, bad_s) != "E_SIG_S_OUT_OF_RANGE":
        precedence_ok = False
    small_a_bad_r = identity_forgery(identity_encoding(), message)
    # A is small order; replace R with a y >= p encoding; the A check comes first.
    precedence_sig = noncanonical_encoding() + small_a_bad_r[32:]
    if (
        verify_structural(identity_encoding(), message, precedence_sig)
        != "E_SIG_SMALL_ORDER_A"
    ):
        precedence_ok = False
    report["checks"]["check_order_precedence"] = precedence_ok
    _expect(
        report["checks"]["check_order_precedence"],
        "check_order_precedence",
        failures,
    )

    # Determinism: every crafted byte artifact is identical on a second run.
    def digest_of_crafted() -> str:
        h = hashlib.sha256()
        for key in sorted(crafted):
            h.update(key.encode("ascii"))
            h.update(crafted[key].encode("ascii"))
        h.update(identity_forgery(identity_encoding(), message))
        h.update(small_order_signature(torsion_encodings()[3], message))
        h.update(mixed_order_key_and_signature(seed, message)[1])
        h.update(x0_sign_bit_r_signature(seed, message))
        h.update(sign_seed(seed, message)[1])
        return h.hexdigest()

    first = digest_of_crafted()
    second = digest_of_crafted()
    report["checks"]["deterministic"] = first == second
    report["crafted_sha256"] = first
    _expect(report["checks"]["deterministic"], "deterministic", failures)

    report["ok"] = not failures
    return report


def main(argv: list[str]) -> int:
    if len(argv) != 1 or argv[0] not in ("--selftest",):
        sys.stderr.write("usage: python tools/edcraft.py --selftest\n")
        return 2
    report = selftest()
    sys.stdout.write(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
