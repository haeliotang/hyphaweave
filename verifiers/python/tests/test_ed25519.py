# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0

"""Strict Ed25519 profile: RFC 8032 vectors, boundaries and the identity forgery."""

from __future__ import annotations

import hashlib
import pathlib

import pytest

from hyphaweave_verify import encoding, ed25519
from hyphaweave_verify.errors import WeaveError

VECTORS = pathlib.Path(__file__).resolve().parents[3] / "vectors"

# RFC 8032 §7.1, test vector 1 (TEST 1: empty message).
RFC8032_PUBLIC_KEY = bytes.fromhex(
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
)
RFC8032_SIGNATURE = bytes.fromhex(
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
    "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
)
RFC8032_MESSAGE = b""


def _published_key(name: str) -> tuple[bytes, bytes, str]:
    """Return (seed, public_key, key_id) for a published synthetic test key."""
    key_dir = VECTORS / "keys"
    metadata = key_dir / (name + ".json")
    if not metadata.exists():  # pragma: no cover - fixtures are committed
        pytest.skip("published test keys are not present")
    import json

    info = json.loads(metadata.read_text(encoding="utf-8"))
    seed = bytes.fromhex((key_dir / info["seed_file"]).read_text(encoding="utf-8").strip())
    public_key = (key_dir / info["pub_bin_file"]).read_bytes()
    return seed, public_key, info["key_id"]


def _sign(seed: bytes, message: bytes) -> bytes:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    return Ed25519PrivateKey.from_private_bytes(seed).sign(message)


def test_rfc8032_vector_1() -> None:
    assert ed25519.verify(RFC8032_PUBLIC_KEY, RFC8032_MESSAGE, RFC8032_SIGNATURE)
    assert not ed25519.verify(RFC8032_PUBLIC_KEY, b"x", RFC8032_SIGNATURE)
    assert not ed25519.verify(RFC8032_PUBLIC_KEY, RFC8032_MESSAGE, bytes(64))


def test_published_key_signatures_verify() -> None:
    for name in ("human-1", "agent-1", "program-1", "org-1", "key-old"):
        seed, public_key, key_id = _published_key(name)
        assert encoding.key_id_from_public_key(public_key) == key_id
        message = b"weave-record/1/sig\nsha256:" + name.encode()
        signature = _sign(seed, message)
        assert ed25519.verify(public_key, message, signature)
        assert ed25519.verify_equation_python(public_key, message, signature)


def test_library_and_pure_python_agree() -> None:
    seed, public_key, _ = _published_key("human-2")
    for message in (b"", b"a", b"longer message " * 10):
        signature = _sign(seed, message)
        assert ed25519.verify(public_key, message, signature)
        assert ed25519.verify_equation_python(public_key, message, signature)


def test_identity_key_forgery_is_rejected() -> None:
    """OpenSSL's raw verifier accepts this; the strict profile must not."""
    identity = ed25519.IDENTITY_ENCODING
    forged = identity + bytes(32)  # R = identity, S = 0
    with pytest.raises(WeaveError) as raised:
        ed25519.verify_signature(identity, b"forged message", forged)
    assert raised.value.code == "E_SIG_SMALL_ORDER_A"
    assert ed25519.verify(identity, b"forged message", forged) is False

    # Variant: R = base point encoding, S = 1 (also a classic forgery against
    # small-order public keys).
    base_point_encoding = bytes.fromhex("5866666666666666666666666666666666666666666666666666666666666666")
    forged_second = base_point_encoding + (1).to_bytes(32, "little")
    assert ed25519.verify(identity, b"m", forged_second) is False


@pytest.mark.parametrize("encoding_bytes", sorted(ed25519.SMALL_ORDER_ENCODINGS))
def test_all_small_order_public_keys_rejected(encoding_bytes: bytes) -> None:
    signature = encoding_bytes + bytes(32)
    with pytest.raises(WeaveError) as raised:
        ed25519.verify_signature(encoding_bytes, b"m", signature)
    assert raised.value.code == "E_SIG_SMALL_ORDER_A"


def test_small_order_r_rejected() -> None:
    seed, public_key, _ = _published_key("human-1")
    message = b"m"
    real = _sign(seed, message)
    identity_r = ed25519.IDENTITY_ENCODING + real[32:]
    with pytest.raises(WeaveError) as raised:
        ed25519.verify_signature(public_key, message, identity_r)
    assert raised.value.code == "E_SIG_SMALL_ORDER_R"


def test_noncanonical_a_rejected() -> None:
    # y = p is non-canonical (must be < p).
    noncanonical = ed25519.P.to_bytes(32, "little")
    with pytest.raises(WeaveError) as raised:
        ed25519.verify_signature(noncanonical, b"m", noncanonical + bytes(32))
    assert raised.value.code == "E_SIG_NONCANONICAL_A"
    # Not a curve point (x^2 has no root).
    not_on_curve = bytes.fromhex(
        "0000000000000000000000000000000000000000000000000000000000000002"
    )
    if not ed25519.is_canonical_point_encoding(not_on_curve):
        with pytest.raises(WeaveError) as raised:
            ed25519.verify_signature(not_on_curve, b"m", bytes(64))
        assert raised.value.code == "E_SIG_NONCANONICAL_A"


def test_noncanonical_r_rejected() -> None:
    _, public_key, _ = _published_key("human-1")
    seed, _, _ = _published_key("human-1")
    real = _sign(seed, b"m")
    p_plus = ed25519.P.to_bytes(32, "little")
    with pytest.raises(WeaveError) as raised:
        ed25519.verify_signature(public_key, b"m", p_plus + real[32:])
    assert raised.value.code == "E_SIG_NONCANONICAL_R"


def test_s_out_of_range_rejected() -> None:
    seed, public_key, _ = _published_key("human-1")
    real = _sign(seed, b"m")
    with pytest.raises(WeaveError) as raised:
        ed25519.verify_signature(public_key, b"m", real[:32] + ed25519.L.to_bytes(32, "little"))
    assert raised.value.code == "E_SIG_S_OUT_OF_RANGE"
    # L - 1 is in range but the equation does not hold with a random R.
    with pytest.raises(WeaveError) as raised:
        ed25519.verify_signature(
            public_key, b"m", real[:32] + (ed25519.L - 1).to_bytes(32, "little")
        )
    assert raised.value.code == "E_SIG_INVALID"


def test_short_key_and_signature_lengths() -> None:
    with pytest.raises(WeaveError) as raised:
        ed25519.verify_signature(bytes(31), b"m", bytes(64))
    assert raised.value.code == "E_SIG_NONCANONICAL_A"
    _, public_key, _ = _published_key("human-1")
    with pytest.raises(WeaveError) as raised:
        ed25519.verify_signature(public_key, b"m", bytes(63))
    assert raised.value.code == "E_ENV_SIG_VALUE"


def test_small_order_canonical_set_is_complete_and_well_formed() -> None:
    assert len(ed25519.SMALL_ORDER_ENCODINGS) == 8
    for encoding_bytes in ed25519.SMALL_ORDER_ENCODINGS:
        assert len(encoding_bytes) == 32
        assert ed25519.is_canonical_point_encoding(encoding_bytes)


def test_verification_is_deterministic() -> None:
    seed, public_key, _ = _published_key("device-1")
    signature = _sign(seed, b"deterministic")
    first = ed25519.verify(public_key, b"deterministic", signature)
    for _ in range(5):
        assert ed25519.verify(public_key, b"deterministic", signature) == first


def test_public_key_canonical_decoding_rules() -> None:
    # y >= p is not a canonical point encoding.
    assert not ed25519.is_canonical_point_encoding(ed25519.P.to_bytes(32, "little"))
    # The eight small-order points are canonical encodings (rejected only as keys).
    assert ed25519.is_canonical_point_encoding(ed25519.IDENTITY_ENCODING)


# ---------------------------------------------------------------------------
# Revision-1 boundaries (decision #34 / S1 + Q1)
# ---------------------------------------------------------------------------


def _encode_point(point) -> bytes:
    x, y, z, _t = point
    z_inverse = pow(z, ed25519.P - 2, ed25519.P)
    x_affine = x * z_inverse % ed25519.P
    y_affine = y * z_inverse % ed25519.P
    value = y_affine | ((x_affine & 1) << 255)
    return value.to_bytes(32, "little")


def _torsion_point() -> tuple:
    return ed25519._decode_point(
        bytes.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),
        "E_SIG_NONCANONICAL_A",
    )


def _mixed_order_signature(message: bytes):
    """Construct a cofactorless-valid signature for a mixed-order public key."""
    private_scalar = 0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF
    base = ed25519._base_point()
    a0 = ed25519._scalar_mult(base, private_scalar)
    mixed = ed25519._point_add(a0, _torsion_point())
    mixed_encoding = _encode_point(mixed)
    r = 1
    while True:
        r_point = ed25519._scalar_mult(base, r)
        r_encoding = _encode_point(r_point)
        k = int.from_bytes(
            hashlib.sha512(r_encoding + mixed_encoding + message).digest(), "little"
        ) % ed25519.L
        if k % 8 == 0:
            break
        r += 1
    s = (r + k * private_scalar) % ed25519.L
    signature = r_encoding + s.to_bytes(32, "little")
    return mixed_encoding, signature


def test_x0_sign_bit_public_key_is_rejected() -> None:
    """RFC 8032 §5.1.3: x = 0 with the sign bit set fails to decode (S1)."""
    x0_a = bytes.fromhex(
        "0100000000000000000000000000000000000000000000000000000000000080"
    )
    with pytest.raises(WeaveError) as raised:
        ed25519.verify_signature(x0_a, b"m", x0_a + bytes(32))
    assert raised.value.code == "E_SIG_NONCANONICAL_A"


def test_x0_sign_bit_r_is_rejected() -> None:
    seed, public_key, _ = _published_key("human-1")
    real = _sign(seed, b"m")
    x0_r = bytes.fromhex(
        "0100000000000000000000000000000000000000000000000000000000000080"
    )
    with pytest.raises(WeaveError) as raised:
        ed25519.verify_signature(public_key, b"m", x0_r + real[32:])
    assert raised.value.code == "E_SIG_NONCANONICAL_R"


@pytest.mark.parametrize("encoding_bytes", sorted(ed25519.SMALL_ORDER_ENCODINGS))
def test_all_eight_small_order_points_as_a_and_r(encoding_bytes: bytes) -> None:
    seed, public_key, _ = _published_key("human-1")
    real = _sign(seed, b"m")
    with pytest.raises(WeaveError) as raised:
        ed25519.verify_signature(encoding_bytes, b"m", encoding_bytes + bytes(32))
    assert raised.value.code == "E_SIG_SMALL_ORDER_A"
    with pytest.raises(WeaveError) as raised:
        ed25519.verify_signature(public_key, b"m", encoding_bytes + real[32:])
    assert raised.value.code == "E_SIG_SMALL_ORDER_R"


def test_s_equals_l_and_l_plus_one() -> None:
    _seed, public_key, _ = _published_key("human-1")
    message = b"m"
    signature = _sign(_published_key("human-1")[0], message)
    for value in (ed25519.L, ed25519.L + 1):
        with pytest.raises(WeaveError) as raised:
            ed25519.verify_signature(
                public_key, message, signature[:32] + value.to_bytes(32, "little")
            )
        assert raised.value.code == "E_SIG_S_OUT_OF_RANGE"


def test_mixed_order_public_key_rejected() -> None:
    """Q1: mixed-order A is rejected with the dedicated code."""
    message = b"weave-record/1/sig\nsha256:any"
    mixed_encoding, signature = _mixed_order_signature(message)
    # The cofactorless equation itself holds for this key/signature ...
    assert ed25519.verify_equation_python(mixed_encoding, message, signature)
    # ... but the strict profile rejects the mixed-order public key.
    with pytest.raises(WeaveError) as raised:
        ed25519.verify_signature(mixed_encoding, message, signature)
    assert raised.value.code == "E_SIG_MIXED_ORDER_A"
    assert ed25519.verify(mixed_encoding, message, signature) is False


def test_small_order_detection_is_point_based() -> None:
    """All eight encodings decode into the torsion subgroup ([8]P == identity)."""
    for encoding_bytes in ed25519.SMALL_ORDER_ENCODINGS:
        point = ed25519._decode_point(encoding_bytes, "E_SIG_NONCANONICAL_A")
        assert ed25519._is_small_order(point)
    # A normal published key is not small-order and is in the prime-order subgroup.
    _seed, public_key, _ = _published_key("human-1")
    point = ed25519._decode_point(public_key, "E_SIG_NONCANONICAL_A")
    assert not ed25519._is_small_order(point)
    assert ed25519._is_prime_order(point)
