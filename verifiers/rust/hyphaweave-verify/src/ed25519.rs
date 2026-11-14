// SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
// SPDX-License-Identifier: Apache-2.0

//! Ed25519 verification under the fixed strict profile of §3.
//!
//! This module is implemented from the specification only (RFC 8032 plus the
//! §3 rulings). It MUST NOT call a library convenience verifier: every step of
//! §3.4 has its own error code and the order of checks is normative.
//!
//! Interface contract (see ARCHITECTURE.md):
//! - [`verify`] performs exactly the checks 2–9 of §3.4 (check 1, the structural
//!   length check, belongs to the envelope/attestation layer) and returns the
//!   [`crate::error_codes::Code`] of the first failing check.
//! - [`public_key_from_seed`] and [`sign`] implement §3.5 and exist so the
//!   RFC 8032 §7.1 cross-check can derive and sign exactly as the specification
//!   says; the verifier itself never signs.
//!
//! Implementation notes:
//! - `curve25519-dalek` supplies field, point and scalar arithmetic only. The
//!   complete RFC 8032 §5.1.3 decoding of §3.2 is performed here: the canonical
//!   `y < p` check and the non-canonical `x = 0` with sign bit 1 rule are
//!   checked explicitly; the square-root computation is the library's, whose
//!   `None` classification is exactly "no square root"; and a decoded point is
//!   required to re-compress to its input encoding, so no lenient library
//!   acceptance of a non-canonical encoding can survive.
//! - Point predicates are evaluated on decoded points, never on encoding lists:
//!   small-order is `[8]P == identity` (§3.3), and mixed-order is `[L]A !=
//!   identity` for a point that is not small-order.

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;
use sha2::{Digest, Sha512};

use crate::error_codes::{e, Code};

/// The order `L = 2^252 + 27742317777372353535851937790883648493` of the
/// Ed25519 base point, little-endian (§3.3).
const L_BYTES: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

/// `p = 2^255 - 19`, little-endian; the largest canonical field element is
/// `p - 1` (§3.2).
const P_BYTES: [u8; 32] = [
    0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
];

/// Little-endian encoding of the field element 1: the `y` coordinate of the
/// identity, one of the two points with `x = 0`.
const ONE_BYTES: [u8; 32] = [
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// Little-endian encoding of the field element `p - 1`: the `y` coordinate of
/// `(0, -1)`, the other point with `x = 0`.
const MINUS_ONE_BYTES: [u8; 32] = [
    0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
];

/// Verifies one Ed25519 signature over one message under §3.4 steps 2–9.
///
/// `public_key` must be the 32 raw public-key octets and `signature` the 64
/// `R ‖ S` octets; the caller performs the structural base64url/length checks
/// first (§3.4 step 1) and maps those to `E_ENV_SIG_VALUE` /
/// `E_MANIFEST_SCHEMA`.
///
/// # Errors
/// Returns the code of the first failing §3.4 step: `E_SIG_NONCANONICAL_A`,
/// `E_SIG_S_OUT_OF_RANGE`, `E_SIG_SMALL_ORDER_A`, `E_SIG_MIXED_ORDER_A`,
/// `E_SIG_NONCANONICAL_R`, `E_SIG_SMALL_ORDER_R` or `E_SIG_INVALID`.
///
/// As a defensive guard for callers that skip step 1 this function also returns
/// `E_ENV_SIG_VALUE` when `signature` is not exactly 64 octets; a conforming
/// caller has already rejected that input with the context-specific step-1
/// code before calling here.
pub fn verify(public_key: &[u8], signature: &[u8], message: &[u8]) -> Result<(), Code> {
    // §3.4 step 1 (structural) belongs to the caller. Guard it so a caller
    // mistake cannot panic; `E_ENV_SIG_VALUE` is the record-signature step-1
    // code (§3.4 table).
    let Ok(signature) = <&[u8; 64]>::try_from(signature) else {
        return Err(e::ENV_SIG_VALUE);
    };

    // §3.4 step 2: the public-key octets are exactly 32.
    let Ok(a_encoded) = <&[u8; 32]>::try_from(public_key) else {
        return Err(e::SIG_NONCANONICAL_A);
    };

    // §3.4 step 3: the last 32 octets are the little-endian scalar S; it must
    // be canonical (`S < L`).
    let (r_slice, s_slice) = signature.split_at(32);
    let mut r_encoded = [0u8; 32];
    r_encoded.copy_from_slice(r_slice);
    let mut s_encoded = [0u8; 32];
    s_encoded.copy_from_slice(s_slice);
    if !le_less_than(&s_encoded, &L_BYTES) {
        return Err(e::SIG_S_OUT_OF_RANGE);
    }

    // §3.4 step 4: decode A with the complete §3.2 procedure.
    let a = decode_point(a_encoded).ok_or(e::SIG_NONCANONICAL_A)?;

    // §3.4 step 5: `[8]A != identity`.
    if a.mul_by_cofactor().is_identity() {
        return Err(e::SIG_SMALL_ORDER_A);
    }

    // §3.4 step 6: `[L]A == identity` (a prime-order-subgroup public key).
    if !is_prime_order(&a) {
        return Err(e::SIG_MIXED_ORDER_A);
    }

    // §3.4 step 7: decode R with the complete §3.2 procedure.
    let r = decode_point(&r_encoded).ok_or(e::SIG_NONCANONICAL_R)?;

    // §3.4 step 8: `[8]R != identity`.
    if r.mul_by_cofactor().is_identity() {
        return Err(e::SIG_SMALL_ORDER_R);
    }

    // §3.4 step 9: k = SHA-512(R ‖ A ‖ M) mod L; accept iff
    // [S]B == R + [k]A (cofactorless, single-message, no context string).
    let s = Scalar::from_bytes_mod_order(s_encoded); // S < L, so this is exact.
    let k = challenge(&r_encoded, a_encoded, message);
    let lhs = ED25519_BASEPOINT_POINT * s;
    let rhs = r + a * k;
    if lhs == rhs {
        Ok(())
    } else {
        Err(e::SIG_INVALID)
    }
}

/// Derives the 32-byte public key from a 32-byte Ed25519 seed (§3.5).
#[must_use]
pub fn public_key_from_seed(seed: &[u8; 32]) -> [u8; 32] {
    let (secret, _prefix) = expand_seed(seed);
    (ED25519_BASEPOINT_POINT * secret).compress().to_bytes()
}

/// Produces an Ed25519 signature over `message` from a 32-byte seed (§3.5).
#[must_use]
pub fn sign(seed: &[u8; 32], message: &[u8]) -> [u8; 64] {
    let (secret, prefix) = expand_seed(seed);
    let public_encoded = (ED25519_BASEPOINT_POINT * secret).compress().to_bytes();

    // §3.5 / RFC 8032 §5.1.6: r = SHA-512(prefix ‖ M) mod L, R = [r]B.
    let mut nonce_hasher = Sha512::new();
    nonce_hasher.update(prefix);
    nonce_hasher.update(message);
    let nonce_digest: [u8; 64] = nonce_hasher.finalize().into();
    let nonce = Scalar::from_bytes_mod_order_wide(&nonce_digest);
    let r_encoded = (ED25519_BASEPOINT_POINT * nonce).compress().to_bytes();

    // §3.5 / RFC 8032 §5.1.6: S = (r + SHA-512(R ‖ A ‖ M)·s) mod L.
    let k = challenge(&r_encoded, &public_encoded, message);
    let s = nonce + k * secret;

    let mut signature = [0u8; 64];
    signature[..32].copy_from_slice(&r_encoded);
    signature[32..].copy_from_slice(&s.to_bytes());
    signature
}

/// Expands a seed into the secret scalar and the nonce prefix (§3.5): the
/// lower half of `SHA-512(seed)` is pruned as RFC 8032 §5.1.5 requires and the
/// upper half is the prefix used for deterministic nonces.
fn expand_seed(seed: &[u8; 32]) -> (Scalar, [u8; 32]) {
    let digest: [u8; 64] = Sha512::digest(seed).into();
    let mut scalar_bytes = [0u8; 32];
    scalar_bytes.copy_from_slice(&digest[..32]);
    // RFC 8032 §5.1.5 pruning ("clamping").
    scalar_bytes[0] &= 248;
    scalar_bytes[31] &= 127;
    scalar_bytes[31] |= 64;

    let mut prefix = [0u8; 32];
    prefix.copy_from_slice(&digest[32..]);
    (Scalar::from_bytes_mod_order(scalar_bytes), prefix)
}

/// `k = SHA-512(R ‖ A ‖ M) mod L` for the encoded points `R` and `A` (§3.4
/// step 9, RFC 8032 §5.1.6 step 4).
fn challenge(r_encoded: &[u8; 32], a_encoded: &[u8; 32], message: &[u8]) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(r_encoded);
    hasher.update(a_encoded);
    hasher.update(message);
    let digest: [u8; 64] = hasher.finalize().into();
    Scalar::from_bytes_mod_order_wide(&digest)
}

/// Decodes one compressed Edwards point with the complete §3.2 procedure
/// (RFC 8032 §5.1.3). `None` means the encoding is not a canonical point.
fn decode_point(encoded: &[u8; 32]) -> Option<EdwardsPoint> {
    // §3.2 steps 1–2: clear bit 255 to obtain `y`, then require `y < p`.
    let sign_bit = encoded[31] >> 7;
    let mut y = *encoded;
    y[31] &= 0x7f;
    if !le_less_than(&y, &P_BYTES) {
        return None;
    }

    // §3.2 step 4: `x = 0` happens exactly when `y² = 1`, i.e. `y = 1` or
    // `y = p - 1`; the only canonical encoding of a point with `x = 0` has sign
    // bit 0, so a sign bit of 1 on either encoding is non-canonical. This is
    // what blocks the identity-point forgery together with §3.4 step 5.
    if sign_bit == 1 && (y == ONE_BYTES || y == MINUS_ONE_BYTES) {
        return None;
    }

    // §3.2 steps 3 and 5: compute the candidate `x = (u/v)^((p+3)/8)`, fail
    // when `u/v` has no square root, and select the root whose parity matches
    // the sign bit. `decompress` is exactly RFC 8032 §5.1.3 steps 2–4; its
    // `None` classifies "no square root". Its two leniencies — accepting a
    // non-canonical `y` and accepting `x = 0` with sign bit 1 — are rejected
    // above.
    let point = CompressedEdwardsY(*encoded).decompress()?;

    // Defence in depth: a canonical encoding round-trips exactly. Rejecting
    // every non-round-tripping input guarantees that no other lenient
    // acceptance of a non-canonical encoding can reach verification.
    if point.compress().to_bytes() != *encoded {
        return None;
    }

    Some(point)
}

/// True when the little-endian 32-byte integer `value` is smaller than `limit`.
///
/// Both arguments are 32-byte little-endian integers; the comparison is exact
/// integer comparison (not constant time), which is fine because the compared
/// values are public signature fields.
fn le_less_than(value: &[u8; 32], limit: &[u8; 32]) -> bool {
    for (&byte, &bound) in value.iter().rev().zip(limit.iter().rev()) {
        if byte != bound {
            return byte < bound;
        }
    }
    false
}

/// True when `point` is in the prime-order subgroup: `[L]point == identity`
/// (§3.3).
fn is_prime_order(point: &EdwardsPoint) -> bool {
    // A `Scalar` is always reduced modulo L, so L itself cannot be represented.
    // Multiplying by the canonical scalar L - 1 and adding one more copy of the
    // point computes the same multiple: [L]P = [L-1]P + P.
    let mut l_minus_one = L_BYTES;
    l_minus_one[0] -= 1; // L is odd, so no borrow is needed.
    let scalar = Scalar::from_bytes_mod_order(l_minus_one);
    (point * scalar + point).is_identity()
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 8032 §7.1 test vectors, transcribed from the stored RFC text
    // (`vectors/external/rfc8032/rfc8032.txt`). The integration test parses
    // the same file; the copies here keep the unit tests self-contained.
    const TEST_1_SEED: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    const TEST_1_PUBLIC: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    const TEST_1_SIGNATURE: &str = concat!(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155",
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    );
    const TEST_1_MESSAGE: &str = "";

    const TEST_2_SEED: &str = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";
    const TEST_2_PUBLIC: &str = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";
    const TEST_2_SIGNATURE: &str = concat!(
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da",
        "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    );
    const TEST_2_MESSAGE: &str = "72";

    const TEST_3_SEED: &str = "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7";
    const TEST_3_PUBLIC: &str = "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025";
    const TEST_3_SIGNATURE: &str = concat!(
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac",
        "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    );
    const TEST_3_MESSAGE: &str = "af82";

    const TEST_1024_SEED: &str = "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5";
    const TEST_1024_PUBLIC: &str =
        "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e";
    const TEST_1024_SIGNATURE: &str = concat!(
        "0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350",
        "aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03",
    );
    const TEST_1024_MESSAGE: &str = concat!(
        "08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98",
        "fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d8",
        "79de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d",
        "658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc",
        "1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4fe",
        "ba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e",
        "06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbef",
        "efd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7",
        "aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed1",
        "85ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2",
        "d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24",
        "554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f270",
        "88d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc",
        "2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b07",
        "07e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128ba",
        "b27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51a",
        "ddd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429e",
        "c96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb7",
        "51fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c",
        "42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8",
        "ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34df",
        "f7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08",
        "d78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649",
        "de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e4",
        "88acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a3",
        "2ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e",
        "6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5f",
        "b93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b5",
        "0d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef1",
        "369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380d",
        "b2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c",
        "0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0",
    );

    const TEST_SHA_SEED: &str = "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42";
    const TEST_SHA_PUBLIC: &str =
        "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf";
    const TEST_SHA_SIGNATURE: &str = concat!(
        "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b589",
        "09351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704",
    );
    const TEST_SHA_MESSAGE: &str = concat!(
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a",
        "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
    );

    struct RfcVector {
        name: &'static str,
        seed: &'static str,
        public_key: &'static str,
        message: &'static str,
        signature: &'static str,
        message_len: usize,
    }

    const RFC8032_VECTORS: [RfcVector; 5] = [
        RfcVector {
            name: "TEST 1",
            seed: TEST_1_SEED,
            public_key: TEST_1_PUBLIC,
            message: TEST_1_MESSAGE,
            signature: TEST_1_SIGNATURE,
            message_len: 0,
        },
        RfcVector {
            name: "TEST 2",
            seed: TEST_2_SEED,
            public_key: TEST_2_PUBLIC,
            message: TEST_2_MESSAGE,
            signature: TEST_2_SIGNATURE,
            message_len: 1,
        },
        RfcVector {
            name: "TEST 3",
            seed: TEST_3_SEED,
            public_key: TEST_3_PUBLIC,
            message: TEST_3_MESSAGE,
            signature: TEST_3_SIGNATURE,
            message_len: 2,
        },
        RfcVector {
            name: "TEST 1024",
            seed: TEST_1024_SEED,
            public_key: TEST_1024_PUBLIC,
            message: TEST_1024_MESSAGE,
            signature: TEST_1024_SIGNATURE,
            message_len: 1023,
        },
        RfcVector {
            name: "TEST SHA(abc)",
            seed: TEST_SHA_SEED,
            public_key: TEST_SHA_PUBLIC,
            message: TEST_SHA_MESSAGE,
            signature: TEST_SHA_SIGNATURE,
            message_len: 64,
        },
    ];

    /// The eight canonical encodings of the small-order points
    /// (`vectors/keys/edge-points/index.json`).
    const SMALL_ORDER_ENCODINGS: [&str; 8] = [
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000080",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    ];

    /// `y = 1` (the identity) with the RFC 8032 sign bit set: the non-canonical
    /// `x = 0` with sign bit 1 encoding.
    const X0_SIGN_BIT_ENCODING: &str =
        "0100000000000000000000000000000000000000000000000000000000000080";
    /// `y = p` (not reduced modulo `p`).
    const NONCANONICAL_Y_P_ENCODING: &str =
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f";
    /// A mixed-order public key from `vectors/keys/edge-points/`.
    const MIXED_ORDER_A_ENCODING: &str =
        "95bdb6042e891155f3f55a3336f7d8b08fd2b5d61bfb79bf59f662bb36c3a288";
    /// Compressed encoding of the Ed25519 base point (a prime-order group
    /// element usable as `R`).
    const BASEPOINT_ENCODING: &str =
        "5866666666666666666666666666666666666666666666666666666666666666";

    fn hex(text: &str) -> Vec<u8> {
        assert_eq!(text.len() % 2, 0, "hex string has an even length");
        text.as_bytes()
            .chunks_exact(2)
            .map(|pair| (hex_digit(pair[0]) << 4) | hex_digit(pair[1]))
            .collect()
    }

    fn hex_digit(byte: u8) -> u8 {
        match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => panic!("invalid hexadecimal digit"),
        }
    }

    fn hex32(text: &str) -> [u8; 32] {
        hex(text).as_slice().try_into().expect("32 bytes")
    }

    fn hex64(text: &str) -> [u8; 64] {
        hex(text).as_slice().try_into().expect("64 bytes")
    }

    #[test]
    fn rfc8032_section_7_1_vectors() {
        for vector in &RFC8032_VECTORS {
            let seed = hex32(vector.seed);
            let public_key = hex32(vector.public_key);
            let message = hex(vector.message);
            let signature = hex64(vector.signature);

            assert_eq!(
                message.len(),
                vector.message_len,
                "{}: message length",
                vector.name
            );
            assert_eq!(
                public_key_from_seed(&seed),
                public_key,
                "{}: derived public key differs",
                vector.name
            );
            assert_eq!(
                sign(&seed, &message).as_slice(),
                signature.as_slice(),
                "{}: deterministic signature differs",
                vector.name
            );
            assert_eq!(
                verify(&public_key, &signature, &message),
                Ok(()),
                "{}: published signature must verify",
                vector.name
            );
            verify(
                &public_key_from_seed(&seed),
                &sign(&seed, &message),
                &message,
            )
            .expect("derived key and signature verify");
        }
    }

    #[test]
    fn small_order_public_keys_are_rejected() {
        let signature = [0u8; 64];
        for encoding in SMALL_ORDER_ENCODINGS {
            assert_eq!(
                verify(&hex32(encoding), &signature, b"message"),
                Err(e::SIG_SMALL_ORDER_A),
                "small-order public key {encoding}"
            );
        }
    }

    #[test]
    fn hostile_edge_encodings_are_rejected() {
        let signature = [0u8; 64];
        assert_eq!(
            verify(&hex32(X0_SIGN_BIT_ENCODING), &signature, b"message"),
            Err(e::SIG_NONCANONICAL_A)
        );
        assert_eq!(
            verify(&hex32(NONCANONICAL_Y_P_ENCODING), &signature, b"message"),
            Err(e::SIG_NONCANONICAL_A)
        );
        assert_eq!(
            verify(&hex32(MIXED_ORDER_A_ENCODING), &signature, b"message"),
            Err(e::SIG_MIXED_ORDER_A)
        );

        // The same hostile encodings used as `R`, against a valid prime-order
        // public key: small-order `R` is `E_SIG_SMALL_ORDER_R`, a non-canonical
        // `R` encoding is `E_SIG_NONCANONICAL_R`.
        let public_key = hex32(TEST_1_PUBLIC);
        for encoding in SMALL_ORDER_ENCODINGS {
            let mut r_signature = [0u8; 64];
            r_signature[..32].copy_from_slice(&hex32(encoding));
            assert_eq!(
                verify(&public_key, &r_signature, b"message"),
                Err(e::SIG_SMALL_ORDER_R),
                "small-order R {encoding}"
            );
        }
        for encoding in [X0_SIGN_BIT_ENCODING, NONCANONICAL_Y_P_ENCODING] {
            let mut r_signature = [0u8; 64];
            r_signature[..32].copy_from_slice(&hex32(encoding));
            assert_eq!(
                verify(&public_key, &r_signature, b"message"),
                Err(e::SIG_NONCANONICAL_R),
                "non-canonical R {encoding}"
            );
        }
    }

    #[test]
    fn scalar_must_be_canonical() {
        let public_key = hex32(TEST_1_PUBLIC);
        let mut signature = [0u8; 64];
        signature[..32].copy_from_slice(&hex32(BASEPOINT_ENCODING));

        // S = L and S = 2^256 - 1 are both out of range.
        signature[32..].copy_from_slice(&L_BYTES);
        assert_eq!(
            verify(&public_key, &signature, b"message"),
            Err(e::SIG_S_OUT_OF_RANGE)
        );
        signature[32..].copy_from_slice(&[0xff; 32]);
        assert_eq!(
            verify(&public_key, &signature, b"message"),
            Err(e::SIG_S_OUT_OF_RANGE)
        );

        // S = L - 1 is canonical; the equation then decides.
        let mut l_minus_one = L_BYTES;
        l_minus_one[0] -= 1;
        signature[32..].copy_from_slice(&l_minus_one);
        assert_eq!(
            verify(&public_key, &signature, b"message"),
            Err(e::SIG_INVALID)
        );
    }

    #[test]
    fn verification_order_is_fixed() {
        // Step 3 before step 4: an out-of-range S wins over a non-canonical A.
        let mut signature = [0u8; 64];
        signature[32..].copy_from_slice(&L_BYTES);
        assert_eq!(
            verify(&hex32(X0_SIGN_BIT_ENCODING), &signature, b"message"),
            Err(e::SIG_S_OUT_OF_RANGE)
        );

        // Step 4 before step 7: a non-canonical A wins over a non-canonical R.
        let mut signature = [0u8; 64];
        signature[..32].copy_from_slice(&hex32(NONCANONICAL_Y_P_ENCODING));
        assert_eq!(
            verify(&hex32(NONCANONICAL_Y_P_ENCODING), &signature, b"message"),
            Err(e::SIG_NONCANONICAL_A)
        );

        // Step 6 before step 8: a mixed-order A wins over a small-order R.
        let mut signature = [0u8; 64];
        signature[..32].copy_from_slice(&hex32(SMALL_ORDER_ENCODINGS[0]));
        assert_eq!(
            verify(&hex32(MIXED_ORDER_A_ENCODING), &signature, b"message"),
            Err(e::SIG_MIXED_ORDER_A)
        );
    }

    #[test]
    fn wycheproof_samples() {
        // A small sample of the C2SP/Wycheproof Ed25519 corpus; the full corpus
        // is checked by `tests/external_ed25519.rs`.
        let prime_order_key = "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa";
        type Sample = (
            &'static str,
            &'static str,
            &'static str,
            &'static str,
            Result<(), Code>,
        );
        let cases: [Sample; 6] = [
            (
                "tcId 1 valid",
                prime_order_key,
                "",
                concat!(
                    "d4fbdb52bfa726b44d1786a8c0d171c3e62ca83c9e5bbe63de0bb2483f8fd6cc",
                    "1429ab72cafc41ab56af02ff8fcc43b99bfe4c7ae940f60f38ebaa9d311c4007",
                ),
                Ok(()),
            ),
            (
                "tcId 10 special R and S values",
                prime_order_key,
                "3f",
                concat!(
                    "0000000000000000000000000000000000000000000000000000000000000000",
                    "0000000000000000000000000000000000000000000000000000000000000000",
                ),
                Err(e::SIG_SMALL_ORDER_R),
            ),
            (
                "tcId 63 S + L",
                prime_order_key,
                "54657374",
                concat!(
                    "7c38e026f29e14aabd059a0f2db8b0cd783040609a8be684db12f82a27774ab0",
                    "67654bce3832c2d76f8f6f5dafc08d9339d4eef676573336a5c51eb6f946b31d",
                ),
                Err(e::SIG_S_OUT_OF_RANGE),
            ),
            (
                "tcId 85 S just above the bound",
                "100fdf47fb94f1536a4f7c3fda27383fa03375a8f527c537e6f1703c47f94f86",
                "6a0bc2b0057cedfc0fa2e3f7f7d39279b30f454a69dfd1117c758d86b19d85e0",
                concat!(
                    "0971f86d2c9c78582524a103cb9cf949522ae528f8054dc20107d999be673ff4",
                    "e25ebf2f2928766b1248bec6e91697775f8446639ede46ad4df4053000000010",
                ),
                Err(e::SIG_S_OUT_OF_RANGE),
            ),
            (
                "tcId 152 identity public key universal forgery",
                "0100000000000000000000000000000000000000000000000000000000000000",
                "6d657373616765",
                concat!(
                    "5866666666666666666666666666666666666666666666666666666666666666",
                    "0100000000000000000000000000000000000000000000000000000000000000",
                ),
                Err(e::SIG_SMALL_ORDER_A),
            ),
            (
                "tcId 160 mixed-order public key",
                "15deb30729eb3e465c88f11b57d0c8d36eb0f670c3b22d2f80ea6049eeb2c23b",
                "6d697865642d6f726465722d302d312d38",
                concat!(
                    "49b0d4daf5493b98c7220f7b785fdf10f4befad3262e00f2cd6813c90d1319f6",
                    "a7c6c0d69149f691d0c6b428642bb08d7046e0abff7e68e6b83547129f51080b",
                ),
                Err(e::SIG_MIXED_ORDER_A),
            ),
        ];

        for (label, public_key, message, signature, expected) in cases {
            let signature = hex64(signature);
            assert_eq!(
                verify(&hex32(public_key), &signature, &hex(message)),
                expected,
                "{label}"
            );
        }
    }

    #[test]
    fn signature_length_is_guarded() {
        let public_key = hex32(TEST_1_PUBLIC);
        let signature = hex64(TEST_1_SIGNATURE);
        assert_eq!(
            verify(&public_key, &signature[..63], b""),
            Err(e::ENV_SIG_VALUE)
        );
        let mut too_long = [0u8; 65];
        too_long[..64].copy_from_slice(&signature);
        assert_eq!(verify(&public_key, &too_long, b""), Err(e::ENV_SIG_VALUE));
        assert_eq!(
            verify(&public_key[..31], &signature, b""),
            Err(e::SIG_NONCANONICAL_A)
        );
    }

    #[test]
    fn signing_round_trip() {
        let seed = [0x42u8; 32];
        let public_key = public_key_from_seed(&seed);
        let message = b"weave-record/1/sig\nsha256:0000000000000000000000000000000000000000000000000000000000000000";
        let signature = sign(&seed, message);
        assert_eq!(verify(&public_key, &signature, message), Ok(()));
        assert_eq!(
            verify(&public_key, &signature, b"a different message"),
            Err(e::SIG_INVALID)
        );
    }
}
