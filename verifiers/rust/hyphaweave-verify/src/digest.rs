// SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
// SPDX-License-Identifier: Apache-2.0

//! Byte constructions and encodings: SHA-256, digest strings, domain-separated
//! record and manifest digests, and key ids (§2).
//!
//! All functions here are pure: they hash bytes the caller supplies, never a
//! file path and never anything re-serialised after a signature was made.

use sha2::{Digest, Sha256};

use crate::json::canonical_object_bytes;
use crate::value::Object;

/// Domain-separation prefixes (§2.1), each ending with exactly one LF.
pub mod prefix {
    /// Prefix of the record digest message.
    pub const RECORD_DIGEST: &[u8] = b"weave-record/1/digest\n";
    /// Prefix of the record signature message.
    pub const RECORD_SIGNATURE: &[u8] = b"weave-record/1/sig\n";
    /// Prefix of the manifest digest message.
    pub const MANIFEST_DIGEST: &[u8] = b"weave-record/1/manifest-digest\n";
    /// Prefix of the manifest signature message.
    pub const MANIFEST_SIGNATURE: &[u8] = b"weave-record/1/manifest\n";
}

/// Lowercase hexadecimal encoding.
#[must_use]
pub fn to_lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0xF)]));
    }
    out
}

/// Computes SHA-256 over `data`.
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Computes SHA-256 over the concatenation of `parts` without materialising it.
#[must_use]
pub fn sha256_concat(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// A digest string of `sha256` over `data`.
#[must_use]
pub fn sha256_digest_string(data: &[u8]) -> String {
    format!("sha256:{}", to_lower_hex(&sha256(data)))
}

/// Record digest (§2.2): SHA-256 over the record-digest prefix and the WR-CJ
/// bytes of the record with its top-level `sigs` member removed.
#[must_use]
pub fn record_digest(record: &Object) -> String {
    let without_sigs = record.without("sigs");
    let canonical = canonical_object_bytes(&without_sigs);
    sha256_digest_string_concat(&[prefix::RECORD_DIGEST, &canonical])
}

/// Manifest digest (§2.4) over the canonical file bytes of `manifest.json`
/// without the optional trailing LF.
#[must_use]
pub fn manifest_digest(canonical_manifest_bytes: &[u8]) -> String {
    sha256_digest_string_concat(&[prefix::MANIFEST_DIGEST, canonical_manifest_bytes])
}

/// SHA-256 over the concatenation of `parts`, formatted as a digest string.
#[must_use]
pub fn sha256_digest_string_concat(parts: &[&[u8]]) -> String {
    format!("sha256:{}", to_lower_hex(&sha256_concat(parts)))
}

/// Byte message that a record signature signs (§2.3).
#[must_use]
pub fn record_signature_message(digest_string: &str) -> Vec<u8> {
    let mut message = Vec::with_capacity(prefix::RECORD_SIGNATURE.len() + digest_string.len());
    message.extend_from_slice(prefix::RECORD_SIGNATURE);
    message.extend_from_slice(digest_string.as_bytes());
    message
}

/// Byte message that a manifest signature signs (§2.4).
#[must_use]
pub fn manifest_signature_message(digest_string: &str) -> Vec<u8> {
    let mut message = Vec::with_capacity(prefix::MANIFEST_SIGNATURE.len() + digest_string.len());
    message.extend_from_slice(prefix::MANIFEST_SIGNATURE);
    message.extend_from_slice(digest_string.as_bytes());
    message
}

/// Parsed form of a digest string (§2.7): `alg:hex`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DigestString<'a> {
    /// Algorithm name token.
    pub algorithm: &'a str,
    /// Lowercase hexadecimal digits.
    pub hex: &'a str,
}

/// Parses a digest string per the §2.7 grammar without interpreting the
/// algorithm. A structurally valid but unsupported algorithm is not an error at
/// this layer; callers decide what an unsupported algorithm means.
#[must_use]
pub fn parse_digest_string(text: &str) -> Option<DigestString<'_>> {
    let (algorithm, hex) = text.split_once(':')?;
    if !is_algorithm_name(algorithm) {
        return None;
    }
    if hex.is_empty()
        || hex.len() > 128
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return None;
    }
    Some(DigestString { algorithm, hex })
}

/// True when `text` is a `sha256:<64 lowercase hex>` digest string.
#[must_use]
pub fn is_sha256_digest(text: &str) -> bool {
    match parse_digest_string(text) {
        Some(digest) => digest.algorithm == "sha256" && digest.hex.len() == 64,
        None => false,
    }
}

/// Returns the raw 32 digest bytes of a `sha256` digest string, if it is one.
#[must_use]
pub fn sha256_digest_bytes(text: &str) -> Option<[u8; 32]> {
    if !is_sha256_digest(text) {
        return None;
    }
    let hex = text.split_once(':')?.1;
    let mut bytes = [0u8; 32];
    for (index, pair) in hex.as_bytes().chunks(2).enumerate() {
        let high = hex_value(pair[0])?;
        let low = hex_value(pair[1])?;
        bytes[index] = (high << 4) | low;
    }
    Some(bytes)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

/// Algorithm-name token grammar (§2.7, §4.3): `^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$`,
/// at most 32 bytes.
#[must_use]
pub fn is_algorithm_name(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.is_empty() || bytes.len() > 32 {
        return false;
    }
    if !bytes[0].is_ascii_lowercase() {
        return false;
    }
    let mut previous_dash = false;
    for &byte in &bytes[1..] {
        match byte {
            b'a'..=b'z' | b'0'..=b'9' => previous_dash = false,
            b'-' => {
                if previous_dash {
                    return false;
                }
                previous_dash = true;
            }
            _ => return false,
        }
    }
    !previous_dash
}

/// Key id (§2.5): `ed25519:` plus the first 32 lowercase hex characters of
/// SHA-256 over the 32 raw public-key bytes.
#[must_use]
pub fn derive_key_id(public_key: &[u8]) -> String {
    let hash = sha256(public_key);
    let hex = to_lower_hex(&hash);
    format!("ed25519:{}", &hex[..32])
}

/// True when `text` is a syntactically valid ed25519 key id (§2.5).
#[must_use]
pub fn is_valid_key_id(text: &str) -> bool {
    let Some(hex) = text.strip_prefix("ed25519:") else {
        return false;
    };
    hex.len() == 32
        && hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
