// SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
// SPDX-License-Identifier: Apache-2.0

//! Strict unpadded base64url (RFC 4648 §5) as required by §2.6.
//!
//! Padding, whitespace, `+`, `/` and non-zero unused trailing bits are all
//! rejected; the decoder never trims padding. Callers map a decode failure to
//! the error code of the field they are decoding.

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn decode_symbol(byte: u8) -> Option<u32> {
    match byte {
        b'A'..=b'Z' => Some(u32::from(byte - b'A')),
        b'a'..=b'z' => Some(u32::from(byte - b'a') + 26),
        b'0'..=b'9' => Some(u32::from(byte - b'0') + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

/// Decodes strict unpadded base64url.
///
/// # Errors
/// Returns `Err(())` for padding, any character outside the alphabet, a length
/// that cannot be produced without padding (1 mod 4), or non-zero unused
/// trailing bits.
pub fn decode(text: &str) -> Result<Vec<u8>, ()> {
    let bytes = text.as_bytes();
    if bytes.len() % 4 == 1 {
        return Err(());
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3 + 2);
    let mut accumulator: u32 = 0;
    let mut bits: u32 = 0;
    for &byte in bytes {
        let symbol = decode_symbol(byte).ok_or(())?;
        accumulator = (accumulator << 6) | symbol;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((accumulator >> bits) as u8);
            accumulator &= (1 << bits) - 1;
        }
    }
    if bits > 0 && accumulator != 0 {
        // Non-zero unused trailing bits: a padded/redundant encoding.
        return Err(());
    }
    Ok(out)
}

/// Decodes strict unpadded base64url and requires exactly `expected` bytes.
pub fn decode_exact(text: &str, expected: usize) -> Result<Vec<u8>, ()> {
    let bytes = decode(text)?;
    if bytes.len() == expected {
        Ok(bytes)
    } else {
        Err(())
    }
}

/// Decodes strict unpadded base64url and requires a length in `min..=max`.
pub fn decode_range(text: &str, min: usize, max: usize) -> Result<Vec<u8>, ()> {
    let bytes = decode(text)?;
    if (min..=max).contains(&bytes.len()) {
        Ok(bytes)
    } else {
        Err(())
    }
}

/// Encodes bytes as unpadded base64url (used by tests and by report metadata;
/// the verifier itself never re-encodes signed material).
#[must_use]
pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let first = u32::from(chunk[0]);
        let second = chunk.get(1).map_or(0, |&byte| u32::from(byte));
        let third = chunk.get(2).map_or(0, |&byte| u32::from(byte));
        let group = (first << 16) | (second << 8) | third;
        out.push(char::from(ALPHABET[(group >> 18) as usize & 0x3F]));
        out.push(char::from(ALPHABET[(group >> 12) as usize & 0x3F]));
        if chunk.len() > 1 {
            out.push(char::from(ALPHABET[(group >> 6) as usize & 0x3F]));
        }
        if chunk.len() > 2 {
            out.push(char::from(ALPHABET[group as usize & 0x3F]));
        }
    }
    out
}
