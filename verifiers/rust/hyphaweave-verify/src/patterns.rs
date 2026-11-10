// SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
// SPDX-License-Identifier: Apache-2.0

//! String grammars shared by the envelope, kind pages and container.
//!
//! The specification writes its grammars as regular expressions; they are
//! implemented as small hand-written scanners so the verifier needs no regex
//! dependency and so each rejection point is explicit.

/// True when `text` is a kind name (§7.1): `^[a-z][a-z0-9]*(?:[.-][a-z][a-z0-9]*)*$`,
/// at most 128 bytes. A kind name must contain a project segment (no bare name).
#[must_use]
pub fn is_kind_name(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.is_empty() || bytes.len() > 128 {
        return false;
    }
    let mut index = 0;
    // First segment: [a-z][a-z0-9]*
    if !bytes[0].is_ascii_lowercase() {
        return false;
    }
    index += 1;
    while index < bytes.len()
        && (bytes[index].is_ascii_lowercase() || bytes[index].is_ascii_digit())
    {
        index += 1;
    }
    // Subsequent segments: [.-][a-z][a-z0-9]*
    let mut has_separator = false;
    while index < bytes.len() {
        let separator = bytes[index];
        if separator != b'.' && separator != b'-' {
            return false;
        }
        has_separator = true;
        index += 1;
        if index >= bytes.len() || !bytes[index].is_ascii_lowercase() {
            return false;
        }
        index += 1;
        while index < bytes.len()
            && (bytes[index].is_ascii_lowercase() || bytes[index].is_ascii_digit())
        {
            index += 1;
        }
    }
    has_separator
}

/// True when `text` is a project slug (§4.1):
/// `^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$`, at most 64 bytes.
#[must_use]
pub fn is_project_slug(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.is_empty() || bytes.len() > 64 {
        return false;
    }
    if !bytes[0].is_ascii_lowercase() {
        return false;
    }
    let mut index = 1;
    while index < bytes.len()
        && (bytes[index].is_ascii_lowercase() || bytes[index].is_ascii_digit())
    {
        index += 1;
    }
    while index < bytes.len() {
        if bytes[index] != b'-' {
            return false;
        }
        index += 1;
        let start = index;
        while index < bytes.len()
            && (bytes[index].is_ascii_lowercase() || bytes[index].is_ascii_digit())
        {
            index += 1;
        }
        if index == start {
            return false;
        }
    }
    true
}

/// True when `text` is an envelope `id` (§4.1): 1–256 Unicode scalar values, no
/// C0/C1 control characters or DEL, and no leading or trailing U+0020 space.
#[must_use]
pub fn is_envelope_id(text: &str) -> bool {
    let mut count = 0usize;
    for character in text.chars() {
        count += 1;
        if count > 256 {
            return false;
        }
        let code = character as u32;
        if code <= 0x1F || (0x7F..=0x9F).contains(&code) {
            return false;
        }
    }
    if count == 0 {
        return false;
    }
    !text.starts_with(' ') && !text.ends_with(' ')
}

/// True when `text` is an actor idempotency key (§4.2): 1–256 Unicode scalar
/// values with no control characters.
#[must_use]
pub fn is_idempotency_key(text: &str) -> bool {
    let mut count = 0usize;
    for character in text.chars() {
        count += 1;
        if count > 256 || character.is_control() {
            return false;
        }
    }
    count > 0
}

/// True when `text` is an actor `model` string (§4.2):
/// `^[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*@[A-Za-z0-9][A-Za-z0-9._+-]*$`,
/// ASCII, at most 256 bytes.
#[must_use]
pub fn is_model_string(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.is_empty() || bytes.len() > 256 {
        return false;
    }
    let mut index = 0;
    if !is_ascii_alnum(bytes[0]) {
        return false;
    }
    while index < bytes.len() && is_model_provider_character(bytes[index]) {
        index += 1;
    }
    if index >= bytes.len() || bytes[index] != b'/' {
        return false;
    }
    index += 1;
    if index >= bytes.len() || !is_ascii_alnum(bytes[index]) {
        return false;
    }
    while index < bytes.len() && is_model_provider_character(bytes[index]) {
        index += 1;
    }
    if index >= bytes.len() || bytes[index] != b'@' {
        return false;
    }
    index += 1;
    if index >= bytes.len() || !is_ascii_alnum(bytes[index]) {
        return false;
    }
    while index < bytes.len() && is_model_version_character(bytes[index]) {
        index += 1;
    }
    index == bytes.len()
}

fn is_ascii_alnum(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_uppercase() || byte.is_ascii_digit()
}

fn is_model_provider_character(byte: u8) -> bool {
    is_ascii_alnum(byte) || matches!(byte, b'.' | b'_' | b'-')
}

fn is_model_version_character(byte: u8) -> bool {
    is_ascii_alnum(byte) || matches!(byte, b'.' | b'_' | b'+' | b'-')
}

/// True when `text` is a reference hint (§6.1): `^[A-Za-z][A-Za-z0-9+.-]*:[^\s]+$`
/// and at most 2048 UTF-8 bytes. Hints are never fetched.
#[must_use]
pub fn is_uri_hint(text: &str) -> bool {
    if text.is_empty() || text.len() > 2048 {
        return false;
    }
    let mut characters = text.chars();
    let Some(first) = characters.next() else {
        return false;
    };
    if !first.is_ascii_alphabetic() {
        return false;
    }
    let mut rest = characters.peekable();
    loop {
        match rest.peek() {
            Some(character)
                if character.is_ascii_alphanumeric() || matches!(character, '+' | '.' | '-') =>
            {
                rest.next();
            }
            _ => break,
        }
    }
    if rest.next() != Some(':') {
        return false;
    }
    let mut has_content = false;
    for character in rest {
        if character.is_whitespace() {
            return false;
        }
        has_content = true;
    }
    has_content
}

/// True when `text` is a valid UTF-8 string of at most `limit` scalar values
/// (used for body string-length rules).
#[must_use]
pub fn scalars_at_most(text: &str, limit: usize) -> bool {
    text.chars().count() <= limit
}

/// True when `text` has between `min` and `max` Unicode scalar values.
#[must_use]
pub fn scalars_between(text: &str, min: usize, max: usize) -> bool {
    let count = text.chars().count();
    (min..=max).contains(&count)
}
