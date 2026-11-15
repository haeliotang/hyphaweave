// SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
// SPDX-License-Identifier: Apache-2.0

//! WR-CJ v1 parser and canonical writer.
//!
//! The specification (§1) requires one decision per byte pass: the first
//! violation in input byte order determines the reported code, duplicate
//! members are rejected at any depth, only integers are allowed, and the file
//! must equal the canonical serialization (optionally plus exactly one LF).
//! A general-purpose JSON library cannot provide that classification, so this
//! module implements the parser and the writer itself.
//!
//! UTF-8 validity is a whole-input precondition (§1.9): an input that is not
//! valid UTF-8 is `E_JSON_INVALID` before any per-position classification.
//!
//! Nesting depth is bounded by `MAX_JSON_DEPTH` (§13): the depth of every value
//! is checked before the parser reads it, so a hostile input stops at its first
//! too-deep value (S3). Neither the parser nor the writer recurses: open
//! containers are kept on a heap stack, so their stack use is the same at depth
//! 1 and at depth `MAX_JSON_DEPTH` (H1-FIX1 R6). Bounded recursion was not
//! enough: in a debug build each parser level took 1.3 KiB (array) to 1.7 KiB
//! (object) of stack on aarch64-apple-darwin, so 32 levels alone took 43 to 56
//! KiB of a thread's stack. `Value`'s `Clone` and `Drop` do not recurse either
//! (see [`Value`]); only the derived `PartialEq` and `Debug` do, on values of
//! at most `MAX_JSON_DEPTH` levels.

use std::cmp::Ordering;
use std::collections::HashSet;

use crate::error_codes::{e, Code};
use crate::value::{Object, Value};

/// A JSON syntax/shape violation together with the byte offset at which it was
/// detected. The code is the §1.9 classification; the offset is diagnostic only
/// and never appears in a report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JsonError {
    /// Registry code for the violation.
    pub code: Code,
    /// Byte offset in the input.
    pub offset: usize,
}

impl JsonError {
    const fn at(code: Code, offset: usize) -> Self {
        Self { code, offset }
    }
}

/// `MAX_JSON_DEPTH` (§13): the top-level value is depth 1, every member value
/// and array element is one level deeper than its container, and a scalar is a
/// leaf at its own depth. A deeper value is `E_JSON_SIZE` (§1.9, S3).
const MAX_DEPTH: usize = crate::limits::MAX_JSON_DEPTH;

/// §1.9 preconditions shared by every entry point: the input must be UTF-8
/// (whole-input precondition, T17/A-L6) and must not start with a BOM.
fn check_preconditions(bytes: &[u8]) -> Result<(), JsonError> {
    if let Err(error) = std::str::from_utf8(bytes) {
        return Err(JsonError::at(e::JSON_INVALID, error.valid_up_to()));
    }
    if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        // A byte-order mark is not part of WR-CJ input (§1.2).
        return Err(JsonError::at(e::JSON_INVALID, 0));
    }
    Ok(())
}

/// Parses a WR-CJ document and requires its top-level value to be an object.
///
/// This is the syntax pass only; canonical byte form is checked by
/// [`parse_canonical_object`]. Returns the first violation in input byte order.
///
/// "Top-level value not an object where an object is required" (§1.9) is a
/// property of the whole value, so it is decided once the value has been
/// read: a violation inside the value — a depth above `MAX_JSON_DEPTH`
/// (`E_JSON_SIZE`), an integer out of range (`E_JSON_NUMBER_RANGE`), any other
/// class of the stage-one pass — is reported first (S2 review A low-1: a
/// 33-level array is `E_JSON_SIZE`, a top-level `18446744073709551616` is
/// `E_JSON_NUMBER_RANGE`).
pub fn parse_object(bytes: &[u8]) -> Result<Object, JsonError> {
    check_preconditions(bytes)?;
    let mut parser = Parser { bytes, pos: 0 };
    parser.skip_whitespace();
    let start = parser.pos;
    let mut value = parser.parse_value()?;
    parser.skip_whitespace();
    if parser.pos != bytes.len() {
        // Trailing non-whitespace content (a second value, a comment, junk).
        return Err(JsonError::at(e::JSON_INVALID, parser.pos));
    }
    // `Value` implements `Drop`, so the object is taken out, not moved out.
    let Value::Object(object) = &mut value else {
        return Err(JsonError::at(e::JSON_INVALID, start));
    };
    Ok(std::mem::take(object))
}

/// Parses any JSON value (WR-CJ input restrictions: no floats, integer range,
/// duplicate members rejected). Used by external canonicalization cross-checks;
/// every `weave-record/1` target requires an object and uses
/// [`parse_object`]/[`parse_canonical_object`].
pub fn parse_value(bytes: &[u8]) -> Result<Value, JsonError> {
    check_preconditions(bytes)?;
    let mut parser = Parser { bytes, pos: 0 };
    parser.skip_whitespace();
    let value = parser.parse_value()?;
    parser.skip_whitespace();
    if parser.pos != bytes.len() {
        return Err(JsonError::at(e::JSON_INVALID, parser.pos));
    }
    Ok(value)
}

/// Parses a file that must be in canonical file form (§1.8): the exact WR-CJ
/// bytes of its value, optionally followed by exactly one LF.
///
/// `max_bytes` is the §13 size limit for this file class; exceeding it is
/// `E_JSON_SIZE`, checked before any parsing.
pub fn parse_canonical_object(bytes: &[u8], max_bytes: usize) -> Result<Object, Code> {
    if bytes.len() > max_bytes {
        return Err(e::JSON_SIZE);
    }
    let object = parse_object(bytes).map_err(|error| error.code)?;
    if !is_canonical_file_form(bytes, &object) {
        return Err(e::JSON_NOT_CANONICAL);
    }
    Ok(object)
}

/// True when `bytes` is exactly the WR-CJ serialization of `object`, optionally
/// followed by one LF.
#[must_use]
pub fn is_canonical_file_form(bytes: &[u8], object: &Object) -> bool {
    let canonical = canonical_object_bytes(object);
    if bytes == canonical.as_slice() {
        return true;
    }
    bytes.len() == canonical.len() + 1
        && bytes.last() == Some(&b'\n')
        && bytes[..canonical.len()] == canonical
}

/// Serializes an object in WR-CJ form (no trailing LF).
#[must_use]
pub fn canonical_object_bytes(object: &Object) -> Vec<u8> {
    let mut out = Vec::new();
    write_object(&mut out, object);
    out
}

/// Serializes a value in WR-CJ form (no trailing LF).
#[must_use]
pub fn canonical_value_bytes(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    write_value(&mut out, value);
    out
}

/// Compares two strings by their UTF-16 code-unit sequences (§1.3). This is not
/// the same order as UTF-8 byte order for supplementary code points.
#[must_use]
pub fn utf16_cmp(left: &str, right: &str) -> Ordering {
    let mut left_units = left.encode_utf16();
    let mut right_units = right.encode_utf16();
    loop {
        match (left_units.next(), right_units.next()) {
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(a), Some(b)) => match a.cmp(&b) {
                Ordering::Equal => {}
                ordering => return ordering,
            },
        }
    }
}

/// A container the writer has opened and not yet closed, with the children
/// still to write.
enum Open<'a> {
    Array {
        items: std::slice::Iter<'a, Value>,
        first: bool,
    },
    Object {
        members: std::vec::IntoIter<(&'a str, &'a Value)>,
        first: bool,
    },
}

fn write_value(out: &mut Vec<u8>, value: &Value) {
    let mut open = Vec::new();
    start_value(out, value, &mut open);
    finish(out, &mut open);
}

fn write_object(out: &mut Vec<u8>, object: &Object) {
    let mut open = Vec::new();
    start_object(out, object, &mut open);
    finish(out, &mut open);
}

/// Writes a scalar completely; for a container writes only its opening
/// bracket and pushes it onto `open`.
fn start_value<'a>(out: &mut Vec<u8>, value: &'a Value, open: &mut Vec<Open<'a>>) {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Int(number) => out.extend_from_slice(number.to_string().as_bytes()),
        Value::Str(text) => write_string(out, text),
        Value::Array(items) => {
            out.push(b'[');
            open.push(Open::Array {
                items: items.iter(),
                first: true,
            });
        }
        Value::Object(object) => start_object(out, object, open),
    }
}

fn start_object<'a>(out: &mut Vec<u8>, object: &'a Object, open: &mut Vec<Open<'a>>) {
    let mut members: Vec<(&str, &Value)> = object.iter().collect();
    members.sort_by(|(left, _), (right, _)| utf16_cmp(left, right));
    out.push(b'{');
    open.push(Open::Object {
        members: members.into_iter(),
        first: true,
    });
}

/// Writes the remaining children and closing brackets of every open
/// container. Open containers live on the heap stack `open`, so the stack use
/// of the writer does not depend on the nesting depth (S3, H1-FIX1 R6).
fn finish(out: &mut Vec<u8>, open: &mut Vec<Open<'_>>) {
    while let Some(innermost) = open.last_mut() {
        let next = match innermost {
            Open::Array { items, first } => match items.next() {
                Some(item) => {
                    if !std::mem::replace(first, false) {
                        out.push(b',');
                    }
                    Some(item)
                }
                None => {
                    out.push(b']');
                    None
                }
            },
            Open::Object { members, first } => match members.next() {
                Some((name, value)) => {
                    if !std::mem::replace(first, false) {
                        out.push(b',');
                    }
                    write_string(out, name);
                    out.push(b':');
                    Some(value)
                }
                None => {
                    out.push(b'}');
                    None
                }
            },
        };
        match next {
            Some(value) => start_value(out, value, open),
            None => {
                open.pop();
            }
        }
    }
}

fn write_string(out: &mut Vec<u8>, text: &str) {
    out.push(b'"');
    for character in text.chars() {
        match character {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\u{0008}' => out.extend_from_slice(b"\\b"),
            '\u{0009}' => out.extend_from_slice(b"\\t"),
            '\u{000A}' => out.extend_from_slice(b"\\n"),
            '\u{000C}' => out.extend_from_slice(b"\\f"),
            '\u{000D}' => out.extend_from_slice(b"\\r"),
            control if (control as u32) < 0x20 => {
                const HEX: &[u8; 16] = b"0123456789abcdef";
                let value = control as usize;
                out.extend_from_slice(b"\\u00");
                out.push(HEX[(value >> 4) & 0xF]);
                out.push(HEX[value & 0xF]);
            }
            other => {
                let mut buffer = [0u8; 4];
                out.extend_from_slice(other.encode_utf8(&mut buffer).as_bytes());
            }
        }
    }
    out.push(b'"');
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

/// A container the parser has opened and not yet closed.
enum Container {
    /// The elements read so far.
    Array(Vec<Value>),
    /// The members read so far, every member name seen (duplicates are
    /// rejected, §1.9) and the name whose value is being read.
    Object {
        object: Object,
        seen: HashSet<String>,
        name: String,
    },
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let byte = self.peek()?;
        self.pos += 1;
        Some(byte)
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    fn error(&self, code: Code) -> JsonError {
        JsonError::at(code, self.pos)
    }

    /// Reads one object member name and the `:` after it, and leaves the
    /// position at the start of the member value.
    fn parse_member_name(&mut self, seen: &mut HashSet<String>) -> Result<String, JsonError> {
        self.skip_whitespace();
        if self.peek() != Some(b'"') {
            return Err(self.error(e::JSON_INVALID));
        }
        let name_offset = self.pos;
        let name = self.parse_string()?;
        // §1.9: a duplicate member name is the first violation at the
        // position of the repeated name, before its value is parsed. The
        // specification example `{"a":1,"a":1.5}` is therefore a duplicate,
        // not a float.
        if !seen.insert(name.clone()) {
            return Err(JsonError::at(e::JSON_DUPLICATE_KEY, name_offset));
        }
        self.skip_whitespace();
        if self.peek() != Some(b':') {
            return Err(self.error(e::JSON_INVALID));
        }
        self.pos += 1;
        self.skip_whitespace();
        Ok(name)
    }

    /// Parses one value starting at the current position.
    ///
    /// Open containers live on the heap stack `open`, not on the call stack, so
    /// the stack use of the parser does not depend on the nesting depth (S3,
    /// H1-FIX1 R6). The depth of every value is checked before the value is
    /// read or its container opened, so `open` never holds more than
    /// `MAX_JSON_DEPTH` containers and a too-deep input stops at its first
    /// too-deep value.
    fn parse_value(&mut self) -> Result<Value, JsonError> {
        let mut open: Vec<Container> = Vec::new();
        loop {
            // A value at depth `open.len() + 1` starts here.
            if open.len() + 1 > MAX_DEPTH {
                // §1.9: a depth violation is `E_JSON_SIZE`, at the position of
                // the first value that is too deep (scalars included).
                return Err(self.error(e::JSON_SIZE));
            }
            let mut value = match self.peek() {
                None => return Err(self.error(e::JSON_INVALID)),
                Some(b'{') => {
                    self.pos += 1;
                    self.skip_whitespace();
                    if self.peek() == Some(b'}') {
                        self.pos += 1;
                        Value::Object(Object::new())
                    } else {
                        let mut seen = HashSet::new();
                        let name = self.parse_member_name(&mut seen)?;
                        open.push(Container::Object {
                            object: Object::new(),
                            seen,
                            name,
                        });
                        continue;
                    }
                }
                Some(b'[') => {
                    self.pos += 1;
                    self.skip_whitespace();
                    if self.peek() == Some(b']') {
                        self.pos += 1;
                        Value::Array(Vec::new())
                    } else {
                        open.push(Container::Array(Vec::new()));
                        continue;
                    }
                }
                Some(b'"') => Value::Str(self.parse_string()?),
                Some(b't') => self.parse_literal(b"true", Value::Bool(true))?,
                Some(b'f') => self.parse_literal(b"false", Value::Bool(false))?,
                Some(b'n') => self.parse_literal(b"null", Value::Null)?,
                Some(b'-' | b'0'..=b'9') => self.parse_number()?,
                Some(_) => return Err(self.error(e::JSON_INVALID)),
            };
            // `value` is complete: add it to the innermost open container, then
            // either start that container's next value or close the container
            // and continue with the container as the completed value.
            loop {
                let Some(container) = open.last_mut() else {
                    return Ok(value);
                };
                self.skip_whitespace();
                match container {
                    Container::Array(items) => {
                        items.push(value);
                        match self.peek() {
                            Some(b',') => {
                                self.pos += 1;
                                self.skip_whitespace();
                                break;
                            }
                            Some(b']') => self.pos += 1,
                            _ => return Err(self.error(e::JSON_INVALID)),
                        }
                    }
                    Container::Object { object, seen, name } => {
                        object.insert(std::mem::take(name), value);
                        match self.peek() {
                            Some(b',') => {
                                self.pos += 1;
                                *name = self.parse_member_name(seen)?;
                                break;
                            }
                            Some(b'}') => self.pos += 1,
                            _ => return Err(self.error(e::JSON_INVALID)),
                        }
                    }
                }
                value = match open.pop() {
                    Some(Container::Array(items)) => Value::Array(items),
                    Some(Container::Object { object, .. }) => Value::Object(object),
                    None => unreachable!("the innermost container was just read"),
                };
            }
        }
    }

    fn parse_literal(&mut self, text: &[u8], value: Value) -> Result<Value, JsonError> {
        if self.bytes[self.pos..].starts_with(text) {
            self.pos += text.len();
            Ok(value)
        } else {
            Err(self.error(e::JSON_INVALID))
        }
    }

    fn parse_number(&mut self) -> Result<Value, JsonError> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        match self.peek() {
            Some(b'0') => {
                self.pos += 1;
                if matches!(self.peek(), Some(b'0'..=b'9')) {
                    // A leading zero is not valid JSON.
                    return Err(self.error(e::JSON_INVALID));
                }
            }
            Some(b'1'..=b'9') => {
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.pos += 1;
                }
            }
            _ => return Err(self.error(e::JSON_INVALID)),
        }
        let mut is_float = false;
        if self.peek() == Some(b'.') {
            is_float = true;
            self.pos += 1;
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(self.error(e::JSON_INVALID));
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            is_float = true;
            self.pos += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(self.error(e::JSON_INVALID));
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        if is_float {
            // A syntactically valid JSON number with a fraction or exponent.
            return Err(self.error(e::JSON_NUMBER_NOT_INTEGER));
        }
        let token = std::str::from_utf8(&self.bytes[start..self.pos])
            .map_err(|_| JsonError::at(e::JSON_INVALID, start))?;
        if token == "-0" {
            // §1.6/§1.9 (S8④): `-0` is a canonical-form deviation classified at
            // its number token during the syntax/number pass.
            return Err(JsonError::at(e::JSON_NOT_CANONICAL, start));
        }
        // Integer syntax was validated above, so a parse failure can only be
        // overflow: a syntactically valid integer outside the representable
        // range, which is `E_JSON_NUMBER_RANGE`.
        let number: i128 = match token.parse() {
            Ok(number) => number,
            Err(_) => return Err(JsonError::at(e::JSON_NUMBER_RANGE, start)),
        };
        const MAX_INT: i128 = (1i128 << 53) - 1;
        if !(-MAX_INT..=MAX_INT).contains(&number) {
            return Err(JsonError::at(e::JSON_NUMBER_RANGE, start));
        }
        Ok(Value::Int(number as i64))
    }

    fn parse_string(&mut self) -> Result<String, JsonError> {
        debug_assert_eq!(self.peek(), Some(b'"'));
        self.pos += 1;
        let mut text = String::new();
        loop {
            let chunk_start = self.pos;
            while let Some(byte) = self.peek() {
                if byte == b'"' || byte == b'\\' || byte < 0x20 {
                    break;
                }
                self.pos += 1;
            }
            if self.pos > chunk_start {
                let chunk = std::str::from_utf8(&self.bytes[chunk_start..self.pos])
                    .map_err(|_| JsonError::at(e::JSON_INVALID, chunk_start))?;
                text.push_str(chunk);
            }
            match self.bump() {
                Some(b'"') => return Ok(text),
                Some(b'\\') => {
                    let escape_offset = self.pos - 1;
                    match self.bump() {
                        Some(b'"') => text.push('"'),
                        Some(b'\\') => text.push('\\'),
                        Some(b'/') => text.push('/'),
                        Some(b'b') => text.push('\u{0008}'),
                        Some(b'f') => text.push('\u{000C}'),
                        Some(b'n') => text.push('\u{000A}'),
                        Some(b'r') => text.push('\u{000D}'),
                        Some(b't') => text.push('\u{0009}'),
                        Some(b'u') => {
                            let first = self.parse_hex4()?;
                            let character = if (0xD800..=0xDBFF).contains(&first) {
                                // A high surrogate must be followed by a low
                                // surrogate escape to form a scalar value.
                                if self.peek() != Some(b'\\')
                                    || self.bytes.get(self.pos + 1) != Some(&b'u')
                                {
                                    return Err(JsonError::at(
                                        e::JSON_LONE_SURROGATE,
                                        escape_offset,
                                    ));
                                }
                                self.pos += 2;
                                let second = self.parse_hex4()?;
                                if !(0xDC00..=0xDFFF).contains(&second) {
                                    return Err(JsonError::at(
                                        e::JSON_LONE_SURROGATE,
                                        escape_offset,
                                    ));
                                }
                                let scalar = 0x1_0000
                                    + ((u32::from(first) - 0xD800) << 10)
                                    + (u32::from(second) - 0xDC00);
                                char::from_u32(scalar)
                                    .ok_or_else(|| self.error(e::JSON_LONE_SURROGATE))?
                            } else if (0xDC00..=0xDFFF).contains(&first) {
                                return Err(JsonError::at(e::JSON_LONE_SURROGATE, escape_offset));
                            } else {
                                char::from_u32(u32::from(first))
                                    .ok_or_else(|| self.error(e::JSON_INVALID))?
                            };
                            text.push(character);
                        }
                        _ => return Err(JsonError::at(e::JSON_INVALID, escape_offset)),
                    }
                }
                Some(_) => {
                    // A raw control character inside a string.
                    return Err(JsonError::at(e::JSON_INVALID, chunk_start));
                }
                None => return Err(self.error(e::JSON_INVALID)),
            }
        }
    }

    fn parse_hex4(&mut self) -> Result<u16, JsonError> {
        let start = self.pos;
        if self.pos + 4 > self.bytes.len() {
            return Err(self.error(e::JSON_INVALID));
        }
        let digits = &self.bytes[start..start + 4];
        let mut value: u16 = 0;
        for &byte in digits {
            let digit = match byte {
                b'0'..=b'9' => u16::from(byte - b'0'),
                b'a'..=b'f' => u16::from(byte - b'a') + 10,
                b'A'..=b'F' => u16::from(byte - b'A') + 10,
                _ => return Err(JsonError::at(e::JSON_INVALID, start)),
            };
            value = value * 16 + digit;
        }
        self.pos += 4;
        Ok(value)
    }
}
