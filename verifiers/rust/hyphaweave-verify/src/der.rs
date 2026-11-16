// SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
// SPDX-License-Identifier: Apache-2.0

//! A strict DER reader written from X.690 for §12.2 check 1 (1a).
//!
//! §12.2 requires the DER rules to come from X.690 and the ASN.1 module
//! definitions only, never from a parsing library's value model, default
//! objects or decoding habits (X1). This module therefore implements the TLV
//! layer itself:
//!
//! - [`read_tlv`] reads one TLV with the X.690 identifier and length rules of
//!   DER: the low-tag-number form for tag numbers 0–30 and the high-tag-number
//!   form (X.690 §8.1.2.4) for larger numbers, whose first subsequent octet is
//!   not `0x80`; definite, minimal lengths only.
//! - [`check_universal_rules`] applies the universal DER content rules (1a)
//!   to every TLV of an encoding, including values of types unknown to the
//!   verifier, **iteratively** (an explicit work list, never recursion), so a
//!   deeply nested hostile receipt cannot overflow the stack.
//!
//! Schema-directed decoding (1b/1c) is in [`crate::timestamp`]; it uses the
//! [`Tlv`] views produced here.

/// ASN.1 tag class (X.690 §8.1.2.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    /// Universal class.
    Universal,
    /// Application class.
    Application,
    /// Context-specific class.
    Context,
    /// Private class.
    Private,
}

/// A tag: class, constructed bit and tag number. A tag number too large for
/// `u64` is represented as `None`; it can never equal a tag of the schema.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tag {
    /// Tag class.
    pub class: Class,
    /// Constructed (`true`) or primitive encoding.
    pub constructed: bool,
    /// Tag number, when it fits in 64 bits.
    pub number: Option<u64>,
}

/// One TLV view into the input bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tlv<'a> {
    /// The identifier.
    pub tag: Tag,
    /// The content octets.
    pub content: &'a [u8],
    /// The whole encoding (identifier, length and content).
    pub raw: &'a [u8],
}

/// Universal tag numbers used by this crate.
pub mod universal {
    /// BOOLEAN.
    pub const BOOLEAN: u64 = 1;
    /// INTEGER.
    pub const INTEGER: u64 = 2;
    /// BIT STRING.
    pub const BIT_STRING: u64 = 3;
    /// OCTET STRING.
    pub const OCTET_STRING: u64 = 4;
    /// NULL.
    pub const NULL: u64 = 5;
    /// OBJECT IDENTIFIER.
    pub const OID: u64 = 6;
    /// ObjectDescriptor (a GraphicString, X.690 §8.23.5).
    pub const OBJECT_DESCRIPTOR: u64 = 7;
    /// EXTERNAL (constructed form only, X.690 §8.18).
    pub const EXTERNAL: u64 = 8;
    /// REAL (X.690 §8.5, §11.3).
    pub const REAL: u64 = 9;
    /// ENUMERATED.
    pub const ENUMERATED: u64 = 10;
    /// EMBEDDED PDV (constructed form only, X.690 §8.17).
    pub const EMBEDDED_PDV: u64 = 11;
    /// UTF8String.
    pub const UTF8_STRING: u64 = 12;
    /// RELATIVE-OID (X.690 §8.20).
    pub const RELATIVE_OID: u64 = 13;
    /// TIME (X.690 §8.25; rejected by §12.2 1a).
    pub const TIME: u64 = 14;
    /// SEQUENCE / SEQUENCE OF.
    pub const SEQUENCE: u64 = 16;
    /// SET / SET OF.
    pub const SET: u64 = 17;
    /// UTCTime.
    pub const UTC_TIME: u64 = 23;
    /// GeneralizedTime.
    pub const GENERALIZED_TIME: u64 = 24;
    /// UniversalString (four-octet units, X.690 §8.23.7).
    pub const UNIVERSAL_STRING: u64 = 28;
    /// CHARACTER STRING, the unrestricted character string type
    /// (constructed form only, X.690 §8.24).
    pub const CHARACTER_STRING: u64 = 29;
    /// BMPString (two-octet units, X.690 §8.23.8).
    pub const BMP_STRING: u64 = 30;
    /// DURATION (X.690 §8.25; rejected by §12.2 1a).
    pub const DURATION: u64 = 34;
}

impl Tlv<'_> {
    /// True for a universal tag with this number.
    #[must_use]
    pub fn is_universal(&self, number: u64) -> bool {
        self.tag.class == Class::Universal && self.tag.number == Some(number)
    }

    /// True for a context-specific tag with this number.
    #[must_use]
    pub fn is_context(&self, number: u64) -> bool {
        self.tag.class == Class::Context && self.tag.number == Some(number)
    }
}

/// A DER violation (§12.2 check 1). The reason is diagnostic only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DerError(pub &'static str);

/// Reads one TLV at the start of `input`; returns it and the remaining bytes.
///
/// # Errors
/// A truncated identifier/length/content, an indefinite or non-minimal
/// length, a high-tag-number form for a number below 31, or a high-tag-number
/// form whose first subsequent octet is `0x80` (X.690 §8.1.2.4.2 c).
pub fn read_tlv(input: &[u8]) -> Result<(Tlv<'_>, &[u8]), DerError> {
    let first = *input.first().ok_or(DerError("truncated identifier"))?;
    let class = match first >> 6 {
        0 => Class::Universal,
        1 => Class::Application,
        2 => Class::Context,
        _ => Class::Private,
    };
    let constructed = first & 0x20 != 0;
    let mut position = 1usize;
    let number = if first & 0x1F == 0x1F {
        // High-tag-number form: base-128 subsequent octets, bit 8 set on all
        // but the last; the first subsequent octet is not 0x80.
        let first_subsequent = *input
            .get(position)
            .ok_or(DerError("truncated high tag number"))?;
        if first_subsequent == 0x80 {
            return Err(DerError("non-minimal high tag number"));
        }
        let mut value: Option<u64> = Some(0);
        loop {
            let octet = *input
                .get(position)
                .ok_or(DerError("truncated high tag number"))?;
            position += 1;
            value = value
                .and_then(|current| current.checked_mul(128))
                .and_then(|current| current.checked_add(u64::from(octet & 0x7F)));
            if octet & 0x80 == 0 {
                break;
            }
        }
        if value.is_some_and(|number| number < 31) {
            return Err(DerError("high tag number form for a low tag number"));
        }
        value
    } else {
        Some(u64::from(first & 0x1F))
    };
    let length_octet = *input.get(position).ok_or(DerError("truncated length"))?;
    position += 1;
    let length: usize = if length_octet & 0x80 == 0 {
        usize::from(length_octet)
    } else {
        let count = usize::from(length_octet & 0x7F);
        if count == 0 {
            return Err(DerError("indefinite length"));
        }
        if count == 0x7F {
            return Err(DerError("reserved length octet"));
        }
        let bytes = input
            .get(position..position + count)
            .ok_or(DerError("truncated length"))?;
        if bytes[0] == 0 {
            return Err(DerError("non-minimal length"));
        }
        let mut value: usize = 0;
        for &byte in bytes {
            value = value
                .checked_mul(256)
                .and_then(|current| current.checked_add(usize::from(byte)))
                .ok_or(DerError("length overflow"))?;
        }
        if value < 128 {
            return Err(DerError("non-minimal length"));
        }
        position += count;
        value
    };
    let end = position
        .checked_add(length)
        .ok_or(DerError("length overflow"))?;
    let content = input
        .get(position..end)
        .ok_or(DerError("truncated content"))?;
    Ok((
        Tlv {
            tag: Tag {
                class,
                constructed,
                number,
            },
            content,
            raw: &input[..end],
        },
        &input[end..],
    ))
}

/// Reads exactly one TLV covering the whole input (no trailing data).
///
/// # Errors
/// As [`read_tlv`], plus trailing data.
pub fn read_single(input: &[u8]) -> Result<Tlv<'_>, DerError> {
    let (tlv, rest) = read_tlv(input)?;
    if !rest.is_empty() {
        return Err(DerError("trailing data"));
    }
    Ok(tlv)
}

/// Splits the content of a constructed TLV into its component TLVs.
///
/// # Errors
/// As [`read_tlv`] for every component.
pub fn children(content: &[u8]) -> Result<Vec<Tlv<'_>>, DerError> {
    let mut out = Vec::new();
    let mut rest = content;
    while !rest.is_empty() {
        let (tlv, next) = read_tlv(rest)?;
        out.push(tlv);
        rest = next;
    }
    Ok(out)
}

/// The DER ordering of SET OF components (X.690 §11.6): their encodings
/// compared as octet strings, the shorter padded with trailing zero octets.
/// Returns true when `left` must not precede `right` (i.e. `left > right`).
#[must_use]
pub fn der_greater(left: &[u8], right: &[u8]) -> bool {
    let length = left.len().max(right.len());
    for index in 0..length {
        let a = left.get(index).copied().unwrap_or(0);
        let b = right.get(index).copied().unwrap_or(0);
        if a != b {
            return a > b;
        }
    }
    false
}

/// True when the components are in ascending DER order (equal neighbours are
/// permitted in a SET OF).
#[must_use]
pub fn is_der_sorted(components: &[Tlv<'_>]) -> bool {
    components
        .windows(2)
        .all(|pair| !der_greater(pair[0].raw, pair[1].raw))
}

/// Applies the universal DER rules of §12.2 1a to every TLV of `input`, which
/// must be exactly one TLV. The walk is iterative.
///
/// # Errors
/// The first violation found.
pub fn check_universal_rules(input: &[u8]) -> Result<(), DerError> {
    let root = read_single(input)?;
    let mut work: Vec<Tlv<'_>> = vec![root];
    while let Some(tlv) = work.pop() {
        if tlv.tag.class == Class::Universal {
            check_universal_tlv(&tlv)?;
        }
        if tlv.tag.constructed {
            let components = children(tlv.content)?;
            // X.690 §11.6: every universal SET in these schemas is a SET OF,
            // so a universal SET (of known or unknown type) is in DER order.
            if tlv.is_universal(universal::SET) && !is_der_sorted(&components) {
                return Err(DerError("SET OF not in DER order"));
            }
            work.extend(components);
        }
    }
    Ok(())
}

/// Framing only (§12.2 1c, open types; §14.1 anchors): `input` is exactly one
/// TLV, every TLV has a valid identifier and a definite minimal length, and
/// the content of every constructed TLV is a sequence of such TLVs. No
/// content rule of 1a is applied. The walk is iterative.
///
/// # Errors
/// The first framing violation found.
pub fn check_framing(input: &[u8]) -> Result<(), DerError> {
    let root = read_single(input)?;
    let mut work: Vec<Tlv<'_>> = vec![root];
    while let Some(tlv) = work.pop() {
        if tlv.tag.constructed {
            work.extend(children(tlv.content)?);
        }
    }
    Ok(())
}

/// The universal primitive types that DER encodes in the primitive form only.
/// EXTERNAL (8), EMBEDDED PDV (11) and CHARACTER STRING (29) are the
/// opposite: X.690 §8.18, §8.17 and §8.24 define them as constructed
/// encodings, so `check_primitive_content` rejects their primitive form.
fn is_primitive_only(number: u64) -> bool {
    matches!(
        number,
        1..=7 | 9 | 10 | 12 | 13 | 14 | 18..=28 | 30..=36
    )
}

fn check_universal_tlv(tlv: &Tlv<'_>) -> Result<(), DerError> {
    let Some(number) = tlv.tag.number else {
        return Ok(());
    };
    if matches!(number, universal::SEQUENCE | universal::SET) {
        if !tlv.tag.constructed {
            return Err(DerError("primitive SEQUENCE/SET"));
        }
        return Ok(());
    }
    if tlv.tag.constructed {
        if is_primitive_only(number) || number == 0 {
            return Err(DerError("constructed form of a primitive type"));
        }
        return Ok(());
    }
    check_primitive_content(number, tlv.content)
}

/// True for the universal character string types: their content octets are
/// re-emitted as decoded by 1c (§12.2), so 1c judges no content rule of
/// theirs; 1a does.
fn is_character_string(number: u64) -> bool {
    matches!(number, 7 | 12 | 18..=22 | 25..=28 | 30)
}

/// The canonical-content rules that §12.2 1c applies to a typed primitive of
/// the schema ("rebuilt from its content octets by the X.690 rules for its
/// type"): every universal primitive rule of 1a except those of the character
/// string types, whose content 1c re-emits as decoded.
///
/// # Errors
/// The violated rule.
pub fn check_typed_content(number: u64, content: &[u8]) -> Result<(), DerError> {
    if is_character_string(number) {
        return Ok(());
    }
    check_primitive_content(number, content)
}

/// The canonical content rules of a universal primitive type (X.690 §8, §10,
/// §11), tag by tag as §12.2 1a lists them (S2-FIX1/T3). Also used by the
/// schema walker for implicitly tagged primitives.
///
/// # Errors
/// The violated rule.
pub fn check_primitive_content(number: u64, content: &[u8]) -> Result<(), DerError> {
    match number {
        0 => Err(DerError("universal tag 0")),
        // X.690 §8.18.1, §8.17.1, §8.24.1: these types are encoded as the
        // constructed encoding of their associated SEQUENCE type.
        universal::EXTERNAL | universal::EMBEDDED_PDV | universal::CHARACTER_STRING => {
            Err(DerError("primitive form of a constructed-only type"))
        }
        // §12.2 1a: TIME and DURATION are rejected wherever they occur, and so
        // are DATE, TIME-OF-DAY, DATE-TIME, OID-IRI and RELATIVE-OID-IRI
        // (S2-FIX2/U4 ③): none occurs in the RFC 3161, 5652 or 5280 modules.
        universal::TIME | universal::DURATION | 31 | 32 | 33 | 35 | 36 => {
            Err(DerError("type rejected by this profile"))
        }
        universal::REAL => check_real(content),
        universal::RELATIVE_OID => check_relative_oid(content),
        // §12.2 1a (X.690 §11.4, §8.23.5; S2-FIX2/U4 ②): the ISO 2022
        // register types.
        7 | 20 | 21 | 25 | 27 => check_iso2022(number, content),
        // X.690 §8.23.5.3 and Table 3, §8.23.10 (S2-FIX2/U4 ①): NumericString,
        // PrintableString, IA5String, VisibleString and UTF8String carry no
        // explicit escape sequence, so no ESC octet.
        18 | 19 | 22 | 26 if content.contains(&0x1B) => {
            Err(DerError("ESC in a string type without escape sequences"))
        }
        // X.690 §8.23.7 / §8.23.8: whole four-octet / two-octet units.
        universal::UNIVERSAL_STRING => {
            if content.len().is_multiple_of(4) {
                Ok(())
            } else {
                Err(DerError("UniversalString partial unit"))
            }
        }
        universal::BMP_STRING => {
            if content.len().is_multiple_of(2) {
                Ok(())
            } else {
                Err(DerError("BMPString partial unit"))
            }
        }

        universal::BOOLEAN => {
            if content == [0x00] || content == [0xFF] {
                Ok(())
            } else {
                Err(DerError("BOOLEAN not 0x00/0xFF"))
            }
        }
        universal::INTEGER | universal::ENUMERATED => check_integer(content),
        universal::BIT_STRING => check_bit_string(content).map(|_| ()),
        universal::NULL => {
            if content.is_empty() {
                Ok(())
            } else {
                Err(DerError("NULL with content"))
            }
        }
        universal::OID => check_oid(content),
        universal::UTF8_STRING => {
            if content.contains(&0x1B) {
                return Err(DerError("ESC in a string type without escape sequences"));
            }
            std::str::from_utf8(content)
                .map(|_| ())
                .map_err(|_| DerError("UTF8String not UTF-8"))
        }
        universal::UTC_TIME => {
            if is_utc_time_form(content) {
                Ok(())
            } else {
                Err(DerError("UTCTime not in DER form"))
            }
        }
        universal::GENERALIZED_TIME => {
            if is_generalized_time_form(content) {
                Ok(())
            } else {
                Err(DerError("GeneralizedTime not in DER form"))
            }
        }
        _ => Ok(()),
    }
}

/// INTEGER: non-empty, shortest two's-complement form (X.690 §8.3.2).
///
/// # Errors
/// Empty content or a redundant leading `0x00`/`0xFF` octet.
pub fn check_integer(content: &[u8]) -> Result<(), DerError> {
    match content {
        [] => Err(DerError("empty INTEGER")),
        [0x00, second, ..] if second & 0x80 == 0 => Err(DerError("non-minimal INTEGER")),
        [0xFF, second, ..] if second & 0x80 != 0 => Err(DerError("non-minimal INTEGER")),
        _ => Ok(()),
    }
}

/// BIT STRING: the unused-bit count is 0–7, 0 when there are no content octets,
/// and the unused bits are zero (X.690 §11.2). Returns the unused-bit count.
///
/// # Errors
/// The violated rule.
pub fn check_bit_string(content: &[u8]) -> Result<u8, DerError> {
    let (&unused, bits) = content.split_first().ok_or(DerError("empty BIT STRING"))?;
    if unused > 7 {
        return Err(DerError("BIT STRING unused bits above 7"));
    }
    match bits.last() {
        None => {
            if unused != 0 {
                return Err(DerError("BIT STRING unused bits without content"));
            }
        }
        Some(last) => {
            let mask = (1u16 << unused) - 1;
            if u16::from(*last) & mask != 0 {
                return Err(DerError("BIT STRING unused bits not zero"));
            }
        }
    }
    Ok(unused)
}

/// OBJECT IDENTIFIER: non-empty, minimal sub-identifiers, complete last one.
///
/// # Errors
/// The violated rule.
pub fn check_oid(content: &[u8]) -> Result<(), DerError> {
    if content.is_empty() {
        return Err(DerError("empty OBJECT IDENTIFIER"));
    }
    let mut at_start = true;
    for &octet in content {
        if at_start && octet == 0x80 {
            return Err(DerError("non-minimal OID sub-identifier"));
        }
        at_start = octet & 0x80 == 0;
    }
    if !at_start {
        return Err(DerError("truncated OID sub-identifier"));
    }
    Ok(())
}

/// A register entry named by a designating escape sequence: the class of
/// set and the octets that follow the class intermediates (further
/// intermediates and the final octet).
type RegisterEntry<'a> = (SetClass, &'a [u8]);

/// The class of a designated set (ISO/IEC 2022).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SetClass {
    /// 94-character graphic set.
    G94,
    /// 96-character graphic set.
    G96,
    /// 94^n-character graphic set.
    G94N,
    /// 96^n-character graphic set.
    G96N,
    /// C0 control set.
    C0,
    /// C1 control set.
    C1,
}

/// The ISO 2022 register types of §12.2 1a (S2-FIX2/U4 ②): starting from the
/// designations X.690 Table 3 assumes for the type (§8.23.5.2), every ESC
/// begins a complete escape sequence (intermediates `0x20`–`0x2F`, then a
/// final `0x30`–`0x7E`); no announcer (`ESC 2/0 F`, §8.23.5.4); and a
/// designating sequence neither names an entry already designated as G0–G3,
/// C0 or C1 nor designates into a G set other than the smallest one for its
/// class (G0 for 94-character sets, G1 for 96-character sets) (§11.4).
/// Whether an escape sequence is needed, and whether its entry is among the
/// type's registrations (§8.23.5.1), is not judged.
///
/// # Errors
/// The violated rule.
fn check_iso2022(number: u64, content: &[u8]) -> Result<(), DerError> {
    // G0, G1, G2, G3, C0, C1.
    let mut designated: [Option<RegisterEntry<'_>>; 6] = [None; 6];
    match number {
        // TeletexString: G0 102 (ESC 2/8 7/5), C0 106 (ESC 2/1 4/5), C1 107
        // (ESC 2/2 4/8).
        20 => {
            designated[0] = Some((SetClass::G94, &[0x75]));
            designated[4] = Some((SetClass::C0, &[0x45]));
            designated[5] = Some((SetClass::C1, &[0x48]));
        }
        // VideotexString: G0 102, C0 1 (ESC 2/1 4/0), C1 73 (ESC 2/2 4/1).
        21 => {
            designated[0] = Some((SetClass::G94, &[0x75]));
            designated[4] = Some((SetClass::C0, &[0x40]));
            designated[5] = Some((SetClass::C1, &[0x41]));
        }
        // GeneralString: G0 6 (ESC 2/8 4/2), C0 1.
        27 => {
            designated[0] = Some((SetClass::G94, &[0x42]));
            designated[4] = Some((SetClass::C0, &[0x40]));
        }
        // GraphicString and ObjectDescriptor (a GraphicString): G0 6.
        _ => designated[0] = Some((SetClass::G94, &[0x42])),
    }
    let mut position = 0usize;
    while let Some(offset) = content[position..].iter().position(|octet| *octet == 0x1B) {
        let start = position + offset + 1;
        let mut end = start;
        while content
            .get(end)
            .is_some_and(|octet| (0x20..=0x2F).contains(octet))
        {
            end += 1;
        }
        if !content
            .get(end)
            .is_some_and(|octet| (0x30..=0x7E).contains(octet))
        {
            return Err(DerError("incomplete ISO 2022 escape sequence"));
        }
        let sequence = &content[start..=end];
        position = end + 1;
        let (class, target, entry): (SetClass, usize, &[u8]) = match sequence {
            [0x20, ..] => return Err(DerError("ISO 2022 announcer")),
            [0x21, rest @ ..] => (SetClass::C0, 4, rest),
            [0x22, rest @ ..] => (SetClass::C1, 5, rest),
            [0x24, second @ 0x28..=0x2B, rest @ ..] => {
                (SetClass::G94N, usize::from(second - 0x28), rest)
            }
            [0x24, second @ 0x2D..=0x2F, rest @ ..] => {
                (SetClass::G96N, usize::from(second - 0x2C), rest)
            }
            [0x24, rest @ ..] => (SetClass::G94N, 0, rest),
            [first @ 0x28..=0x2B, rest @ ..] => (SetClass::G94, usize::from(first - 0x28), rest),
            [first @ 0x2D..=0x2F, rest @ ..] => (SetClass::G96, usize::from(first - 0x2C), rest),
            // Not a designation (an invocation, for example): not judged.
            _ => continue,
        };
        let key = (class, entry);
        if designated.contains(&Some(key)) {
            return Err(DerError("ISO 2022 re-designation of an entry in force"));
        }
        let smallest = match class {
            SetClass::G94 | SetClass::G94N => Some(0),
            SetClass::G96 | SetClass::G96N => Some(1),
            SetClass::C0 | SetClass::C1 => None,
        };
        if smallest.is_some_and(|smallest| smallest != target) {
            return Err(DerError("ISO 2022 designation into a larger G set"));
        }
        designated[target] = Some(key);
    }
    Ok(())
}

/// RELATIVE-OID: at least one sub-identifier, each in the fewest octets and
/// complete, as for OBJECT IDENTIFIER (X.690 §8.20).
///
/// # Errors
/// The violated rule.
pub fn check_relative_oid(content: &[u8]) -> Result<(), DerError> {
    check_oid(content).map_err(|_| DerError("RELATIVE-OID not canonical"))
}

/// REAL in DER (X.690 §8.5, §11.3; §12.2 1a): primitive (the caller), plus
/// zero as no content octets; binary base 2 with scaling factor 0, exponent
/// and mantissa each in the fewest octets (the long exponent format only for
/// four or more exponent octets), mantissa odd; decimal only in the NR3 form
/// of §11.3.2; special values exactly one octet `0x40`–`0x43`.
///
/// # Errors
/// The violated rule.
pub fn check_real(content: &[u8]) -> Result<(), DerError> {
    let Some((&first, rest)) = content.split_first() else {
        // §8.5.2: plus zero.
        return Ok(());
    };
    if first & 0x80 != 0 {
        // §8.5.7: binary. §11.3.1: base 2, F = 0.
        if first & 0x30 != 0 {
            return Err(DerError("REAL base other than 2"));
        }
        if first & 0x0C != 0 {
            return Err(DerError("REAL scaling factor not 0"));
        }
        let (exponent, mantissa) = match first & 0x03 {
            format @ 0..=2 => {
                let count = usize::from(format) + 1;
                if rest.len() < count {
                    return Err(DerError("REAL truncated exponent"));
                }
                rest.split_at(count)
            }
            _ => {
                // §8.5.7.4 d: a length octet X, then X exponent octets; DER
                // uses this format only when the fewest octets are four or more.
                let (&count, tail) = rest
                    .split_first()
                    .ok_or(DerError("REAL truncated exponent"))?;
                let count = usize::from(count);
                if count < 4 {
                    return Err(DerError("REAL long exponent format below four octets"));
                }
                if tail.len() < count {
                    return Err(DerError("REAL truncated exponent"));
                }
                tail.split_at(count)
            }
        };
        check_integer(exponent).map_err(|_| DerError("REAL exponent not minimal"))?;
        // §8.5.7.5, §11.3.1: N unsigned, fewest octets, odd.
        match (mantissa.first(), mantissa.last()) {
            (None, _) | (_, None) => Err(DerError("REAL empty mantissa")),
            (Some(0x00), _) => Err(DerError("REAL mantissa not minimal")),
            (_, Some(last)) if last & 1 == 0 => Err(DerError("REAL mantissa even")),
            _ => Ok(()),
        }
    } else if first & 0x40 == 0 {
        // §8.5.8, §11.3.2: decimal, NR3 only.
        if first != 0x03 {
            return Err(DerError("REAL decimal form other than NR3"));
        }
        if is_der_nr3(rest) {
            Ok(())
        } else {
            Err(DerError("REAL NR3 text not in DER form"))
        }
    } else {
        // §8.5.9: special values, exactly one content octet.
        if rest.is_empty() && (0x40..=0x43).contains(&first) {
            Ok(())
        } else {
            Err(DerError("REAL reserved special value"))
        }
    }
}

/// The DER NR3 text of X.690 §11.3.2.2–6:
/// `-?[1-9]([0-9]*[1-9])?.E(+0|-?[1-9][0-9]*)`.
fn is_der_nr3(text: &[u8]) -> bool {
    let text = text.strip_prefix(b"-").unwrap_or(text);
    let Some(mark) = text.windows(2).position(|pair| pair == b".E") else {
        return false;
    };
    let (mantissa, exponent) = (&text[..mark], &text[mark + 2..]);
    let mantissa_ok = !mantissa.is_empty()
        && mantissa.iter().all(u8::is_ascii_digit)
        && mantissa.first() != Some(&b'0')
        && mantissa.last() != Some(&b'0');
    let exponent_ok = exponent == b"+0" || {
        let digits = exponent.strip_prefix(b"-").unwrap_or(exponent);
        !digits.is_empty() && digits.iter().all(u8::is_ascii_digit) && digits[0] != b'0'
    };
    mantissa_ok && exponent_ok
}

/// UTCTime DER form `YYMMDDHHMMSSZ`, matched against the whole content.
#[must_use]
pub fn is_utc_time_form(content: &[u8]) -> bool {
    content.len() == 13 && content[..12].iter().all(u8::is_ascii_digit) && content[12] == b'Z'
}

/// GeneralizedTime DER form `YYYYMMDDHHMMSS[.f+]Z` with no trailing zero in the
/// fraction and no empty fraction, matched against the whole content (X7).
#[must_use]
pub fn is_generalized_time_form(content: &[u8]) -> bool {
    if content.len() < 15 || !content[..14].iter().all(u8::is_ascii_digit) {
        return false;
    }
    let rest = &content[14..];
    if rest == b"Z" {
        return true;
    }
    let Some((&b'.', tail)) = rest.split_first() else {
        return false;
    };
    let Some((&b'Z', fraction)) = tail.split_last() else {
        return false;
    };
    !fraction.is_empty()
        && fraction.iter().all(u8::is_ascii_digit)
        && fraction.last() != Some(&b'0')
}

/// Encodes a dotted OBJECT IDENTIFIER into its DER content octets.
///
/// # Panics
/// Never for the constant identifiers this crate uses (two or more arcs).
#[must_use]
pub fn oid(dotted: &str) -> Vec<u8> {
    let arcs: Vec<u64> = dotted
        .split('.')
        .map(|arc| arc.parse().unwrap_or(0))
        .collect();
    let mut out = Vec::new();
    let mut push_arc = |value: u64| {
        let mut stack = vec![(value & 0x7F) as u8];
        let mut rest = value >> 7;
        while rest > 0 {
            stack.push(((rest & 0x7F) as u8) | 0x80);
            rest >>= 7;
        }
        out.extend(stack.iter().rev());
    };
    let first = arcs.first().copied().unwrap_or(0) * 40 + arcs.get(1).copied().unwrap_or(0);
    push_arc(first);
    for &arc in arcs.iter().skip(2) {
        push_arc(arc);
    }
    out
}

/// Encodes a TLV with a definite minimal length.
#[must_use]
pub fn encode(identifier: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![identifier];
    let length = content.len();
    if length < 128 {
        out.push(length as u8);
    } else {
        let bytes = length.to_be_bytes();
        let skip = bytes.iter().take_while(|byte| **byte == 0).count();
        out.push(0x80 | (bytes.len() - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
    out.extend_from_slice(content);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lengths_must_be_minimal_and_definite() {
        assert!(read_single(&[0x04, 0x01, 0xAA]).is_ok());
        assert!(read_single(&[0x04, 0x81, 0x01, 0xAA]).is_err());
        assert!(read_single(&[0x24, 0x80, 0x00, 0x00]).is_err());
        assert!(read_single(&[0x04, 0x02, 0xAA]).is_err());
        assert!(read_single(&[0x04, 0x01, 0xAA, 0x00]).is_err());
    }

    #[test]
    fn high_tag_numbers_follow_x690() {
        // [APPLICATION 16384] minimal form `5f 81 80 00`.
        let tlv = read_single(&[0x5F, 0x81, 0x80, 0x00, 0x00]).expect("minimal high tag");
        assert_eq!(tlv.tag.number, Some(16384));
        assert_eq!(tlv.tag.class, Class::Application);
        // First subsequent octet 0x80 is not minimal.
        assert!(read_single(&[0x5F, 0x80, 0x81, 0x00, 0x00]).is_err());
        // A number below 31 in the high form.
        assert!(read_single(&[0x5F, 0x1E, 0x00]).is_err());
        assert!(read_single(&[0x5F, 0x1F, 0x00]).is_ok());
    }

    #[test]
    fn universal_rules() {
        assert!(check_universal_rules(&[0x01, 0x01, 0x01]).is_err());
        assert!(check_universal_rules(&[0x01, 0x01, 0xFF]).is_ok());
        assert!(check_universal_rules(&[0x02, 0x02, 0x00, 0x01]).is_err());
        assert!(check_universal_rules(&[0x02, 0x02, 0x00, 0x80]).is_ok());
        assert!(check_universal_rules(&[0x02, 0x02, 0xFF, 0x80]).is_err());
        assert!(check_universal_rules(&[0x03, 0x02, 0x01, 0x01]).is_err());
        assert!(check_universal_rules(&[0x03, 0x02, 0x01, 0x02]).is_ok());
        assert!(check_universal_rules(&[0x05, 0x01, 0x00]).is_err());
        assert!(check_universal_rules(&[0x06, 0x02, 0x80, 0x01]).is_err());
        assert!(check_universal_rules(&[0x24, 0x03, 0x04, 0x01, 0x00]).is_err());
        // SET OF in DER order.
        assert!(check_universal_rules(&[0x31, 0x06, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01]).is_err());
        assert!(check_universal_rules(&[0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02]).is_ok());
    }

    /// X.690 §8.18, §8.17, §8.24: EXTERNAL (8), EMBEDDED PDV (11) and
    /// CHARACTER STRING (29) only have a constructed encoding (H1-FIX2 Y4).
    #[test]
    fn constructed_only_universal_types() {
        // Constructed form, holding one INTEGER: framing only, accepted.
        for tag in [0x28, 0x2B, 0x3D] {
            assert!(
                check_universal_rules(&[tag, 0x03, 0x02, 0x01, 0x01]).is_ok(),
                "constructed {tag:#04x}"
            );
        }
        // Primitive form: a DER violation.
        for tag in [0x08, 0x0B, 0x1D] {
            assert!(
                check_universal_rules(&[tag, 0x01, 0x00]).is_err(),
                "primitive {tag:#04x}"
            );
            assert!(
                check_universal_rules(&[tag, 0x00]).is_err(),
                "empty primitive {tag:#04x}"
            );
        }
        // Inside an open-type position (a SEQUENCE component), same answer.
        assert!(check_universal_rules(&[0x30, 0x05, 0x3D, 0x03, 0x02, 0x01, 0x01]).is_ok());
        assert!(check_universal_rules(&[0x30, 0x03, 0x1D, 0x01, 0x00]).is_err());
        // The neighbouring restricted string types stay primitive-only.
        assert!(check_universal_rules(&[0x1E, 0x02, 0x00, 0x41]).is_ok());
        assert!(check_universal_rules(&[0x3E, 0x04, 0x1E, 0x02, 0x00, 0x41]).is_err());
        assert!(check_universal_rules(&[0x1C, 0x04, 0x00, 0x00, 0x00, 0x41]).is_ok());
        assert!(check_universal_rules(&[0x3C, 0x00]).is_err());
    }

    fn real(content: &[u8]) -> bool {
        check_universal_rules(&encode(0x09, content)).is_ok()
    }

    /// §12.2 1a, X.690 §8.5 and §11.3 (S2-FIX1/T3): REAL in DER.
    #[test]
    fn real_values() {
        // Plus zero; binary base 2, F = 0, minimal exponent, odd mantissa.
        assert!(real(&[]));
        assert!(real(&[0x80, 0x00, 0x01]));
        assert!(real(&[0xC0, 0xFF, 0x03]));
        assert!(real(&[0x81, 0x01, 0x00, 0x01]));
        assert!(real(&[0x83, 0x04, 0x01, 0x00, 0x00, 0x00, 0x01]));
        // Base 8 / 16, scaling factor, even, empty or padded mantissa.
        assert!(!real(&[0x90, 0x00, 0x01]));
        assert!(!real(&[0xA0, 0x00, 0x01]));
        assert!(!real(&[0x84, 0x00, 0x01]));
        assert!(!real(&[0x80, 0x00, 0x02]));
        assert!(!real(&[0x80, 0x00]));
        assert!(!real(&[0x80, 0x00, 0x00, 0x01]));
        // Exponent not in the fewest octets; long format below four octets.
        assert!(!real(&[0x81, 0x00, 0x01, 0x01]));
        assert!(!real(&[0x81, 0xFF, 0x80, 0x01]));
        assert!(!real(&[0x83, 0x03, 0x01, 0x00, 0x00, 0x01]));
        assert!(!real(&[0x83, 0x01, 0x01, 0x01]));
        assert!(!real(&[0x83, 0x05, 0x00, 0x00, 0x80, 0x00, 0x00, 0x01]));
        assert!(!real(&[0x82, 0x01, 0x00]));
        // Decimal: NR3 only, in the §11.3.2 form.
        assert!(real(b"\x031.E+0"));
        assert!(real(b"\x03-12.E-3"));
        assert!(real(b"\x03105.E7"));
        assert!(!real(b"\x011"));
        assert!(!real(b"\x0210.5"));
        assert!(!real(b"\x0310.E+0"));
        assert!(!real(b"\x0301.E+0"));
        assert!(!real(b"\x031.E+1"));
        assert!(!real(b"\x031.E-0"));
        assert!(!real(b"\x031.E01"));
        assert!(!real(b"\x03 1.E+0"));
        assert!(!real(b"\x031E+0"));
        assert!(!real(b"\x03.E+0"));
        // Special values: one octet 0x40-0x43; the rest reserved.
        for special in 0x40..=0x43u8 {
            assert!(real(&[special]));
        }
        assert!(!real(&[0x44]));
        assert!(!real(&[0x7F]));
        assert!(!real(&[0x40, 0x00]));
        // Constructed REAL.
        assert!(check_universal_rules(&[0x29, 0x00]).is_err());
    }

    /// §12.2 1a by universal tag number (S2-FIX1/T3), apart from REAL.
    #[test]
    fn universal_rules_by_tag_number() {
        // 0: never, whatever its length or form.
        assert!(check_universal_rules(&[0x00, 0x00]).is_err());
        assert!(check_universal_rules(&[0x20, 0x00]).is_err());
        // 13 RELATIVE-OID: as OBJECT IDENTIFIER.
        assert!(check_universal_rules(&[0x0D, 0x02, 0x81, 0x01]).is_ok());
        assert!(check_universal_rules(&[0x0D, 0x00]).is_err());
        assert!(check_universal_rules(&[0x0D, 0x02, 0x80, 0x01]).is_err());
        assert!(check_universal_rules(&[0x0D, 0x01, 0x81]).is_err());
        // 14 TIME, 34 DURATION: rejected.
        assert!(check_universal_rules(&[0x0E, 0x00]).is_err());
        assert!(check_universal_rules(&[0x1F, 0x22, 0x02, 0x31, 0x59]).is_err());
        // 7, 20, 21, 25, 27: complete escape sequences, no announcer, no
        // re-designation, smallest G set (S2-FIX2/U4 ②).
        for tag in [0x07u8, 0x14, 0x15, 0x19, 0x1B] {
            let ok = |content: &[u8]| check_universal_rules(&encode(tag, content)).is_ok();
            assert!(ok(&[0x41, 0x42]), "{tag:#04x}");
            assert!(!ok(&[0x41, 0x1B]), "{tag:#04x}");
            assert!(!ok(&[0x1B, 0x28, 0x1B]), "{tag:#04x}");
            assert!(!ok(&[0x1B, 0x20, 0x41]), "{tag:#04x}");
            // Registration 87 (94-set, final 4/9) into G0: a new designation.
            assert!(ok(&[0x1B, 0x28, 0x49]), "{tag:#04x}");
            // The same entry into G1: not the smallest G set for a 94-set.
            assert!(!ok(&[0x1B, 0x29, 0x49]), "{tag:#04x}");
            // Designating it twice: the second is a re-designation.
            assert!(!ok(&[0x1B, 0x28, 0x49, 0x1B, 0x28, 0x49]), "{tag:#04x}");
            // A 96-set (final 4/1) into G1 is the smallest; into G2 it is not.
            assert!(ok(&[0x1B, 0x2D, 0x41]), "{tag:#04x}");
            assert!(!ok(&[0x1B, 0x2E, 0x41]), "{tag:#04x}");
            // A locking shift (no intermediate) is not a designation.
            assert!(ok(&[0x1B, 0x6E]), "{tag:#04x}");
        }
        // The assumed G0 of TeletexString is 102 (final 7/5), of GeneralString
        // 6 (final 4/2), and GeneralString's C0 is 1 (final 4/0): designating
        // an entry in force is a violation; 6 into a TeletexString's G0 is not.
        assert!(check_universal_rules(&[0x14, 0x03, 0x1B, 0x28, 0x75]).is_err());
        assert!(check_universal_rules(&[0x14, 0x03, 0x1B, 0x28, 0x42]).is_ok());
        assert!(check_universal_rules(&[0x1B, 0x03, 0x1B, 0x28, 0x42]).is_err());
        assert!(check_universal_rules(&[0x1B, 0x03, 0x1B, 0x21, 0x40]).is_err());
        // 28 UniversalString, 30 BMPString: whole units.
        assert!(check_universal_rules(&[0x1C, 0x03, 0x00, 0x00, 0x00]).is_err());
        assert!(check_universal_rules(&[0x1E, 0x03, 0x00, 0x41, 0x00]).is_err());
        // 31-33, 35, 36: rejected like TIME and DURATION (S2-FIX2/U4 ③).
        for tag in [0x1F, 0x20, 0x21, 0x23, 0x24] {
            assert!(
                check_universal_rules(&[0x1F, tag, 0x01, 0x41]).is_err(),
                "{tag:#04x}"
            );
        }
        // 12, 18, 19, 22, 26: no ESC (S2-FIX2/U4 ①).
        for tag in [0x0C, 0x12, 0x13, 0x16, 0x1A] {
            assert!(
                check_universal_rules(&[tag, 0x01, 0x31]).is_ok(),
                "{tag:#04x}"
            );
            assert!(
                check_universal_rules(&[tag, 0x01, 0x1B]).is_err(),
                "{tag:#04x}"
            );
        }
        // 15 and 37 or more: framing only.
        assert!(check_universal_rules(&[0x0F, 0x01, 0xFF]).is_ok());
        assert!(check_universal_rules(&[0x1F, 0x25, 0x01, 0xFF]).is_ok());
        assert!(check_universal_rules(&[0x3F, 0x25, 0x01, 0xFF]).is_err());
    }

    /// Framing only (§12.2 1c open types; §14.1 anchors): no content rule.
    #[test]
    fn framing_ignores_content_rules() {
        let bad_utf8 = [0x30, 0x03, 0x0C, 0x01, 0xB9];
        assert!(check_framing(&bad_utf8).is_ok());
        assert!(check_universal_rules(&bad_utf8).is_err());
        assert!(check_framing(&[0x30, 0x03, 0x0C, 0x02, 0xB9]).is_err());
        assert!(check_framing(&[0x30, 0x01, 0x0C]).is_err());
        assert!(check_framing(&[0x30, 0x00, 0x00]).is_err());
    }

    #[test]
    fn time_forms_match_the_whole_content() {
        assert!(is_utc_time_form(b"261101120000Z"));
        assert!(!is_utc_time_form(b"261101120000Z\n"));
        assert!(is_generalized_time_form(b"20261101120000Z"));
        assert!(is_generalized_time_form(b"20261101120000.1234567Z"));
        assert!(!is_generalized_time_form(b"20261101120000.10Z"));
        assert!(!is_generalized_time_form(b"20261101120000.Z"));
        assert!(!is_generalized_time_form(b"20261101120000Z\n"));
    }

    #[test]
    fn deep_nesting_does_not_recurse() {
        // 3,000 nested SEQUENCEs walked on a 64 KiB stack: the walk is
        // iterative, so the depth never reaches the call stack.
        let mut encoding = vec![0x05, 0x00];
        for _ in 0..3_000 {
            encoding = encode(0x30, &encoding);
        }
        let handle = std::thread::Builder::new()
            .stack_size(64 * 1024)
            .spawn(move || check_universal_rules(&encoding).is_ok())
            .expect("spawn");
        assert!(handle.join().expect("no stack overflow"));
    }

    #[test]
    fn oid_encoding() {
        assert_eq!(
            oid("1.2.840.113549.1.7.2"),
            vec![0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02]
        );
        assert_eq!(
            oid("2.16.840.1.101.3.4.2.1"),
            vec![0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]
        );
    }
}
