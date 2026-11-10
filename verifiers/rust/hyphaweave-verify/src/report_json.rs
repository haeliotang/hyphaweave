// SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
// SPDX-License-Identifier: Apache-2.0

//! Report serialization (§14.6).
//!
//! The report bytes are fixed: one JSON object on standard output, UTF-8,
//! **sorted keys**, **two spaces of indentation**, **ASCII-only output**
//! (`ensure_ascii`, so every non-ASCII scalar is a `\uXXXX` escape including
//! surrogate pairs) and exactly **one trailing LF**. No absolute paths,
//! usernames, hostnames, current times, randomness or environment values.
//!
//! [`to_bytes`] reproduces Python's
//! `json.dumps(report, sort_keys=True, indent=2, ensure_ascii=True) + "\n"`
//! (the comparison form used by the H0 gate) from the [`Report`] data model:
//!
//! - object keys are sorted by Unicode code point (the report's keys are
//!   ASCII, where code-point order equals UTF-16 and byte order);
//! - each member/item is on its own line with two spaces per nesting level,
//!   `": "` after a member name and `","` before the next member;
//! - an empty array is `[]` and an empty object is `{}` on one line;
//! - `"` and `\` are escaped, the five short control escapes `\b \t \n \f \r`
//!   are used, any other control character below U+0020 is `\u00XX`, DEL
//!   (U+007F) is `\u007F`, every scalar at or above U+0080 is `\uXXXX`
//!   (lowercase hex; surrogate pairs for
//!   supplementary code points) and `/` is never escaped.
//!
//! The report's field set follows §14.6: `container` is present only for a
//! container target, `cases` only for the `vectors` target, and `attestation`
//! only inside record entries that carry one (a `weave.erased` placeholder).
//! Optional values that could not be determined render as JSON `null`; they are
//! never omitted.

use crate::error_codes::Code;
use crate::report::{
    ContainerReport, OriginReport, RecordReport, RefReport, Report, SigReportEntry, Summary,
    Target, TimestampReport, VerifierInfo,
};
use crate::value::{Object, Value};

/// Serializes a report to its normative bytes (§14.6).
#[must_use]
pub fn to_bytes(report: &Report) -> Vec<u8> {
    let value = report_value(report);
    let mut out = Vec::new();
    write_value(&mut out, &value, 0);
    out.push(b'\n');
    out
}

/// Builds the JSON value tree of a report.
///
/// The vector runner reuses this projection for `expected_container` matching so
/// that an expectation is compared against exactly the bytes the report would
/// print.
pub(crate) fn report_value(report: &Report) -> Value {
    let mut object = Object::new();
    object.insert("checks_disabled", code_array(&report.checks_disabled));
    object.insert("report_version", Value::Str(report.report_version.clone()));
    object.insert("spec", Value::Str(report.spec.clone()));
    object.insert("target", Value::Str(report.target.as_str().to_owned()));
    object.insert("verdict", Value::Str(report.verdict.as_str().to_owned()));
    object.insert("input", input_value(report));
    object.insert(
        "records",
        Value::Array(report.records.iter().map(record_value).collect()),
    );
    object.insert("summary", summary_value(&report.summary));
    object.insert("limitations", string_array(&report.limitations));
    object.insert("verifier", verifier_value(&report.verifier));
    // §14.6: the container object is present only for a container target.
    if report.target == Target::Container {
        let container = report
            .container
            .as_ref()
            .map_or(Value::Null, container_value);
        object.insert("container", container);
    }
    // §14.6: per-case results exist only for the vectors target.
    if report.target == Target::Vectors {
        let cases = report
            .cases
            .iter()
            .map(|case| {
                let mut entry = Object::new();
                entry.insert("id", Value::Str(case.id.clone()));
                entry.insert("matched", Value::Bool(case.matched));
                entry.insert("expected", Value::Str(case.expected.clone()));
                entry.insert("actual", Value::Str(case.actual.clone()));
                Value::Object(entry)
            })
            .collect();
        object.insert("cases", Value::Array(cases));
    }
    Value::Object(object)
}

/// Builds the JSON value tree of a container report.
pub(crate) fn container_value(container: &ContainerReport) -> Value {
    let mut object = Object::new();
    object.insert("created_at", optional_string(&container.created_at));
    object.insert(
        "manifest_digest",
        optional_string(&container.manifest_digest),
    );
    object.insert("level_claimed", optional_string(&container.level_claimed));
    object.insert("level_verified", optional_string(&container.level_verified));
    object.insert("anchor_verified", optional_bool(container.anchor_verified));
    object.insert(
        "chain",
        match &container.chain {
            None => Value::Null,
            Some(chain) => {
                let mut entry = Object::new();
                entry.insert("status", Value::Str(chain.status.clone()));
                Value::Object(entry)
            }
        },
    );
    object.insert(
        "previous_manifest_digest",
        optional_string(&container.previous_manifest_digest),
    );
    object.insert(
        "record_count",
        container
            .record_count
            .map_or(Value::Null, |count| Value::Int(count_i64(count))),
    );
    object.insert("errors", code_array(&container.errors));
    object.insert("notices", code_array(&container.notices));
    object.insert(
        "timestamps",
        Value::Array(container.timestamps.iter().map(timestamp_value).collect()),
    );
    Value::Object(object)
}

/// Builds the JSON value tree of a record report.
pub(crate) fn record_value(record: &RecordReport) -> Value {
    let mut object = Object::new();
    object.insert("digest", optional_string(&record.digest));
    object.insert("id", optional_string(&record.id));
    object.insert("kind", optional_string(&record.kind));
    object.insert("stage", optional_string(&record.stage));
    object.insert("origin", origin_value(record.origin.as_ref()));
    object.insert("kind_known", optional_bool(record.kind_known));
    object.insert("verdict", Value::Str(record.verdict.as_str().to_owned()));
    object.insert("errors", code_array(&record.errors));
    object.insert("notices", code_array(&record.notices));
    object.insert(
        "refs",
        Value::Array(record.refs.iter().map(ref_value).collect()),
    );
    object.insert(
        "sigs",
        Value::Array(record.sigs.iter().map(sig_value).collect()),
    );
    // §14.6: an erased placeholder entry optionally carries its attestation
    // resolution; other record entries never do.
    if let Some(attestation) = &record.attestation {
        let mut entry = Object::new();
        entry.insert("digest", Value::Str(attestation.digest.clone()));
        entry.insert("state", Value::Str(attestation.state.clone()));
        object.insert("attestation", Value::Object(entry));
    }
    Value::Object(object)
}

fn input_value(report: &Report) -> Value {
    let mut object = Object::new();
    object.insert("sha256", Value::Str(report.input.sha256.clone()));
    object.insert("size", Value::Int(count_i64(report.input.size)));
    Value::Object(object)
}

fn verifier_value(verifier: &VerifierInfo) -> Value {
    let mut object = Object::new();
    object.insert("name", Value::Str(verifier.name.clone()));
    object.insert("version", Value::Str(verifier.version.clone()));
    Value::Object(object)
}

fn summary_value(summary: &Summary) -> Value {
    let mut object = Object::new();
    match summary {
        Summary::Verdicts(counts) => {
            object.insert("valid", Value::Int(count_i64(counts.valid)));
            object.insert("invalid", Value::Int(count_i64(counts.invalid)));
            object.insert("unverifiable", Value::Int(count_i64(counts.unverifiable)));
            object.insert("erased", Value::Int(count_i64(counts.erased)));
        }
        Summary::Vectors(counts) => {
            object.insert("case_count", Value::Int(count_i64(counts.case_count)));
            object.insert("matched", Value::Int(count_i64(counts.matched)));
            object.insert("mismatched", Value::Int(count_i64(counts.mismatched)));
        }
    }
    Value::Object(object)
}

fn origin_value(origin: Option<&OriginReport>) -> Value {
    match origin {
        None => Value::Null,
        Some(origin) => {
            let mut object = Object::new();
            object.insert("project", Value::Str(origin.project.clone()));
            object.insert("instance", Value::Str(origin.instance.clone()));
            Value::Object(object)
        }
    }
}

fn ref_value(reference: &RefReport) -> Value {
    let mut object = Object::new();
    object.insert("index", Value::Int(index_i64(reference.index)));
    object.insert("rel", Value::Str(reference.rel.clone()));
    object.insert("state", Value::Str(reference.state.clone()));
    Value::Object(object)
}

fn sig_value(signature: &SigReportEntry) -> Value {
    let mut object = Object::new();
    object.insert("key", Value::Str(signature.key.clone()));
    object.insert("state", Value::Str(signature.state.clone()));
    Value::Object(object)
}

fn timestamp_value(timestamp: &TimestampReport) -> Value {
    let mut object = Object::new();
    object.insert("index", Value::Int(index_i64(timestamp.index)));
    object.insert("path", optional_string(&timestamp.path));
    object.insert("state", Value::Str(timestamp.state.clone()));
    object.insert("gen_time", optional_string(&timestamp.gen_time));
    Value::Object(object)
}

fn optional_string(value: &Option<String>) -> Value {
    value.clone().map_or(Value::Null, Value::Str)
}

fn optional_bool(value: Option<bool>) -> Value {
    value.map_or(Value::Null, Value::Bool)
}

fn code_array(codes: &[Code]) -> Value {
    Value::Array(
        codes
            .iter()
            .map(|code| Value::Str((*code).to_owned()))
            .collect(),
    )
}

fn string_array(items: &[String]) -> Value {
    Value::Array(items.iter().cloned().map(Value::Str).collect())
}

fn count_i64(number: u64) -> i64 {
    i64::try_from(number).unwrap_or(i64::MAX)
}

fn index_i64(number: usize) -> i64 {
    i64::try_from(number).unwrap_or(i64::MAX)
}

fn write_value(out: &mut Vec<u8>, value: &Value, depth: usize) {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Int(number) => out.extend_from_slice(number.to_string().as_bytes()),
        Value::Str(text) => write_string(out, text),
        Value::Array(items) => write_array(out, items, depth),
        Value::Object(object) => write_object(out, object, depth),
    }
}

fn write_array(out: &mut Vec<u8>, items: &[Value], depth: usize) {
    if items.is_empty() {
        out.extend_from_slice(b"[]");
        return;
    }
    out.push(b'[');
    for (index, item) in items.iter().enumerate() {
        if index > 0 {
            out.push(b',');
        }
        out.push(b'\n');
        write_indent(out, depth + 1);
        write_value(out, item, depth + 1);
    }
    out.push(b'\n');
    write_indent(out, depth);
    out.push(b']');
}

fn write_object(out: &mut Vec<u8>, object: &Object, depth: usize) {
    if object.is_empty() {
        out.extend_from_slice(b"{}");
        return;
    }
    // Python's `sort_keys=True` sorts by Unicode code point; the report's
    // member names are ASCII, so Rust's `str` ordering is identical.
    let mut members: Vec<(&str, &Value)> = object.iter().collect();
    members.sort_by(|left, right| left.0.cmp(right.0));
    out.push(b'{');
    for (index, (name, value)) in members.iter().enumerate() {
        if index > 0 {
            out.push(b',');
        }
        out.push(b'\n');
        write_indent(out, depth + 1);
        write_string(out, name);
        out.extend_from_slice(b": ");
        write_value(out, value, depth + 1);
    }
    out.push(b'\n');
    write_indent(out, depth);
    out.push(b'}');
}

fn write_indent(out: &mut Vec<u8>, depth: usize) {
    for _ in 0..depth {
        out.extend_from_slice(b"  ");
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
            control if (control as u32) < 0x20 => write_u_escape(out, control as u32),
            // Python's `ensure_ascii` also escapes DEL (U+007F).
            '\u{007F}' => write_u_escape(out, 0x7F),
            ascii if (ascii as u32) < 0x80 => out.push(ascii as u8),
            bmp if (bmp as u32) <= 0xFFFF => write_u_escape(out, bmp as u32),
            supplementary => {
                // Python's ensure_ascii emits a UTF-16 surrogate pair.
                let offset = supplementary as u32 - 0x1_0000;
                write_u_escape(out, 0xD800 + (offset >> 10));
                write_u_escape(out, 0xDC00 + (offset & 0x3FF));
            }
        }
    }
    out.push(b'"');
}

fn write_u_escape(out: &mut Vec<u8>, value: u32) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.extend_from_slice(b"\\u");
    out.push(HEX[((value >> 12) & 0xF) as usize]);
    out.push(HEX[((value >> 8) & 0xF) as usize]);
    out.push(HEX[((value >> 4) & 0xF) as usize]);
    out.push(HEX[(value & 0xF) as usize]);
}
