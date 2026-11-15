// SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
// SPDX-License-Identifier: Apache-2.0

//! R6 (H1-FIX1): nesting can never overflow the stack (§13, S3).
//!
//! The deepest legal inputs and the limit-plus-one inputs of `MAX_JSON_DEPTH`
//! and `MAX_LICENCE_NESTING`, and the hostile inputs of the H1 reviews (JSON
//! nested 1,023 levels, a licence with 400,000 parenthesis pairs), are verified
//! through the public API on a thread whose stack is 128 KiB. A stack overflow
//! aborts the whole test process, so this test fails loudly if any parser,
//! writer, `Clone` or `Drop` recursed with the input depth: 400,000 levels at
//! even 8 bytes a level need about 3 MiB.
//!
//! The legal depths are covered with arrays and with objects, because object
//! levels cost more stack than array levels wherever nesting costs stack.
//!
//! Why 128 KiB (debug build, which is what `cargo test` runs):
//!
//! - Nesting adds nothing. The JSON parser and writer and `Value`'s `Clone` and
//!   `Drop` keep open containers on the heap, so on aarch64-apple-darwin the
//!   peak stack of `verify_record` is 42.3 KiB for the depth-limit-32 record
//!   with one nested object and with 30 (it was 67.0 KiB with 30 before they
//!   stopped recursing). The licence parser recurses at most
//!   `MAX_LICENCE_NESTING` (16) levels and is not on the deepest path: 0, 8
//!   and 16 levels peak at the same 30.9 KiB.
//! - The fixed cost dominates, and it is larger on x86_64. Ed25519 verification
//!   goes through curve25519-dalek's AVX2 backend there, whose debug frames
//!   are large (`FieldElement2625x4::square_and_negate_D` alone is 28.3 KiB).
//!   The deepest direct-call chain from `verify_record` in the debug objects
//!   for x86_64-unknown-linux-gnu is 65.9 KiB, through `is_prime_order` and
//!   `ExtendedPoint::double`; the same analysis gives 41.0 KiB on aarch64,
//!   where 42.3 KiB was measured. That chain alone is larger than the former
//!   64 KiB, which explains the overflow on the ubuntu-latest CI runner.
//! - glibc carves the thread descriptor (about 2.3 KiB) and the static TLS
//!   block (about 2 to 3 KiB with its surplus) out of the requested size, and
//!   the thread entry and this file's closure add about 2 KiB.
//!
//! So about 66 + 2 + 5 = 73 KiB is needed on x86_64 Linux; 128 KiB leaves
//! more than 50 KiB for frame-size drift across toolchains and dependency
//! versions, and is still far too small for any recursion over 400,000 levels.
//!
//! That 128 KiB is dominated by signature verification, so it would not notice
//! a parser, writer, `Clone` or `Drop` that recursed only up to
//! `MAX_JSON_DEPTH` again (the recursive parser alone took 58 KiB for 32
//! object levels on aarch64). The JSON layer is therefore also checked on its
//! own on a `TIGHT_STACK` thread, at the legal depth through the parser and at
//! 100,000 levels through the writer, `Clone` and `Drop` (a `Value` can be
//! built deeper than the parser accepts). In the x86_64-unknown-linux-gnu
//! debug objects the deepest direct-call chains are 6.8 KiB from
//! `json::parse_object`, 13.9 KiB from `canonical_object_bytes` (most of it
//! the stable sort's on-stack scratch), 4.7 KiB from `Value::clone` and 2.7
//! KiB from `Value::drop`, whatever the depth; with the glibc and thread-entry
//! overhead above that is about 21 KiB, inside 32 KiB.

use std::fs;
use std::path::PathBuf;

use hyphaweave_verify::error_codes::e;
use hyphaweave_verify::json::{canonical_object_bytes, canonical_value_bytes, parse_object};
use hyphaweave_verify::limits::MAX_JSON_DEPTH;
use hyphaweave_verify::report::Verdict;
use hyphaweave_verify::value::{Object, Value};
use hyphaweave_verify::{verify_record, VerifyOptions};

const SMALL_STACK: usize = 128 * 1024;
const TIGHT_STACK: usize = 32 * 1024;

fn vector(relative: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../vectors")
        .join(relative);
    fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

/// Runs `verify_record` on a `SMALL_STACK` thread and returns `(verdict, errors)`.
fn on_small_stack(bytes: Vec<u8>) -> (Verdict, Vec<&'static str>) {
    std::thread::Builder::new()
        .stack_size(SMALL_STACK)
        .spawn(move || {
            let report = verify_record(&bytes, &VerifyOptions::new()).expect("no usage error");
            let errors = report
                .records
                .first()
                .map(|record| record.errors.clone())
                .unwrap_or_default();
            (report.verdict, errors)
        })
        .expect("spawn small-stack thread")
        .join()
        .expect("the verifier must not crash on a small stack")
}

/// `{"body":[[[...]]]}`-style nesting: `depth` JSON value levels in total.
fn nested_json(depth: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(depth * 2 + 16);
    out.extend_from_slice(b"{\"a\":");
    out.extend(std::iter::repeat_n(b'[', depth.saturating_sub(2)));
    out.push(b'0');
    out.extend(std::iter::repeat_n(b']', depth.saturating_sub(2)));
    out.push(b'}');
    out
}

/// `{"a":{"a":...{}}}`: `depth` JSON value levels in total, every container an
/// object. Object frames are the larger ones in the parser and the writer, so
/// array nesting alone does not cover the worst case.
fn nested_json_objects(depth: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(depth * 6 + 2);
    out.extend(std::iter::repeat_n(b"{\"a\":".as_slice(), depth - 1).flatten());
    out.push(b'0');
    out.extend(std::iter::repeat_n(b'}', depth - 1));
    out
}

/// The `depth-limit-32` vector with its 30 nested arrays (depths 3 to 32)
/// replaced by `containers` nested objects, so the record still parses,
/// passes the canonical-form check and is serialized for its digest.
fn depth_vector_with_objects(containers: usize) -> Vec<u8> {
    let text = String::from_utf8(vector("jcs/depth-limit-32/record.json")).expect("UTF-8 vector");
    let arrays = format!("{}{}", "[".repeat(30), "]".repeat(30));
    let objects = format!(
        "{}{{}}{}",
        "{\"a\":".repeat(containers - 1),
        "}".repeat(containers - 1)
    );
    assert!(text.contains(&format!("\"nested\":{arrays},")));
    text.replacen(&arrays, &objects, 1).into_bytes()
}

#[test]
fn json_depth_limit_and_plus_one_on_a_small_stack() {
    let (verdict, errors) = on_small_stack(vector("jcs/depth-limit-32/record.json"));
    assert!(
        !errors.contains(&e::JSON_SIZE),
        "depth 32 is legal: {verdict:?} {errors:?}"
    );
    let (verdict, errors) = on_small_stack(vector("jcs/depth-limit-plus-one/record.json"));
    assert_eq!((verdict, errors), (Verdict::Invalid, vec![e::JSON_SIZE]));
}

#[test]
fn hostile_json_nesting_on_a_small_stack() {
    for depth in [33usize, 1_023, 400_000] {
        let (verdict, errors) = on_small_stack(nested_json(depth));
        assert_eq!(
            (verdict, errors),
            (Verdict::Invalid, vec![e::JSON_SIZE]),
            "depth {depth}"
        );
    }
}

#[test]
fn object_nesting_limit_and_hostile_input_on_a_small_stack() {
    let (verdict, errors) = on_small_stack(depth_vector_with_objects(30));
    assert!(
        !errors.contains(&e::JSON_SIZE),
        "objects to depth 32 are legal: {verdict:?} {errors:?}"
    );
    let (verdict, errors) = on_small_stack(depth_vector_with_objects(31));
    assert_eq!((verdict, errors), (Verdict::Invalid, vec![e::JSON_SIZE]));
    for depth in [33usize, 1_023, 400_000] {
        let (verdict, errors) = on_small_stack(nested_json_objects(depth));
        assert_eq!(
            (verdict, errors),
            (Verdict::Invalid, vec![e::JSON_SIZE]),
            "depth {depth}"
        );
    }
}

/// A too-deep document is rejected at its first too-deep value: the reported
/// offset is where depth `MAX_JSON_DEPTH + 1` begins, however much deeper the
/// input goes, so the parser never reads (or opens a container) past it.
#[test]
fn too_deep_json_is_rejected_at_its_first_too_deep_value() {
    // Arrays: depth 1 is the object at 0, depth k >= 2 starts at 5 + (k - 2).
    // Objects: depth k starts at 5 * (k - 1).
    let first_too_deep_array = 5 + (MAX_JSON_DEPTH + 1 - 2);
    let first_too_deep_object = 5 * MAX_JSON_DEPTH;
    for depth in [33usize, 1_023, 400_000] {
        let array = nested_json(depth);
        let object = nested_json_objects(depth);
        let (array_error, object_error) = std::thread::Builder::new()
            .stack_size(SMALL_STACK)
            .spawn(move || (parse_object(&array), parse_object(&object)))
            .expect("spawn small-stack thread")
            .join()
            .expect("the parser must not crash on a small stack");
        let array_error = array_error.expect_err("too deep");
        let object_error = object_error.expect_err("too deep");
        assert_eq!(
            (array_error.code, array_error.offset),
            (e::JSON_SIZE, first_too_deep_array),
            "arrays, depth {depth}"
        );
        assert_eq!(
            (object_error.code, object_error.offset),
            (e::JSON_SIZE, first_too_deep_object),
            "objects, depth {depth}"
        );
    }
}

/// Runs `job` on a `TIGHT_STACK` thread.
fn on_tight_stack<T: Send + 'static>(job: impl FnOnce() -> T + Send + 'static) -> T {
    std::thread::Builder::new()
        .stack_size(TIGHT_STACK)
        .spawn(job)
        .expect("spawn tight-stack thread")
        .join()
        .expect("the JSON layer must not crash on a tight stack")
}

#[test]
fn parser_at_the_depth_limit_on_a_tight_stack() {
    for bytes in [
        nested_json(MAX_JSON_DEPTH),
        nested_json_objects(MAX_JSON_DEPTH),
    ] {
        let round_trip = on_tight_stack(move || {
            let object = parse_object(&bytes).expect("depth 32 is legal");
            let copy = object.clone();
            let written = canonical_object_bytes(&copy);
            drop((object, copy));
            (written, bytes)
        });
        assert_eq!(round_trip.0, round_trip.1);
    }
}

#[test]
fn writer_clone_and_drop_at_100_000_levels_on_a_tight_stack() {
    const LEVELS: usize = 100_000;
    for objects in [false, true] {
        let (written, copy_written) = on_tight_stack(move || {
            let mut value = Value::Int(0);
            for _ in 1..LEVELS {
                value = if objects {
                    let mut object = Object::new();
                    object.insert("a", value);
                    Value::Object(object)
                } else {
                    Value::Array(vec![value])
                };
            }
            let copy = value.clone();
            let written = canonical_value_bytes(&value);
            drop(value);
            let copy_written = canonical_value_bytes(&copy);
            drop(copy);
            (written, copy_written)
        });
        let (open, close) = if objects {
            ("{\"a\":", "}")
        } else {
            ("[", "]")
        };
        let expected = format!("{}0{}", open.repeat(LEVELS - 1), close.repeat(LEVELS - 1));
        assert!(written == expected.as_bytes(), "objects: {objects}");
        assert!(copy_written == expected.as_bytes(), "objects: {objects}");
    }
}

#[test]
fn licence_nesting_limit_and_hostile_input_on_a_small_stack() {
    let (verdict, errors) = on_small_stack(vector("labels/licence-nesting-limit-16/record.json"));
    assert!(
        !errors.contains(&e::ENV_LICENCE),
        "16 levels are legal: {verdict:?} {errors:?}"
    );
    let (verdict, errors) = on_small_stack(vector("labels/licence-nesting-plus-one/record.json"));
    assert_eq!((verdict, errors), (Verdict::Invalid, vec![e::ENV_LICENCE]));
    // The H1 review's 400,000 parenthesis pairs (about 800 KB, under 1 MiB).
    let record = vector("labels/licence-valid/record.json");
    let text = String::from_utf8(record).expect("UTF-8 vector");
    let deep = format!("{}MIT{}", "(".repeat(400_000), ")".repeat(400_000));
    let start = text.find("\"licence\":\"").expect("licence member") + "\"licence\":\"".len();
    let end = start + text[start..].find('"').expect("licence end");
    let hostile = format!("{}{}{}", &text[..start], deep, &text[end..]);
    let (verdict, errors) = on_small_stack(hostile.into_bytes());
    assert_eq!((verdict, errors), (Verdict::Invalid, vec![e::ENV_LICENCE]));
}
