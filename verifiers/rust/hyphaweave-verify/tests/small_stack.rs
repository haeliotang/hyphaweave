// SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
// SPDX-License-Identifier: Apache-2.0

//! R6 (H1-FIX1): nesting can never overflow the stack (§13, S3).
//!
//! The deepest legal inputs and the limit-plus-one inputs of `MAX_JSON_DEPTH`
//! and `MAX_LICENCE_NESTING`, and the hostile inputs of the H1 reviews (JSON
//! nested 1,023 levels, a licence with 400,000 parenthesis pairs), are verified
//! through the public API on a thread whose stack is 64 KiB. A stack overflow
//! aborts the whole test process, so this test fails loudly if any parser,
//! writer or `Drop` recursed with the input depth.

use std::fs;
use std::path::PathBuf;

use hyphaweave_verify::error_codes::e;
use hyphaweave_verify::report::Verdict;
use hyphaweave_verify::{verify_record, VerifyOptions};

const SMALL_STACK: usize = 64 * 1024;

fn vector(relative: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../vectors")
        .join(relative);
    fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

/// Runs `verify_record` on a 64 KiB stack and returns `(verdict, errors)`.
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
        .expect("the verifier must not crash on a 64 KiB stack")
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
