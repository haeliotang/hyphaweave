// SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
// SPDX-License-Identifier: Apache-2.0

//! External cross-check: RFC 8785 JCS test documents (gate 4).
//!
//! The profile mapping is documented in
//! `vectors/external/rfc8785-jcs/PROVENANCE.md`: four documents are
//! representable under WR-CJ v1 and must canonicalize byte-for-byte to the
//! official output; the two documents containing floats must be rejected with
//! `E_JSON_NUMBER_NOT_INTEGER` instead of producing a float serialization. The
//! official byte sequence is also cross-checked against the `outhex` form.
//!
//! The verifier never reads external test data at runtime; this test is gate
//! tooling only.

use std::fs;
use std::path::PathBuf;

use hyphaweave_verify::error_codes::e;
use hyphaweave_verify::json;

fn testdata() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../vectors/external/rfc8785-jcs/testdata")
}

fn parse_hex(text: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    for token in text.split_whitespace() {
        bytes.push(u8::from_str_radix(token, 16).expect("hex byte"));
    }
    bytes
}

#[test]
fn rfc8785_documents_match_profile_mapping() {
    let root = testdata();
    let mut accepted = 0usize;
    let mut rejected = 0usize;
    for name in ["arrays", "french", "structures", "unicode", "values", "weird"] {
        let input = fs::read(root.join(format!("input/{name}.json"))).expect("input");
        let output = fs::read(root.join(format!("output/{name}.json"))).expect("output");
        let outhex = fs::read_to_string(root.join(format!("outhex/{name}.txt"))).expect("outhex");
        assert_eq!(output, parse_hex(&outhex), "{name}: output != outhex");
        match json::parse_value(&input) {
            Ok(value) => {
                let canonical = json::canonical_value_bytes(&value);
                assert_eq!(
                    canonical,
                    output,
                    "{name}: canonical form differs from the RFC 8785 output"
                );
                accepted += 1;
            }
            Err(error) => {
                assert_eq!(
                    error.code,
                    e::JSON_NUMBER_NOT_INTEGER,
                    "{name}: unexpected rejection code {}",
                    error.code
                );
                rejected += 1;
            }
        }
    }
    assert_eq!(accepted, 4, "four documents must canonicalize");
    assert_eq!(rejected, 2, "two float documents must be rejected");
    println!("RFC 8785 JCS: {accepted} documents canonicalized, {rejected} rejected");
}
