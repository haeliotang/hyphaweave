// SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
// SPDX-License-Identifier: Apache-2.0

//! Exact-byte tests for the §14.6 report serializer.
//!
//! The expected strings below are hand-written to be exactly what Python's
//! `json.dumps(report, sort_keys=True, indent=2, ensure_ascii=True) + "\n"`
//! produces for the same value: sorted keys, two-space indent, one item per
//! line, `[]`/`{}` inline when empty, `": "` after member names, ASCII-only
//! output, one trailing LF. They are raw strings so the `\uXXXX` escapes and
//! the escaped backslashes are readable literally.

use hyphaweave_verify::error_codes::{e, n};
use hyphaweave_verify::report::{
    AttestationReport, ChainReport, ContainerReport, InputIdentity, OriginReport, RecordReport,
    RefReport, Report, SigReportEntry, Summary, Target, TimestampReport, VectorCaseReport,
    VectorCounts, Verdict, VerdictCounts, VerifierInfo,
};
use hyphaweave_verify::report_json::to_bytes;
use hyphaweave_verify::{VERIFIER_NAME, VERIFIER_VERSION};

const CONTAINER_EXPECTED: &str = r##"{
  "checks_disabled": [
    "E_JSON_INVALID",
    "E_SIG_REQUIRED"
  ],
  "container": {
    "anchor_verified": true,
    "chain": {
      "status": "unverified"
    },
    "created_at": "2026-01-02T03:04:05.678Z",
    "errors": [
      "E_TS_UNTRUSTED"
    ],
    "level_claimed": "L2",
    "level_verified": "L0",
    "manifest_digest": "sha256:4444",
    "notices": [],
    "previous_manifest_digest": null,
    "record_count": 2,
    "timestamps": [
      {
        "gen_time": null,
        "index": 0,
        "path": "signatures/timestamp-1.tsr",
        "state": "present-unverified"
      }
    ]
  },
  "input": {
    "sha256": "sha256:abcdef",
    "size": 42
  },
  "limitations": [
    "",
    "slash / stays literal",
    "quote \" backslash \\ control \u0001 tab \t newline \n cr \r bs \b ff \f",
    "non-ASCII: \u00e9, \u65e5\u672c\u8a9e, emoji \ud83d\ude00, U+2028 \u2028 U+2029 \u2029"
  ],
  "records": [
    {
      "digest": "sha256:1111",
      "errors": [],
      "id": "note",
      "kind": "weave.note",
      "kind_known": true,
      "notices": [
        "N_REF_MISSING"
      ],
      "origin": {
        "instance": "ed25519:1234",
        "project": "acme"
      },
      "refs": [
        {
          "index": 0,
          "rel": "derived_from",
          "state": "found"
        }
      ],
      "sigs": [
        {
          "key": "ed25519:abcd",
          "state": "valid"
        }
      ],
      "stage": "accepted",
      "verdict": "valid"
    },
    {
      "attestation": {
        "digest": "sha256:3333",
        "state": "missing"
      },
      "digest": "sha256:2222",
      "errors": [],
      "id": "gone",
      "kind": "weave.erased",
      "kind_known": true,
      "notices": [],
      "origin": null,
      "refs": [],
      "sigs": [],
      "stage": null,
      "verdict": "erased"
    }
  ],
  "report_version": "1",
  "spec": "weave-record/1",
  "summary": {
    "erased": 1,
    "invalid": 0,
    "unverifiable": 0,
    "valid": 1
  },
  "target": "container",
  "verdict": "invalid",
  "verifier": {
    "name": "hyphaweave-verify-rs",
    "version": "0.1.0"
  }
}
"##;

const VECTORS_EXPECTED: &str = r##"{
  "cases": [
    {
      "actual": "valid",
      "expected": "valid",
      "id": "jcs/canonical-tricky",
      "matched": true
    },
    {
      "actual": "valid",
      "expected": "invalid",
      "id": "sig/valid-single",
      "matched": false
    }
  ],
  "checks_disabled": [],
  "input": {
    "sha256": "sha256:ffff",
    "size": 33
  },
  "limitations": [],
  "records": [],
  "report_version": "1",
  "spec": "weave-record/1",
  "summary": {
    "case_count": 2,
    "matched": 1,
    "mismatched": 1
  },
  "target": "vectors",
  "verdict": "invalid",
  "verifier": {
    "name": "hyphaweave-verify-rs",
    "version": "0.1.0"
  }
}
"##;

const RECORD_EXPECTED: &str = r##"{
  "checks_disabled": [],
  "input": {
    "sha256": "sha256:7777",
    "size": 321
  },
  "limitations": [
    "L1 chain claim not verified"
  ],
  "records": [
    {
      "digest": "sha256:8888",
      "errors": [],
      "id": "r1",
      "kind": "weave.note",
      "kind_known": true,
      "notices": [],
      "origin": {
        "instance": "ed25519:9999",
        "project": "proj"
      },
      "refs": [],
      "sigs": [
        {
          "key": "ed25519:9999",
          "state": "valid"
        }
      ],
      "stage": "proposed",
      "verdict": "valid"
    }
  ],
  "report_version": "1",
  "spec": "weave-record/1",
  "summary": {
    "erased": 0,
    "invalid": 0,
    "unverifiable": 0,
    "valid": 1
  },
  "target": "record",
  "verdict": "valid",
  "verifier": {
    "name": "hyphaweave-verify-rs",
    "version": "0.1.0"
  }
}
"##;

#[test]
fn verifier_identity_matches_hand_written_expectations() {
    // The expected byte strings embed the current identity; a version bump must
    // update them deliberately rather than drift silently.
    assert_eq!(VERIFIER_NAME, "hyphaweave-verify-rs");
    assert_eq!(VERIFIER_VERSION, "0.1.0");
}

#[test]
fn container_report_is_byte_exact() {
    let report = container_report();
    let bytes = to_bytes(&report);
    assert_eq!(String::from_utf8(bytes).unwrap(), CONTAINER_EXPECTED);
}

#[test]
fn vectors_report_is_byte_exact_and_has_no_container() {
    let report = vectors_report();
    let bytes = to_bytes(&report);
    let text = String::from_utf8(bytes).unwrap();
    assert_eq!(text, VECTORS_EXPECTED);
    assert!(!text.contains("\"container\""));
    assert!(!text.contains("\"attestation\""));
}

#[test]
fn record_report_is_byte_exact_and_omits_container_and_cases() {
    let report = record_report();
    let bytes = to_bytes(&report);
    let text = String::from_utf8(bytes).unwrap();
    assert_eq!(text, RECORD_EXPECTED);
    assert!(!text.contains("\"container\""));
    assert!(!text.contains("\"cases\""));
}

#[test]
fn forward_slashes_are_not_escaped() {
    let text = String::from_utf8(to_bytes(&container_report())).unwrap();
    assert!(text.contains("\"signatures/timestamp-1.tsr\""));
    assert!(!text.contains("\\/"));
}

#[test]
fn output_is_ascii_with_one_trailing_lf() {
    let bytes = to_bytes(&container_report());
    assert!(bytes.is_ascii());
    assert!(bytes.iter().any(|&byte| byte == b'\n'));
    assert_eq!(bytes.last(), Some(&b'\n'));
    assert_ne!(bytes[bytes.len() - 2], b'\n');
}

fn base_report(target: Target, verdict: Verdict) -> Report {
    Report {
        checks_disabled: Vec::new(),
        report_version: hyphaweave_verify::REPORT_VERSION.to_owned(),
        spec: hyphaweave_verify::SPEC.to_owned(),
        target,
        verdict,
        input: InputIdentity {
            sha256: "sha256:0000".to_owned(),
            size: 0,
        },
        records: Vec::new(),
        container: None,
        summary: Summary::Verdicts(VerdictCounts::default()),
        limitations: Vec::new(),
        cases: Vec::new(),
        verifier: VerifierInfo {
            name: VERIFIER_NAME.to_owned(),
            version: VERIFIER_VERSION.to_owned(),
        },
    }
}

fn container_report() -> Report {
    let first = RecordReport {
        digest: Some("sha256:1111".to_owned()),
        id: Some("note".to_owned()),
        kind: Some("weave.note".to_owned()),
        stage: Some("accepted".to_owned()),
        origin: Some(OriginReport {
            project: "acme".to_owned(),
            instance: "ed25519:1234".to_owned(),
        }),
        kind_known: Some(true),
        verdict: Verdict::Valid,
        errors: Vec::new(),
        notices: vec![n::REF_MISSING],
        refs: vec![RefReport {
            index: 0,
            rel: "derived_from".to_owned(),
            state: "found".to_owned(),
        }],
        sigs: vec![SigReportEntry {
            key: "ed25519:abcd".to_owned(),
            state: "valid".to_owned(),
        }],
        attestation: None,
    };
    let placeholder = RecordReport {
        digest: Some("sha256:2222".to_owned()),
        id: Some("gone".to_owned()),
        kind: Some("weave.erased".to_owned()),
        stage: None,
        origin: None,
        kind_known: Some(true),
        verdict: Verdict::Erased,
        errors: Vec::new(),
        notices: Vec::new(),
        refs: Vec::new(),
        sigs: Vec::new(),
        attestation: Some(AttestationReport {
            digest: "sha256:3333".to_owned(),
            state: "missing".to_owned(),
        }),
    };
    let mut report = base_report(Target::Container, Verdict::Invalid);
    report.checks_disabled = vec![e::JSON_INVALID, e::SIG_REQUIRED];
    report.input = InputIdentity {
        sha256: "sha256:abcdef".to_owned(),
        size: 42,
    };
    report.records = vec![first, placeholder];
    report.container = Some(ContainerReport {
        created_at: Some("2026-01-02T03:04:05.678Z".to_owned()),
        manifest_digest: Some("sha256:4444".to_owned()),
        level_claimed: Some("L2".to_owned()),
        level_verified: Some("L0".to_owned()),
        anchor_verified: Some(true),
        chain: Some(ChainReport {
            status: "unverified".to_owned(),
        }),
        previous_manifest_digest: None,
        record_count: Some(2),
        errors: vec![e::TS_UNTRUSTED],
        notices: Vec::new(),
        timestamps: vec![TimestampReport {
            index: 0,
            path: Some("signatures/timestamp-1.tsr".to_owned()),
            state: "present-unverified".to_owned(),
            gen_time: None,
        }],
    });
    report.summary = Summary::Verdicts(VerdictCounts {
        valid: 1,
        invalid: 0,
        unverifiable: 0,
        erased: 1,
    });
    report.limitations = vec![
        String::new(),
        "slash / stays literal".to_owned(),
        "quote \" backslash \\ control \u{0001} tab \t newline \n cr \r bs \u{0008} ff \u{000C}"
            .to_owned(),
        "non-ASCII: \u{00E9}, \u{65E5}\u{672C}\u{8A9E}, emoji \u{1F600}, U+2028 \u{2028} U+2029 \u{2029}"
            .to_owned(),
    ];
    report
}

fn vectors_report() -> Report {
    let mut report = base_report(Target::Vectors, Verdict::Invalid);
    report.input = InputIdentity {
        sha256: "sha256:ffff".to_owned(),
        size: 33,
    };
    report.cases = vec![
        VectorCaseReport {
            id: "jcs/canonical-tricky".to_owned(),
            matched: true,
            expected: "valid".to_owned(),
            actual: "valid".to_owned(),
        },
        VectorCaseReport {
            id: "sig/valid-single".to_owned(),
            matched: false,
            expected: "invalid".to_owned(),
            actual: "valid".to_owned(),
        },
    ];
    report.summary = Summary::Vectors(VectorCounts {
        case_count: 2,
        matched: 1,
        mismatched: 1,
    });
    report
}

fn record_report() -> Report {
    let mut report = base_report(Target::Record, Verdict::Valid);
    report.input = InputIdentity {
        sha256: "sha256:7777".to_owned(),
        size: 321,
    };
    report.records = vec![RecordReport {
        digest: Some("sha256:8888".to_owned()),
        id: Some("r1".to_owned()),
        kind: Some("weave.note".to_owned()),
        stage: Some("proposed".to_owned()),
        origin: Some(OriginReport {
            project: "proj".to_owned(),
            instance: "ed25519:9999".to_owned(),
        }),
        kind_known: Some(true),
        verdict: Verdict::Valid,
        errors: Vec::new(),
        notices: Vec::new(),
        refs: Vec::new(),
        sigs: vec![SigReportEntry {
            key: "ed25519:9999".to_owned(),
            state: "valid".to_owned(),
        }],
        attestation: None,
    }];
    report.summary = Summary::Verdicts(VerdictCounts {
        valid: 1,
        invalid: 0,
        unverifiable: 0,
        erased: 0,
    });
    report.limitations = vec!["L1 chain claim not verified".to_owned()];
    report
}
