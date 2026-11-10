<!-- SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Provenance: RFC 8785 (JCS) test data

## Source

- Upstream: `cyberphone/json-canonicalization`, directory `testdata/`.
- URL: <https://github.com/cyberphone/json-canonicalization/tree/32a48195b9b20fe67b1795e39e4509f14d860b45/testdata>
- Commit: `32a48195b9b20fe67b1795e39e4509f14d860b45` (retrieved 2026-11-10).
- License: Apache-2.0 (upstream `LICENSE` copied verbatim; copyright 2018 Anders
  Rundgren).
- Retrieval artifact: the GitHub codeload archive of the repository at the commit above;
  only `testdata/` was extracted. Every extracted file is stored verbatim: no line-ending
  conversion, no JSON reformatting, no renaming.

`SOURCE.json.sha256` is the SHA-256 of the stored `SHA256SUMS` manifest, which lists the
SHA-256 of every retrieved file (so each file is individually verifiable). This is reported
instead of a single-artifact hash because the upstream "test data" is a directory of six
input/output pairs plus a hex form and a README, not one file.

## What was extracted

| File | Role |
|---|---|
| `testdata/input/*.json` | non-canonicalized RFC 8785 test documents (six) |
| `testdata/output/*.json` | official expected canonical serialization of the matching input |
| `testdata/outhex/*.txt` | the same expected canonical bytes in space-separated hexadecimal |
| `testdata/README.md` | upstream description of the test data |

The six pairs are `arrays`, `french`, `structures`, `unicode`, `values`, `weird`. Each
`output/<name>.json` is the exact byte sequence of the RFC 8785 canonical form (no trailing
LF); each `outhex/<name>.txt` is that same byte sequence in hex. `tools/check_external.py`
cross-checks every output file against its outhex form and then compares the canonicalizer's
result against `output/<name>.json`.

## Mapping to the Hyphaweave profile (WR-CJ v1)

WR-CJ v1 is RFC 8785 JCS **plus** the stricter production-profile restrictions of
`weave-record/1`: numbers MUST be integers in `[-(2^53-1), +(2^53-1)]` and duplicate object
member names are rejected while parsing. The RFC 8785 test data is a canonicalization
function suite, not a file-format suite, so the profile mapping below is per document:

| Input | Numbers in document | Expected behaviour under WR-CJ v1 | Why |
|---|---|---|---|
| `arrays.json` | integers only | canonicalize to the official output exactly | pure structure/ordering test |
| `french.json` | integers only | canonicalize to the official output exactly | member ordering is by UTF-16 code units, not locale |
| `structures.json` | contains `56.0` (a float) | **reject** with `E_JSON_NUMBER_NOT_INTEGER` | floats are not representable (decision C2) |
| `unicode.json` | integers only | canonicalize to the official output exactly | literal UTF-8 emission of an escaped combining mark |
| `values.json` | all numbers are floats/exponents | **reject** with `E_JSON_NUMBER_NOT_INTEGER` | floats are not representable (decision C2) |
| `weird.json` | integers only | canonicalize to the official output exactly | escaping, surrogate pairs and C1 controls; no normalisation |

For the four documents that WR-CJ v1 accepts, the comparison is byte equality between
`canonical(parse(input))` and `output/<name>.json`. For the two float documents the official
output is *not* treated as an expected canonical byte string: a conforming WR-CJ v1
implementation must reject the input instead of producing a float serialization. This is
intentional and is the documented stricter-profile mapping required by the contract
(§16.4).

The input files are deliberately not canonical (`values.json` has an exponent, `structures.json`
has `56.0`), so the §2.8 "file bytes must already be canonical" rule is not applied to them;
they exercise the canonicalization function only.

No input file exercises duplicate member names, so `E_JSON_DUPLICATE_KEY` is not part of
this mapping (it is covered by the independent JCS vectors of the repository).
