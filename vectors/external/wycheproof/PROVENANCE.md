<!-- SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Provenance: Project Wycheproof Ed25519 test vectors

## Source

- Upstream: `C2SP/wycheproof` (the C2SP-maintained continuation of Google's Project
  Wycheproof), file `testvectors_v1/ed25519_test.json`.
- URL: <https://github.com/C2SP/wycheproof/blob/d5f724a21e449bbf8f142e032a6bf86884f2851c/testvectors_v1/ed25519_test.json>
- Commit: `d5f724a21e449bbf8f142e032a6bf86884f2851c` (retrieved 2026-11-10).
- License: Apache-2.0 (upstream `LICENSE` copied verbatim).
- File stored verbatim as `testvectors_v1/ed25519_test.json`; SHA-256 is listed in
  `SOURCE.json` and `SHA256SUMS`.

The file's own header declares `"algorithm": "EDDSA"`, `"schema": "eddsa_verify_schema_v1.json"`
and `"numberOfTests": 210`, distributed over 111 test groups (one public key per group).

## What was extracted

The whole file is kept unmodified; the cross-check reads every test group and every test.
No vector is copied to another location and no field is rewritten.

## Mapping to the Hyphaweave profile (WR-CJ v1, §4 / decision Q1)

The `weave-record/1` Ed25519 profile is deliberately **stricter** than some
permissible RFC 8032 implementations: canonical point encodings are required,
the eight small-order points are rejected for both `A` and `R`, `S` must be
canonical, and only the cofactorless equation is accepted. It does **not**
require a public key to be a member of the prime-order subgroup; that choice
is recorded here because it is exactly where the Wycheproof `acceptable`
class splits.

Per-class expected outcome (counts are pinned in `tools/check_external.py`, so
a changed data file fails the gate):

| Wycheproof `result` / flag | Tests | tcIds | Expected under our profile | Rationale |
|---|---|---|---|---|
| `valid` (`Valid`, `Ktv`, `TinkOverflow`) | 117 | 1–9, 71–84, 86–150, 181–209 | **accept** | signature verifies under the strict cofactorless equation with canonical encodings |
| `invalid` | 64 | 10–70, 85, 151, 210 | **reject** | signature, encoding or scalar is wrong; must fail (tcId 210 also carries `MixedOrderPublicKey`, but its `result` is `invalid`, so it is rejected) |
| `acceptable` + `MixedOrderPublicKey` | 21 | 160–180 | **accept** | the signature satisfies the cofactorless equation exactly; the public key is canonically encoded and not one of the eight small-order points; the H0 profile adds no subgroup-membership rule (decision 2026-11-10: honest keys are prime-order, mixed-order keys are an attacker construction, and rejecting them would need an extra scalar multiplication without a decision-level requirement) |
| `acceptable` + `SmallOrderPublicKey` | 8 | 152–159 | **reject** | the public key is one of the eight small-order points, which §4 step 3 mandates rejecting |

The complete per-vector outcome table (one row per tcId, generated from this
pinned file and the rule above) is committed next to it as
`EXPECTED_OUTCOMES.json`; `tools/check_external.py` fails if the committed
classes or counts drift.

So the gate expects **117 + 21 accept** and **64 + 8 reject**, with **zero**
unexpected outcomes. (An earlier draft of the contract said all `acceptable`
cases should be rejected; that is impossible for the 21 mixed-order vectors
under the written profile, and the 2026-11-10 decision corrected the mapping.
`spec/weave-record-1.md` §3.6 and `docs/open-questions.md` Q1 say the same.)

Relevant test flags in this file: `Valid`, `Ktv` (known test vector),
`TinkOverflow`, `InvalidSignature`, `InvalidEncoding`,
`SignatureMalleability`, `SignatureWithGarbage`, `CompressedSignature`,
`TruncatedSignature`, `InvalidKtv`, `MixedOrderPublicKey`,
`SmallOrderPublicKey`. The check reports the per-class counts and lists every
outcome mismatch (not just the first).

The verifier is not allowed to read `vectors/external/` at runtime; this data
exists only for the `tools/check_external.py` gate.
