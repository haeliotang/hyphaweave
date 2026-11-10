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

## Mapping to the Hyphaweave profile (WR-CJ v1, Ed25519 profile)

The `weave-record/1` Ed25519 profile is **stricter** than some permissible RFC 8032
implementations: canonical point encodings are required, the eight small-order points and
every mixed-order public key are rejected (the decided profile requires a prime-order
subgroup public key, `E_SIG_MIXED_ORDER_A`; Inceptless decision 2026-11-10 #34, Q1), `S`
must be canonical, and only the cofactorless equation is accepted. Because all 29
Wycheproof `acceptable` vectors use either a small-order or a mixed-order public key, they
are **all rejected** by this profile.

Per-class expected outcome (counts are pinned in `tools/check_external.py`, so a changed
data file fails the gate):

| Wycheproof `result` | Tests | tcIds | Expected under our profile | Rationale |
|---|---|---|---|---|
| `valid` (`Valid`, `Ktv`, `TinkOverflow`) | 117 | 1–9, 71–84, 86–150, 181–209 | **accept** | canonical encodings and a prime-order subgroup key: the signature verifies under the strict cofactorless equation |
| `invalid` | 64 | 10–70, 85, 151, 210 | **reject** | signature, encoding or scalar is wrong; must fail (tcId 210 also carries `MixedOrderPublicKey`, but its `result` is `invalid`, so it is rejected either way) |
| `acceptable` + `SmallOrderPublicKey` | 8 | 152–159 | **reject** | the public key is one of the eight small-order points (`E_SIG_SMALL_ORDER_A`) |
| `acceptable` + `MixedOrderPublicKey` | 21 | 160–180 | **reject** | the public key is not in the prime-order subgroup (`E_SIG_MIXED_ORDER_A`); the decided profile rejects mixed-order keys rather than accepting them |

Expected gate totals: **117 accept**, **64 + 29 = 93 reject**, **210/210**, zero unexpected
outcomes. The complete per-vector outcome table (one row per tcId, generated from this
pinned file and the rule above) is committed next to it as `EXPECTED_OUTCOMES.json`;
`tools/check_external.py` fails if the committed table, the classes or the counts drift,
and reports every individual mismatch (not just the first).

Relevant test flags in this file: `Valid`, `Ktv` (known test vector), `TinkOverflow`,
`InvalidSignature`, `InvalidEncoding`, `SignatureMalleability`,
`SignatureWithGarbage`, `CompressedSignature`, `TruncatedSignature`, `InvalidKtv`,
`MixedOrderPublicKey`, `SmallOrderPublicKey`.

The verifier is not allowed to read `vectors/external/` at runtime; this data exists only
for the `tools/check_external.py` gate.
