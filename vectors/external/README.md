<!-- SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# External reference data

Downloaded, **unmodified** official test data used by `tools/check_external.py` (CI gate 4).
The format's own vectors are not derived from this data: it exists only to cross-check the
reference verifier against independent third-party sources.

| Directory | Source | Version | License |
|---|---|---|---|
| `rfc8785-jcs/` | `cyberphone/json-canonicalization` `testdata/` | commit `32a48195b9b20fe67b1795e39e4509f14d860b45` | Apache-2.0 |
| `rfc8032/` | RFC Editor copy of RFC 8032 | RFC 8032 (January 2017) | IETF Trust Legal Provisions (BCP 78) |
| `wycheproof/` | `C2SP/wycheproof` `testvectors_v1/ed25519_test.json` | commit `d5f724a21e449bbf8f142e032a6bf86884f2851c` | Apache-2.0 |

Each directory contains:

- `SOURCE.json` — `name`, `url`, `commit`, `sha256`, `license`, `retrieved_at`, plus the
  per-file SHA-256 map and a note on what `sha256` covers (the stored `SHA256SUMS`
  manifest; for single-file sources this is still the manifest, whose one entry is the
  file).
- `SHA256SUMS` — `sha256sum`-format list of every retrieved official file, sorted by path.
- `PROVENANCE.md` — what was extracted, how, and the mapping from the third-party test data
  to the stricter `weave-record/1` profile.
- The official files themselves, byte-for-byte as retrieved.

No network access happens at verification time. `tools/check_external.py` verifies the
file hashes, then checks the documented mapping; it exits non-zero on any mismatch.

Notes on the stricter-profile mapping (details in each `PROVENANCE.md`):

- RFC 8785: integer-only documents must canonicalize to the official output bytes; the two
  documents containing floating-point numbers must be **rejected** by WR-CJ v1
  (`E_JSON_NUMBER_NOT_INTEGER`), because the format only represents integers.
- RFC 8032 §7.1: all five Ed25519 vectors must verify.
- Wycheproof Ed25519: `valid` → accept, `invalid` → reject, `acceptable` → **reject**
  (stricter, documented Q1 choice).
