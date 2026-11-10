<!-- SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Provenance: RFC 8032 test vectors

## Source

- Document: RFC 8032, "Edwards-Curve Digital Signature Algorithm (EdDSA)",
  IRTF, January 2017 (Informational). Retrieved from the RFC Editor's canonical copy.
- URL: <https://www.rfc-editor.org/rfc/rfc8032.txt>
- Commit/version: RFC 8032 (January 2017); RFC Editor text is immutable once published, so
  no repository commit applies. The retrieved file's SHA-256 is recorded in `SOURCE.json`
  and in `SHA256SUMS`.
- License: IETF Trust Legal Provisions (BCP 78). The document's Copyright Notice is part of
  the stored text; the file is kept unmodified and is redistributed here only as test data
  with that notice intact. `SOURCE.json` records the license as
  "IETF Trust Legal Provisions (BCP 78); Copyright Notice is inside rfc8032.txt".

The full RFC text (`rfc8032.txt`, 103210 bytes) is stored verbatim, unmodified. It starts
with five blank lines exactly as distributed by the RFC Editor; nothing was normalised.

## What was extracted

Only **§7.1 "Test Vectors for Ed25519"** is used by `tools/check_external.py`. It contains
five pure-EdDSA vectors:

| Test | Message |
|---|---|
| TEST 1 | empty message (0 bytes) |
| TEST 2 | 1 byte `72` |
| TEST 3 | 2 bytes `af82` |
| TEST 1024 | 1023-byte hexadecimal message |
| TEST SHA(abc) | 64-byte message (SHA-512 of `abc`) |

Each vector provides `SECRET KEY` (32-byte seed), `PUBLIC KEY` (32-byte compressed Edwards
point) and `SIGNATURE` (64 bytes). §7.2 (`Ed25519ctx`) and §7.3 (`Ed25519ph`) are **not**
used: `weave-record/1` uses PureEdDSA with no context string and no pre-hash, so those
vectors belong to different algorithms and would not test the profile.

The RFC text is paginated (page footers and form feeds appear in the middle of the
hexadecimal message of TEST 1024), so the cross-check parser reconstructs the hexadecimal
runs label-by-label and ignores page furniture. Extraction is done at check time from this
stored file; no extracted copy is committed separately, so the mapping cannot drift from
the official text.

## Mapping to the Hyphaweave profile (WR-CJ v1, §4)

Every §7.1 vector must be **accepted**: the strict Ed25519 profile (canonical point
encodings, no small-order `A`/`R`, `S < L`, cofactorless `[S]B = R + [k]A`) is the RFC 8032
verification equation applied without the cofactored variant, and these vectors use
canonical encodings and standard keys. A single rejected vector is a gate failure.

The seed (SECRET KEY) is not used directly by the check; the stored PUBLIC KEY is the
verification key. (Deriving the public key from the seed would test key generation, which
the profile does not constrain beyond the RFC.)
