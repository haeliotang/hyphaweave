<!-- SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# `tools/` - independent vector-generation tooling

Everything here exists so that the conformance vectors under `vectors/` are
produced by an implementation that is **independent of the reference
verifier**. The hard rule (H0 prompt §2.3; see `vectors/README.md`) is:

> vector-generation scripts MUST NOT import `hyphaweave_verify`; every expected
> verdict and error code in `expected.json` is hand-authored from the contract,
> never obtained by running the verifier.

`tools/gen_vectors.py` and `tools/gen_vectors_extra.py` additionally assert at
the end of a run that `hyphaweave_verify` was not imported.

## Libraries (imported by the generators)

| file | purpose |
|---|---|
| `wcj.py` | Independent WR-CJ v1 canonicalizer and strict canonical-bytes parser. Own implementation of spec §1 (UTF-16 member order, ECMAScript escaping, integers only, duplicate-key/lone-surrogate rejection, optional single trailing LF). Errors carry the H0 code (`E_JSON_*`). |
| `keyutil.py` | Strict unpadded base64url (§3.5), key ids (§3.4), Ed25519 sign/verify through `cryptography`, and the four domain-separation prefixes of §3. |
| `recordlib.py` | Record/container construction: `weave-record/1` envelopes, record digests (§3.1), record and manifest signatures (§3.2/§3.3), manifest and directory-container file maps (§11), key-declaration / key-revocation records, and mutation helpers for negative containers. |

These modules are, deliberately, a second implementation of the same rules as
the reference verifier: a disagreement between them is a finding, not a
nuisance.

## Generators

| file | owner | purpose |
|---|---|---|
| `make_keys.py` | core | Deterministic synthetic test-key inventory under `vectors/keys/` (see `vectors/keys/README.md`). Re-runnable and idempotent; `--check` proves the files on disk match the derivation. |
| `gen_vectors.py` | core | Generates the `jcs`, `digest`, `sig`, `ref`, `stage`, `actor` and `labels` cases from a hand-authored case table. `--check` proves the on-disk cases match the generator. |
| `gen_vectors_extra.py` | vectors-extra | Generates `erasure`, `grant`, `key-lifecycle`, `container` and `integrity-levels` cases (including the local OpenSSL RFC 3161 test timestamps). |
| `gen_index.py` | core | Scans every case directory and writes `vectors/index.json` (all twelve categories). `--check` proves the index is current. |
| `check_external.py` | vectors-extra | Gate 4: cross-checks WR-CJ/Ed25519 against the official RFC 8785, RFC 8032 and Wycheproof data under `vectors/external/`. This is the only tool here that may import the verifier. |
| `check_schemas.py` | schemas-writer | JSON Schema self-check gate over the vectors. |
| `anti_verification.py` | Lead | Gate 3: bit-flip survivors and check-family coverage. |

## Regeneration order

From the repository root:

```bash
./.venv/bin/python tools/make_keys.py             # once; keys are deterministic
./.venv/bin/python tools/gen_vectors.py
./.venv/bin/python tools/gen_vectors_extra.py
./.venv/bin/python tools/gen_index.py
```

`make_keys.py`, `gen_vectors.py` and `gen_index.py` are deterministic:
re-running them is a byte-for-byte no-op (`--check` verifies this and exits 1
on drift). The committed RFC 3161 test replies are generated once by the
vectors-extra TSA procedure; see `vectors/integrity-levels/README.md`.
The RSA test-TSA private key cannot be derived deterministically from a seed,
so `make_keys.py` creates it on first run and then reuses it byte-for-byte.

## Conventions

* Python: `./.venv/bin/python` (pinned dependencies in the verifier
  `pyproject.toml`; the tools themselves need `cryptography`).
* All files are Apache-2.0 with SPDX headers; JSON/binary files are covered by
  `REUSE.toml`.
* Temporary files are not written by these tools; generators only write the
  repository paths listed above.
