<!-- SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# `tools/` - independent vector-generation tooling

Everything here exists so that the conformance vectors under `vectors/` are
produced by an implementation that is **independent of the reference
verifier**. The hard rule is:

> vector-generation scripts MUST NOT import `hyphaweave_verify`; every expected
> verdict and error code in `expected.json` is hand-authored from the
> specification, never obtained by running the verifier.

`tools/gen_vectors.py` and `tools/gen_vectors_extra.py` additionally assert at
the end of a run that `hyphaweave_verify` was not imported.

## Libraries (imported by the generators)

| file | purpose |
|---|---|
| `wcj.py` | Independent WR-CJ v1 canonicalizer and strict canonical-bytes parser: UTF-16 member order, ECMAScript escaping, integers only, duplicate-key/lone-surrogate rejection, optional single trailing LF, and a single-pass parser that reports the first violation in input byte order (`E_JSON_*`). |
| `keyutil.py` | Strict unpadded base64url, key ids, Ed25519 sign/verify through `cryptography`, and the four domain-separation prefixes. |
| `recordlib.py` | Record/container construction: `weave-record/1` envelopes, record digests, record and manifest signatures, manifest and directory-container file maps, key-declaration (with `body.owner` and counter-signatures) / key-revocation records, and mutation helpers for negative containers. |
| `edcraft.py` | Deterministic pure-Python Edwards-25519 arithmetic and crafted-signature helpers (identity forgery, all eight small-order encodings as A and as R, `x=0` sign-bit encodings, non-canonical `y >= p` encodings, `S = L`, `S = L+1`, mixed-order `A = [a]B + T` with cofactorless-valid signatures). It also exposes `verify_structural(..., checks=...)`, an independent oracle used to prove that a crafted signature becomes valid when the targeted check is removed. **Never imports the verifier.** |

These modules are, deliberately, a second implementation of the same rules as
the reference verifier: a disagreement between them is a finding, not a
nuisance.

## Generators and gate tools

| file | owner | purpose |
|---|---|---|
| `make_keys.py` | core | Deterministic synthetic test-key inventory under `vectors/keys/`: named keys, the `weave.key.declared` keyset (strictly increasing `recorded_at`, `human-1` is the self-attested root, every other declaration carries `body.owner` plus the owner/previous-key counter-signature), the deterministic edge-point public-key material, and the RFC 3161 test TSA. Re-runnable; `--check` proves the files on disk match the derivation. |
| `gen_vectors.py` | core | Generates the `jcs`, `digest`, `sig`, `ref`, `stage`, `actor` and `labels` cases from a hand-authored case table (including the Ed25519 boundary cases crafted with `edcraft.py`). `--check` proves the on-disk cases match the generator. |
| `gen_vectors_extra.py` | vectors-extra | Generates `erasure`, `grant`, `key-lifecycle`, `container` and `integrity-levels` cases (including TSRs crafted with the committed test TSA key). |
| `gen_index.py` | core | Scans every case directory and writes `vectors/index.json` (all twelve categories, excluding the frozen candidate set). `--check` proves the index is current. |
| `check_spec_examples.py` | vectors-core | Gate: extracts the fenced JSON examples from `spec/` and validates them against the schemas / the verifier. |
| `check_external.py` | vectors-extra | Gate 4: cross-checks WR-CJ/Ed25519 against the official RFC 8785, RFC 8032 and Wycheproof data under `vectors/external/`. This is the only gate tool that may import the verifier. |
| `check_schemas.py` | schemas-writer | JSON Schema self-check gate over the vectors. |
| `anti_verification.py` | QA | Gate 3: true source-level ablation of verifier checks over the whole vector suite. |
| `byte_flip_gate.py` | QA | Gate 3(a): flips every input byte of every positive case; documented exemptions live in `vectors/GATE-3-EXCEPTIONS.md`. |
| `check_frozen.py` | QA | Gate 7: validates the frozen-candidate `SHA256SUMS` file set and count. |

## Regeneration order

From the repository root:

```bash
./.venv/bin/python tools/make_keys.py             # deterministic key material
./.venv/bin/python tools/gen_vectors.py
./.venv/bin/python tools/gen_vectors_extra.py
./.venv/bin/python tools/gen_index.py
```

`make_keys.py`, `gen_vectors.py`, `gen_vectors_extra.py` and `gen_index.py` are
deterministic: re-running them is a byte-for-byte no-op and `--check` exits
non-zero on drift (CI runs all four). The committed RFC 3161 test replies are
generated once by the vectors-extra TSA procedure; see
`vectors/integrity-levels/README.md`. The RSA test-TSA private key cannot be
derived deterministically from a seed, so `make_keys.py` creates it on first
run and then reuses it byte-for-byte.

## Conventions

* Python: `./.venv/bin/python` (pinned dependencies in the verifier
  `pyproject.toml`; the tools themselves need `cryptography`).
* All files are Apache-2.0 with SPDX headers; JSON/binary files are covered by
  `REUSE.toml`.
* Temporary files are not written by these tools; generators only write the
  repository paths listed above.
