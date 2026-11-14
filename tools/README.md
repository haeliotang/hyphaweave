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
| `byte_flip_gate.py` | QA | Gate 3(a): flips every input byte of every positive case; documented exemptions live in `vectors/GATE-3-EXCEPTIONS.md` (for `.tsr` receipts only four named DER fields, by byte range; S1-FIX4 W8). |
| `crash_fuzz.py` | QA | Gate 3(c): deterministic crash fuzzing over six input classes (fixed CI seed, `--seed` for any other deterministic batch), plus a replay of the committed 146-input regression corpus under `tools/crash_corpus/`. A non-{0,1,2} exit code or a `Traceback` on stderr is a gate failure. |

**Load.** `anti_verification.py`, `byte_flip_gate.py` and `crash_fuzz.py` default
to `--jobs min(8, cpu_count)`. Each worker runs one verifier at a time, but the
three together with other work can saturate a developer machine; when they run
alongside the other gates (or alongside anything else), pass **`--jobs 2`** to
each. CI runs them one after another on its own runner.
| `check_frozen.py` | QA | Gate 7: validates the frozen-candidate `SHA256SUMS` file set and count. |

## Crash fuzz gate (`crash_fuzz.py`, `crash_corpus/`)

`tools/crash_fuzz.py` feeds the verifier a fixed, deterministic batch of
malformed inputs and requires every mutant to be rejected **cleanly**. Each
mutant is executed as a **real CLI subprocess** (`python -m
hyphaweave_verify.cli`, 60 s timeout, parallel workers), so the gate observes
exactly what a user would: the process exit code must be `0`, `1` or `2`
and stderr must not contain `Traceback` (exit code `3` is the §14.7 test-only
hook, active only behind `--test-hooks`, which the gate never passes). A non-conforming exit code, a
traceback, a timeout or a signal is a crash and makes the gate fail; a crash is
never an accepted rejection.

* Six classes, 300 **effective** mutants each by default, seed `20261111`:
  `container-dir`, `container-zip`, `previous`, `tsa`, `keyset`, `record`. A
  mutation that leaves every file byte-for-byte unchanged (a no-op) is neither
  run nor counted; the next indices of that class are drawn instead, so the
  batch stays deterministic (S1-FIX4 W11).
* Mutations are deterministic from `(seed, class, index)`: byte
  set/flip/truncate/insert/delete/duplicate, JSON structure mutations
  (delete/replace/add member, type change, deep nesting, duplicate key) and zip
  header-field mutations. `tsa` mutants also re-point the (unsigned) attestation
  digest for the mutated `.tsr`, so the DER parsing path is exercised.
* `--seed S` runs another deterministic batch (a fixed seed alone cannot prove
  the absence of crashes: the S1-FIX3 recheck found one with seed 777). A
  failure prints the seed, so `--seed S` reproduces it. `--jsonl PATH` emits one
  result per mutant for 3.12/3.14 parity; `--classes` and `--count` exist for
  debugging. CI runs the fixed defaults; run further seeds before a hand-off.
* The committed regression corpus under `tools/crash_corpus/` holds the 145
  crash inputs found by the S1-FIX2 recheck (6 `previous` + 139 `tsa`) and the
  `--tsa-trust` PEM with an invalid certificate version found with seed 777 by
  the S1-FIX3 recheck (`tsa-s777-00048`, now a usage error). Each run replays it
  first and requires zero crashes. `index.json` records the recheck
  seed, category and index for traceability; `file_id` directories contain only
  the mutated (overlay) files, and the base container is copied from `vectors/`.
  Regeneration uses the recheck2 helper scripts (`make_job` in `fuzz.py`,
  `regen.py`), kept outside the repository in the planning directory:
  `python recheck2/scripts/regen.py <export> <work> <category> <index>`.

### `.tsr` byte flips and the DER path (S1-FIX3 V2c, S1-FIX4 W8)

For a **directory-form** container the gate rewrites the (unsigned) attestation
`signatures/manifest.sig.json` so the timestamps entry for the mutated `.tsr`
lists the mutant digest; the mutation therefore reaches strict DER parsing
instead of stopping at the file-level `E_TS_FILE` check. There is no committed
positive zip-form container that embeds a `.tsr`, so the zip path does not need
that rewriting: the same DER-decoding paths are covered by the committed bad-DER
vectors (`integrity-levels/l2-ts-der-*`) and by the `tsa` class of
`crash_fuzz.py` (which always synchronises the digest). An accepted `.tsr` flip
is exempt only inside the four DER fields no §12.2 check reads beyond strict
DER (`digestAlgorithms`, non-signer certificates, `crls`, `unsignedAttrs`),
computed from the receipt structure; every other accepted flip is a survivor.

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
