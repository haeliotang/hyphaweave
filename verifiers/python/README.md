<!-- SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# hyphaweave-verify-python — reference verifier

A complete, offline, deterministic verifier for the `weave-record/1` exchange format
(H0 draft, milestone H0). It implements the record envelope, the container layout,
manifest and manifest signatures, key lifecycle and authorisation, labels and
consent, erasure, the five-state reference resolution, and L2 RFC 3161 timestamps.

**Status: draft (decisions 2026-11-10 #34 and #42).** `weave-record/1` v0.1 has not
passed its J1/J2 round-trip acceptance cases yet, and this is currently the only
implementation, so it is not yet an independent implementation. The specification
and the vector set are the authority: this package is the reference implementation
of the rules, it does not define them.

## Install and run

```bash
# From the repository root (the pinned virtualenv is created by the project setup):
./.venv/bin/pip install -e verifiers/python

# Verify one record (optionally with a key-lifecycle context):
./.venv/bin/hyphaweave-verify record vectors/stage/accepted-signed/record.json \
    --keys vectors/keys/keyset

# Verify a container directory or its zip form:
./.venv/bin/hyphaweave-verify container vectors/container/l0-minimal/container
./.venv/bin/hyphaweave-verify container vectors/container/zip-valid/container.zip

# L2 container with an explicit TSA trust anchor:
./.venv/bin/hyphaweave-verify container vectors/integrity-levels/l2-valid/container \
    --keys vectors/keys/keyset \
    --tsa-trust vectors/integrity-levels/l2-valid/tsa.crt.pem

# Run the conformance vectors (gate 2 oracle) and the frozen regression set:
./.venv/bin/hyphaweave-verify vectors vectors
./.venv/bin/hyphaweave-verify vectors vectors/frozen/v0.1

# `python -m` is equivalent:
./.venv/bin/python -m hyphaweave_verify.cli --version
```

Exit codes: `0` = valid (or every vector case matched; a standalone erased
placeholder is a successful structural verification), `1` = invalid, unverifiable
or at least one vector mismatch, `2` = usage or IO error (no report on stdout).

## Determinism

stdout is exactly one JSON report per verification run:

* `json.dumps(sort_keys=True, ensure_ascii=True, indent=2)` plus one trailing LF;
* records in manifest order; refs/signatures in input order;
* `errors`/`notices`/`checks_disabled` sorted and de-duplicated;
* no wall clock, no network, no locale/timezone/cwd dependence, no absolute paths,
  usernames, hostnames or environment values anywhere in a report;
* the same input bytes always produce byte-identical report bytes.

## Report format (`report_version: "1"`)

| field | meaning |
|---|---|
| `checks_disabled` | sorted tokens of the test-only skip hook (normally empty) |
| `report_version` / `spec` | `"1"` / `"weave-record/1"` |
| `target` | `record`, `container` or `vectors` |
| `verdict` | `valid`, `invalid`, `unverifiable`, or `erased` for a placeholder record |
| `input` | `{sha256, size}`: the record file bytes; for a directory container the **manifest digest** and manifest byte count; for a zip container the archive hash and size |
| `records[]` | one entry per record: `digest`, `id`, `kind`, `stage`, `origin`, `kind_known`, `verdict`, `errors`, `notices`, `refs[]` (`index`,`rel`,`state`), `sigs[]` (`key`,`state`), and for `weave.erased` placeholders an `attestation` (`digest`,`state`) |
| `container` | container target only: `created_at`, `manifest_digest`, `level_claimed`, `level_verified` (**always `"L0"`** — the verifier never claims the chain was verified), `anchor_verified` (true only for a claimed L2 whose whole timestamp chain verified against a trust anchor), `chain` (`absent`/`unverified`), `previous_manifest_digest`, `record_count`, `timestamps[]` (`index`,`path`,`state`,`gen_time`), plus container-level `errors`/`notices` |
| `summary` | counts of record verdicts |
| `limitations` | stable English statements of what was not verified |
| `verifier` | `{name: "hyphaweave-verify-python", version}` |

The `vectors` target adds `cases[]` (`id`, `ok`, `verdict`, `mismatches`) and a
case-based `summary` `{"case_count", "matched", "mismatched"}` (record verdict
counts are only used for the `record`/`container` targets).

A field that cannot be produced (for example the digest of a file that is not
canonical JSON) is `null`. Container-level failures before record listing report
`records: []` and one primary error code. `sigs[].state` is one of `valid`,
`invalid`, `unverified` or `ignored` (unknown algorithm, Q13).

## Conformance vectors

`hyphaweave-verify vectors <dir>` discovers every `expected.json` under `<dir>`,
runs each case in-process and compares:

* `verdict` exactly;
* `errors` as a **set** against the aggregated errors (`container.errors` plus
  every `records[].errors`);
* `notices` expected ⊆ actual aggregated notices;
* `expected_digest` against the record digest (a container case matches when a
  listed record carries it);
* `expected_resolution` against the record's `refs[].state` order (a standalone
  `weave.erased` placeholder uses its `attestation.state`);
* `expected_container` as a recursive subset of `report.container`;
* `records` as per-record subsets matched by `id`.

Argument tokens follow the vector-case format: `@keyset` → the suite's `keys/keyset`,
`@case` → the case directory, anything else → a path relative to the case
directory. The runner is deterministic and reports the first mismatch reasons per
case.

## Test-only hook: `WEAVE_VERIFY_SKIP_CHECKS`

`WEAVE_VERIFY_SKIP_CHECKS` is **test-only machinery** used by the repository's
anti-verification gate to prove that every error-code family is exercised by the
vectors. It is a comma-separated list of error codes or family prefixes:

```bash
WEAVE_VERIFY_SKIP_CHECKS=E_SIG ./hyphaweave-verify vectors vectors
WEAVE_VERIFY_SKIP_CHECKS=E_KEY_UNKNOWN,E_ENV_FORMAT ./hyphaweave-verify record record.json
```

A skipped check is treated as passed: the code is not recorded and the verdict is
computed without it. The report always echoes the supplied tokens (sorted,
unique) in `checks_disabled` so a report can never be silently degraded. Unset or
empty means normal operation. The hook is documented here as test-only and must
not be used to weaken production verification.

## Limitations (also listed per report where relevant)

* Offline, single-container verification: references to records outside the
  container and the supplied keyset resolve as `missing` even if copies exist
  elsewhere; continuous multi-container chains are out of scope.
* An L1/L2 internal hash-chain head is a claim that cannot be recomputed from the
  exported records: `chain.status` is always `unverified` and `level_verified` is
  reported as `L0` for L1 (notice `N_CHAIN_CLAIM_UNVERIFIED`).
* Trust is trust-on-first-use from key-lifecycle records in the context; there is
  no certificate authority and no network revocation distribution. **Trust roots
  come only from the verifier-supplied `--keys` keyset** (decision #42): a
  self-signed human/organization declaration in the keyset is a root, while a
  container/target human/organization declaration is valid only when its key is
  already trusted or it is cosigned by a trusted human/organization key
  (iterative closure). Otherwise it is unverifiable (`E_KEY_UNTRUSTED`) and, when
  it only carries its own self-signature, a `N_SELF_ATTESTED_ROOT_KEY` notice is
  emitted. There is no root election by claimed `recorded_at`; with no `--keys`
  the trust set is empty.
* A `key-compromise` revocation invalidates **every** signature of that key (the
  claimed `recorded_at` is not evidence). Only a verified external RFC 3161
  timestamp covering the record with `genTime + accuracy` **strictly before**
  `effective_at` rescues it (accuracy absent counts as 0, microsecond
  comparison; equality does not rescue). If timestamp receipts exist but no
  trust anchor was supplied the signature is unverifiable (`E_TS_UNTRUSTED`);
  with no timestamp evidence at all it is invalid (`E_KEY_COMPROMISED`).
* A key declaration for an agent/program/device key requires `body.owner`, an
  owner of human/organization class (`E_KEY_OWNER_MISSING` when the owner is
  missing or of the wrong class), the owner's cosignature
  (`E_KEY_DECLARED_NOT_COSIGNED`), and an owner that is trusted
  (`E_KEY_UNTRUSTED` otherwise; an unresolvable owner is `E_KEY_UNKNOWN`).
* An offline verifier never reports a reference as `moved`: a digest mismatch
  cannot be verified (`unverifiable`, `N_REF_UNVERIFIABLE`); `moved` would require
  locating the record elsewhere through hints, which requires network access.
* Missing human cosignature on an `accepted` record is reported as
  `N_NO_HUMAN_SIGNATURE` (notice; the record may stay valid).
* Unknown signature algorithms are structurally validated and then ignored (Q13);
  a required signature that is only available under unknown algorithms makes the
  record `unverifiable` (`E_KEY_UNKNOWN` or `E_SIG_UNVERIFIABLE`). The same
  symmetry applies to manifest signatures.
* L2 timestamps require an explicit `--tsa-trust` anchor matching the signer leaf
  certificate's SHA-256 fingerprint. Without it a timestamp is
  `present-unverified`, the container is at most `unverifiable`
  (`E_TS_UNTRUSTED`), never `valid`. TSTInfo `accuracy` is parsed
  (seconds/millis/micros, absent = 0) and only used for compromise rescue, where
  `genTime + accuracy` must be strictly earlier than the revocation time. The
  RFC 3161 profile is fixed: granted
  status, TSTInfo v1, sha256 imprints and digests, RSA PKCS#1 v1.5 / ECDSA
  signature algorithms only (RSA-PSS is rejected), the signer certificate must be
  carried in the token, ESS `signingCertificateV2` is required, EKU
  `timeStamping`/KeyUsage and certificate validity are checked at `genTime`, and
  renewal chains (`timestamps[].renews`) must form exactly one chain
  (`E_TS_RENEWAL`). The report still says `level_verified: "L0"`; a claimed L2 is
  reported as L0 plus `anchor_verified: true`.
* The embedded `previous/manifest.json` is checked by digest only; its own
  signature is not re-verified (`N_PREVIOUS_SIG_UNVERIFIED`).
* `weave.erased` placeholders carry no content: their integrity rests on the
  signed attestation, the retained original digest and the manifest entry
  (G3b). A standalone placeholder is reported `erased` with its attestation
  reference state but without container cross-checks.
* Labels, consent coverage and licence claims are checked for consistency only;
  their truth is not established offline.
* Unregistered kinds are transported and integrity-checked but their bodies are
  never interpreted (K3 forward compatibility).
* Grant `scope`, `evidence` and `remedy` are audit information, not
  authorisation conditions in H0; `scope` only participates in the delegated
  sub-grant subset check. A delegated sub-grant must be a subset of its parent
  (kinds, actions, scope, validity window) and the parent must be transferable;
  a grant's optional `revocation` list restricts who may revoke it (default: the
  granter's key and its explicit rotation successors). The whole authorisation
  chain, ancestors included, is evaluated at the verified record's claimed
  `recorded_at` (and at the grant's own `recorded_at` when the grant record
  itself is verified). `occurred_at` and `executed_at` are claims.
* Salt randomness cannot be tested offline; the verifier only checks the
  encoding and length requirement.

## Code reading order

1. `errors.py` — the closed error/notice registry (mirrors `spec/error-codes.md`).
2. `canonical.py` — WR-CJ canonical serialization and the strict parser.
3. `encoding.py` — domain-separated digests, unpadded base64url, key ids.
4. `ed25519.py` — the strict Ed25519 profile: fixed step order
   (length → S<L → A decode incl. `x=0` sign bit → small-order A → mixed-order A
   rejection `E_SIG_MIXED_ORDER_A` → R decode → small-order R → cofactorless
   equation); the identity-key forgery and the non-canonical `x=0` encodings are
   rejected by the explicit pre-checks.
5. `times.py` / `grammar.py` — TS grammar and shared small grammars.
6. `refs.py` — origin/reference objects and five-state resolution.
7. `kinds.py` — kind registry and body schemas.
8. `envelope.py` — record envelope validation.
9. `keys.py`, `grants.py`, `labels.py`, `erase.py` — kind semantics and state.
10. `manifest.py`, `container.py` — container layout, manifests and aggregation.
11. `verifier.py` — per-record pipeline and the cross-record fixed point.
12. `timestamps.py` — RFC 3161 L2 token verification.
13. `report.py`, `cli.py`, `vectors_runner.py` — deterministic reporting and the
    two command-line surfaces.

## Dependencies

Pinned exactly in `pyproject.toml`:

* `cryptography==46.0.5` — Ed25519 signature verification (after the explicit
  profile pre-checks) and X.509 certificate inspection for RFC 3161 tokens;
* `asn1crypto==1.5.1` — DER parsing of `TimeStampResp`/CMS tokens;
* `jsonschema==4.23.0` — dependency of the repository's schema self-check tooling
  and kept pinned for reproducible environments.

The canonical serializer, parser, digest/signature construction, reference
resolution and report serialization are implemented here without third-party
libraries so the strict profile (integers only, duplicate rejection, closed
codes) is under this package's control.

## Tests

```bash
./.venv/bin/python -m pytest verifiers/python/tests
```

The suite covers canonical JSON (UTF-16 ordering including astral-plane keys,
escaping, duplicates, number edge cases, canonical-file rules), strict
base64url, key ids, Ed25519 boundaries and the identity-key forgery, fixed
digest/signature values from the published vectors, envelope rules (including the
key-lifecycle agent-member exception), reference states, key lifecycle effects,
grant authorisation, label propagation, container/L1/L2 behaviour, report
determinism across TZ/LANG/cwd, exit codes, the skip hook, registry parity with
`spec/error-codes.md`, and a full run of the committed vector suite.
