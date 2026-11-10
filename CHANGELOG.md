<!-- SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com> -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Changelog

All notable changes to this repository are recorded here. The format is a
draft and may be replaced before the first public release.

## H1 — 2026-11-11 — DRAFT, UNRELEASED

Milestone H1 adds a **second, independent verifier** for `weave-record/1`,
written in Rust from the specification (`spec/`) and the conformance vectors
(`vectors/`) only. **H1 has not been externally reviewed.** The format itself is
still a draft: v0.1 has **not** passed the J1/J2 round-trip acceptance cases, the
regression set remains the candidate `vectors/frozen/v0.1-candidate/`, and no
compatibility promise is made. The H0 sections below describe the earlier H0
hand-off snapshot; in particular, the H0 statement that only one implementation
exists is superseded by this milestone.

### Added

- **Independent Rust verifier** (`verifiers/rust/`): the `hyphaweave-verify`
  0.1.0 library and the `hyphaweave-verify-rs` command line, implementing the
  record envelope, references, labels and consent, key lifecycle and grants,
  erasure, the L0/L1/L2 container format (including the RFC 3161 timestamp
  profile of §12) and the deterministic §14.6 report. The CLI exposes `record`,
  `container` and `vectors` with `--keys`, `--tsa-trust`, `--previous` and
  `--json`; reports are byte-stable and never depend on the clock, locale, time
  zone, environment or filesystem order. The implementation was written from
  the specification and the vectors only; the Python reference verifier is used
  only as a black box by the gate-3 comparison, never read as source.
- **Tests**: unit tests in the modules, integration tests for the external
  vectors (RFC 8032, Wycheproof, RFC 8785-derived canonical JSON), the §14.6
  report bytes and the committed L2 timestamp cases, plus the conformance runner
  over `vectors/` and the candidate regression set.
- **Supply chain** (`verifiers/rust/deny.toml`): a real `cargo deny check`
  policy with a narrow licence allow list (Apache-2.0, MIT, BSD-3-Clause,
  Unicode-3.0, the identifiers the locked tree requires), crates.io as the only
  allowed source, and active bans/advisories checks. Two timing-side-channel
  advisories that concern secret-key operations (RSA private-key operations and
  constant-time big-integer arithmetic on secrets) are ignored with a written
  reason because the verifier only performs public-key signature verification
  and handles no secret key material.
  `REUSE.toml` now covers `verifiers/rust/**`, and
  `verifiers/rust/README.md` documents the build, CLI, library API, crate
  layout, dependency table and tests.
- **CI**: a new `rust` job in `.github/workflows/ci.yml` runs `cargo fmt
  --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test`, the
  verifier over `vectors` and `vectors/frozen/v0.1-candidate`, `cargo deny
  check`, `cargo audit`, and the gate-3 report-comparison script. The existing
  Python `gates` job is unchanged. This entry does not claim that any CI run
  passed.
- **Gate 3 tooling** (`verifiers/rust/scripts/`): `compare_reports.py` runs both
  implementations over every case with the case's reproduced arguments,
  normalizes only the §14.6 `verifier` identity object and compares the
  remaining report bytes. It runs the Python black box only after the Rust
  verifier passes every vector (the H1 ordering rule), and it fails on any
  difference not explicitly listed in the empty-by-default
  `gate3_known_differences.json`.
- **Findings** (`docs/h1-findings.md`): the specification ambiguities and
  implementation-shape choices that an independent implementation must resolve,
  with the chapter, the possible readings, the chosen reading and reason,
  whether a committed vector pins it, the Python black-box agreement (filled in
  after gate 3) and a proposed wording change. This is the single place for H1
  findings.

### Explicitly not yet true in H1

- **H1 has not been externally reviewed.** Passing the shared vectors is
  necessary but not sufficient evidence that the format is implementable from
  the specification alone; an outside review of the Rust verifier and of the
  findings still has to happen.
- **Gate results are not asserted here.** The Rust gates and the gate-3 report
  comparison are run on the integrated tree; this changelog claims none of them
  passed until their results are recorded in the H1 hand-off.
- **The format is not accepted and not stable.** J1/J2 acceptance and the
  official freeze of the regression set are still pending, exactly as the H0
  sections below state.

## 0.1.0 — 2026-11-10 — DRAFT, UNRELEASED

Milestone H0: the `weave-record/1` v0.1 specification set, JSON Schemas,
conformance vectors and the Python reference verifier. This version is a draft
for review. It is not published, not tagged, and not accepted as a stable
version of the format. The contents below describe the repository after
**revision 1** (decision 2026-11-10 #34).

### Added

- **Specification** (`spec/`): a 2,357-line normative
  `weave-record/1` specification covering the record envelope, references,
  containers and manifests, erasure, grants and authorization, integrity levels
  L0/L1/L2, the five-state reference resolution model, the strict Ed25519
  verification profile, WR-CJ canonical JSON, size limits and
  forward-compatibility rules. Eight registered kind pages (936 lines
  in total, one per `weave.*` kind), a closed error-code and notice
  registry in `spec/error-codes.md` (112 error codes and 14 notices), and a 697-line step-by-step offline verification guide
  for an L0 container using only common tools.
- **Schemas** (`schemas/`): 11 JSON Schema 2020-12 documents — envelope,
  references, manifest, and the eight registered kinds — plus `schemas/README.md`
  and a local offline self-check (72 positive vector inputs validated and 43
  structural-negative assertions checked).
- **Conformance vectors** (`vectors/`): 284 positive and negative cases across 12
  categories (jcs 24, digest 5, sig 43, ref 12, stage 17, actor 26, labels 34,
  erasure 11, grant 27, key-lifecycle 29, container 27, integrity-levels 29),
  including 72 positive cases (40 record, 32 container); deliberately public
  synthetic test keys; a generated index; provenance for the official external
  test data used for cross-checks (RFC 8785 canonicalization with 6 document
  pairs, RFC 8032 Ed25519 with 5 vectors, the Wycheproof Ed25519 suite with 210
  cases, all acceptable cases rejected per Q1); committed RFC 3161 test
  timestamp replies; and a **v0.1 candidate regression set** of 178 cases
  (601 files, 2.4 MB; `vectors/frozen/v0.1-candidate/FROZEN.md`), with a
  SHA-256 manifest over its 600 non-manifest files and a verified case count.
  The candidate set becomes the frozen set only after J1/J2 acceptance.
- **Reference verifier** (`verifiers/python/`): `hyphaweave_verify` 0.1.0, the
  `hyphaweave-verify` command-line tool (`record`, `container`, `vectors`,
  `--keys`, `--tsa-trust`, `--previous`), deterministic JSON reports with
  per-record verdicts and error codes, a pytest test suite (237 passed, 0
  skipped), and full L0 verification plus the L1/L2 structural checks. L2
  RFC 3161 timestamps are verified only against an explicit trust anchor;
  without one the timestamp is reported as `present-unverified` and the
  container as `unverifiable`. Dependency versions are pinned in
  `verifiers/python/constraints.txt`.
- **Tooling** (`tools/`): independent vector generators that do not import the
  verifier (`wcj`, `keyutil`, `recordlib`, `edcraft`, `gen_vectors`,
  `gen_vectors_extra`, `gen_index`, `make_keys`), the schema self-check, the
  external-data cross-check, the true source-ablation gate
  (`anti_verification.py`), the byte-flip gate (`byte_flip_gate.py`), the
  specification-example validator (`check_spec_examples.py`) and the
  candidate-freeze checker (`check_frozen.py`).
- **Repository metadata**: licensing split (Apache-2.0 for code, schemas and
  vectors; CC-BY-4.0 for specification and documentation prose), REUSE
  annotations, the Inceptless CLA v1.0 (finalized upstream during H0, decisions
  #27/#28), README files in English and Chinese, SECURITY, CONTRIBUTING, the
  positioning document, and CI workflow `.github/workflows/ci.yml`.

### Revision 1 (decision 2026-11-10 #34)

Revision 1 responds to two independent reviews. It changes wire-observable
semantics, so it is listed separately from the initial H0 snapshot:

- **Ed25519 profile completed and made deterministic.** Full RFC 8032 §5.1.3
  decoding including the "x = 0 with sign bit 1" decoding failure; point-based
  small-order rejection (`[8]P == identity`); mixed-order public keys are now
  rejected (`E_SIG_MIXED_ORDER_A`); the order of length, `S < L`, `A` decode,
  `A` small-order, `A` mixed-order, `R` decode, `R` small-order and equation
  checks is fixed, with one error code per step.
- **Key declarations require counter-signatures.** `weave.key.declared` gains a
  `body.owner` (required for agent/program/device keys,
  `E_KEY_OWNER_MISSING`); declarations must be self-signed and counter-signed
  (`E_KEY_DECLARED_NOT_COSIGNED`). A first human/organization key may bootstrap
  with a self-signature only and must produce `N_SELF_ATTESTED_ROOT_KEY` (Q33).
- **Grants tightened.** `weave.grant` gains a `revocation` key list; delegated
  sub-grants must be subsets of their parent in kinds, actions, scope and
  validity window; the delegation chain is depth-limited with deterministic
  codes; a revoke record can no longer serve as an authority; revocation
  authority follows the granter's explicitly rotated successors only. All
  stages, including `proposed`, require grant coverage.
- **Compromise revocation now really retracts.** A signature by a key revoked
  for `key-compromise` is valid only when covered by a verified external
  RFC 3161 timestamp whose `genTime` is at or before the revocation's
  `effective_at`; claimed `recorded_at` is no longer evidence. Retired/other
  revocation uses the revocation boundary with equality counting as revoked.
- **RFC 3161 verification profile written into the specification.** Status,
  digest and signature algorithm allow-lists, ESS `signingCertificateV2`,
  certificate-in-token, timeStamping EKU, certificate validity at `genTime`,
  messageDigest, messageImprint, CMS signature, trust-anchor semantics, and the
  renewal chain are mandatory and covered by vectors. L2 is reported as
  "L0 plus `anchor_verified`"; `level_verified` is always `"L0"`.
- **Other semantics aligned with the decisions.** `moved` now means a hint-based
  relocation (digest mismatch is `unverifiable`); consent revocation is enforced
  (`E_CONSENT_REVOKED`); the previous-manifest chain must have the same origin;
  label propagation covers all four derived relations; erasure executors may be
  human, organization, an agent with a grant, or a program/device with a valid
  basis grant; `valid_from` is enforced; same-key-id declarations take the
  earliest valid declaration (no pinning); unknown-algorithm signature entries
  are ignored (Q13) with `E_SIG_UNVERIFIABLE` when no required signature can be
  verified.
- **New codes and notices.** Added `E_SIG_MIXED_ORDER_A`, `E_SIG_UNVERIFIABLE`,
  `E_KEY_OWNER_MISSING`, `E_KEY_DECLARED_NOT_COSIGNED`, `E_CONSENT_REVOKED`,
  `E_TS_RENEWAL`, `N_SELF_ATTESTED_ROOT_KEY`, `N_NO_HUMAN_SIGNATURE`.
  `E_ENV_SIG_ALG` is no longer emitted (retained for old vectors);
  `E_ERASE_ACTOR`, `E_MANIFEST_CHAIN`, `E_KEY_ROTATION_KEYS` and `E_JSON_*`
  definitions were tightened.
- **JCS error precedence written down.** A single left-to-right parse reports
  the first violation by input byte order: `+1`, `01`, `.5`, trailing commas and
  comments are `E_JSON_INVALID`; floats and exponents are
  `E_JSON_NUMBER_NOT_INTEGER`; legal out-of-range integers are
  `E_JSON_NUMBER_RANGE`; `-0` is `E_JSON_NOT_CANONICAL`.
- **Vectors and gates.** The vector set was extended and regenerated, the
  `rel` vocabulary lost `erases`/`revokes`, and freeze candidates changed:
  `vectors/frozen/v0.1` was replaced by `vectors/frozen/v0.1-candidate` (the
  official freeze starts after J1/J2 acceptance, with SHA-256 manifest, case
  count and CI verification). Gate 3 is now true source-level ablation plus a
  byte-flip gate over every positive byte; a specification-example validator
  checks that every complete JSON example in `spec/` is valid. The previous
  claim that every error-code family was covered is withdrawn: coverage is
  measured by the ablation and byte-flip gates instead.
- **Dependencies pinned.** `verifiers/python/constraints.txt` pins the exact
  transitive dependency versions the verifier was tested with; CI installs with
  `-c constraints.txt`.

### Revision 2 (decision 2026-11-10 #42)

Revision 2 is a focused follow-up after the revision-1 re-verification. It
changes the remaining trust-selection and timestamp-comparison behaviour:

- **Trust roots now come only from the locally supplied keyset** (the `--keys`
  directory, the verifier's local trust input under E4). A self-signed
  `human`/`organization` declaration in that keyset is a root; a
  `human`/`organization` declaration in the container or target must chain to
  that trust through a valid counter-signature, otherwise it is `unverifiable`
  with `E_KEY_UNTRUSTED` (and `N_SELF_ATTESTED_ROOT_KEY` when it is only
  self-signed). There is no time-ordered root selection, backdating cannot create
  a root, the keyset is evaluated before the container, and an untrusted container
  declaration must not invalidate other declarations.
- **Grant chains are evaluated at the verified record's claimed `recorded_at`**
  for the whole chain, including ancestors; verifying a grant record itself uses
  that grant's own `recorded_at`.
- **Compromise-revocation rescue is strict and precision-aware:** a signature by
  a compromised key is valid only with a verified external timestamp whose
  `genTime + accuracy` is strictly before the revocation's `effective_at`
  (missing `accuracy` counts as zero).
- **Missing trust information is not forgery:** a timestamp receipt present but
  without a trust anchor is `unverifiable` (`E_TS_UNTRUSTED`), while a signature
  with no timestamp evidence at all is `invalid` (`E_KEY_COMPROMISED`).
- **Wrong-class owner keys** are `invalid` (`E_KEY_OWNER_MISSING`), and the error
  registry gains `E_KEY_UNTRUSTED` (effect `unverifiable`), making the closed
  registry **113 error codes and 14 notices**.
- **Vectors and the candidate regression set were regenerated** after the
  semantic changes and the trust-model update: **294 vector cases**, and a
  **candidate regression set of 179 cases / 617 files / 2.5 MB** across the 12
  categories (verdicts: 71 valid, 1 erased, 100 invalid, 7 unverifiable;
  `vectors/frozen/v0.1-candidate/`). The candidate regression set remains a
  candidate; formal freezing still requires J1/J2 acceptance.
- **Verification for this revision:** `pytest` reports **246 passed, 0 skipped**;
  the conformance vectors pass **294/294** and the candidate set **179/179**. The
  remaining gates also pass on the final tree: true source-mutation ablation
  (109 mutations, 97 killed, 0 unpinned survivors, 11 documented equivalent plus
  1 documented redundant, including both mandated counterexample mutations
  killed), exhaustive byte-flip over the 144 positive cases (201,626 mutants;
  197,480 invalid, 2,730 fail-closed `unverifiable`, 1,416 exempt bytes with
  documented reasons; 0 survivors, 0 crashes), external cross-checks (RFC 8785
  6/6, RFC 8032 5/5, Wycheproof 210/210 with all `acceptable` cases rejected),
  schema/example/REUSE checks, the offline L0 manual verification, and the
  candidate checks (616/616 SHA-256 entries, `check_frozen` PASS, selection rule
  reproducible, deleting a case turns the check red). All gates were run
  locally; this file does not claim that a GitHub Actions run has passed.
- Pre-publication documentation updates: the repository is described as public
  while the format remains a draft (README, README.zh-CN, positioning,
  CONTRIBUTING, SECURITY), and Q33/P1/P2 were resolved in
  `docs/open-questions.md`.

### Explicitly not yet true in this version

- **The format is not accepted.** `weave-record/1` v0.1 has **not** been
  accepted by the J1/J2 round-trip acceptance cases; that acceptance is what
  would make v0.1 valid. The draft may still change.
- **There is only one implementation.** The Python reference verifier is the
  only verifier in this repository, so the format cannot yet claim independent
  implementations. The second (Rust) implementation is deliberately left to a
  separate implementer and is not part of H0.
- **The regression set is a candidate.** `vectors/frozen/v0.1-candidate/` is not
  frozen. Its conclusions may still change with a new decision; the official
  freeze begins only after J1/J2 acceptance.
- **No transport package.** The planned offline transport component has not
  been extracted or shipped.
- **No project adapters.** Export and import adapters for the projects that will
  use `weave-record/1` live in those projects and are not part of this
  repository.
- **Public, still draft.** The repository is public now, but that does not make
  the format stable: it is a draft and has not passed J1/J2 acceptance. The
  workflow in `.github/workflows/ci.yml` mirrors the local gates; this changelog
  does not claim that a particular GitHub Actions run passed. The verifier has
  not been released to PyPI and is installed from this repository.
- **Some implementation-shape details remain PROVISIONAL.** They are listed in
  `docs/open-questions.md` §3; they do not change the decided behaviours.

### Verifying this snapshot

The gate commands are listed in [CONTRIBUTING.md](CONTRIBUTING.md) and run in
[`.github/workflows/ci.yml`](.github/workflows/ci.yml). Run them from the
repository root to check this snapshot.

For the revision-1 hand-off snapshot, the gates were run in the build
environment and reported:

- **Gate 1 — pytest:** 237 passed, 0 skipped.
- **Gate 2 — conformance vectors:** all 284 vector cases matched their expected
  verdicts and error codes.
- **Gate 3 — true source ablation:** 107 mutations, 95 killed (90 by a changed
  conclusion, 5 by an internal precondition rather than acceptance), 0 unpinned
  survivors (11 documented equivalent mutations plus 1 documented redundant
  check). Exhaustive byte-flip over the 144 positive cases (including the
  candidate set): 338 files, 193,618 bytes, 193,618 mutants; 186,524 rejected as
  invalid, 5,674 reported `unverifiable` (fail-closed), 1,420 exempt bytes with
  documented reasons; 0 survivors, 0 crashes.
- **Gate 4 — external cross-check:** RFC 8785 6/6 document pairs, RFC 8032 5/5
  signatures, Wycheproof 210/210 outcomes (117 accepted, 93 rejected; all
  `acceptable` cases rejected per Q1).
- **Gate 5 — schema self-check and REUSE lint:** `check_schemas.py` exits 0
  (284 cases, 72 positive inputs, 43 structural assertions); `reuse lint`
  reports the repository compliant.
- **Gate 6 — offline manual verification:** the L0 worked example was verified
  by hand with `sha256sum`, OpenSSL 3.x and a JSON viewer; all checks passed.
- **Gate 7 — candidate regression set:** 178/178 cases matched; the SHA-256
  manifest verifies all 600 other files and the case count is 178; the formal
  freeze condition is J1/J2 acceptance.

These results describe this snapshot only; they are not a promise about later
revisions, and the commands above are the authority.
