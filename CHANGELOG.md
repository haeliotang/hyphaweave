<!-- SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com> -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Changelog

All notable changes to this repository are recorded here. The format is a
draft and may be replaced before the first public release.

## H1-FIX2 — 2026-11-15 — DRAFT, UNRELEASED

Revision 2 of the Rust verifier (decision 2026-11-15 #3, rulings Y1–Y10),
after the two re-reviews of H1-FIX1.

### Changed

- **Record identity** (Y1): references, erasure placeholders and the §10.3
  cross-checks are matched by the full `(origin.project, origin.instance, id)`
  identity. A cross-instance reference is now `missing` (§6.3), a placeholder
  of another instance no longer satisfies §10.3 rule 1, and placeholders of two
  instances no longer contradict each other.
- **Strict DER** (Y4): EXTERNAL, EMBEDDED PDV and CHARACTER STRING are
  constructed-only (X.690 §8.18, §8.19, §8.21.1); their primitive form is a
  check-1 violation.
- **Signer certificate version** (Y5): v1 (absent), v2 and v3 per the RFC 5280
  module; extensions require v3 and unique identifiers v2 or v3.
- **Crash-fuzz gate** (Y6): `scripts/crash_fuzz.py` never enables the test
  hooks, so only exit codes 0–2 pass; an exit 3 now fails the gate.
- **Gate 3** (Y10): each known-difference entry names the report fields that
  may differ and the comparison script's own reading of `expected.json`
  (`vector_basis`); a further field difference, a listed field that no longer
  differs, a different basis, or a classification inconsistent with the basis
  fails the gate.
- **Tests** (Y1, Y2): `tests/identity.rs` (three identity cases through
  `verify_container`) and `tests/l2_probes.rs` (the `Extension.critical`
  DEFAULT row and the chain-head `renews` rule, with a re-signed receipt).
- **Findings** (Y3, Y8, Y9): `docs/h1-findings.md` F57–F66 and the
  reclassification of F42, F44, F47 and F55.

## H1-FIX1 — 2026-11-14 — DRAFT, UNRELEASED

Revision 1 of the Rust verifier (decision 2026-11-11 #2, rulings R1–R7, and the
parts of S1–S16 that fall to Rust). It brings `verifiers/rust/` up to
specification revision 3 and the S1 rounds that followed it (S1-FIX1 to
S1-FIX5, X6, X7). The Rust verifier was still written from the specification
and the vectors only; the Python verifier is run only as a black box.

### Changed

- **Specification revision 3 implemented**: governing key class and keyset
  pins (`E_KEY_CLASS_CONFLICT`), order-independent revocations including keyset
  records, revocation validity, grant own-window and depth rules, JSON and SPDX
  nesting limits, the closed `L_*` limitation identifiers, the §14.6 report
  byte rule and field shapes, the nullable input identity, the container stop
  rules (W5), the `--previous` link verified in the target context, and the
  timestamp check order (W6).
- **RFC 3161 check 1** is a strict DER check written from X.690 and the module
  definitions (`src/der.rs`, `src/timestamp.rs`); the `cms`, `x509-cert`,
  `der`, `spki` and `const-oid` crates are no longer direct dependencies.
  `der`, `spki` and `const-oid` are still used transitively through `rsa` and
  `ecdsa`, in check 10 only (decoding the signer's public key and an ECDSA
  signature value); no check-1 decision depends on them.
- **Zip form**: the archive structure is parsed in the §11.9 order, ZIP64 is
  accepted, prefix/comment/trailing bytes are rejected, members are
  decompressed lazily under a cap and `readable/` is never decompressed.
- **Bounded reads**: directory files through probes bounded by their class
  limit, blobs hashed while streaming, record targets read to at most
  `MAX_RECORD_BYTES + 1` bytes; operator inputs are `lstat`-checked and bounded.
- **Test hook** (R3, S13): `VerifyOptions::skip_checks` exists only with the
  `test-hooks` cargo feature; the CLI reads the hook only behind `--test-hooks`
  and exits 3 when checks were disabled.
- **Dependencies** (R2): `rsa` 0.10, `p256`/`p384` 0.14, MSRV 1.87; `cargo audit`
  and `cargo deny` run without ignored advisories.
- **CI** (R1): `cargo fmt --manifest-path verifiers/rust/Cargo.toml --all
  --check`; a standing Rust crash-fuzz step (`scripts/crash_fuzz.py`).
- **Tests**: survivor probes in the default `cargo test` (R4), a 64 KiB-stack
  nesting test (R6); `scripts/diff_fuzz.py` for differential fuzzing.
- **Findings** (R7): `docs/h1-findings.md` records the status of F1–F17 after
  revision 3, the review items missing from the H1 hand-off and the new
  ambiguities found while implementing revision 3.

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

### Revision 3 (decision 2026-11-11 #2)

Revision 3 implements rulings S1–S17 that followed the H1/J1a reviews of the
second independent implementation. (The counts in this subsection describe the
revision-3 hand-off; the S1 rounds below changed several of them, and the
current counts are given there.) It is a wire-visible specification revision:
it closes ambiguities found by two independent implementations, adds resource
limits the earlier text lacked, fixes four reference-verifier defects, and turns
the report's `limitations` field into a closed identifier vocabulary. The Rust
implementation (H1-FIX1) follows in a separate change set after this revision is
merged.

- **Clarified trust and revocation state.** A key's class and validity window are
  governed by the declaration that established its trust; a container/target
  redeclaration cannot override them, a different-class redeclaration is invalid
  with the new `E_KEY_CLASS_CONFLICT`, and a backdated `recorded_at` never wins
  (S1). Key revocations from the whole verification context — keyset included —
  take effect independently of record order; retired/other uses the earliest
  effective time and compromise rescue uses the earliest `T` (S2).
- **Resource limits and bounded reads.** `MAX_JSON_DEPTH` = 32 (value nesting
  depth), `MAX_LICENCE_NESTING` = 16 and `MAX_TS_ACCURACY` = 86,400 s are new;
  violations report `E_JSON_SIZE`, `E_ENV_LICENCE` and `E_TS_SCHEMA`
  respectively, and nesting must never crash a verifier (S3, S11). Directory and
  zip containers are read within per-class limits; ZIP64 must be accepted; zip
  prefix bytes, trailing bytes and archive comments are rejected (S4, S5).
- **Deterministic verdicts and reports.** An empty `sigs` array is structurally
  valid and `E_SIG_REQUIRED` is applied by the §4.4 precedence (S7); an
  unverifiable manifest signature no longer stops record processing (S7); the
  S8 ambiguity rulings are normative (manifest multi-error reporting, missing
  attestation file, missing `body.public_key`, `-0` token order, envelope
  sub-order, nested-object codes, zip details, the keyset structural/semantic
  boundary, report construction details, check-order precedence; fourteen of
  them recorded in `docs/open-questions.md` as decided by principle); a grant
  may be issued for future effect, a grant revocation must itself be valid, and
  depth bounds are inclusive (S9, S10); `input` fields are `null` when their
  identity cannot be determined within the limits (S14).
- **Closed limitation vocabulary.** `limitations` is now a sorted, unique array
  of ten `L_*` identifiers (S12); report construction is pinned byte-for-byte in
  §14.6, including the serializer's `\u007f` escaping.
- **Test-only hook hardened.** `WEAVE_VERIFY_SKIP_CHECKS` is read only with the
  explicit global `--test-hooks` parameter, an unknown token is a usage error,
  and a skipped check makes the CLI exit `3` (S13).
- **Definitions and matcher semantics.** `recorded_at`/`occurred_at` are defined,
  every `rel` has a direction, and a record's salt is fixed across exports
  (S15). The H1 findings F1–F17 are adopted (report identity, dedicated
  nested-object codes, envelope sub-order, unverifiable manifest continuation,
  terminal blocking conditions, undetermined report fields, the keyset boundary,
  input identity, report construction, inert `sigs[].alg` bytes, hook tokens,
  command-surface details, stop rules, matcher semantics).
- **Error registry.** New `E_KEY_CLASS_CONFLICT`; extended conditions for
  `E_JSON_SIZE`, `E_ENV_LICENCE`, `E_TS_SCHEMA`, `E_MANIFEST_UNSIGNED`,
  `E_MANIFEST_CHAIN`, `E_CONTAINER_ZIP`, `E_ENV_SIGS`; the envelope-level
  `E_ENV_MISSING_FIELD`/`E_ENV_UNKNOWN_FIELD` rows are narrowed to the top-level
  envelope; the closed registry is **114 error codes, 14 notices and 10
  limitation identifiers**.
- **Schemas.** The record `sigs` array is structurally 0–16 entries (the
  must-sign rule stays in the specification); the SPDX approximation is
  documented as a character-alphabet check whose grammar and depth are enforced
  by the verifier.
- **Vectors.** The main corpus grows from **294 to 343 cases** (+49) across the
  twelve categories, pinning every new ruling and fixed error code; the
  expectation format gains `expected_input`, `limitations` and `notices_absent`,
  plus exact empty-`records` assertions. The candidate regression set is
  regenerated from the gated state: **190 cases** (179 previous, +23 selected new
  cases, −12 previous representatives displaced by a lexicographically earlier
  case for the same code); every change is listed in
  `vectors/frozen/v0.1-candidate/FROZEN.md` (S17).
- **Reference verifier.** The Python verifier implements the revision:
  authoritative keyset declarations, order-independent revocation state, bounded
  streaming reads, ZIP64, nesting limits, the new report and limitation
  vocabulary, `--test-hooks`/exit 3, and the four differential-fuzz defect fixes.
  The test suite reports **277 passed**.
- **Tooling.** The vector generators gain the new expectation fields; the schema
  self-check learns the new structural predicates; the true-source ablation gate
  grows to **141 mutations (128 killed, 11 documented equivalent, 2 documented
  redundant, 0 unpinned survivors)**; the byte-flip gate documents the
  deliberately unsigned `proposed` positive cases.

### S1 rounds after revision 3 (decisions 2026-11-11 #5, #12, #14, #16, 2026-11-12 #1)

Five review rounds on the revised text and on the Python verifier (S1-FIX1 to
S1-FIX5) followed revision 3 before it was merged. Each is wire-visible; the Rust
implementation on its own branch has not yet followed them (H1-FIX1).

**S1-FIX1 (decision 2026-11-11 #5, T1–T17).**

- A missing or malformed `weave.key.declared` `body.public_key` is
  `E_KEY_PUBLIC_KEY`, before `E_KIND_BODY_SCHEMA` (T1).
- Retired/other and key-compromise revocations act independently, the stricter
  result wins; there is no "compromise overrides retirement" (T2).
- TSA `accuracy`: a millis/micros component outside 1–999 is `E_TS_SCHEMA`; a total
  above `MAX_TS_ACCURACY` or an overflow is *unusable evidence*
  (`present-unverified`, `E_TS_UNTRUSTED`, container unverifiable, never a rescue);
  `genTime` is truncated to milliseconds before the rescue comparison (T3).
- Any keyset declaration governs its key's class and window; conflicting keyset
  declarations are a usage error (exit 2); "earlier" is `(recorded_at, record
  digest)` everywhere (T4). `sigs` is structurally 0–16 entries (T5).
- The zip structure rules of §11.9 (local header versus central directory, data
  descriptors, no gaps or overlaps, EOCD/ZIP64 counts, `readable/` entry safety),
  parsed by the verifier itself (T6); the candidate set only grows (T7).
- A revocation signed by an already-revoked key does not take effect (T9); one
  TOFU predicate for `N_KEY_TOFU` and `L_KEY_TRUST_TOFU`, the manifest signature
  included (T10); `E_KEY_ROTATION_KEYS` precedes `E_SIG_*` (T13); member order is
  UTF-16 code-unit order (T14); the directory form is bounded by
  `MAX_CONTAINER_UNCOMPRESSED_BYTES` too (T15); the oversize-record report shape
  is fixed (T16).

**S1-FIX2 (decision 2026-11-11 #12, U1–U12).**

- `--previous` accepts a zip and its failures are `E_MANIFEST_CHAIN` (U1); the §13
  entry-count and declared-total limits apply to the zip form as
  `E_CONTAINER_SIZE`, `readable/` excluded from the total (U2).
- A self-revocation exempts only its own effect (U3); the governing class is
  decided from structurally valid declarations before and independently of the
  trust closure (U4, U5); rotated key material counts as TOFU (U6).
- `L_TSA_TRUST_UNVERIFIED` only for a `present-unverified` receipt (U7); the
  records-listing stage reports all of its violations together (U8); only
  single-volume archives (U9).

**S1-FIX3 (decision 2026-11-11 #14, V1–V8).**

- Decompression never crashes; target and previous use one member reader (V1).
- Any receipt DER/structure failure is check 1's `E_TS_SCHEMA`, receipts must be
  strict DER, with fixed version values (V2).
- A supplied previous container only links the chain: two members read, the rest
  not verified, new limitation `L_PREVIOUS_CONTENT_UNVERIFIED` (V3).
- `public_key` encoding is structural (V5); central-directory version-needed ≤ 63
  and per-entry disk start 0 (V6); `record_count` keeps the manifest count once
  the manifest structure passed (V7); a permanent crash-fuzz gate (V8).

**S1-FIX4 (decision 2026-11-11 #16, W1–W11).**

- **W1.** A supplied previous container's manifest signature is verified in the
  **target** container's verification context: the key must be a §11.3 required
  key of the target (keyset plus the target's own declared/rotated records, never
  the previous container's), trusted in the target's final trust closure, and
  usable under §9.4 at the previous manifest's `created_at` (a compromise always
  broke the link; S1-FIX5 X2 replaced this). Device-signed exports whose keyset holds only the owner link
  again; a key rotated away links through the target's rotation record.
- **W2.** §11.9 rules 1–4 apply to every entry of a supplied previous zip; only
  name safety, duplicate names, CRC and `readable/` rules are skipped for the
  unread members.
- **W3.** §12.2 check 1 is a real DER check in sub-steps 1a–1e: universal DER rules
  over every TLV (universal SETs in DER order), a full decode, a DER re-encoding
  of the decoded receipt that must equal the input (every SET OF sorted —
  `digestAlgorithms`, `certificates`, `crls`, `signedAttrs`, `unsignedAttrs`,
  `attrValues`, RDNs — and no DEFAULT encoded), the version values, and decoding
  of every carried certificate and its extension values; the TSTInfo gets 1a–1c
  on its own.
- **W4.** `--keys`, `--tsa-trust` and the `--previous` path are operator inputs
  checked before verification; any read or decode failure is a usage error
  (exit 2, the file named on stderr, no report).
- **W5.** A container-level invalid error at the cross-record, blob or
  previous-chain stage stops the pipeline: later stages report no code, notice,
  limitation or timestamp entry. Inside the previous-chain stage the supplied
  previous is verified first, and `L_PREVIOUS_CONTENT_UNVERIFIED` has one
  criterion (the stage ran and the supplied signature verified).
- **W6.** The complete timestamp order: file checks, then the renewal-chain shape,
  then checks 1–13 and 15 per receipt; one code per receipt; an algorithm/key-type
  mismatch is check 10 (`E_TS_CMS`).
- **W7.** The zip check order: locate the EOCD (prefix and trailing bytes) → parse
  the central directory → §13 limits (`E_CONTAINER_SIZE`, stop) → every remaining
  structural rule.
- **W10.** Every `ed25519` entry of an attestation file is judged, the first
  failing entry in array order deciding the code (a supplied previous follows the
  same rule); every top-level keyset entry whose name ends in `.json`, hidden names
  included, is a keyset file, and one that is not a regular file is a usage error
  (exit 2).
- **W8, W9, W11 (gates).** No blanket `.tsr` byte-flip exemption; the V3 core
  checks are pinned by vectors; crash-fuzz skips no-op mutants, prints the seed on
  failure, and its corpus gains the seed-777 PEM.

**S1-FIX5 (decision 2026-11-12 #1, X1–X5).**

- **X1.** §12.2 check 1's DER rules come from X.690 and the ASN.1 module
  definitions only. The DEFAULT components are listed with the encodings of their
  defaults; the ESSCertIDv2 default is `{id-sha256}` without parameters, so an
  explicit `{id-sha256, NULL}` is valid and an explicit `{id-sha256}` is
  `E_TS_SCHEMA`. A value of an open type (an unregistered attribute's value, for
  example) is judged by its TLV framing only, whatever its tag class. `genTime`
  and the other time values are compared as their raw DER form, so seven or more
  fractional digits are valid. The high-tag-number form follows X.690 §8.1.2.4
  (only the first subsequent octet may not be `0x80`).
- **X2.** On the previous link a `key-compromise` revocation is judged like a
  retired one, against the previous `created_at`: `created_at` before the
  compromise time links, at or after it is `E_MANIFEST_CHAIN`.
- **X3.** `--keys`, its entries, `--tsa-trust` and `--previous` are examined with
  `lstat` before opening; a FIFO, device or socket is a usage error (exit 2) and
  never blocks; `--tsa-trust` is read with the bound `MAX_TIMESTAMP_BYTES`.
- **X5.** On the previous link a rotation record that is not valid supplies no
  key material (§11.5 rule 1).
- **X6 (decision 2026-11-12 #2).** The `parameters` of the signer's
  `digestAlgorithm` and `signatureAlgorithm` have a fixed form: SHA-2 absent or
  `NULL`, `rsaEncryption` `NULL`, sha*WithRSAEncryption absent or `NULL` (as
  corrected by X7), ECDSA absent; any other form is `E_TS_SCHEMA`.
- **X7 (decision 2026-11-12 #3).** UTCTime/GeneralizedTime forms are matched
  against the whole content (a trailing line feed is `E_TS_SCHEMA`); every
  whole-string pattern of the verifier uses a full match; the token carries
  exactly one `SignerInfo`, whose version matches its `sid` (RFC 5652 §5.3);
  check 1e decodes the signer certificate only, every
  other carried certificate is an open type.

**Current counts (S1-FIX5 hand-off).** Registry: 114 error codes, 14 notices, 11
limitation identifiers (no code added in S1-FIX1–FIX5 except
`L_PREVIOUS_CONTENT_UNVERIFIED` in S1-FIX3). Vectors: main corpus **498 cases**
(revision 3 hand-off 343; +41 S1-FIX1, +19 S1-FIX2, +18 S1-FIX3, +47 S1-FIX4,
+30 S1-FIX5); candidate regression set **202 cases**. No gate figures are recorded
for the S1 rounds; the only recorded figures are those of the revision-1 snapshot
under "Verifying this snapshot" below.

### Explicitly not yet true in this version

- **The format is not accepted.** `weave-record/1` v0.1 has **not** been
  accepted by the J1/J2 round-trip acceptance cases; that acceptance is what
  would make v0.1 valid. The draft may still change.
- **Only one implementation follows this revision.** On this branch the Python
  reference verifier is the only verifier. A second, independent implementation
  (Rust, H1) exists on a separate branch but has not yet been brought up to
  revision 3 and the S1 rounds, so the format cannot yet claim two conforming
  independent implementations.
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
