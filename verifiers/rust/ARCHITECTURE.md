<!-- SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# H1 Rust verifier — architecture and workstream contract

This document is the internal contract for the H1 implementation. It describes
the module layout, the interfaces between workstreams, how to build and test,
and the rules that keep the second implementation independent of the first.

The implementation is written **from the specification and the conformance
vectors only**. The following must never be read by any workstream:

- `verifiers/python/**` — the Python reference verifier;
- `tools/**` — the vector generators contain implementation details;
- `git log -p` / `git show` output touching those paths;
- `~/.claude/plans/hyphaweave-h0/**`;
- `/Users/hao/Documents/epiweave/docs/design/**`.

The Python verifier may be executed as a **black box** only for gate 3 (the two
implementation report comparison), and only after the Rust verifier has passed
every committed vector. Never read its source.

Repository text is English. Every source file carries the two SPDX header lines.

## Building and testing

Run from the repository root (`/Users/hao/Documents/hyphaweave`). The DSH file
sandbox only allows writes inside the repository, so the cargo registry cache is
kept in the already-ignored `.tmp-work/` directory:

```bash
export PATH="$HOME/.cargo/bin:$PATH"
export CARGO_HOME="$PWD/.tmp-work/cargo-home"
cargo build --manifest-path verifiers/rust/Cargo.toml
cargo test  --manifest-path verifiers/rust/Cargo.toml -p hyphaweave-verify
```

- Do not add or change dependencies in `Cargo.toml` without asking the Lead.
  The dependency set is fixed; `deny.toml` and `cargo deny check licenses` are
  part of the gates.
- Do not run `cargo fmt` (it would reformat other workstreams' files); write
  formatted code by hand. The Lead runs `cargo fmt` once during integration.
- Do not run any `git` write command. The Lead owns all commits. Read-only
  `git status` is fine.
- Only edit the files assigned to your workstream. Never edit another
  workstream's file; if an interface is insufficient, message the Lead.
- `todo!()` stubs in other modules compile; you can build at any time.

## Module map and ownership

| file | workstream | contents |
|---|---|---|
| `src/value.rs` | Lead (done) | JSON value tree |
| `src/json.rs` | Lead (done) | WR-CJ parser + canonical writer + canonical file form |
| `src/b64.rs` | Lead (done) | strict unpadded base64url |
| `src/digest.rs` | Lead (done) | SHA-256, digest strings, key ids, domain prefixes |
| `src/time.rs` | Lead (done) | TS literal grammar/arithmetic |
| `src/limits.rs` | Lead (done) | §13 limits |
| `src/patterns.rs` | Lead (done) | shared string grammars |
| `src/error_codes.rs` | Lead (done) | closed error/notice registry |
| `src/labels.rs` | Lead (done) | SPDX licence expression syntax |
| `src/envelope.rs` | Lead | envelope structure + `sigs` grammar + reference/label parsing |
| `src/report.rs`, `src/options.rs`, `src/lib.rs` | Lead | report model, inputs, public API |
| `src/record.rs`, `src/context.rs` | Lead | per-record pipeline, trust/key/grant state, cross-record checks |
| `src/ed25519.rs` | **crypto** | §3 Ed25519 profile (from RFC 8032 + §3 only) |
| `src/timestamp.rs` | **l2** | §12 RFC 3161 / CMS / X.509 |
| `src/zip.rs`, `src/container.rs` | **container** | §11 container + zip reader |
| `src/kinds.rs` | **kinds** | registered-kind body schemas + signing obligations |
| `src/report_json.rs`, `src/vectors.rs`, `hyphaweave-verify-rs/src/main.rs` | **cli** | report bytes, vectors runner, CLI |
| `.github/workflows/ci.yml` Rust job, `deny.toml`, `REUSE.toml`, `README*`, `CHANGELOG.md`, `docs/h1-findings.md`, `verifiers/rust/README.md` | **docs** | repository-level deliverables |

## Shared rules

- A `Code` is `&'static str` from `crate::error_codes` (`e::…`, `n::…`). Never
  invent a code; the registry is closed.
- `VerifyOptions::skipped(code)` is the test-only §14.7 hook. If your module
  performs a check that has an error code, evaluate `options.skipped(code)`
  before returning that code — but still perform the *structural* parsing that
  later steps need. The ablation gate relies on this.
- Parsing/IO failures that are input defects are reported in the `Report`;
  only keyset/CLI/IO failures are `UsageError` (exit 2).
- Determinism: no wall clock, no locale, no environment, no filesystem order.
  Iterate `BTreeMap`/sorted vectors.
- Size limits are enforced while reading, never after materialising.
- Keep the source files reasonably sized and comment each check with the
  specification section it implements.

## Workstream contracts

### crypto — `src/ed25519.rs`

Implement §3 exactly, from the specification plus RFC 8032 and the external
vectors under `vectors/external/` (read-only input).

Public interface (keep these signatures):

```rust
pub fn verify(public_key: &[u8], signature: &[u8], message: &[u8]) -> Result<(), Code>;
pub fn public_key_from_seed(seed: &[u8; 32]) -> [u8; 32];
pub fn sign(seed: &[u8; 32], message: &[u8]) -> [u8; 64];
```

- `verify` performs §3.4 steps 2–9 in the fixed order and returns the code of
  the first failing step. `E_ENV_SIG_VALUE`/`E_MANIFEST_SCHEMA` (step 1) belong
  to the caller.
- Use `curve25519-dalek` point/scalar arithmetic, **not** its convenience
  verifier. Point decoding must be implemented per §3.2: canonical `y < p`
  check, square-root check, and the `x = 0` with sign-bit-1 rule. The
  small-order predicate must be point-based (`[8]P == identity`), never an
  encoding list. Mixed-order means `[L]A != identity`.
- Unit tests required in the same file: RFC 8032 §7.1 vectors (all 5; derived
  public keys and signatures must verify), the eight small-order encodings and
  `x0-sign-bit`/`noncanonical-y-p` edge keys from `vectors/keys/edge-points/`,
  `S >= L` rejection, non-canonical R, and a handful of Wycheproof cases.
- Integration tests for the external gates (RFC 8032 and Wycheproof): add
  `tests/external_ed25519.rs` in the crate root. Read
  `../../../vectors/external/rfc8032/rfc8032.txt` and
  `../../../vectors/external/wycheproof/testvectors_v1/ed25519_test.json` plus
  `EXPECTED_OUTCOMES.json` relative to `env!("CARGO_MANIFEST_DIR")`. Parse the
  Wycheproof JSON with `hyphaweave_verify::json::parse_object` (it is ordinary
  JSON, not WR-CJ: `parse_object` allows whitespace/member order, rejects
  duplicate keys and non-integer numbers — the file satisfies those rules).
  EXPECTED_OUTCOMES maps `expected`/`result`: `valid` → accepted, `invalid` →
  rejected, `acceptable` → rejected per §3.7 (map to the first failing §3.4
  code; at minimum rejected). Print a summary with `--nocapture`.

### l2 — `src/timestamp.rs`

Implement §12 exactly (check table §12.2, anchors §12.3, renewal chain §12.4,
effects §12.5). Read `vectors/integrity-levels/**` as test material (the L2
cases carry crafted `.tsr` files), `vectors/keys/tsa/`, and the RFCs cited in
the specification.

Public interface (keep these signatures):

```rust
pub fn verify_chain(
    entries: &[AttestationTimestamp],
    manifest_digest: &[u8; 32],
    files: &BTreeMap<String, Vec<u8>>,
    trust_anchors: &[[u8; 32]],
) -> ChainEvidence;
pub fn receipt_effect(error: Code) -> &'static str;
pub fn load_trust_anchors(file_contents: &[Vec<u8>]) -> Result<Vec<[u8; 32]>, UsageError>;
```

- Parse with RustCrypto (`der`, `cms`, `x509-cert`, `spki`, `const-oid`,
  `rsa`, `p256`, `p384`, `signature`). No network, no chain building; anchor
  comparison is the SHA-256 of the signer leaf certificate DER (§12.3).
- `files` has already been checked to contain each listed `.tsr` with matching
  digest; read receipt bytes from it. Verify the renewal chain's imprints
  (§12.4): first receipt = raw 32-byte manifest digest; renewal =
  `SHA-256(previous .tsr bytes || raw manifest digest)`.
- `ChainEvidence.receipts` is aligned with `entries`; `chain_error` is the
  §12.2 check-14 code (`E_TS_RENEWAL`) when the chain structure is wrong;
  `anchor_verified` is true only when the chain is complete and every receipt
  passes check 15.
- Add unit tests in the file and an integration test
  `tests/external_l2.rs` that walks every case in
  `vectors/integrity-levels/` whose `expected.json` mentions `E_TS_*` or
  `anchor_verified`, and asserts the per-receipt outcomes (invalid code,
  present-unverified, verified). Use the case's `container/signatures/*.tsr`
  bytes, the computed manifest digest (SHA-256 of
  `weave-record/1/manifest-digest\n || manifest.json bytes without the optional
  LF`), and `tsa.crt.pem` when the case expects a trusted anchor.

### container — `src/zip.rs`, `src/container.rs`

Implement §11 (layout, manifest, attestation file, levels, records consistency,
blobs, previous chain) and the container order of §14.5. `container::
verify_container(input, options) -> Result<Report, UsageError>` is the entry
point; all container content defects are reported, never `Err`.

Data in: `ContainerInput::{Directory(PathBuf), Zip(Vec<u8>), Files(BTreeMap)}`.
Materialise a `BTreeMap<String, Vec<u8>>`:
- `Directory`: recursive enumeration in sorted relative-path order; reject
  symlinks/non-regular files; enforce `MAX_CONTAINER_ENTRIES` and the total
  uncompressed-byte limit while reading.
- `Zip`: `zip::read_zip` (pure-Rust minimal reader; stored + deflate via
  `miniz_oxide`; reject encryption/unsupported compression with
  `E_CONTAINER_ZIP`, enforce entry/size limits while inflating).
Then follow the container check order exactly; the key rules:

1. Entry safety/layout (`E_CONTAINER_ENTRY`; unknown top-level entries, bad
   paths, duplicate names, unknown files under `signatures/`/`previous/`;
   `readable/` is ignored entirely and never parsed/hashed). Extra file in
   `records/` → `E_MANIFEST_RECORD_EXTRA`; extra file in `blobs/` →
   `E_MANIFEST_BLOB`.
2. `manifest.json` missing → `E_MANIFEST_MISSING`; parse with
   `json::parse_canonical_object(.., limits::MAX_MANIFEST_BYTES)` (JSON codes
   pass through).
3. Manifest schema (`E_MANIFEST_SCHEMA`, `E_MANIFEST_FORMAT`,
   `E_MANIFEST_VERSION`, `E_MANIFEST_LEVEL`, `E_MANIFEST_RECORDS`; details in
   §11.2/§11.2.1). Manifest structure invalid before records → container
   invalid, `records: []`, exactly one container error (§14.5).
4. Manifest digest = `digest::manifest_digest(canonical manifest bytes without
   LF)`; compare with `signatures/manifest.sig.json.digest` → `E_MANIFEST_DIGEST`
   (invalid; before signature verification). Parse the attestation file with
   `json::parse_canonical_object(.., limits::MAX_SIGFILE_BYTES)`; schema per
   §11.3 (`E_MANIFEST_SCHEMA`), `timestamps` mandatory (`E_MANIFEST_LEVEL` for
   L0/L1 non-empty, `E_MANIFEST_L2_NO_TIMESTAMP` for L2 empty), `E_TS_FILE`
   for missing/mismatched `.tsr`.
5. Manifest signature: parse the `signatures[]` array with the shared
   `envelope::parse_signature_array` helper (added by the Lead; if absent,
   message the Lead). Empty → `E_MANIFEST_UNSIGNED`; known-alg failure →
   `E_MANIFEST_SIG_INVALID`; no verifiable declared-key signature →
   unverifiable `E_KEY_UNKNOWN`/`E_SIG_UNVERIFIABLE`. Signature verification
   must use the context's key state: build the `context::World` with the
   container's parsed records first (parsing records early is fine; their errors
   are reported later), then call
   `world.check_manifest_signatures(&sig_entries, &manifest.created_at)`.
   If the manifest digest or signature check is invalid, stop: `records: []`
   and exactly one container error.
6. Level/chain completeness per §11.2/§11.4 (`E_MANIFEST_L1_NO_HEAD`,
   `E_MANIFEST_L1_NO_POSITION`; `N_CHAIN_CLAIM_UNVERIFIED`);
   `level_verified` always `"L0"`, `anchor_verified` from timestamps.
7. Records listing (§11.2.1, §11.6): each manifest entry needs
   `records/<64 hex>.json` (`E_MANIFEST_RECORD_MISSING`), canonical parse,
   matching digest (`E_MANIFEST_RECORD_DIGEST`), matching `id`/`kind`
   (`E_MANIFEST_RECORDS`). Extra/unlisted/malformed file names
   `E_MANIFEST_RECORD_EXTRA`. These errors make the container invalid but
   record processing continues for the files that are present.
   Parse each present record with `envelope::parse_record_file`; build
   `Vec<Option<RecordFile>>` in manifest order (`None` = parse failed) and
   create `context::World::new(slots, options)?`.
8. Timestamp chain: `timestamp::load_trust_anchors(&options.tsa_trust)?`, then
   `timestamp::verify_chain(entries, &manifest_digest_raw, &files, &anchors)`;
   `world.set_timestamp_evidence(evidence.clone())` **before**
   `world.evaluate_all()`. Report `container.timestamps` entries and container
   errors/effects: any receipt invalid → container invalid; any
   present-unverified (or claimed L2 without trusted chain) → unverifiable
   `E_TS_UNTRUSTED`; `anchor_verified` true only when the whole chain verified.
   (Internal order: timestamps may be verified before evaluating records; the
   reported check order does not change.)
9. Per-record reports: `world.evaluate_all()`, then
   `world.container_cross_checks()` (§10.3 erasure, §8.5 local-only export,
   §5.4 idempotency duplicate); merge `record_errors`/`record_notices` into the
   reports (an error makes a `valid` record `invalid`; sort and dedupe).
10. Blobs (§11.7) `E_MANIFEST_BLOB`.
11. Previous-manifest chain (§11.5) `E_MANIFEST_CHAIN_MISSING`,
    `E_MANIFEST_CHAIN_UNEXPECTED`, `E_MANIFEST_CHAIN`, and `--previous`
    (`options.previous`): recompute that container's manifest digest and
    compare. From the current container also report
    `N_PREVIOUS_SIG_UNVERIFIED` when a previous manifest is embedded and its
    signature was not re-verified.
12. Aggregate: container verdict `invalid` if any container or record error;
    else `unverifiable` if any unverifiable container condition or record, else
    `valid`. Top-level never `erased`. `summary` counts record verdicts.
    `input` identity: zip bytes for zip; for a directory container the manifest
    digest and manifest byte size (§14.6/Q27); for materialised files use the
    manifest bytes.

`Report` fields that cannot be determined because an earlier check failed are
`None`/empty, never invented. If a container-level invalid failure happens
before record processing, report `records: []` and exactly one container error.

### kinds — `src/kinds.rs`

Implement §7.2 plus all eight kind pages under `spec/kinds/` (read-only), and
the body tables of §5.5, §9.1–§9.3, §10.2, §8.6. `parse_body(record)` is
§14.5 check (6) and returns the structured [`KindBody`]; it must return the
first schema/semantic-without-context error. `obligation(record, body)` derives
the §4.4 signing requirement.

Rules to get exactly right:
- Closed variant objects: unknown member inside `grant`/`revoke` (or any other
  closed body variant) is `E_GRANT_SCHEMA`; unknown member at the `body` root of
  a registered kind is allowed (§7.5); unknown kinds are `KindBody::Opaque` and
  the body is never inspected (§7.3).
- Body member tables and their codes: key declaration (`E_KEY_PUBLIC_KEY`,
  `E_KEY_ID_MISMATCH`, `E_KEY_OWNER_MISSING` presence part, `E_KEY_VALIDITY`);
  rotation (`E_KEY_ROTATION_KEYS`); revocation (`E_KEY_REVOKE_EFFECTIVE`,
  closed `reason` vocabulary); grant (`E_GRANT_SCHEMA`, list bounds, closed
  action/kind vocabularies, `E_KEY_VALIDITY` for the window); consent
  (`E_CONSENT_VALIDITY`); erasure (closed `reason`, reference objects);
  `E_KIND_BODY_SCHEMA` for any other body-shape violation of a registered kind.
- Kind↔envelope constraints that need no context: declaration
  `actor.key == body.key` / `actor.type == body.key_type`; rotation
  `actor.key == body.old_key`; the seven kinds are `accepted` only (already
  enforced by `envelope.rs`). Use the codes the kind pages name (for the
  declaration `E_ENV_ACTOR*`/`E_ACTOR_KEY_TYPE_MISMATCH`; if a page names none,
  message the Lead and record it in `docs/h1-findings.md`-style notes in your
  reply).
- Parse reference objects with `envelope::parse_ref_object`, mapping its
  `E_ENV_REFS` to the kind's body code where the kind page says so.
- Unit tests in the file and/or `tests/kinds.rs`: iterate the vector case
  directories (`vectors/<category>/<case>/record.json`) whose `expected.json`
  targets a record and expects a kind-level code (`E_KIND_BODY_SCHEMA`,
  `E_GRANT_SCHEMA`, `E_KEY_*`, `E_CONSENT_VALIDITY`, ...), call
  `envelope::parse_record_file` + `kinds::parse_body`, and assert the code.
  Cases whose defect is later-stage (actor/authz/context) are out of scope for
  this module.

### cli — `src/report_json.rs`, `src/vectors.rs`, `hyphaweave-verify-rs/src/main.rs`

1. `report_json::to_bytes(&Report) -> Vec<u8>` must reproduce Python's
   `json.dumps(report, sort_keys=True, indent=2, ensure_ascii=True) + "\n"`
   exactly, because gate 3 compares the two implementations' report bytes:
   - keys sorted (UTF-16 order; report keys are ASCII), two-space indent,
     `": "` after keys, one item per line, empty array `[]` and empty object
     `{}` inline, exactly one trailing LF;
   - every non-ASCII scalar escaped as `\uXXXX` (surrogate pairs for
     supplementary code points), control characters `\u00XX` except the
     `\b \t \n \f \r` shorthands; `/` never escaped; no other differences.
   Build a `crate::value::Value` tree from the `Report` and serialize it with
   your own writer (the crate has no serde dependency).
2. `vectors::verify_vectors(dir, options) -> Result<Report, UsageError>`:
   discover `<category>/<case>/expected.json` deterministically (sorted
   recursion), read `expected.json` with `json::parse_object` (it is canonical
   JSON but may or may not carry the trailing LF; use `parse_object`, not the
   canonical-form check), then reproduce the case:
   - `target: "record"`: read `input` bytes → `crate::verify_record(bytes,
     case_options)`.
   - `target: "container"`: `input` is a directory (`verbatim_manifest`-free
     path) or `.zip` file inside the case dir → `crate::verify_container`.
   - `args` tokens: `@keyset` resolves to the `keys/keyset` directory found by
     walking up from the vectors directory until a `keys/keyset` directory
     exists; `@case` is the case directory; other tokens are paths relative to
     the case directory. `--keys <dir>` → load the directory's top-level
     `*.json` files sorted by name into `VerifyOptions::keyset`;
     `--tsa-trust <pem>` → `VerifyOptions::tsa_trust` file contents;
     `--previous <dir>` → `VerifyOptions::previous`.
   - Matching (`vectors/README.md`): verdict exact; errors as a set over
     `container.errors ∪ all records[].errors`; notices as a subset over the
     same union; `expected_digest` against `records[0].digest` for record
     targets; `expected_resolution` (map of reference index → state) against
     `records[0].refs`; `expected_container` recursive subset match of the
     report's `container` object (nested objects recursive, arrays/values
     exact); `records` per-id subset match (`verdict`/`errors` when present).
   - `Report.summary` = `Summary::Vectors{case_count, matched, mismatched}`,
     one `cases[]` entry per case (`id`, `matched`, `expected`, `actual`),
     `target: Target::Vectors`, top-level verdict `Valid` iff mismatched == 0,
     `input` = `sha256`/`size` of a deterministic representation — the sorted
     case-id list joined with `\n` (document this in the module docs; the
     layout is PROVISIONAL per P7).
3. CLI binary `hyphaweave-verify-rs`, argument surface exactly as §14.1:
   ```
   hyphaweave-verify-rs record <file> [--keys <dir>] [--json]
   hyphaweave-verify-rs container <dir|zip> [--keys <dir>] [--tsa-trust <pem>] [--previous <dir>] [--json]
   hyphaweave-verify-rs vectors <dir> [--tsa-trust <pem>] [--json]
   hyphaweave-verify-rs --help | --version
   ```
   `--json` accepted and default. Read `WEAVE_VERIFY_SKIP_CHECKS` (comma
   separated; unset/empty = normal) into `VerifyOptions::skip_checks`; the
   library echoes the sorted list in `checks_disabled`. On success print
   `report_json::to_bytes` to stdout. Exit codes: 0 for `valid`/`erased` or all
   vectors matched, 1 otherwise, 2 for usage/IO (no report on stdout; message on
   stderr). Do not print anything else. Keyset dir loading: top-level `*.json`
   files sorted by file name; I/O errors → exit 2. `--keys`/`--tsa-trust`/
   `--previous` are also accepted by `vectors`? No: only as documented above.
   Keep `main.rs` small; put helpers in the bin crate.

### docs — repository deliverables

- `.github/workflows/ci.yml`: add one `rust` job (do not touch the existing
  `gates` job). Commands: `cargo fmt --check`, `cargo clippy --all-targets --
  -D warnings`, `cargo test`, `cargo run -p hyphaweave-verify-rs -- vectors
  vectors`, frozen set run, `cargo deny check`, and the report-comparison
  script step. Use `dtolnay/rust-toolchain@stable`, `taiki-e/install-action`
  for cargo-deny (or `cargo install cargo-deny --locked`), and check out the
  Python setup step only for the comparison job. Local equivalents must be
  documented.
- `verifiers/rust/deny.toml`: allow only permissive licences (Apache-2.0,
  MIT, BSD-2-Clause, BSD-3-Clause, ISC, Zlib, Unicode-3.0, Unlicense,
  CC0-1.0, MPL-2.0? — check actual dependency licences with
  `cargo deny check licenses` and list exactly what is needed; no copyleft
  beyond MPL if unavoidable). Do not silence licence checks.
- Root `REUSE.toml`: add the new Rust tree (`verifiers/rust/**`) to the
  Apache-2.0 annotation list; `reuse lint` must pass (use
  `.venv/bin/reuse lint`; the sandbox has no global reuse).
- `verifiers/rust/README.md`: how to build and run; state explicitly
  "written from the specification and vectors only" and list the dependency
  purposes and licences.
- Root `README.md`/`README.zh-CN.md`: change **only** the sentence that says
  only one implementation exists, to say there are two implementations and H1
  has not yet had external review. Leave every other status statement as is.
- `CHANGELOG.md`: add an entry for H1.
- `docs/h1-findings.md` (CC-BY-4.0 header): the specification-ambiguity
  findings of §4 of the task, one section per finding with chapter, possible
  readings, chosen reading + reason, whether vectors pin it, Python
  black-box agreement (filled in after gate 3), proposed wording change.
  Also keep a `registry-notes` scratch list that other workstreams append to
  by messaging you.

## Reporting back

When your workstream is complete, send the Lead: (1) what is implemented,
(2) `cargo build` / `cargo test` status with counts, (3) files touched,
(4) open questions or interface changes needed, (5) anything a gate will need
to check. If you are blocked, say exactly what you need.
