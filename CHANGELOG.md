<!-- SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com> -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Changelog

All notable changes to this repository are recorded here. The format is a
draft and may be replaced before the first public release.

## 0.1.0 — 2026-11-10 — DRAFT, UNRELEASED

Milestone H0: the `weave-record/1` v0.1 specification set, JSON Schemas,
conformance vectors and the Python reference verifier. This version is a draft
for review. It is not published, not tagged, and not accepted as a stable
version of the format.

### Added

- **Specification** (`spec/`): a 1,962-line normative `weave-record/1`
  specification covering the record envelope, references, containers and
  manifests, erasure, grants and authorization, integrity levels L0/L1/L2, the
  five-state reference resolution model, the strict Ed25519 verification
  profile, WR-CJ canonical JSON, size limits and forward-compatibility rules.
  Eight registered kind pages (one per `weave.*` kind), a closed error-code and
  notice registry in `spec/error-codes.md`, and a 672-line step-by-step offline
  verification guide for an L0 container using only common tools.
- **Schemas** (`schemas/`): 11 JSON Schema 2020-12 documents — envelope,
  references, manifest, and the eight registered kinds — with a local offline
  self-check script.
- **Conformance vectors** (`vectors/`): 181 positive and negative cases across
  12 categories (jcs 18, digest 5, sig 22, ref 12, stage 17, actor 26, labels 23,
  erasure 7, grant 12, key-lifecycle 9, container 20, integrity-levels 10),
  deliberately public synthetic test keys, a generated index, frozen v0.1
  regression cases (see `vectors/frozen/v0.1/FROZEN.md`), and provenance for the
  official external test data used for cross-checks (RFC 8785 canonicalization,
  RFC 8032 Ed25519, the Wycheproof Ed25519 suite).
- **Reference verifier** (`verifiers/python/`): `hyphaweave_verify` 0.1.0, the
  `hyphaweave-verify` command-line tool (`record`, `container`, `vectors`,
  `--keys`, `--tsa-trust`, `--previous`), deterministic JSON reports with
  per-record verdicts and error codes, and full L0 and L1 verification. L2
  RFC 3161 timestamps are verified only against an explicit trust anchor;
  without one the timestamp is reported as `present-unverified` and the
  container as `unverifiable`.
- **Tooling** (`tools/`): independent vector generators that do not import the
  verifier (`wcj`, `keyutil`, `recordlib`, `gen_vectors`, `gen_index`,
  `make_keys`), the schema self-check, the external-data cross-check, and the
  anti-verification gate that mutates positive vectors and disables check
  families to prove the vectors test what they claim to test.
- **Repository metadata**: licensing split (Apache-2.0 for code, schemas and
  vectors; CC-BY-4.0 for specification and documentation prose), REUSE
  annotations, the Inceptless CLA draft, README files in English and Chinese,
  SECURITY, CONTRIBUTING, the positioning document, and CI workflow
  `.github/workflows/ci.yml`.

### Explicitly not yet true in this version

- **The format is not accepted.** `weave-record/1` v0.1 has **not** been
  accepted by the J1/J2 round-trip acceptance cases; that acceptance is what
  would make v0.1 valid. The draft may still change.
- **There is only one implementation.** The Python reference verifier is the
  only verifier in this repository, so the format cannot yet claim independent
  implementations. The second (Rust) implementation is deliberately left to a
  separate implementer and is not part of H0.
- **No transport package.** The planned offline transport component has not
  been extracted or shipped.
- **No project adapters.** Export and import adapters for the projects that will
  use `weave-record/1` live in those projects and are not part of this
  repository.
- **Not published.** The repository is private and has not been pushed to a
  public host; the CI workflow exists but has never run on GitHub. The verifier
  has not been released to PyPI and is installed from this repository.
- **Not every question is settled.** Decisions that fill gaps in the decision
  draft are marked `PROVISIONAL` in the specification and tracked in
  `docs/open-questions.md`.

### Verifying this snapshot

The gate commands are listed in [CONTRIBUTING.md](CONTRIBUTING.md) and run in
[`.github/workflows/ci.yml`](.github/workflows/ci.yml). Run them from the
repository root to check this snapshot; the repository does not claim in this
file that any particular gate run passed.
