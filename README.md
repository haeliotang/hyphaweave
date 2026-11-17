<!-- SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com> -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/hyphaweave-mono-inverse.svg">
    <img src="assets/hyphaweave-mono.svg" width="120" alt="Hyphaweave — Two threads, braided">
  </picture>
</p>

# Hyphaweave

**The common thread between independent systems.**

Hyphaweave defines `weave-record/1`, a format for exchanging and referencing
records across independent projects: records are exported into one common
format, accepted verbatim, and cross-project references are always
"origin + id + digest". Each project keeps its own internal storage. This
repository holds the specification, JSON Schemas, conformance vectors and the
Python reference verifier for format version `weave-record/1`.

## Status: draft, not stable, not accepted

Read this before using anything in this repository:

- **Draft, not stable.** `weave-record/1` is at draft v0.1. The format can still
  change, and no compatibility promise is made before v1.0.
- **Not accepted yet.** `weave-record/1` v0.1 has **not** passed the J1/J2
  round-trip acceptance cases yet. Until those round trips between independent
  projects are actually performed, v0.1 is not valid. H0 produces the
  specification, schemas, vectors and the Python verifier; it does not perform
  the round trips.
- **Two implementations: the Python reference verifier and the Rust verifier;
  both have followed revision 3, including the S2 round, its revisions S2-FIX1 to
  S2-FIX6 and the supplement S2-FIX2b.** The Python
  reference verifier lives in `verifiers/python/`; the second, independent
  implementation (milestone H1, `verifiers/rust/`) was written from the
  specification and the conformance vectors only. Its revisions H1-FIX1 to
  H1-FIX2B implement revision 3 of the specification and the S1 rounds, and its
  findings (`docs/h1-findings.md`) led to the S2 round of revision 3 (decision
  2026-11-15 #8) and its revisions S2-FIX1 and S2-FIX2 (decisions 2026-11-15 #18
  and #22, the supplement S2-FIX2b, decision 2026-11-15 #32, S2-FIX3, decision
  2026-11-16 #1, and S2-FIX4, S2-FIX5 and S2-FIX6, decisions 2026-11-16 #4, #9 and #13),
  which both verifiers now implement (the Rust follow-ups H1-S2 to H1-S5, decisions
  2026-11-15 #20 and 2026-11-16 #10, #13 and #14), and the S3 round on blob error codes
  (decision 2026-11-16 #44) with its revisions S3-FIX1 and S3-FIX2 (decisions 2026-11-17
  #5 and 2026-11-18 #2 and #3), and the S4 round on two disagreements in the signature
  layer (decision 2026-11-18 #4): each passes all 815 main vectors and the
  202 candidate regression vectors, and their reports are byte-identical on every case (the
  gate-3 allow list is empty). Passing the same vectors is necessary but not sufficient
  evidence that the format is implementable from the text alone.
- **Public, still draft.** The repository is public now, but that does not make
  `weave-record/1` stable: it remains a draft, and v1.0 still depends on the
  J1/J2 acceptance cases and on a second implementation that conforms to the
  current revision. The verifier has not been released to PyPI and is installed
  from this repository. The workflow in `.github/workflows/ci.yml` runs the
  same commands as the local gates below; this README does not claim that a
  particular GitHub Actions run passed.
- **H0 scope only.** There is no offline transport package, no project export or
  import adapter, and no network service in this repository.
- **Revised after review.** This snapshot includes H0 revision 1 (decision
  2026-11-10 #34), revision 2 (decision 2026-11-10 #42) and revision 3 (decision
  2026-11-11 #2) with its five follow-up rounds S1-FIX1 to S1-FIX5 (decisions
  2026-11-11 #5, #12, #14 and #16, and 2026-11-12 #1, #2 and #3) and the S2 round
  (decision 2026-11-15 #8) with its revisions S2-FIX1 to S2-FIX6 and the supplement
  S2-FIX2b (decisions 2026-11-15 #18, #22 and #32, and 2026-11-16 #1, #4, #9 and #13),
  and the S3 round on blob error codes with its revisions S3-FIX1 and S3-FIX2 (decisions
  2026-11-16 #44, 2026-11-17 #5 and 2026-11-18 #2 and #3), and the S4 round (decision
  2026-11-18 #4). Independent reviews found
  wire-semantics
  defects, and the revisions changed the format rules, the error-code registry,
  the trust-root model, the resource limits, the verifier and the vectors.
  Revision 3 reacts to the review of the second (Rust) implementation, which
  ran against the earlier text on its own branch; the S1 rounds then closed the
  defects that further reviews found in the revised text and in the Python
  verifier, and the S2 round closed the ambiguities and Python defects that the
  second implementation recorded (among them a security defect: a key
  declaration signed by a compromised key was accepted when the only receipt
  that could rescue it failed). The S3 round gave every blob violation one code, and
  S3-FIX1 closed the remaining disagreements between the two verifiers that its reviews
  and the differential fuzz found (among them a security defect in the Rust verifier: a
  zip directory entry named `../x/` or `/abs/` skipped the path-safety check and the
  container was accepted), and S3-FIX2 closed one more that the narrow review of S3-FIX1
  found (the Rust verifier took a zero-data entry with the DOS directory attribute and no
  final `/` for a directory entry, and accepted a zip that held `blobs/sha256` without a
  blob listing) and made `N_READABLE_PRESENT` independent of the order of the zip central
  directory, as the reference verifier already had it. The S4 round closed two older
  disagreements in the signature layer that the differential fuzz found: which
  declarations make a key "declared human" for `N_NO_HUMAN_SIGNATURE` (the reference
  verifier changed), and a revocation whose outcome in the Rust verifier depended on the
  order in which it computed the key state. The regression set is a **candidate**
  (`vectors/frozen/v0.1-candidate/`); official freeze begins only after J1/J2
  acceptance. See [`CHANGELOG.md`](CHANGELOG.md).

The Python verifier is a reference implementation, not a product: it is written
to make the specification testable and to give a second implementer something
to compare against, not to imply that the format is final.

## What is in this repository

| Path | Contents |
| --- | --- |
| [`spec/weave-record-1.md`](spec/weave-record-1.md) | Normative specification (RFC 2119 keywords) covering the envelope, references, containers, erasure and authorization. |
| [`spec/kinds/`](spec/kinds/) | One page per registered `weave.*` kind. |
| [`spec/error-codes.md`](spec/error-codes.md) | Closed registry of verifier error codes and notices. |
| [`spec/offline-verification.md`](spec/offline-verification.md) | Step-by-step manual verification of an L0 container with common tools only (`sha256sum`, `openssl`, a JSON viewer). |
| [`schemas/`](schemas/) | JSON Schema 2020-12 for the envelope, references, manifests and registered kinds. |
| [`vectors/`](vectors/) | Positive and negative conformance vectors, the v0.1 candidate regression set (freeze follows J1/J2 acceptance), deliberately public test keys, and provenance for official external test data. |
| [`verifiers/python/`](verifiers/python/) | `hyphaweave_verify` 0.1.0 and the `hyphaweave-verify` command line. |
| [`tools/`](tools/) | Independent vector generators (they do not import the verifier) and the gate scripts. |
| [`docs/positioning.md`](docs/positioning.md) | Non-normative positioning: scope, non-goals, responsibilities, risks. |
| [`docs/open-questions.md`](docs/open-questions.md) | The questions decided by decision 2026-11-10 #34 (Q1–Q33) and the implementation-shape choices that remain PROVISIONAL. |

## Using the verifier

The verifier needs Python 3.11 or newer and has no network access at runtime.
Its JSON reports are deterministic: the same input produces the same bytes on
any machine.

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
python -m pip install -c verifiers/python/constraints.txt -e "verifiers/python[dev]"
```

The exact dependency versions used for the H0 build are pinned in
[`verifiers/python/constraints.txt`](verifiers/python/constraints.txt); only the
versions pinned there and in `pyproject.toml` are guaranteed. The S1 rounds ran
the gates locally on Python 3.12 (the CI version) and on Python 3.14 with
identical results; Python 3.11 has not been exercised. The 3.12 workflow is
defined in `.github/workflows/ci.yml` and is not claimed here to have passed.

The command-line surface is:

```bash
hyphaweave-verify record <file> [--keys <dir>] [--json]
hyphaweave-verify container <dir|zip> [--keys <dir>] [--tsa-trust <pem>] [--previous <dir|zip>]
hyphaweave-verify vectors <dir> [--tsa-trust <pem>]
hyphaweave-verify --help
hyphaweave-verify --version
```

For example, from the repository root:

```bash
# one record, with external key-lifecycle records supplied as context
hyphaweave-verify record path/to/record.json --keys vectors/keys/keyset

# a container directory or zip; no timestamp trust anchor is supplied here
hyphaweave-verify container path/to/container

# the conformance vectors; the candidate regression set is a directory argument too
hyphaweave-verify vectors vectors
hyphaweave-verify vectors vectors/frozen/v0.1-candidate
```

`--keys` points at a directory of key-lifecycle records (every top-level entry
whose name ends in `.json`); it supplies public keys and their declared
lifecycle, and is not part of the container being verified. `--tsa-trust`
supplies L2 timestamp trust anchors (a file of PEM certificates). `--previous`
takes the previous container of the chain, as a directory or a zip, and links
it: only its `manifest.json` and `signatures/manifest.sig.json` are read, its
manifest signature is verified **in the context of the container being
verified** (the supplied keyset plus that container's own key records, so a
device key that the keyset trusts only through its owner links as well), and its
manifest digest must equal the container's `previous_manifest.digest`.
Everything else in the previous container is not verified; the report says so
with `L_PREVIOUS_CONTENT_UNVERIFIED`, and to verify the previous container
itself, run it as a target. `--keys`, `--tsa-trust` and the `--previous` path
are operator inputs: one that cannot be read or decoded is a usage error
(exit `2`, no report).

Every run prints exactly one deterministic JSON report to stdout (no colour, no
progress output); usage and I/O errors go to stderr. Exit status: `0` means
valid (or `erased` for an erasure placeholder, or every vector case matched),
`1` means invalid, unverifiable or a vector mismatch, `2` means a usage or I/O
error, and `3` means that the test-only check-skip hook (`--test-hooks`, never
for production use) disabled at least one check. Reported verdicts are `valid`, `invalid`, `unverifiable` and
`erased`; `unverifiable` is used honestly when a check cannot be completed (for
example an unknown key or a missing timestamp trust anchor), and such a result
is never reported as `valid`. The verifier does not use the network, the wall
clock, the locale, the time zone or the current directory in its output.

L2 timestamps are verified only against a trust anchor supplied with
`--tsa-trust`. Without one, a timestamp is reported as `present-unverified` and
the container as `unverifiable`. A container's `level_verified` is always `"L0"`
(the internal hash chain of L1/L2 cannot be re-verified offline); L2 reports
`anchor_verified: true` only when the whole timestamp chain verifies against a
supplied anchor. The TSA key and certificate under `vectors/keys/tsa/` are
public test material; never trust them outside the test vectors.

## Running the gates

From the repository root, with the virtual environment activated and `reuse`
installed (`python -m pip install reuse==5.0.2`):

```bash
python tools/make_keys.py --check
python tools/gen_vectors.py --check
python tools/gen_vectors_extra.py --check
python tools/gen_index.py --check
python -m pytest verifiers/python/tests -q
hyphaweave-verify vectors vectors
( cd vectors/frozen/v0.1-candidate && sha256sum -c --strict SHA256SUMS )
python tools/check_frozen.py
hyphaweave-verify vectors vectors/frozen/v0.1-candidate
python tools/check_schemas.py
python tools/check_external.py
python tools/anti_verification.py
python tools/byte_flip_gate.py
python tools/crash_fuzz.py
python tools/check_spec_examples.py
reuse lint
```

These are the same commands as the Python job of
[`.github/workflows/ci.yml`](.github/workflows/ci.yml). The three last gates
before `check_spec_examples.py` start parallel workers; on a machine that also
runs other work, add `--jobs 2` to each (see [`tools/README.md`](tools/README.md)).
This README does not claim that a particular gate run passed; run the commands
to check your checkout. The only recorded gate figures are those of the
revision-1 snapshot, kept in [`CHANGELOG.md`](CHANGELOG.md) ("Verifying this
snapshot").

To verify a container by hand without trusting any implementation, follow
[`spec/offline-verification.md`](spec/offline-verification.md): it uses only
`sha256sum`, `openssl` and a JSON viewer, and works through an L0 container
example from `vectors/`.

## Non-goals

Hyphaweave deliberately does **not** do the following:

- **No identity provider.** It does not decide who is a human, issue credentials
  or handle login. A key identifier is a public-key fingerprint; DIDs and URLs
  are only hints.
- **No blockchain and no transparency log.** Time anchoring uses RFC 3161
  timestamps; records can carry timestamps from several services.
- **No sync service and no network.** The verifier is offline; the planned
  transport component moves files but provides no server, relay network or
  discovery.
- **No storage unification.** Each project keeps its internal storage.
- **No proof that facts are true.** A signature proves which key signed which
  bytes and that the bytes have not changed.
- **No global deletion guarantee.** Erasure constrains exported artifacts and
  references; copies that have already spread elsewhere are not promised to be
  deleted.
- **No exception channel for agents.** Strictest-label propagation and the
  `local-only` export refusal apply to agents exactly as they do to humans.

See [`docs/positioning.md`](docs/positioning.md) for the longer non-normative
version.

## Licensing

- Code, JSON Schemas and conformance vectors: **Apache-2.0**.
- Specification and documentation prose: **CC-BY-4.0**.
- Brand assets (`assets/`): the project logo is reserved under
  `LicenseRef-Inceptless-Brand`; it may be used to refer to the project, but not
  in a way that suggests official status or endorsement.
- External test data under `vectors/external/` keeps the license of its
  upstream source, recorded next to the data.

See [`LICENSING.md`](LICENSING.md) for the full split and the SHA-256 of the
official license texts. Contributions require the Inceptless Contributor
License Agreement (CLA v1.0, in force since 2026-11-10, decisions #27/#28); the
repository is now public, but external contributions are accepted only once the
CLA signing check is active for it. See [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Security and contact

Security reports and all other contact: **support@inceptless.com** — the only
address used by this repository. Please read [`SECURITY.md`](SECURITY.md) first:
the test keys under `vectors/keys/` are deliberately public test material, not
leaked secrets, and a signature does not prove that the signed claims are true.

The repository is public now; security reports still go to support@inceptless.com rather than to a public issue (see [`SECURITY.md`](SECURITY.md)).
