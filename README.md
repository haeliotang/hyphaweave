<!-- SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com> -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

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
  specification, schemas, vectors and one verifier; it does not perform the
  round trips.
- **Not independently implemented yet.** Only **one** implementation exists:
  the Python reference verifier in this repository. A single implementation
  cannot demonstrate that the format is implementable from the specification
  alone, so this repository does **not** claim independent implementations.
  The Rust verifier (milestone H1) is deliberately left to a separate
  implementer and is not part of H0.
- **Not published.** The repository is currently private and has not been pushed
  to a public host. The CI workflow exists but has never run on GitHub, and the
  verifier has not been released to PyPI. It is installed from this repository.
- **H0 scope only.** There is no offline transport package, no project export or
  import adapter, and no network service in this repository.

The Python verifier is a reference implementation, not a product: it is written
to make the specification testable and to give a second implementer something
to compare against, not to imply that the format is settled.

## What is in this repository

| Path | Contents |
| --- | --- |
| [`spec/weave-record-1.md`](spec/weave-record-1.md) | Normative specification (RFC 2119 keywords) covering the envelope, references, containers, erasure and authorization. |
| [`spec/kinds/`](spec/kinds/) | One page per registered `weave.*` kind. |
| [`spec/error-codes.md`](spec/error-codes.md) | Closed registry of verifier error codes and notices. |
| [`spec/offline-verification.md`](spec/offline-verification.md) | Step-by-step manual verification of an L0 container with common tools only (`sha256sum`, `openssl`, a JSON viewer). |
| [`schemas/`](schemas/) | JSON Schema 2020-12 for the envelope, references, manifests and registered kinds. |
| [`vectors/`](vectors/) | Positive and negative conformance vectors, a frozen v0.1 regression set, deliberately public test keys, and provenance for official external test data. |
| [`verifiers/python/`](verifiers/python/) | `hyphaweave_verify` 0.1.0 and the `hyphaweave-verify` command line. |
| [`tools/`](tools/) | Independent vector generators (they do not import the verifier) and the gate scripts. |
| [`docs/positioning.md`](docs/positioning.md) | Non-normative positioning: scope, non-goals, responsibilities, risks. |
| [`docs/open-questions.md`](docs/open-questions.md) | Provisional choices H0 made where the decision draft left gaps. |

## Using the verifier

The verifier needs Python 3.11 or newer and has no network access at runtime.
Its JSON reports are deterministic: the same input produces the same bytes on
any machine.

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
python -m pip install -e "verifiers/python[dev]"
```

The command-line surface is:

```bash
hyphaweave-verify record <file> [--keys <dir>] [--json]
hyphaweave-verify container <dir|zip> [--keys <dir>] [--tsa-trust <pem>] [--previous <dir>]
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

# the conformance vectors; the frozen set is a directory argument as well
hyphaweave-verify vectors vectors
hyphaweave-verify vectors vectors/frozen/v0.1
```

`--keys` points at a directory of key-lifecycle records (its top-level
`*.json` files); it supplies public keys and their declared lifecycle, and is
not part of the container being verified. `--tsa-trust` supplies L2 timestamp
trust anchors; `--previous` additionally checks a previous container's manifest
digest against the embedded chain.

Every run prints exactly one deterministic JSON report to stdout (no colour, no
progress output); usage and I/O errors go to stderr. Exit status: `0` means
valid (or `erased` for an erasure placeholder, or every vector case matched),
`1` means invalid, unverifiable or a vector mismatch, and `2` means a usage or
I/O error. Reported verdicts are `valid`, `invalid`, `unverifiable` and
`erased`; `unverifiable` is used honestly when a check cannot be completed (for
example an unknown key or a missing timestamp trust anchor), and such a result
is never reported as `valid`. The verifier does not use the network, the wall
clock, the locale, the time zone or the current directory in its output.

L2 timestamps are verified only against a trust anchor supplied with
`--tsa-trust`. Without one, a timestamp is reported as `present-unverified` and
the container as `unverifiable`. The TSA key and certificate under
`vectors/keys/tsa/` are public test material; never trust them outside the test
vectors.

## Running the gates

From the repository root, with the virtual environment activated and `reuse`
installed (`python -m pip install reuse==5.0.2`):

```bash
python -m pytest verifiers/python/tests -q
hyphaweave-verify vectors vectors
hyphaweave-verify vectors vectors/frozen/v0.1
python tools/check_schemas.py
python tools/check_external.py
python tools/anti_verification.py
reuse lint
```

These are the same commands as [`.github/workflows/ci.yml`](.github/workflows/ci.yml).
This README does not claim that a particular gate run passed; run the commands
to check your checkout. The gate results reported for the H0 hand-off snapshot
are summarized in [`CHANGELOG.md`](CHANGELOG.md).

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
- Brand assets (none are present in this repository): reserved under
  `LicenseRef-Inceptless-Brand`.
- External test data under `vectors/external/` keeps the license of its
  upstream source, recorded next to the data.

See [`LICENSING.md`](LICENSING.md) for the full split and the SHA-256 of the
official license texts. Contributions require the Inceptless Contributor
License Agreement (CLA v1.0, in force since 2026-11-10, decisions #27/#28); the
repository is private and does not accept external contributions yet. See
[`CONTRIBUTING.md`](CONTRIBUTING.md).

## Security and contact

Security reports and all other contact: **support@inceptless.com** — the only
address used by this repository. Please read [`SECURITY.md`](SECURITY.md) first:
the test keys under `vectors/keys/` are deliberately public test material, not
leaked secrets, and a signature does not prove that the signed claims are true.

The repository currently has no public issue tracker because it is private.
